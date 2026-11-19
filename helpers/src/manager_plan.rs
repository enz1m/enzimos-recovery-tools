// SPDX-License-Identifier: MIT
use crate::{
    accounts, drives,
    endpoints::{self, Endpoint},
    file_paths, reviews,
};
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::CString,
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::MetadataExt},
    },
    path::Path,
};
fn text<'a>(v: &'a Value, k: &str) -> Result<&'a str> {
    v[k].as_str()
        .ok_or_else(|| Error("file operation field".into()))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
pub fn absent(parent: &std::fs::File, name: &std::ffi::OsStr) -> Result<()> {
    let name = CString::new(name.as_bytes()).map_err(|_| Error("destination filename".into()))?;
    let mut st = std::mem::MaybeUninit::<libc::stat>::uninit();
    let result = unsafe {
        libc::fstatat(
            parent.as_raw_fd(),
            name.as_ptr(),
            st.as_mut_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    };
    require(
        result < 0 && std::io::Error::last_os_error().raw_os_error() == Some(libc::ENOENT),
        "destination already exists or cannot be observed",
    )
}
/// `items`: files and folders to create; each occupies at least one allocation
/// unit (32 KiB clusters on large FAT/exFAT drives turn many small files into
/// far more space than their byte total).
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatvfs).")]
pub fn free(directory: &std::fs::File, required: u64, items: u64) -> Result<u64> {
    let mut info = std::mem::MaybeUninit::<libc::statvfs>::uninit();
    require(
        unsafe { libc::fstatvfs(directory.as_raw_fd(), info.as_mut_ptr()) } == 0,
        "destination space unavailable",
    )?;
    let info = unsafe { info.assume_init() };
    let available = info
        .f_bavail
        .checked_mul(info.f_frsize)
        .ok_or_else(|| Error("destination space overflow".into()))?;
    let required = items
        .checked_mul(info.f_frsize.max(512))
        .and_then(|slack| required.checked_add(slack))
        .ok_or_else(|| Error("destination space overflow".into()))?;
    let reserve = (4 * 1024 * 1024).max(required / 50);
    require(
        required.checked_add(reserve).is_some_and(|n| n < available),
        "not enough free destination space",
    )?;
    Ok(available)
}
pub fn same_tree(a: &Endpoint, b: &Endpoint) -> bool {
    match (&a.external, &b.external) {
        (None, None) => true,
        (Some(a), Some(b)) => a.unique == b.unique && a.drive["id"] == b.drive["id"],
        _ => false,
    }
}
pub fn plan(request: &Value) -> Result<Value> {
    drives::private()?;
    let user = accounts::authenticated_account()?;
    let _operation = enzimos_policy::operation::lock()?;
    let operation = text(request, "operation")?;
    require(
        matches!(operation, "copy" | "delete" | "rename" | "mkdir"),
        "unknown file operation",
    )?;
    let source = Endpoint::new(&request["source"])?;
    let mut value = json!({"operation":operation,"source":source.binding()});
    let mut destination = None;
    if operation == "mkdir" {
        let parent = text(request, "path")?;
        let fd = source.open(parent, true)?;
        let m = fd.metadata()?;
        let name = file_paths::name(text(request, "name")?)?;
        absent(&fd, std::ffi::OsStr::new(name))?;
        value["parent"] = json!(parent);
        value["parent_identity"] = json!([m.dev(), m.ino()]);
        value["name"] = json!(name);
    } else {
        let mut scan = endpoints::scan(&source, &request["paths"], operation == "copy")?;
        require(
            !scan.records.is_empty(),
            "no regular files or folders selected",
        )?;
        if operation == "rename" {
            require(scan.roots.len() == 1, "rename one item at a time")?;
            let name = file_paths::name(text(request, "name")?)?;
            let parent = scan.roots[0]
                .parent()
                .and_then(Path::to_str)
                .ok_or_else(|| Error("rename parent path".into()))?;
            let held = source.open(parent, true)?;
            absent(&held, std::ffi::OsStr::new(name))?;
            value["name"] = json!(name);
        }
        if operation == "copy" {
            let end = Endpoint::new(&request["destination"])?;
            let target = end.normalize(text(request, "path")?)?;
            let target_text = target
                .to_str()
                .ok_or_else(|| Error("destination encoding".into()))?;
            let fd = end.open(target_text, true)?;
            let names = scan
                .roots
                .iter()
                .map(|r| r.file_name().unwrap())
                .collect::<BTreeSet<_>>();
            require(
                names.len() == scan.roots.len(),
                "selected names duplicated; copy separately",
            )?;
            if same_tree(&source, &end) {
                require(
                    !scan.roots.iter().any(|p| target.starts_with(p)),
                    "folder cannot be copied into itself",
                )?;
            }
            for name in names {
                absent(&fd, name)?;
            }
            if end.external.as_ref().is_some_and(|d| {
                crate::fat_names::restricted(d.drive["fstype"].as_str().unwrap_or(""))
            }) {
                crate::fat_names::partition(&mut scan.records, &mut scan.skipped);
                require(
                    !scan.records.is_empty(),
                    "no selected item can be stored on this drive",
                )?;
            }
            let mut total = 0u64;
            for r in &scan.records {
                if r["kind"] == "file" {
                    let bytes = r["identity"][3]
                        .as_u64()
                        .ok_or_else(|| Error("review file size".into()))?;
                    total = total
                        .checked_add(bytes)
                        .ok_or_else(|| Error("selection byte overflow".into()))?;
                    if end
                        .external
                        .as_ref()
                        .is_some_and(|d| d.drive["fstype"] == "vfat")
                    {
                        require(
                            bytes < 1u64 << 32,
                            "FAT32 cannot hold files larger than four GiB",
                        )?;
                    }
                }
            }
            free(&fd, total, scan.records.len() as u64)?;
            let m = fd.metadata()?;
            value["destination"] = end.binding();
            value["parent"] = json!(target_text);
            value["parent_identity"] = json!([m.dev(), m.ino()]);
            value["bytes"] = json!(total);
            destination = Some(end);
        }
        value["roots"] = json!(scan.roots);
        value["records"] = json!(scan.records);
        value["skipped"] = json!(scan.skipped);
    }
    source.check()?;
    if let Some(d) = destination {
        d.check()?;
    }
    reviews::Store::new(Path::new(drives::STATE), 0)?.save(&value, user.uid, user.gid)
}
