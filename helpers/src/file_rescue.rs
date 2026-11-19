// SPDX-License-Identifier: MIT
//! Existing recovery wizard wire contract, using durable one-shot reviews.
use crate::{
    accounts, drives,
    endpoints::{self, Endpoint},
    manager_apply, manager_plan, rescue_copy, reviews,
};
use enzimos_platform::{Error, Result, files, json, require};
use serde_json::{Value, json as value};
use std::{collections::BTreeSet, os::unix::fs::MetadataExt, path::Path};
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v[key]
        .as_str()
        .ok_or_else(|| Error("backup field type".into()))
}
/// The wizard preserves full source paths in a new backup tree. Drag and drop
/// preserves selected basenames, as the file manager does.
pub fn layout(records: &mut [Value], roots: &[std::path::PathBuf], direct: bool) -> Result<()> {
    if direct {
        let names = roots.iter().map(|p| p.file_name()).collect::<BTreeSet<_>>();
        require(
            names.len() == roots.len() && !names.contains(&None),
            "selected names duplicated; copy separately",
        )?;
    } else {
        for row in records {
            let path = Path::new(text(row, "source")?);
            let relative = path
                .strip_prefix("/")
                .map_err(|_| Error("backup source must be absolute".into()))?;
            let relative = relative
                .to_str()
                .filter(|s| !s.is_empty())
                .ok_or_else(|| Error("backup relative path".into()))?;
            crate::file_paths::destination(relative)?;
            row["relative"] = value!(relative);
        }
    }
    Ok(())
}
fn direct(v: &Value) -> Result<bool> {
    match v.get("direct") {
        None => Ok(false),
        Some(Value::Bool(b)) => Ok(*b),
        _ => Err(Error("backup direct flag type".into())),
    }
}
pub fn plan(request: &Value) -> Result<Value> {
    drives::private()?;
    let user = accounts::authenticated_account()?;
    let _operation = enzimos_policy::operation::lock()?;
    let source = Endpoint::new(&value!({}))?;
    let drive = text(request, "drive")?;
    let destination = Endpoint::new(&value!({"drive":drive}))?;
    let direct = direct(request)?;
    let parent = if direct {
        request
            .get("destination_path")
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| Error("backup destination path type".into()))
            })
            .transpose()?
            .unwrap_or("")
    } else {
        ""
    };
    let parent = destination.normalize(parent)?;
    let parent = parent
        .to_str()
        .ok_or_else(|| Error("backup destination encoding".into()))?;
    let target = destination.open(parent, true)?;
    let mut scan = endpoints::scan(&source, &request["paths"], true)?;
    require(
        !scan.records.is_empty(),
        "no regular files or folders selected",
    )?;
    layout(&mut scan.records, &scan.roots, direct)?;
    if direct {
        for root in &scan.roots {
            manager_plan::absent(
                &target,
                root.file_name()
                    .ok_or_else(|| Error("backup selection name".into()))?,
            )?;
        }
    }
    let fat = destination
        .external
        .as_ref()
        .is_some_and(|d| d.drive["fstype"] == "vfat");
    if destination
        .external
        .as_ref()
        .is_some_and(|d| crate::fat_names::restricted(d.drive["fstype"].as_str().unwrap_or("")))
    {
        crate::fat_names::partition(&mut scan.records, &mut scan.skipped);
    }
    let mut bytes = 0u64;
    let mut count = 0usize;
    for r in &scan.records {
        if r["kind"] == "file" {
            let n = r["identity"][3]
                .as_u64()
                .ok_or_else(|| Error("backup byte count".into()))?;
            require(
                !fat || n < 1u64 << 32,
                "FAT32 cannot hold files larger than four GiB",
            )?;
            bytes = bytes
                .checked_add(n)
                .ok_or_else(|| Error("backup total overflow".into()))?;
            count += 1;
        }
    }
    let free = manager_plan::free(&target, bytes, scan.records.len() as u64)?;
    let m = target.metadata()?;
    source.check()?;
    destination.check()?;
    let label = destination
        .external
        .as_ref()
        .ok_or_else(|| Error("backup requires external drive".into()))?
        .drive["label"]
        .clone();
    let payload = value!({"operation":"rescue-copy","source":source.binding(),"destination":destination.binding(),"drive":drive,"direct":direct,"parent":parent,"parent_identity":[m.dev(),m.ino()],"roots":scan.roots,"records":scan.records,"skipped":scan.skipped,"bytes":bytes,"files":count});
    let saved =
        reviews::Store::new(Path::new(drives::STATE), 0)?.save(&payload, user.uid, user.gid)?;
    Ok(
        value!({"plan":saved["plan"],"digest":saved["digest"],"bytes":bytes,"files":count,"skipped":scan.skipped.len(),"destination":label,"free":free}),
    )
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (localtime_r, strftime, time)."
)]
fn folder_name() -> Result<String> {
    let now = unsafe { libc::time(std::ptr::null_mut()) };
    require(now >= 0, "backup clock unavailable")?;
    let mut date = std::mem::MaybeUninit::<libc::tm>::uninit();
    require(
        !unsafe { libc::localtime_r(&now, date.as_mut_ptr()) }.is_null(),
        "backup date unavailable",
    )?;
    let mut buffer = [0u8; 32];
    let n = unsafe {
        libc::strftime(
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            c"%Y%m%d-%H%M%S".as_ptr(),
            date.as_ptr(),
        )
    };
    require(n > 0, "backup date bound")?;
    let date =
        std::str::from_utf8(&buffer[..n]).map_err(|_| Error("backup date encoding".into()))?;
    Ok(format!("enzimOS-backup-{date}-{}", files::random_hex(8)?))
}
pub fn copy<F: FnMut(Value) -> Result<()>>(request: &Value, emit: F) -> Result<Value> {
    drives::private()?;
    let user = accounts::authenticated_account()?;
    let _operation = enzimos_policy::operation::lock()?;
    let token = text(request, "plan")?;
    let store = reviews::Store::new(Path::new(drives::STATE), 0)?;
    let mut source = None;
    let mut destination = None;
    let mut record = store.consume(token, text(request, "digest")?, user.uid, |r| {
        json::fields(r, "operation source destination drive direct parent parent_identity roots records skipped bytes files owner gid created digest")?;
        require(r["operation"] == "rescue-copy" && r["gid"].as_u64() == Some(user.gid as u64), "backup review identity changed")?;
        let s = manager_apply::binding(&r["source"])?;
        let d = manager_apply::binding(&r["destination"])?;
        require(s.external.is_none() && d.external.as_ref().is_some_and(|p|p.drive["id"] == r["drive"]), "backup review drive changed")?;
        let rows = r["records"].as_array().ok_or_else(||Error("backup reviewed records".into()))?;
        endpoints::verify(&s, rows)?;
        let parent = d.open(text(r, "parent")?, true)?;
        let m = parent.metadata()?;
        require(r["parent_identity"] == value!([m.dev(),m.ino()]), "backup destination folder changed")?;
        manager_plan::free(&parent, r["bytes"].as_u64().ok_or_else(||Error("backup reviewed bytes".into()))?, rows.len() as u64)?;
        require(r["direct"].is_boolean(), "backup reviewed direct flag")?;
        if r["direct"] == true {
            for root in r["roots"].as_array().ok_or_else(||Error("backup reviewed roots".into()))? {
                let p = Path::new(text_root(root)?);
                manager_plan::absent(&parent, p.file_name().ok_or_else(||Error("backup reviewed name".into()))?)?;
            }
        }
        s.check()?; d.check()?;
        require(accounts::authenticated_account()? == user, "administrator identity changed")?;
        source = Some(s); destination = Some(d); Ok(())
    })?;
    let source = source.ok_or_else(|| Error("backup source unavailable".into()))?;
    let destination = destination.ok_or_else(|| Error("backup destination unavailable".into()))?;
    let direct = record["direct"] == true;
    source.check()?;
    destination.check()?;
    let folder = if direct {
        let p = text(&record, "parent")?;
        if p.is_empty() {
            "/".to_owned()
        } else {
            p.to_owned()
        }
    } else {
        let folder = folder_name()?;
        let root = rescue_copy::mkdir(&destination.directory, &folder, user.uid, user.gid)?;
        let m = root.metadata()?;
        record["parent"] = value!(&folder);
        record["parent_identity"] = value!([m.dev(), m.ino()]);
        folder
    };
    rescue_copy::execute_legacy(&source, &destination, &record, token, direct, emit)?;
    let result = value!({"copied":true,"items":record["records"].as_array().map_or(0,Vec::len),"folder":folder,"files":record["files"],"bytes":record["bytes"],"skipped":record["skipped"].as_array().map_or(0,Vec::len),"drive":record["drive"]});
    store.complete(token, &result)?;
    Ok(result)
}
fn text_root(v: &Value) -> Result<&str> {
    v.as_str()
        .ok_or_else(|| Error("backup reviewed root path".into()))
}
