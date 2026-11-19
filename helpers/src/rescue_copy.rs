// SPDX-License-Identifier: MIT
//! No-overwrite copying with independent readback, retained incomplete markers.
use crate::{endpoints::Endpoint, file_paths, manager_plan};
use enzimos_platform::{Error, Result, files, mount_identity, require};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    ffi::CString,
    fs::File,
    io::{Read, Seek, SeekFrom, Write},
    os::{
        fd::{AsFd, AsRawFd, FromRawFd},
        unix::fs::MetadataExt,
    },
    time::{Duration, Instant},
};
#[allow(unsafe_code, reason = "Linux syscall ABI (openat).")]
pub fn exclusive(parent: &File, name: &str, readwrite: bool) -> Result<File> {
    require(
        !name.is_empty() && !matches!(name, "." | "..") && !name.contains('/') && name.len() <= 255,
        "copy record name",
    )?;
    let name = CString::new(name).map_err(|_| Error("copy filename encoding".into()))?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_CREAT
                | libc::O_EXCL
                | libc::O_NOFOLLOW
                | libc::O_CLOEXEC
                | if readwrite {
                    libc::O_RDWR
                } else {
                    libc::O_WRONLY
                },
            0o600,
        )
    };
    require(fd >= 0, "copy record already exists or unavailable")?;
    Ok(unsafe { File::from_raw_fd(fd) })
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchown, mkdirat, openat).")]
pub fn mkdir(parent: &File, name: &str, uid: u32, gid: u32) -> Result<File> {
    let name = CString::new(file_paths::component(name)?).unwrap();
    require(
        unsafe { libc::mkdirat(parent.as_raw_fd(), name.as_ptr(), 0o700) } == 0,
        "destination folder already exists",
    )?;
    let fd = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
        )
    };
    require(fd >= 0, "new copy folder unavailable")?;
    let file = unsafe { File::from_raw_fd(fd) };
    require(
        unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "copy folder ownership failed",
    )?;
    file.sync_all()?;
    parent.sync_all()?;
    Ok(file)
}
#[allow(unsafe_code, reason = "Linux syscall ABI (posix_fadvise).")]
pub fn copy_file<F: FnMut(u64) -> Result<()>>(
    source: &mut File,
    output: &mut File,
    expected: &Value,
    mut progress: F,
) -> Result<String> {
    let before = source.metadata()?;
    require(
        before.is_file() && file_paths::identity(&before)? == *expected,
        "selected file changed after review",
    )?;
    let bytes = expected[3]
        .as_u64()
        .ok_or_else(|| Error("reviewed file byte count".into()))?;
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut sum = Sha256::new();
    let mut copied = 0u64;
    loop {
        let n = source.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        copied = copied
            .checked_add(n as u64)
            .ok_or_else(|| Error("copy byte overflow".into()))?;
        require(copied <= bytes, "source file grew")?;
        output.write_all(&buffer[..n])?;
        sum.update(&buffer[..n]);
        progress(n as u64)?;
    }
    require(
        copied == bytes && file_paths::identity(&source.metadata()?)? == *expected,
        "source changed during copy; retain incomplete bytes",
    )?;
    output.sync_all()?;
    // Request cache eviction before synced destination hash readback. This is
    // advisory; it does not prove a physical-device reread or power-loss persistence.
    unsafe { libc::posix_fadvise(output.as_raw_fd(), 0, 0, libc::POSIX_FADV_DONTNEED) };
    output.seek(SeekFrom::Start(0))?;
    let mut readback = Sha256::new();
    let mut checked = 0u64;
    loop {
        let n = output.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        checked = checked
            .checked_add(n as u64)
            .ok_or_else(|| Error("readback byte overflow".into()))?;
        require(checked <= bytes, "destination grew during readback")?;
        readback.update(&buffer[..n]);
        progress(n as u64)?;
    }
    let sum = sum.finalize();
    require(
        checked == bytes && readback.finalize() == sum,
        "copy readback failed; retain incomplete bytes",
    )?;
    Ok(format!("{sum:x}"))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (fchown).")]
fn owner(file: &File, uid: u32, gid: u32) -> Result<()> {
    require(
        unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } == 0,
        "copy file ownership failed",
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (futimens).")]
fn preserved_time(file: &File, expected: &Value) -> Result<()> {
    let ns = expected[4]
        .as_i64()
        .ok_or_else(|| Error("source timestamp".into()))?;
    let time = libc::timespec {
        tv_sec: ns.div_euclid(1000000000),
        tv_nsec: ns.rem_euclid(1000000000),
    };
    let times = [time, time];
    require(
        unsafe { libc::futimens(file.as_raw_fd(), times.as_ptr()) } == 0,
        "copy timestamp preservation failed",
    )
}
pub fn execute<F: FnMut(Value) -> Result<()>>(
    source: &Endpoint,
    destination: &Endpoint,
    record: &Value,
    token: &str,
    emit: F,
) -> Result<Value> {
    execute_style(source, destination, record, token, Style::Manager, emit)
}
#[derive(Clone, Copy, PartialEq)]
enum Style {
    Manager,
    Direct,
    NewTree,
}
pub fn execute_legacy<F: FnMut(Value) -> Result<()>>(
    source: &Endpoint,
    destination: &Endpoint,
    record: &Value,
    token: &str,
    direct: bool,
    emit: F,
) -> Result<Value> {
    execute_style(
        source,
        destination,
        record,
        token,
        if direct {
            Style::Direct
        } else {
            Style::NewTree
        },
        emit,
    )
}
#[allow(unsafe_code, reason = "Linux syscall ABI (unlinkat).")]
fn execute_style<F: FnMut(Value) -> Result<()>>(
    source: &Endpoint,
    destination: &Endpoint,
    record: &Value,
    token: &str,
    style: Style,
    mut emit: F,
) -> Result<Value> {
    require(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "copy review token",
    )?;
    let uid = record["owner"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .filter(|n| (1000..u32::MAX).contains(n))
        .ok_or_else(|| Error("copy administrator identity".into()))?;
    let gid = record["gid"]
        .as_u64()
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error("copy administrator group".into()))?;
    let parent = record["parent"]
        .as_str()
        .ok_or_else(|| Error("copy parent path".into()))?;
    let root = destination.open(parent, true)?;
    let m = root.metadata()?;
    require(
        record["parent_identity"] == json!([m.dev(), m.ino()]),
        "destination folder changed",
    )?;
    let total = record["bytes"]
        .as_u64()
        .ok_or_else(|| Error("copy total bytes".into()))?;
    manager_plan::free(
        &root,
        total,
        record["records"].as_array().map_or(0, Vec::len) as u64,
    )?;
    let marker = if style == Style::NewTree {
        "INCOMPLETE.txt".to_owned()
    } else {
        format!(".enzimos-incomplete-{token}.txt")
    };
    let mut incomplete = exclusive(&root, &marker, false)?;
    owner(&incomplete, uid, gid)?;
    incomplete.write_all(b"Incomplete copy. Keep the original files.\n")?;
    incomplete.sync_all()?;
    root.sync_all()?;
    let mut done = 0u64;
    let mut last = Instant::now() - Duration::from_secs(1);
    let mut owned: BTreeMap<String, (u64, u64, u64)> = BTreeMap::new();
    let mut manifest = Vec::new();
    let rows = record["records"]
        .as_array()
        .ok_or_else(|| Error("copy reviewed records".into()))?;
    require(rows.len() <= file_paths::LIMIT, "copy record count")?;
    let total_files = rows.iter().filter(|r| r["kind"] == "file").count();
    let mut files_done = 0usize;
    // The drive checks spawn lsblk; running them per file (twice) made large
    // copies of small files take tens of minutes. Check the drives at most
    // every two seconds and at the end; the destination folder's identity and
    // mount are still checked before every file and publication.
    let last_drive_check = std::cell::Cell::new(None::<Instant>);
    let drives = |force: bool| -> Result<()> {
        if force
            || last_drive_check
                .get()
                .is_none_or(|at| at.elapsed() >= Duration::from_secs(2))
        {
            source.check()?;
            destination.check()?;
            last_drive_check.set(Some(Instant::now()));
        }
        Ok(())
    };
    let check = || -> Result<()> {
        drives(false)?;
        let named = destination.open(parent, true)?;
        let m = named.metadata()?;
        require(
            (m.dev(), m.ino()) == (root.metadata()?.dev(), root.metadata()?.ino())
                && mount_identity::id(named.as_fd(), true)?
                    == mount_identity::id(root.as_fd(), true)?,
            "destination folder replaced or remounted",
        )
    };
    for r in rows {
        check()?;
        let relative = r["relative"]
            .as_str()
            .ok_or_else(|| Error("copy relative path".into()))?;
        let parts = file_paths::destination(relative)?;
        require(!parts.is_empty(), "copy relative filename")?;
        let mut parent = root.try_clone()?;
        for (i, part) in parts[..parts.len() - 1].iter().enumerate() {
            let key = parts[..i + 1].iter().collect::<std::path::PathBuf>();
            let key = key
                .to_str()
                .ok_or_else(|| Error("copied directory encoding".into()))?;
            if style == Style::NewTree && !owned.contains_key(key) {
                // This style is used only inside a newly created backup folder.
                // Never adopt a pre-existing ancestor, even there.
                let child = mkdir(
                    &parent,
                    part.to_str()
                        .ok_or_else(|| Error("copied name encoding".into()))?,
                    uid,
                    gid,
                )?;
                let m = child.metadata()?;
                owned.insert(
                    key.to_owned(),
                    (m.dev(), m.ino(), mount_identity::id(child.as_fd(), true)?),
                );
            }
            let child = file_paths::open_destination(
                &parent,
                part.to_str()
                    .ok_or_else(|| Error("copied name encoding".into()))?,
            )?;
            let m = child.metadata()?;
            require(
                owned.get(key)
                    == Some(&(m.dev(), m.ino(), mount_identity::id(child.as_fd(), true)?)),
                "copied directory replaced or remounted",
            )?;
            parent = child;
        }
        let name = parts
            .last()
            .unwrap()
            .to_str()
            .ok_or_else(|| Error("copy filename encoding".into()))?;
        if r["kind"] == "directory" {
            let child = mkdir(&parent, name, uid, gid)?;
            let m = child.metadata()?;
            owned.insert(
                relative.to_owned(),
                (m.dev(), m.ino(), mount_identity::id(child.as_fd(), true)?),
            );
        } else {
            require(
                r["kind"] == "file",
                "copy admits only regular files and folders",
            )?;
            let source_path = r["source"]
                .as_str()
                .ok_or_else(|| Error("copy source path".into()))?;
            let mut input = source.open(source_path, false)?;
            require(
                r["mount"] == mount_identity::id(input.as_fd(), true)?,
                "source remounted",
            )?;
            let temporary = format!(".partial-{}", files::random_hex(8)?);
            let mut output = exclusive(&parent, &temporary, true)?;
            let checksum = copy_file(&mut input, &mut output, &r["identity"], |n| {
                done = done
                    .checked_add(n)
                    .ok_or_else(|| Error("copy progress overflow".into()))?;
                if last.elapsed() >= Duration::from_millis(200) {
                    check()?;
                    let fresh = source.open(source_path, false)?;
                    require(
                        file_paths::identity(&fresh.metadata()?)? == r["identity"]
                            && r["mount"] == mount_identity::id(fresh.as_fd(), true)?,
                        "source changed during copy",
                    )?;
                    let mut progress = json!({"bytes":done,"total":total.checked_mul(2).ok_or_else(||Error("copy progress bound".into()))?});
                    if style != Style::Manager {
                        progress["files"] = json!(files_done);
                        progress["total_files"] = json!(total_files);
                    }
                    emit(json!({"progress":progress}))?;
                    last = Instant::now();
                }
                Ok(())
            })?;
            owner(&output, uid, gid)?;
            preserved_time(&output, &r["identity"])?;
            output.sync_all()?;
            check()?;
            file_paths::rename_new(&parent, &temporary, name, true)?;
            let mut entry = json!({"path":relative,"sha256":checksum});
            if style != Style::Manager {
                entry["bytes"] = r["identity"][3].clone();
            }
            manifest.push(entry);
            files_done += 1;
        }
        parent.sync_all()?;
    }
    drives(true)?;
    check()?;
    let report_name = if style == Style::NewTree {
        "COPY-REPORT.json".to_owned()
    } else {
        format!(".enzimos-copy-report-{token}.json")
    };
    let mut report = exclusive(&root, &report_name, false)?;
    owner(&report, uid, gid)?;
    report.write_all(&enzimos_platform::json::canonical(
        &json!({"files":manifest,"skipped":record.get("skipped").cloned().unwrap_or(json!([]))}),
    )?)?;
    report.sync_all()?;
    root.sync_all()?;
    let marker = CString::new(marker).unwrap();
    require(
        unsafe { libc::unlinkat(root.as_raw_fd(), marker.as_ptr(), 0) } == 0,
        "copy completed but incomplete marker retained",
    )?;
    root.sync_all()?;
    Ok(
        json!({"operation":"copy","items":record["roots"].as_array().map_or(0,Vec::len),"completed":true,"skipped":record["skipped"].as_array().map_or(0,Vec::len)}),
    )
}
