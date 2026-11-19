// SPDX-License-Identifier: MIT
//! A mutable source name is moved into an exclusive private holding directory.
//! An unexpected captured inode remains there and is never deleted.
use crate::file_paths;
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    ffi::{CString, OsStr},
    fs::File,
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::ffi::OsStrExt,
    },
};
#[allow(unsafe_code, reason = "Linux syscall ABI (fstatat).")]
fn stat(parent: &File, name: &CString) -> Result<libc::stat> {
    let mut st = std::mem::MaybeUninit::uninit();
    require(
        unsafe {
            libc::fstatat(
                parent.as_raw_fd(),
                name.as_ptr(),
                st.as_mut_ptr(),
                libc::AT_SYMLINK_NOFOLLOW,
            )
        } == 0,
        "delete item unavailable",
    )?;
    Ok(unsafe { st.assume_init() })
}
fn identity(st: &libc::stat) -> Result<Value> {
    let ns = |s: i64, n: i64| {
        s.checked_mul(1000000000)
            .and_then(|s| s.checked_add(n))
            .ok_or_else(|| Error("delete timestamp bound".into()))
    };
    Ok(json!([
        st.st_dev,
        st.st_ino,
        st.st_mode,
        st.st_size,
        ns(st.st_mtime, st.st_mtime_nsec)?,
        ns(st.st_ctime, st.st_ctime_nsec)?
    ]))
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (fchmod, mkdirat, openat, unlinkat)."
)]
pub fn remove<F: FnOnce() -> Result<()>>(
    parent: &File,
    name: &OsStr,
    expected: &Value,
    directory: bool,
    token: &str,
    index: usize,
    fresh: F,
) -> Result<()> {
    require(
        token.len() == 32
            && token
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && index < 100000,
        "delete holding identity",
    )?;
    let name =
        CString::new(name.as_bytes()).map_err(|_| Error("delete filename encoding".into()))?;
    require(
        !name.as_bytes().contains(&b'/') && !matches!(name.as_bytes(), b"" | b"." | b".."),
        "delete item component",
    )?;
    let before = stat(parent, &name)?;
    let observed = identity(&before)?;
    let expected = expected
        .as_array()
        .filter(|a| a.len() == 6)
        .ok_or_else(|| Error("delete reviewed identity".into()))?;
    let actual = observed.as_array().unwrap();
    require(
        if directory {
            actual[..3] == expected[..3]
        } else {
            actual == expected
        },
        "item changed during deletion; remaining items retained",
    )?;
    require(
        directory == (before.st_mode & libc::S_IFMT == libc::S_IFDIR),
        "delete item kind changed",
    )?;
    let holding_name = CString::new(format!(".enzimos-delete-{token}-{index}")).unwrap();
    require(
        unsafe { libc::mkdirat(parent.as_raw_fd(), holding_name.as_ptr(), 0o700) } == 0,
        "delete holding directory already exists",
    )?;
    let raw = unsafe {
        libc::openat(
            parent.as_raw_fd(),
            holding_name.as_ptr(),
            libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC,
        )
    };
    require(raw >= 0, "delete holding directory unavailable")?;
    let holding = unsafe { File::from_raw_fd(raw) };
    require(
        unsafe { libc::fchmod(holding.as_raw_fd(), 0o700) } == 0,
        "delete holding directory mode",
    )?;
    holding.sync_all()?;
    parent.sync_all()?;
    fresh()?;
    // The holding directory is private, so the fallback never needs linkat; a
    // plain rename keeps the source capture atomic.
    if let Err(error) = file_paths::move_new(parent, &name, &holding, c"item", false) {
        // rmdir only succeeds while nothing was captured.
        let empty = unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                holding_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } == 0;
        return Err(Error(format!(
            "delete capture failed ({}); holding directory {}",
            error.0,
            if empty { "removed" } else { "retained" }
        )));
    }
    holding.sync_all()?;
    parent.sync_all()?;
    let captured = stat(&holding, &CString::new("item").unwrap())?;
    let captured_identity = identity(&captured)?;
    require(
        captured_identity.as_array().unwrap()[..5] == actual[..5]
            && captured.st_uid == before.st_uid
            && captured.st_gid == before.st_gid,
        "source name changed during capture; private holding item retained for review",
    )?;
    require(
        unsafe {
            libc::unlinkat(
                holding.as_raw_fd(),
                c"item".as_ptr(),
                if directory { libc::AT_REMOVEDIR } else { 0 },
            )
        } == 0,
        "captured item could not be removed; private holding item retained",
    )?;
    holding.sync_all()?;
    drop(holding);
    require(
        unsafe {
            libc::unlinkat(
                parent.as_raw_fd(),
                holding_name.as_ptr(),
                libc::AT_REMOVEDIR,
            )
        } == 0,
        "removed item has an unresolved holding directory",
    )?;
    parent.sync_all()?;
    Ok(())
}
