// SPDX-License-Identifier: MIT
//! Use NSS, rather than parsing /etc/passwd and missing directory-backed users.
use enzimos_platform::{Error, Result, require};
use serde_json::{Value, json};
use std::{
    collections::BTreeSet,
    ffi::{CStr, CString},
};
#[allow(unsafe_code, reason = "Native pointer or callback ABI.")]
unsafe fn string(p: *const libc::c_char) -> Result<String> {
    require(!p.is_null(), "account field unavailable")?;
    let b = unsafe { CStr::from_ptr(p) }.to_bytes();
    require(b.len() <= 4096, "account field bound")?;
    String::from_utf8(b.to_vec()).map_err(|_| Error("account field encoding".into()))
}
pub fn valid_name(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && !s.starts_with('-')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Account {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
}
#[allow(unsafe_code, reason = "Linux syscall ABI (getpwnam_r).")]
pub fn lookup(name: &str) -> Result<Account> {
    require(valid_name(name), "invalid account name")?;
    let name = CString::new(name).unwrap();
    let mut buffer = vec![0u8; 65536];
    let mut row = std::mem::MaybeUninit::<libc::passwd>::uninit();
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwnam_r(
            name.as_ptr(),
            row.as_mut_ptr(),
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    require(code == 0 && !result.is_null(), "account lookup unavailable")?;
    let row = unsafe { row.assume_init() };
    let name = unsafe { string(row.pw_name) }?;
    require(
        (1000..u32::MAX).contains(&row.pw_uid) && valid_name(&name),
        "ordinary account required",
    )?;
    Ok(Account {
        name,
        uid: row.pw_uid,
        gid: row.pw_gid,
    })
}
pub fn authenticated_account() -> Result<Account> {
    let user = authenticated_user()?;
    lookup(&user)
}
#[allow(
    unsafe_code,
    reason = "Linux syscall ABI (endpwent, getgrnam, getpwent, setpwent)."
)]
pub fn administrators() -> Result<Value> {
    let name = CString::new("wheel").unwrap();
    let group = unsafe { libc::getgrnam(name.as_ptr()) };
    if group.is_null() {
        return Ok(json!([]));
    }
    let gid = unsafe { (*group).gr_gid };
    let mut members = BTreeSet::new();
    let mut p = unsafe { (*group).gr_mem };
    if !p.is_null() {
        for _ in 0..4096 {
            let member = unsafe { *p };
            if member.is_null() {
                break;
            }
            members.insert(unsafe { string(member) }?);
            p = unsafe { p.add(1) };
        }
        require(unsafe { (*p).is_null() }, "administrator group bound")?;
    }
    unsafe { libc::setpwent() };
    struct End;
    impl Drop for End {
        #[allow(unsafe_code, reason = "Linux syscall ABI (endpwent).")]
        fn drop(&mut self) {
            unsafe { libc::endpwent() };
        }
    }
    let _end = End;
    let mut rows = Vec::new();
    let mut count = 0;
    loop {
        let entry = unsafe { libc::getpwent() };
        if entry.is_null() {
            break;
        }
        count += 1;
        require(count <= 16384, "account enumeration bound")?;
        let uid = unsafe { (*entry).pw_uid };
        if uid < 1000 || uid == u32::MAX {
            continue;
        }
        let user = unsafe { string((*entry).pw_name) }?;
        let shell = unsafe { string((*entry).pw_shell) }?;
        if !valid_name(&user)
            || !(members.contains(&user) || unsafe { (*entry).pw_gid } == gid)
            || matches!(
                shell.as_str(),
                "/usr/bin/nologin" | "/bin/false" | "/sbin/nologin"
            )
        {
            continue;
        }
        let label = unsafe { string((*entry).pw_gecos) }?;
        let label = label
            .split(',')
            .next()
            .filter(|s| !s.is_empty())
            .unwrap_or(&user);
        require(
            !label.chars().any(char::is_control),
            "account label invalid",
        )?;
        rows.push(json!({"name":user,"label":label}));
        require(rows.len() <= 256, "administrator count bound")?;
    }
    Ok(json!(rows))
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getpwnam).")]
pub fn authenticated_user() -> Result<String> {
    require(
        unsafe { libc::geteuid() } == 0,
        "administrator authentication required",
    )?;
    let user = std::env::var("SUDO_USER")
        .map_err(|_| Error("authenticated administrator unavailable".into()))?;
    require(valid_name(&user), "invalid authenticated account")?;
    let c = CString::new(user.clone()).unwrap();
    let p = unsafe { libc::getpwnam(c.as_ptr()) };
    require(
        !p.is_null() && unsafe { (*p).pw_uid } >= 1000,
        "ordinary administrator required",
    )?;
    let admins = administrators()?;
    require(
        admins.as_array().unwrap().iter().any(|a| a["name"] == user),
        "administrator membership changed",
    )?;
    Ok(user)
}
