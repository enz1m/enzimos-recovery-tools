// SPDX-License-Identifier: MIT
//! Fresh PAM entry and preview bind online completion to the actual restored boot.
use crate::{accounts, restore_inspect};
use enzimos_platform::{Result, files, json, require};
use enzimos_policy::{
    identity, operation, recovery_adoption, recovery_confirmation, recovery_records,
};
use serde_json::{Value, json as value};
use std::{
    ffi::CString,
    os::{fd::AsRawFd, unix::fs::MetadataExt},
    path::Path,
};
#[allow(unsafe_code, reason = "Linux syscall ABI (renameat2).")]
pub(crate) fn retire_notice(id: &str) -> Result<()> {
    let parent = files::directory(Path::new("/run"), Some(0))?;
    let path = Path::new("/run/enzimos-recovery-needed");
    match std::fs::symlink_metadata(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
        Ok(_) => (),
    }
    let marker = files::open_relative(&parent, Path::new("enzimos-recovery-needed"))?;
    let body = files::read_file(&marker, 4096, Some(0), true)?;
    let expected = files::identity(&marker.metadata()?);
    let private = files::ensure_directory(Path::new("/run/enzimos"), 0o700, 0)?;
    require(
        private.metadata()?.mode() & 0o7777 == 0o700,
        "Unsafe recovery notice directory.",
    )?;
    let name = CString::new(format!("finished-{id}-{}.notice", files::random_hex(16)?)).unwrap();
    require(
        files::identity(
            &files::open_relative(&parent, Path::new("enzimos-recovery-needed"))?.metadata()?,
        ) == expected,
        "Recovery notice changed.",
    )?;
    require(
        unsafe {
            libc::renameat2(
                parent.as_raw_fd(),
                c"enzimos-recovery-needed".as_ptr(),
                private.as_raw_fd(),
                name.as_ptr(),
                libc::RENAME_NOREPLACE,
            )
        } == 0,
        "Recovery notice retirement refused.",
    )?;
    // Retain the moved notice even if its identity changed; never delete a racer.
    private.sync_all()?;
    parent.sync_all()?;
    let archived = files::open_relative(
        &private,
        Path::new(std::str::from_utf8(name.as_bytes()).unwrap()),
    )?;
    let captured = files::identity(&archived.metadata()?);
    let mut rename_identity = expected;
    // rename changes ctime, while every other recorded property and the bytes
    // must stay exact. The held source must still name the captured inode.
    rename_identity.5 = captured.5;
    rename_identity.6 = captured.6;
    require(
        captured == rename_identity
            && files::identity(&marker.metadata()?) == captured
            && files::read_file(&archived, 4096, Some(0), true)? == body,
        "Recovery notice changed; archived bytes retained for review.",
    )
}
pub fn finish(request: &Value) -> Result<Value> {
    json::fields(request, "action digest id")?;
    let id = recovery_records::text(request, "id")?;
    recovery_records::job_id(id)?;
    identity::sha(recovery_records::text(request, "digest")?)?;
    accounts::authenticated_account()?;
    let lock = operation::lock()?;
    let state = restore_inspect::inspect_locked(&lock)?;
    require(
        state["digest"] == request["digest"],
        "Recovery state changed. Refresh before continuing.",
    )?;
    let activation = &state["activations"][id];
    let run = &state["runs"][id];
    require(
        matches!(activation["phase"].as_str(), Some("selected" | "adopted")),
        "Recovery activation is unavailable.",
    )?;
    require(
        matches!(run["phase"].as_str(), Some("executed" | "complete")),
        "The independent recovery run has not completed.",
    )?;
    accounts::authenticated_account()?;
    let confirmation = recovery_confirmation::confirm_locked(&lock)?;
    require(
        confirmation["id"] == id,
        "Recovery completion differs from the running system.",
    )?;
    let result = if run["phase"] == "executed" {
        recovery_confirmation::finish_locked(id, &lock)?
    } else {
        value!({"status":"recovery-run-complete","id":id})
    };
    if activation["phase"] == "selected" {
        accounts::authenticated_account()?;
        recovery_adoption::adopt_locked(
            id,
            recovery_records::text(&activation["intent"], "intent_sha256")?,
            &lock,
        )?;
    }
    retire_notice(id)?;
    Ok(
        value!({"message":"Recovery completed. This system can receive updates again.","result":result}),
    )
}
