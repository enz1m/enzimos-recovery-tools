// SPDX-License-Identifier: MIT
//! Root boot presentation completes only explicitly authorized, executed work.
use crate::{
    restore_finish,
    session_state::{self, Decision, Notice},
};
use enzimos_platform::{Error, Result, files, require};
use enzimos_policy::{
    boot_menu, media_receipt, operation, recovery_adoption, recovery_confirmation,
    recovery_journal::{Journal, Kind},
    recovery_records as records,
};
use serde_json::Value;
use std::{
    ffi::CStr,
    path::Path,
    time::{Duration, Instant},
};
const NOTICE: &str = "/run/enzimos-recovery-needed";
const REQUEST: &str =
    "/sys/firmware/efi/efivars/EnzimosRecoveryUI-dac8e170-20d1-4c6d-9e2f-56d03a6f7193";
const KIOSK: &str = "[terminal]\nvt = 1\n[default_session]\nuser = \"enzimos-recovery\"\ncommand = \"/usr/bin/enzimos-recovery-session\"\n";
#[allow(unsafe_code, reason = "Linux syscall ABI (getpwnam_r, getspnam_r).")]
fn kiosk_account() -> Result<()> {
    let mut buffer = zeroize::Zeroizing::new(vec![0u8; 65536]);
    let mut passwd: libc::passwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getpwnam_r(
            c"enzimos-recovery".as_ptr(),
            &mut passwd,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    require(
        code == 0 && !result.is_null() && (1..1000).contains(&passwd.pw_uid) && passwd.pw_gid != 0,
        "locked system recovery account required",
    )?;
    require(
        !passwd.pw_name.is_null() && !passwd.pw_shell.is_null(),
        "kiosk account fields missing",
    )?;
    let name = unsafe { CStr::from_ptr(passwd.pw_name) }.to_bytes();
    let shell = unsafe { CStr::from_ptr(passwd.pw_shell) }.to_bytes();
    require(
        name == b"enzimos-recovery"
            && [
                b"/usr/bin/nologin".as_slice(),
                b"/bin/nologin",
                b"/usr/bin/false",
                b"/bin/false",
            ]
            .contains(&shell),
        "recovery system account must refuse ordinary logins",
    )?;
    let mut shadow: libc::spwd = unsafe { std::mem::zeroed() };
    let mut result = std::ptr::null_mut();
    let code = unsafe {
        libc::getspnam_r(
            c"enzimos-recovery".as_ptr(),
            &mut shadow,
            buffer.as_mut_ptr().cast(),
            buffer.len(),
            &mut result,
        )
    };
    require(
        code == 0 && !result.is_null() && !shadow.sp_pwdp.is_null(),
        "recovery account lock unavailable",
    )?;
    let password = unsafe { CStr::from_ptr(shadow.sp_pwdp) }.to_bytes();
    require(
        password == b"*" || password.starts_with(b"!"),
        "recovery system account password is not locked",
    )
}
fn snapshot(command: &str) -> Result<Decision> {
    let runs = Journal::open(Kind::Runs, false)?;
    let activations = Journal::open(Kind::Activations, false)?;
    let decision = session_state::evaluate(command, &runs.records, &activations.records)?;
    runs.unchanged()?;
    activations.unchanged()?;
    Ok(decision)
}
fn complete_run(id: &str, lock: &files::Lock) -> Result<()> {
    let runs = Journal::open(Kind::Runs, false)?;
    let activations = Journal::open(Kind::Activations, false)?;
    let run = runs
        .records
        .get(id)
        .ok_or_else(|| Error("automatic run missing".into()))?;
    let activation = activations
        .records
        .get(id)
        .ok_or_else(|| Error("automatic activation missing".into()))?;
    let parameters = enzimos_policy::recovery_run_parameters::Parameters::parse(records::text(
        &run["entry"],
        "options",
    )?)?;
    parameters.matches_record(run, &activation["intent"]["job"])?;
    require(
        parameters.automatic
            && matches!(run["phase"].as_str(), Some("executed" | "complete"))
            && matches!(activation["phase"].as_str(), Some("selected" | "adopted")),
        "automatic recovery is incomplete; no replay",
    )?;
    runs.unchanged()?;
    activations.unchanged()?;
    require(
        recovery_confirmation::confirm_locked(lock)?["id"] == id,
        "actual automatic restored boot differs",
    )?;
    if run["phase"] == "executed" {
        recovery_confirmation::finish_locked(id, lock)?;
    }
    if activation["phase"] == "selected" {
        recovery_adoption::adopt_locked(
            id,
            records::text(&activation["intent"], "intent_sha256")?,
            lock,
        )?;
    }
    println!("ENZIMOS_RECOVERY_AUTOCOMPLETE {id}");
    Ok(())
}
fn completion(command: &str) -> Result<Decision> {
    let deadline = Instant::now() + Duration::from_secs(30);
    let lock = loop {
        if let Some(lock) = operation::try_lock()? {
            break lock;
        }
        require(
            Instant::now() < deadline,
            "recovery completion lock deadline",
        )?;
        std::thread::sleep(Duration::from_millis(200));
    };
    let decision = snapshot(command)?;
    if let Some(id) = &decision.identifier {
        if decision.complete_media && media_receipt::complete_locked(id, &lock)? {
            println!("ENZIMOS_MEDIA_RECOVERY_AUTOCOMPLETE {id}");
        }
        if decision.complete_run {
            complete_run(id, &lock)?;
        }
    }
    snapshot(command)
}
fn notice(body: &str) -> Result<()> {
    files::atomic(Path::new(NOTICE), body.as_bytes(), 0o644, Some(0), true)
}
pub fn boot() -> Result<Value> {
    operation::root_only()?;
    enzimos_policy::storage_runtime::initial_namespace()?;
    restore_finish::retire_notice(&format!("boot-{}", operation::boot_id()?))?;
    let body = files::read_kernel(Path::new("/proc/cmdline"), 65536)?;
    let command =
        std::str::from_utf8(&body).map_err(|_| Error("recovery boot command encoding".into()))?;
    let decision = match completion(command) {
        Ok(decision) => decision,
        Err(error) => {
            eprintln!(
                "Recovery metadata needs attention: {}",
                error.0.chars().take(500).collect::<String>()
            );
            Decision {
                identifier: None,
                complete_media: false,
                complete_run: false,
                notice: Some(Notice::MetadataAttention),
                retained_errors: Vec::new(),
            }
        }
    };
    for error in &decision.retained_errors {
        eprintln!("{error}");
    }
    if let Some(kind) = &decision.notice {
        notice(match kind {
            Notice::Confirmation => "Recovery confirmation required\n",
            Notice::Unfinished => {
                "Snapshot recovery did not finish. Your previous system is still available. Open Boot logs or Terminal for details.\n"
            }
            Notice::MetadataAttention => "Recovery metadata needs attention\n",
        })?;
    }
    // BIOS installations use Limine and deliberately omit the rEFInd tree.
    if Path::new("/sys/firmware/efi").try_exists()? {
        let _menu_lock = operation::lock()?;
        let volume = enzimos_policy::boot_volume::Volume::observe()?;
        boot_menu::render_live(&volume, false)?;
    }
    match std::fs::symlink_metadata(REQUEST) {
        Ok(_) => {
            if files::read_kernel(Path::new(REQUEST), 8192)? == [6, 0, 0, 0, 1] {
                notice("Recovery session requested from boot menu\n")?;
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.into()),
    }
    let requested = match std::fs::symlink_metadata(NOTICE) {
        Ok(_) => {
            files::read(Path::new(NOTICE), 4096, Some(0), true)?;
            true
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    let config = if requested {
        kiosk_account()?;
        KIOSK.as_bytes().to_vec()
    } else {
        files::read(Path::new("/etc/greetd/config.toml"), 65536, Some(0), true)?
    };
    require(!config.is_empty(), "normal display configuration missing")?;
    files::atomic(
        Path::new("/run/enzimos-greetd.toml"),
        &config,
        0o644,
        Some(0),
        true,
    )?;
    Ok(serde_json::json!({"recovery_requested":requested,"automatic_replay":false}))
}
