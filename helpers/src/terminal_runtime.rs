// SPDX-License-Identifier: MIT
use crate::{
    accounts,
    terminal_bus::{MANAGER, Manager, PATH},
    terminal_contract::{self as contract, Properties},
};
use enzimos_platform::{Error, Result, files, process, process_identity, require};
use serde_json::{Value, json};
use std::{path::Path, time::Duration};
use zbus::zvariant::{OwnedObjectPath, Value as Variant};
fn installed(path: &str, elf: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    let parent = files::directory(Path::new(path).parent().unwrap(), Some(0))?;
    let held = files::open_relative(&parent, Path::new(Path::new(path).file_name().unwrap()))?;
    let metadata = held.metadata()?;
    require(
        metadata.uid() == 0
            && metadata.mode() & 0o022 == 0
            && metadata.nlink() == 1
            && (!elf || metadata.mode() & 0o111 != 0),
        "terminal installation untrusted",
    )?;
    let bytes = files::read_file(&held, 32 * 1024 * 1024, Some(0), true)?;
    require(
        !elf || bytes.starts_with(b"\x7fELF"),
        "native terminal executable required",
    )
}
async fn properties(
    manager: &Manager,
    path: &OwnedObjectPath,
    account: &accounts::Account,
) -> Result<contract::Snapshot> {
    require(
        path.as_str().starts_with("/org/freedesktop/systemd1/unit/") && path.as_str().len() <= 512,
        "terminal unit path refused",
    )?;
    let unit: Properties = manager
        .call(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &("org.freedesktop.systemd1.Unit",),
        )
        .await?;
    let service: Properties = manager
        .call(
            path.as_str(),
            "org.freedesktop.DBus.Properties",
            "GetAll",
            &("org.freedesktop.systemd1.Service",),
        )
        .await?;
    contract::validate(&unit, &service, account)
}
async fn session(account: &accounts::Account) -> Result<()> {
    installed(contract::WRAPPER, true)?;
    installed(contract::RC, false)?;
    let manager = Manager::new().await?;
    let existing = manager.unit().await?;
    let (path, start_job) = if let Some(path) = existing {
        let state = properties(&manager, &path, account).await?;
        require(
            matches!(state.active.as_str(), "active" | "activating"),
            "previous terminal is stopping or failed; inspect it before a new session",
        )?;
        (path, None)
    } else {
        require(
            accounts::authenticated_account()? == *account,
            "terminal administrator changed",
        )?;
        let args = contract::arguments(account)?;
        let starts = vec![(contract::WRAPPER, args, false)];
        let properties = vec![
            ("Description", Variant::from("enzimOS Recovery Terminal")),
            ("Type", Variant::from("exec")),
            ("User", Variant::from("0")),
            ("KillMode", Variant::from("control-group")),
            ("Restart", Variant::from("no")),
            ("ExecStart", Variant::from(starts)),
        ];
        let auxiliary: Vec<(&str, Vec<(&str, Variant<'_>)>)> = Vec::new();
        let job: OwnedObjectPath = manager
            .call(
                PATH,
                MANAGER,
                "StartTransientUnit",
                &(contract::UNIT, "fail", properties, auxiliary),
            )
            .await?;
        require(
            job.as_str().starts_with("/org/freedesktop/systemd1/job/") && job.as_str().len() <= 128,
            "terminal start outcome uncertain",
        )?;
        let path = manager.unit().await?.ok_or_else(|| {
            Error("terminal exited before its start could be observed; no retry".into())
        })?;
        (path, Some(job))
    };
    // The reference is owned by this bus connection. Cancellation releases it,
    // while PID1 continues to own the terminal and its complete control group.
    manager
        .call::<_, ()>(PATH, MANAGER, "RefUnit", &(contract::UNIT,))
        .await?;
    let result = async {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
        let initial = loop {
            let state = properties(&manager, &path, account).await?;
            if state.active == "active" {
                break state;
            }
            // StartTransientUnit returns a queued job before the unit must
            // become activating. Wait only for this connection's original job.
            let queued = if state.active == "inactive" && state.pid == 0 {
                if let Some(original) = &start_job {
                    let value: zbus::zvariant::OwnedValue = manager
                        .call(
                            path.as_str(),
                            "org.freedesktop.DBus.Properties",
                            "Get",
                            &("org.freedesktop.systemd1.Unit", "Job"),
                        )
                        .await?;
                    let actual: (u32, OwnedObjectPath) = value
                        .try_into()
                        .map_err(|_| Error("terminal queued job signature differs".into()))?;
                    contract::queued_start(&actual, original).is_ok()
                } else {
                    false
                }
            } else {
                false
            };
            require(
                (state.active == "activating" || queued) && tokio::time::Instant::now() < deadline,
                &format!(
                    "terminal start not confirmed: state={} main_pid={} invocation_bytes={}",
                    state.active,
                    state.pid,
                    state.invocation.len()
                ),
            )?;
            tokio::time::sleep(Duration::from_millis(100)).await;
        };
        require(
            accounts::authenticated_account()? == *account,
            "terminal administrator changed",
        )?;
        let root = std::path::PathBuf::from(format!("/proc/{}", initial.pid));
        let bytes = files::read_kernel(&root.join("stat"), 8192)?;
        let stat = process_identity::parse_stat(
            std::str::from_utf8(&bytes)
                .map_err(|_| Error("terminal process identity encoding".into()))?,
            initial.pid,
        )?;
        // PID1 owns the Root supervisor; its fixed openvt/setpriv child runs
        // as the reviewed administrator. Pin the supervisor to its actual UID.
        let owned = process_identity::Retained::open(
            initial.pid,
            stat.start_ticks,
            0,
            &[std::path::PathBuf::from(contract::WRAPPER)],
        )?;
        let status = files::read_kernel(&root.join("status"), 65536)?;
        require(
            process_identity::parse_uids(
                std::str::from_utf8(&status)
                    .map_err(|_| Error("terminal process UID encoding".into()))?,
            )? == [0; 4],
            "native Root terminal wrapper required",
        )?;
        let mut expected = contract::arguments(account)?.join("\0").into_bytes();
        expected.push(0);
        require(
            files::read_kernel(&root.join("cmdline"), 4096)? == expected,
            "terminal process arguments changed",
        )?;
        installed(contract::WRAPPER, true)?;
        manager.recheck().await?;
        owned.recheck()?;
        let switched = process::run("/usr/bin/chvt", &["8"], &[], Duration::from_secs(5), 4096)?;
        require(switched.status.success(), "terminal focus failed")?;
        let deadline = tokio::time::Instant::now() + Duration::from_secs(86400);
        loop {
            let state = properties(&manager, &path, account).await?;
            require(
                state.invocation == initial.invocation,
                "terminal invocation changed; no retry",
            )?;
            if matches!(state.active.as_str(), "inactive" | "failed") {
                require(
                    owned.exited()?,
                    "terminal process remains after unit completion",
                )?;
                return require(
                    state.active == "inactive",
                    "terminal exited with a failure; check its journal",
                );
            }
            if state.active == "active" {
                require(
                    state.pid == initial.pid,
                    "terminal MainPID changed; no retry",
                )?;
                owned.recheck()?;
            }
            require(
                tokio::time::Instant::now() < deadline,
                "terminal remains managed by systemd; wait limit reached",
            )?;
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
    }
    .await;
    let released = manager
        .call::<_, ()>(PATH, MANAGER, "UnrefUnit", &(contract::UNIT,))
        .await;
    result?;
    released
}
pub fn execute(request: &Value) -> Result<Value> {
    enzimos_platform::json::fields(request, "action")?;
    require(request["action"] == "terminal", "terminal action required")?;
    let account = accounts::authenticated_account()?;
    let _lock = files::Lock::acquire(Path::new("/run/enzimos-recovery-terminal.lock"), 0)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(session(&account))?;
    Ok(json!({"terminal":true}))
}
