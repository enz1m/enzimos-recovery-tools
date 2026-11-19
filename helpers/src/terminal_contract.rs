// SPDX-License-Identifier: MIT
//! A terminal is reused only for the exact authenticated account and native unit.
use crate::accounts::{Account, valid_name};
use enzimos_platform::{Error, Result, require};
use std::collections::HashMap;
use zbus::zvariant::OwnedValue;
pub const UNIT: &str = "enzimos-recovery-terminal.service";
pub const WRAPPER: &str = "/usr/lib/enzimos-recovery/enzimos-recovery-open-terminal";
pub const RC: &str = "/usr/lib/enzimos-recovery/terminalrc";
pub type Properties = HashMap<String, OwnedValue>;
pub type Exec = (String, Vec<String>, bool, u64, u64, u64, u64, u32, i32, i32);
pub fn arguments(account: &Account) -> Result<Vec<String>> {
    require(
        valid_name(&account.name)
            && (1000..u32::MAX).contains(&account.uid)
            && account.gid > 0
            && account.gid < u32::MAX,
        "ordinary terminal account required",
    )?;
    Ok(vec![
        WRAPPER.into(),
        account.name.clone(),
        account.uid.to_string(),
        account.gid.to_string(),
    ])
}
pub fn field<T: TryFrom<OwnedValue>>(values: &Properties, key: &str) -> Result<T> {
    T::try_from(
        values
            .get(key)
            .ok_or_else(|| Error("terminal unit property missing".into()))?
            .try_clone()
            .map_err(|_| Error("terminal unit property type".into()))?,
    )
    .map_err(|_| Error("terminal unit property type".into()))
}
#[derive(Debug, PartialEq, Eq)]
pub struct Snapshot {
    pub active: String,
    pub pid: u32,
    pub invocation: Vec<u8>,
}
pub fn validate(unit: &Properties, service: &Properties, account: &Account) -> Result<Snapshot> {
    let args = arguments(account)?;
    require(
        unit.len() <= 512 && service.len() <= 512,
        "terminal property count bound",
    )?;
    let starts: Vec<Exec> = field(service, "ExecStart")?;
    require(
        field::<String>(unit, "Id")? == UNIT
            && field::<bool>(unit, "Transient")?
            && field::<String>(unit, "FragmentPath")? == format!("/run/systemd/transient/{UNIT}")
            && field::<Vec<String>>(unit, "DropInPaths")?.is_empty()
            && field::<String>(service, "User")? == "0"
            && field::<String>(service, "Type")? == "exec"
            && field::<String>(service, "KillMode")? == "control-group"
            && field::<String>(service, "Restart")? == "no"
            && starts.len() == 1
            && starts[0].0 == WRAPPER
            && starts[0].1 == args
            && !starts[0].2,
        "existing terminal does not belong to this authenticated account",
    )?;
    let active: String = field(unit, "ActiveState")?;
    let pid: u32 = field(service, "MainPID")?;
    let invocation: Vec<u8> = field(unit, "InvocationID")?;
    let group: String = field(service, "ControlGroup")?;
    require(
        matches!(
            active.as_str(),
            "active" | "activating" | "deactivating" | "inactive" | "failed"
        ) && pid < i32::MAX as u32
            && (invocation.is_empty() || invocation.len() == 16)
            && (group == format!("/system.slice/{UNIT}")
                || (group.is_empty()
                    && pid == 0
                    && matches!(active.as_str(), "inactive" | "failed"))),
        "terminal unit state refused",
    )?;
    require(
        active != "active" || (pid > 0 && invocation.len() == 16),
        "terminal process unavailable",
    )?;
    Ok(Snapshot {
        active,
        pid,
        invocation,
    })
}

/// Observation only: an inactive unit may wait for its original queued start.
/// A vanished, replaced or unrelated job is never adopted or retried.
pub fn queued_start(
    actual: &(u32, zbus::zvariant::OwnedObjectPath),
    original: &zbus::zvariant::OwnedObjectPath,
) -> Result<()> {
    require(
        actual.0 > 0
            && actual.1 == *original
            && original.as_str() == format!("/org/freedesktop/systemd1/job/{}", actual.0),
        "terminal original queued start differs",
    )
}
