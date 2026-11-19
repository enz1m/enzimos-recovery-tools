// SPDX-License-Identifier: MIT
//! Fixed system-manager wrapper: open a VT and drop to the reviewed ordinary UID.
use enzimos_platform::{Error, Result, process, require};
use enzimos_recovery_tools::{accounts, terminal_contract};
use std::time::Duration;
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid, getppid).")]
fn run() -> Result<()> {
    require(
        unsafe { libc::geteuid() } == 0 && unsafe { libc::getppid() } == 1,
        "system-manager terminal entry required",
    )?;
    enzimos_policy::namespaces::initial()?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(args.len() == 3, "terminal account arguments required")?;
    let account = accounts::lookup(&args[0])?;
    require(
        terminal_contract::arguments(&account)?[1..] == args,
        "terminal account identity changed",
    )?;
    require(
        accounts::administrators()?
            .as_array()
            .ok_or_else(|| Error("administrator inventory unavailable".into()))?
            .iter()
            .any(|a| a["name"] == account.name),
        "terminal administrator membership changed",
    )?;
    let uid = account.uid.to_string();
    let gid = account.gid.to_string();
    let terminal = process::run(
        "/usr/bin/openvt",
        &[
            "-c",
            "8",
            "-s",
            "-w",
            "--",
            "/usr/bin/setpriv",
            "--reuid",
            &uid,
            "--regid",
            &gid,
            "--init-groups",
            "--reset-env",
            "/usr/bin/bash",
            "--rcfile",
            terminal_contract::RC,
        ],
        &[],
        Duration::from_secs(86400),
        65536,
    );
    let returned = process::run("/usr/bin/chvt", &["1"], &[], Duration::from_secs(5), 4096);
    require(terminal?.status.success(), "terminal shell failed")?;
    require(returned?.status.success(), "return to recovery failed")
}
fn main() {
    if let Err(error) = run() {
        eprintln!("Recovery terminal: {error}");
        std::process::exit(1);
    }
}
