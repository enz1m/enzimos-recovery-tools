// SPDX-License-Identifier: MIT
//! Root endpoint entered only through the private, freshly authenticated PAM pipe.
use enzimos_platform::{Error, Result, json, require};
use enzimos_recovery_tools::{accounts, file_dispatch, protocol, restore_inspect};
use serde_json::{Value, json as value};
use std::{
    io::{BufReader, Write},
    time::Duration,
};
fn execute<W: Write>(request: &Value, output: &mut W) -> Result<Value> {
    let account = accounts::authenticated_account()?;
    match request["action"].as_str() {
        Some(action) if action.starts_with("files_") => file_dispatch::execute(request, output),
        Some("authenticate") => {
            json::fields(request, "action")?;
            Ok(value!({"authenticated_user":account.name}))
        }
        Some("inspect") => {
            json::fields(request, "action")?;
            restore_inspect::inspect()
        }
        Some("snapshot_details") => restore_inspect::details(request),
        Some("finish") => enzimos_recovery_tools::restore_finish::finish(request),
        Some("restore") => enzimos_recovery_tools::restore_schedule::restore(request),
        Some("terminal") => enzimos_recovery_tools::terminal_runtime::execute(request),
        Some("logs") => {
            json::fields(request, "action")?;
            let body = enzimos_policy::operation::query(
                "/usr/bin/journalctl",
                &[
                    "-b",
                    "--no-pager",
                    "-n",
                    "300",
                    "-T",
                    "su",
                    "-T",
                    "sudo",
                    "-o",
                    "short-monotonic",
                ],
                Duration::from_secs(20),
                2 * 1024 * 1024,
                &[0],
            )?;
            let text = String::from_utf8_lossy(&body);
            let start = text.char_indices().rev().nth(31999).map_or(0, |(i, _)| i);
            Ok(value!({"logs":&text[start..]}))
        }
        _ => Err(Error("Unknown or unavailable recovery action.".into())),
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (getppid, prctl).")]
fn run() -> Result<()> {
    accounts::authenticated_account()?;
    let parent = unsafe { libc::getppid() };
    require(
        parent > 1
            && unsafe { libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL) } == 0
            && unsafe { libc::getppid() } == parent,
        "Recovery authentication pipe closed.",
    )?;
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    require(args.len() == 1, "Invalid recovery request.")?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    let mut input = BufReader::new(stdin.lock());
    let mut output = stdout.lock();
    let request = if args[0] == "--stdin" {
        protocol::emit(&mut output, &value!({"ready":true}))?;
        let bytes = protocol::read_line(&mut input)?
            .ok_or_else(|| Error("Recovery input closed.".into()))?;
        json::decode(&bytes, protocol::MAX_REQUEST)?
    } else {
        require(args[0].len() <= 4096, "Invalid recovery request.")?;
        json::decode(args[0].as_bytes(), 4096)?
    };
    protocol::serve(request, &mut input, &mut output, execute)
}
fn main() {
    if let Err(error) = run() {
        let _ = protocol::emit(
            &mut std::io::stdout(),
            &value!({"error":error.to_string().chars().take(500).collect::<String>()}),
        );
        std::process::exit(1);
    }
}
