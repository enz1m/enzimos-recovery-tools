// SPDX-License-Identifier: MIT
use enzimos_platform::{Error, Result, json, require};
use enzimos_recovery_tools::{accounts, console};
use serde_json::Value;
use std::{
    io::Read,
    process::{Child, Command, Stdio},
};
const HELPER: &str = "/usr/lib/enzimos-recovery/enzimos-recovery-helper";
struct Owned(Child, bool);
impl Drop for Owned {
    fn drop(&mut self) {
        if !self.1 {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn call(request: &Value) -> Result<Value> {
    let body = String::from_utf8(json::canonical(request)?)
        .map_err(|_| Error("console request encoding".into()))?;
    require(body.len() <= 4096, "console request bound")?;
    let root = unsafe { libc::geteuid() } == 0;
    let mut command = if root {
        Command::new(HELPER)
    } else {
        Command::new("/usr/bin/sudo")
    };
    if !root {
        command.args(["-k", "--", HELPER]);
    }
    command
        .arg(body)
        .env_clear()
        .env("PATH", "/usr/bin")
        .env("TERM", "linux")
        .env("LC_ALL", "C")
        .env("LANG", "C");
    if root {
        command.env("SUDO_USER", accounts::authenticated_account()?.name);
    }
    // Preserve the controlling terminal for sudo's own password prompt and
    // foreground interruption. No password enters an argument or output pipe.
    command
        .stdin(Stdio::inherit())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = Owned(command.spawn()?, false);
    let stdout = child
        .0
        .stdout
        .take()
        .ok_or_else(|| Error("console response unavailable".into()))?;
    let mut output = Vec::new();
    stdout.take(32 * 1024 * 1024 + 1).read_to_end(&mut output)?;
    require(
        output.len() <= 32 * 1024 * 1024,
        "console response byte bound",
    )?;
    let status = child.0.wait()?;
    child.1 = true;
    let response = json::decode(&output, 32 * 1024 * 1024)?;
    if !status.success() || response["error"].is_string() {
        return Err(Error(
            response["error"]
                .as_str()
                .unwrap_or("recovery command failed; check administrator authentication")
                .chars()
                .take(500)
                .collect(),
        ));
    }
    Ok(response)
}
fn main() {
    let result = (|| {
        let args = std::env::args().skip(1).collect::<Vec<_>>();
        let command = console::Command::parse(&args)?;
        console::execute(
            command,
            call,
            &mut std::io::stdin().lock(),
            &mut std::io::stdout().lock(),
        )
    })();
    if let Err(error) = result {
        eprintln!("Recovery: {error}");
        std::process::exit(1);
    }
}
