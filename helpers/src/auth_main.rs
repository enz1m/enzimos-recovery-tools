// SPDX-License-Identifier: MIT
use enzimos_platform::{Result, json};
use enzimos_recovery_tools::authentication;
use serde_json::json as value;
use std::io::Write;
fn run() -> Result<i32> {
    authentication::install_lifetime_guard()?;
    let body = authentication::read_line(std::io::stdin(), 65536)?;
    let request = json::decode(&body, 65536)?;
    authentication::run(request)
}
fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(e) => {
            let _ = writeln!(std::io::stdout(), "{}", value!({"error":e.to_string()}));
            std::process::exit(1);
        }
    }
}
