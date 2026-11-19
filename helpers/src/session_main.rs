// SPDX-License-Identifier: MIT
fn main() {
    if std::env::args_os().len() != 1 {
        eprintln!("session state takes no arguments");
        std::process::exit(2);
    }
    if let Err(error) = enzimos_recovery_tools::session_runtime::boot() {
        eprintln!("native recovery session refused: {error}");
        std::process::exit(2);
    }
}
