// SPDX-License-Identifier: MIT
//! Console requests use the same validated Root adapter as the graphical UI.
use enzimos_platform::{Error, Result, require};
use enzimos_policy::{identity, recovery_records as records};
use serde_json::{Value, json};
use std::io::{BufRead, Write};
pub const HELP: &str = "enzimOS console recovery\n\nSign in with your normal account password. Administrator commands may ask for it\nagain through sudo. An encrypted disk also needs its separate unlock passphrase.\nThe boot menu's Command-line recovery mode skips the graphical login and desktop.\n\nStart here:\n  enzimos-recovery-cli list              List validated bootable restore points\n  enzimos-recovery-cli status            Show pending/completed recovery runs\n  enzimos-recovery-cli logs              Show recent boot warnings\n  sudo journalctl -b --no-pager          Read the complete current boot log\n  sudo snapper -c root list              List existing Btrfs root snapshots\n  sudo snapper -c home list              List existing Btrfs home snapshots\n\nRestore an existing point:\n  1. Run list and copy its generation ID.\n  2. Run restore GENERATION and review the confirmation.\n  3. Run sudo systemctl reboot. Choose Start enzimOS so the prepared independent\n     recovery environment can run. Do not replace its one-shot boot.\n  4. After restoration, run status, then finish RUN_ID to confirm and adopt the\n     recovered system so updates can resume.\n\nOnly validated, bootable restore points are offered. Your home files and package\ntrust are preserved. If no compatible point is listed, do not delete or replace\nsubvolumes manually. This console requires a bootable installed root; it is not\nan offline repair USB.\n\nOther commands:\n  enzimos-recovery-cli --help            Show this guide again\n  sudo systemctl reboot                 Restart\n  sudo systemctl poweroff               Shut down\n  exit                                  Return to Recovery\n";
#[derive(Debug, PartialEq, Eq)]
pub enum Command {
    Help,
    List,
    Status,
    Logs,
    Restore(String),
    Finish(String),
}
impl Command {
    pub fn parse(args: &[String]) -> Result<Self> {
        match args {
            [] => Ok(Self::Help),
            [arg] if matches!(arg.as_str(), "-h" | "--help") => Ok(Self::Help),
            [arg] => match arg.as_str() {
                "list" => Ok(Self::List),
                "status" => Ok(Self::Status),
                "logs" => Ok(Self::Logs),
                _ => Err(Error("unknown command or missing restore/finish ID".into())),
            },
            [arg, id] if arg == "restore" => {
                identity::safe_id(id)?;
                Ok(Self::Restore(id.clone()))
            }
            [arg, id] if arg == "finish" => {
                records::job_id(id)?;
                Ok(Self::Finish(id.clone()))
            }
            _ => Err(Error(
                "use list, status, logs, restore GENERATION or finish RUN_ID".into(),
            )),
        }
    }
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value[key]
        .as_str()
        .filter(|s| s.len() <= 65536)
        .ok_or_else(|| Error("recovery response field missing".into()))
}
pub fn execute<F: FnMut(&Value) -> Result<Value>, R: BufRead, W: Write>(
    command: Command,
    mut call: F,
    input: &mut R,
    output: &mut W,
) -> Result<()> {
    if command == Command::Help {
        output.write_all(HELP.as_bytes())?;
        return Ok(());
    }
    if command == Command::Logs {
        writeln!(
            output,
            "{}",
            text(&call(&json!({"action":"logs"}))?, "logs")?
        )?;
        return Ok(());
    }
    let state = call(&json!({"action":"inspect"}))?;
    match command {
        Command::List => {
            let choices = state["choices"]
                .as_array()
                .ok_or_else(|| Error("recovery choices unavailable".into()))?;
            require(choices.len() <= 64, "recovery choice count bound")?;
            writeln!(output, "Validated bootable Btrfs restore points:")?;
            for choice in choices {
                let generation = identity::safe_id(text(choice, "generation")?)?;
                let available = choice["available"]
                    .as_bool()
                    .ok_or_else(|| Error("restore availability missing".into()))?;
                writeln!(
                    output,
                    "  {generation}  |  {}",
                    if available {
                        "ready"
                    } else {
                        text(choice, "reason")?
                    }
                )?;
            }
            if choices.is_empty() {
                writeln!(
                    output,
                    "  No compatible bootable restore point is registered."
                )?;
            }
        }
        Command::Status => {
            let runs = state["runs"]
                .as_object()
                .ok_or_else(|| Error("recovery runs unavailable".into()))?;
            require(runs.len() <= records::MAX_JOBS, "recovery run count bound")?;
            if runs.is_empty() {
                writeln!(output, "No recovery run is pending.")?;
            }
            for (id, run) in runs {
                records::run(run, id)?;
                let phase = text(run, "phase")?;
                let activation = state["activations"][id]["phase"].as_str().unwrap_or("none");
                require(
                    matches!(
                        activation,
                        "none" | "prepared" | "published" | "selecting" | "selected" | "adopted"
                    ),
                    "recovery activation phase refused",
                )?;
                writeln!(output, "{id}: {phase}; activation: {activation}")?;
                if matches!(phase, "executed" | "complete")
                    && matches!(activation, "selected" | "adopted")
                    && (phase != "complete" || activation != "adopted")
                {
                    writeln!(output, "  To finish: enzimos-recovery-cli finish {id}")?;
                }
            }
        }
        Command::Restore(generation) => {
            let choices = state["choices"]
                .as_array()
                .ok_or_else(|| Error("recovery choices unavailable".into()))?;
            require(choices.len() <= 64, "recovery choice count bound")?;
            let selected = choices
                .iter()
                .filter(|c| c["generation"] == generation)
                .collect::<Vec<_>>();
            require(
                selected.len() == 1,
                "unknown or ambiguous restore point; run list again",
            )?;
            let choice = selected[0];
            require(choice["available"] == true, "restore point unavailable")?;
            let digest = identity::sha(text(&state, "digest")?)?;
            let birth = identity::safe_id(text(choice, "birth")?)?;
            writeln!(
                output,
                "Restore system files from {generation}. Home files and package trust are preserved."
            )?;
            write!(output, "Type RESTORE to prepare this recovery: ")?;
            output.flush()?;
            let mut confirm = String::new();
            std::io::Read::take(&mut *input, 1025).read_line(&mut confirm)?;
            require(confirm.len() <= 1024, "restore confirmation input bound")?;
            if confirm.trim_end_matches(['\n', '\r']) != "RESTORE" {
                writeln!(output, "Cancelled. Nothing was staged.")?;
                return Ok(());
            }
            let response = call(
                &json!({"action":"restore","digest":digest,"birth":birth,"generation":generation}),
            )?;
            let run = records::job_id(text(&response, "run")?)?;
            writeln!(output, "{}\nRun ID: {run}", text(&response, "message")?)?;
            writeln!(
                output,
                "Next: sudo systemctl reboot; choose Start enzimOS for the prepared recovery. See --help for completion steps."
            )?;
        }
        Command::Finish(id) => {
            let digest = identity::sha(text(&state, "digest")?)?;
            let response = call(&json!({"action":"finish","digest":digest,"id":id}))?;
            writeln!(output, "{}", text(&response, "message")?)?;
        }
        Command::Help | Command::Logs => unreachable!(),
    }
    Ok(())
}
