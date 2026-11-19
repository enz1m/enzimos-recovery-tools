// SPDX-License-Identifier: MIT
//! Failed recovery is presented for review. Only executed recovery can finish.
use enzimos_platform::{Result, require};
use enzimos_policy::{recovery_activation, recovery_journal::Records, recovery_records};
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Notice {
    Confirmation,
    Unfinished,
    MetadataAttention,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Decision {
    pub identifier: Option<String>,
    pub complete_media: bool,
    pub complete_run: bool,
    pub notice: Option<Notice>,
    pub retained_errors: Vec<String>,
}
pub fn evaluate(command_line: &str, runs: &Records, activations: &Records) -> Result<Decision> {
    require(
        command_line.len() <= 65536 && !command_line.contains('\0'),
        "recovery boot command line bound",
    )?;
    let markers = command_line
        .split_whitespace()
        .filter_map(|word| word.strip_prefix("enzimos.staged="))
        .collect::<Vec<_>>();
    // An ambiguous marker is never a request to mutate either named transaction.
    if markers.len() > 1 {
        return Ok(Decision {
            identifier: None,
            complete_media: false,
            complete_run: false,
            notice: Some(Notice::MetadataAttention),
            retained_errors: vec!["Ambiguous restored boot identity".into()],
        });
    }
    for (id, value) in runs {
        recovery_records::run(value, id)?;
    }
    for (id, value) in activations {
        recovery_activation::validate(value, id)?;
    }
    let mut decision = Decision {
        identifier: None,
        complete_media: false,
        complete_run: false,
        notice: None,
        retained_errors: Vec::new(),
    };
    if let Some(id) = markers.first() {
        recovery_records::job_id(id)?;
        decision.identifier = Some((*id).into());
        decision.complete_media = true;
        let run = runs.get(*id);
        let activation = activations.get(*id);
        if run.is_none() && activation.is_none() {
            decision.notice = Some(Notice::MetadataAttention);
            return Ok(decision);
        }
        let run_phase = run.and_then(|r| r["phase"].as_str());
        let activation_phase = activation.and_then(|r| r["phase"].as_str());
        if run.is_some() && activation.is_none() {
            decision.notice = Some(Notice::MetadataAttention);
            return Ok(decision);
        }
        if matches!(run_phase, Some("staged" | "running" | "failed")) {
            decision.notice = Some(Notice::Unfinished);
            decision
                .retained_errors
                .push("Recovery did not complete; explicit review required".into());
            return Ok(decision);
        }
        let automatic = run
            .and_then(|r| r["entry"]["options"].as_str())
            .is_some_and(|s| s.split_whitespace().any(|w| w == "enzimos.restore-ui=1"));
        decision.complete_run = automatic
            && matches!(activation_phase, Some("selected" | "adopted"))
            && (run_phase == Some("executed")
                || run_phase == Some("complete") && activation_phase == Some("selected"));
        if activation_phase == Some("selected")
            || activation_phase == Some("adopted") && run_phase == Some("executed")
        {
            decision.notice = Some(Notice::Confirmation);
        }
    } else {
        for run in runs.values() {
            let automatic = run["entry"]["options"]
                .as_str()
                .unwrap()
                .split_whitespace()
                .any(|w| w == "enzimos.restore-ui=1");
            if automatic && matches!(run["phase"].as_str(), Some("staged" | "running" | "failed")) {
                decision.notice = Some(Notice::Unfinished);
                let error = run["result"]["error"]
                    .as_str()
                    .unwrap_or("Interrupted before completion");
                decision.retained_errors.push(format!(
                    "Previous snapshot recovery {}: {}",
                    run["phase"].as_str().unwrap(),
                    error.chars().take(500).collect::<String>()
                ));
            }
        }
    }
    Ok(decision)
}
