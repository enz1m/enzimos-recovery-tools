// SPDX-License-Identifier: MIT
use enzimos_policy::{recovery_journal::Records, recovery_records};
use enzimos_recovery_tools::{
    protocol,
    session_state::{self, Notice},
};
use serde_json::json;
use std::io::Cursor;
#[test]
fn persistent_browse_pipe_refuses_every_mutation_and_duplicate_key_before_executor() {
    let frames = b"{\"action\":\"files_list\"}\n{\"action\":\"files_copy\"}\n{\"action\":\"files_drives\",\"action\":\"files_list\"}\n{\"action\":\"files_drives\"}\n";
    let mut output = Vec::new();
    let mut calls = Vec::new();
    protocol::serve(
        json!({"action":"browse_session","_stream":true}),
        &mut Cursor::new(frames),
        &mut output,
        |request, _| {
            calls.push(request["action"].as_str().unwrap().to_owned());
            Ok(json!({"ok":true}))
        },
    )
    .unwrap();
    assert_eq!(calls, ["files_list", "files_drives"]);
    let lines = String::from_utf8(output)
        .unwrap()
        .lines()
        .map(|s| serde_json::from_str::<serde_json::Value>(s).unwrap())
        .collect::<Vec<_>>();
    assert_eq!(lines[0], json!({"authenticated":true}));
    assert_eq!(lines.len(), 5);
    assert!(lines[2].get("error").is_some());
    assert!(lines[3].get("error").is_some());
    assert!(
        protocol::serve(
            json!({"action":"browse_session","_stream":1}),
            &mut Cursor::new([]),
            &mut Vec::new(),
            |_, _| panic!("invalid stream dispatched")
        )
        .is_err()
    );
}
#[test]
fn bounded_frames_handle_partial_eof_and_refuse_oversize_before_dispatch() {
    let mut input = Cursor::new(b"{\"action\":\"files_list\"}");
    assert!(protocol::read_line(&mut input).unwrap().is_some());
    assert!(protocol::read_line(&mut input).unwrap().is_none());
    let mut oversized = Cursor::new(vec![b'a'; protocol::MAX_REQUEST + 2]);
    assert!(protocol::read_line(&mut oversized).is_err());
}
fn run(phase: &str) -> serde_json::Value {
    let (entry, title) = recovery_records::run_entry_names("job1").unwrap();
    json!({"schema":1,"id":"job1","phase":phase,"plan_sha256":"a".repeat(64),"flavor":"linux","image":format!("ri-{}","b".repeat(64)),"created_boot":"00000000-0000-0000-0000-000000000001","entry":{"uefi_entry":entry,"uefi_previous":"normal.conf","uefi_mode":"one-shot","bios_title":title,"bios_previous":1,"bios_own":2,"options":"quiet enzimos.restore-ui=1"},"result":{"error":"Retained failure"}})
}
#[test]
fn failed_automatic_recovery_remains_visible_without_replay_and_ambiguous_boot_never_mutates() {
    let runs = Records::from([("job1".into(), run("failed"))]);
    let decision = session_state::evaluate("quiet", &runs, &Records::new()).unwrap();
    assert_eq!(decision.notice, Some(Notice::Unfinished));
    assert!(!decision.complete_run);
    assert!(!decision.complete_media);
    assert_eq!(decision.retained_errors.len(), 1);
    let ambiguous = session_state::evaluate(
        "enzimos.staged=job1 enzimos.staged=job1",
        &runs,
        &Records::new(),
    )
    .unwrap();
    assert_eq!(ambiguous.notice, Some(Notice::MetadataAttention));
    assert!(!ambiguous.complete_run);
    assert!(!ambiguous.complete_media);
    assert!(ambiguous.identifier.is_none());
    let executed = Records::from([("job1".into(), run("executed"))]);
    assert!(
        !session_state::evaluate("enzimos.staged=job1", &executed, &Records::new())
            .unwrap()
            .complete_run
    );
    assert_eq!(
        session_state::evaluate("enzimos.staged=job1", &executed, &Records::new())
            .unwrap()
            .notice,
        Some(Notice::MetadataAttention)
    );
    assert!(
        !session_state::evaluate("enzimos.staged=job1", &runs, &Records::new())
            .unwrap()
            .complete_run
    );
    assert_eq!(
        session_state::evaluate("enzimos.staged=unknown", &Records::new(), &Records::new())
            .unwrap()
            .notice,
        Some(Notice::MetadataAttention)
    );
}
