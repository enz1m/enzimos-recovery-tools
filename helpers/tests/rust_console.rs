// SPDX-License-Identifier: MIT
use enzimos_recovery_tools::console::{self, Command};
use serde_json::json;
use std::io::Cursor;
fn state() -> serde_json::Value {
    json!({"digest":"a".repeat(64),"choices":[{"generation":"gen1","birth":"birth1","available":true}],"runs":{},"activations":{}})
}
#[test]
fn console_restore_requires_literal_confirmation_and_uses_the_observed_digest() {
    for confirm in ["", "yes\n", "RESTORE extra\n"] {
        let mut calls = Vec::new();
        console::execute(
            Command::Restore("gen1".into()),
            |v| {
                calls.push(v.clone());
                Ok(state())
            },
            &mut Cursor::new(confirm),
            &mut Vec::new(),
        )
        .unwrap();
        assert_eq!(calls, [json!({"action":"inspect"})]);
    }
    let mut calls = Vec::new();
    console::execute(
        Command::Restore("gen1".into()),
        |v| {
            calls.push(v.clone());
            Ok(if v["action"] == "inspect" {
                state()
            } else {
                json!({"message":"Prepared","run":"ui-job1"})
            })
        },
        &mut Cursor::new("RESTORE\n"),
        &mut Vec::new(),
    )
    .unwrap();
    assert_eq!(
        calls[1],
        json!({"action":"restore","digest":"a".repeat(64),"birth":"birth1","generation":"gen1"})
    );
}
#[test]
fn console_refuses_ambiguous_choices_and_malformed_commands_before_mutation() {
    for args in [
        vec!["restore"],
        vec!["restore", "../root"],
        vec!["finish", "job", "extra"],
        vec!["list", "foreign"],
    ] {
        assert!(Command::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>()).is_err());
    }
    let mut duplicate = state();
    let choice = duplicate["choices"][0].clone();
    duplicate["choices"].as_array_mut().unwrap().push(choice);
    let mut calls = 0;
    assert!(
        console::execute(
            Command::Restore("gen1".into()),
            |_| {
                calls += 1;
                Ok(duplicate.clone())
            },
            &mut Cursor::new("RESTORE\n"),
            &mut Vec::new()
        )
        .is_err()
    );
    assert_eq!(calls, 1);
    console::execute(
        Command::Help,
        |_| panic!("help requested privilege"),
        &mut Cursor::new(""),
        &mut Vec::new(),
    )
    .unwrap();
}
