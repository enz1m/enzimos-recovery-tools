// SPDX-License-Identifier: MIT
use enzimos_recovery_tools::{authentication, inventory};
use serde_json::json;
#[test]
fn account_password_handoff_refuses_unlisted_users_and_line_injection() {
    let admins = json!([{"name":"admin","label":"Administrator"}]);
    let v = json!({"user":"admin","password":"fixture","request":{"action":"inspect"}});
    let (user, _, request) = authentication::validate_request(&v, &admins).unwrap();
    assert_eq!(user, "admin");
    assert_eq!(request["_stream"], true);
    for (k, value) in [
        ("user", json!("root")),
        ("user", json!("-c")),
        ("password", json!("bad\nline")),
        ("password", json!("bad\0line")),
        ("password", json!("")),
        ("request", json!([])),
    ] {
        let mut bad = v.clone();
        bad[k] = value;
        assert!(authentication::validate_request(&bad, &admins).is_err());
    }
    assert_eq!(
        authentication::read_line(&b"abc\nsecond\n"[..], 3)
            .unwrap()
            .as_slice(),
        b"abc"
    );
    assert!(authentication::read_line(&b"abcd\n"[..], 3).is_err());
}
#[test]
fn package_changes_describe_restore_direction_and_refuse_duplicates() {
    let v = inventory::changes("linux 1\nremoved 2\n", "linux 2\nadded 1\n").unwrap();
    assert_eq!(
        v["changes"],
        json!(["Remove added 1", "linux   2 → 1", "Restore removed 2"])
    );
    assert!(
        v["summary"]
            .as_str()
            .unwrap()
            .contains("1 restored · 1 removed")
    );
    assert!(inventory::changes("linux 1\nlinux 2\n", "").is_err());
    assert!(inventory::changes("linux\n", "").is_err());
}
