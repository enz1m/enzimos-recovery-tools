// SPDX-License-Identifier: MIT
use enzimos_recovery_tools::{
    accounts::Account,
    terminal_contract::{self as c, Exec, Properties},
};
use zbus::zvariant::{OwnedValue, Value};
fn put<T: Into<OwnedValue>>(p: &mut Properties, key: &str, value: T) {
    p.insert(key.into(), value.into());
}
fn complex<T: Into<Value<'static>>>(p: &mut Properties, key: &str, value: T) {
    p.insert(key.into(), OwnedValue::try_from(value.into()).unwrap());
}
fn fixture() -> (Account, Properties, Properties) {
    let a = Account {
        name: "admin".into(),
        uid: 1000,
        gid: 1000,
    };
    let mut u = Properties::new();
    let mut s = Properties::new();
    put(
        &mut u,
        "Id",
        OwnedValue::try_from(Value::from(c::UNIT)).unwrap(),
    );
    put(&mut u, "Transient", true);
    put(
        &mut u,
        "FragmentPath",
        OwnedValue::try_from(Value::from(format!("/run/systemd/transient/{}", c::UNIT))).unwrap(),
    );
    complex(&mut u, "DropInPaths", Vec::<String>::new());
    complex(&mut u, "InvocationID", vec![1u8; 16]);
    put(
        &mut u,
        "ActiveState",
        OwnedValue::try_from(Value::from("active")).unwrap(),
    );
    for (key, v) in [
        ("User", "0"),
        ("Type", "exec"),
        ("KillMode", "control-group"),
        ("Restart", "no"),
    ] {
        put(&mut s, key, OwnedValue::try_from(Value::from(v)).unwrap());
    }
    put(
        &mut s,
        "ControlGroup",
        OwnedValue::try_from(Value::from(format!("/system.slice/{}", c::UNIT))).unwrap(),
    );
    put(&mut s, "MainPID", 1234u32);
    let exec: Exec = (
        c::WRAPPER.into(),
        c::arguments(&a).unwrap(),
        false,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    complex(&mut s, "ExecStart", vec![exec]);
    (a, u, s)
}
#[test]
fn terminal_reuse_requires_the_exact_ordinary_account_and_native_transient_unit() {
    let (a, u, s) = fixture();
    assert_eq!(c::validate(&u, &s, &a).unwrap().pid, 1234);
    for account in [
        Account {
            name: "other".into(),
            ..a.clone()
        },
        Account {
            uid: 1001,
            ..a.clone()
        },
        Account {
            gid: 1001,
            ..a.clone()
        },
    ] {
        assert!(c::validate(&u, &s, &account).is_err());
    }
    for (key, v) in [
        ("KillMode", "process"),
        ("Restart", "always"),
        ("User", "1000"),
        ("ControlGroup", "/user.slice/foreign"),
    ] {
        let (_, u, mut s) = fixture();
        put(&mut s, key, OwnedValue::try_from(Value::from(v)).unwrap());
        assert!(c::validate(&u, &s, &a).is_err());
    }
    let (_, mut u, s) = fixture();
    complex(
        &mut u,
        "DropInPaths",
        vec!["/etc/systemd/system/foreign.conf".to_string()],
    );
    assert!(c::validate(&u, &s, &a).is_err());
    let (_, mut u, s) = fixture();
    put(&mut u, "Transient", false);
    assert!(c::validate(&u, &s, &a).is_err());
}
#[test]
fn terminal_refuses_root_groups_changed_commands_and_wrong_property_types() {
    let (a, u, mut s) = fixture();
    let exec: Exec = (
        "/usr/bin/python3".into(),
        vec!["python3".into()],
        false,
        0,
        0,
        0,
        0,
        0,
        0,
        0,
    );
    complex(&mut s, "ExecStart", vec![exec]);
    assert!(c::validate(&u, &s, &a).is_err());
    let (a, u, mut s) = fixture();
    put(&mut s, "MainPID", true);
    assert!(c::validate(&u, &s, &a).is_err());
    for account in [
        Account {
            uid: 0,
            ..a.clone()
        },
        Account {
            gid: 0,
            ..a.clone()
        },
        Account {
            name: "--root".into(),
            ..a.clone()
        },
    ] {
        assert!(c::arguments(&account).is_err());
    }
    let (_, mut u, s) = fixture();
    complex(&mut u, "InvocationID", vec![1u8; 15]);
    assert!(c::validate(&u, &s, &a).is_err());
}

#[test]
fn inactive_terminal_waits_only_for_its_original_queued_job() {
    use zbus::zvariant::OwnedObjectPath;
    let original = OwnedObjectPath::try_from("/org/freedesktop/systemd1/job/41").unwrap();
    assert!(c::queued_start(&(41, original.clone()), &original).is_ok());
    for (id, path) in [
        (0, "/"),
        (42, "/org/freedesktop/systemd1/job/42"),
        (40, "/org/freedesktop/systemd1/job/41"),
        (41, "/org/freedesktop/systemd1/job/041"),
    ] {
        assert!(
            c::queued_start(&(id, OwnedObjectPath::try_from(path).unwrap()), &original).is_err()
        );
    }
}
