// SPDX-License-Identifier: MIT
mod common;
use enzimos_platform::{Error, files};
use enzimos_recovery_tools::reviews::Store;
use serde_json::json;
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn reviewed_file_operations_expire_bind_administrator_and_cannot_replay() {
    let temp = common::fixture();
    let path = temp.path().join("fixture");
    let owner = unsafe { libc::geteuid() };
    let store = Store::new(&path, owner).unwrap();
    let payload =
        json!({"operation":"delete","roots":["/home/admin/fixture"],"records":[],"bytes":0});
    let expired = store.save(&payload, 1000, 1000).unwrap();
    let expired_name = expired["plan"].as_str().unwrap();
    let expired_path = path.join(format!("{expired_name}.json"));
    let mut expired_record: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&expired_path).unwrap()).unwrap();
    expired_record["created"] = json!(expired_record["created"].as_f64().unwrap() - 901.0);
    expired_record.as_object_mut().unwrap().remove("digest");
    let expired_sha = enzimos_platform::json::fingerprint(&expired_record).unwrap();
    expired_record["digest"] = json!(&expired_sha);
    files::atomic(
        &expired_path,
        &enzimos_platform::json::canonical(&expired_record).unwrap(),
        0o600,
        Some(owner),
        true,
    )
    .unwrap();
    let mut called = false;
    assert!(
        store
            .consume(expired_name, &expired_sha, 1000, |_| {
                called = true;
                Ok(())
            })
            .is_err()
    );
    assert!(!called);
    assert!(expired_path.exists());
    std::fs::remove_file(expired_path).unwrap();
    let reviewed = store.save(&payload, 1000, 1000).unwrap();
    let name = reviewed["plan"].as_str().unwrap();
    let sha = reviewed["digest"].as_str().unwrap();
    assert!(store.consume(name, sha, 1001, |_| Ok(())).is_err());
    assert!(
        store
            .consume(name, &"0".repeat(64), 1000, |_| Ok(()))
            .is_err()
    );
    assert!(
        store
            .consume(name, sha, 1000, |_| Err(Error("source changed".into())))
            .is_err()
    );
    assert!(path.join(format!("{name}.json")).exists());
    let value = store
        .consume(name, sha, 1000, |v| {
            assert_eq!(v["operation"], "delete");
            Ok(())
        })
        .unwrap();
    assert_eq!(value["owner"], 1000);
    assert!(!path.join(format!("{name}.json")).exists());
    assert!(path.join(format!("{name}.consumed")).exists());
    assert!(store.consume(name, sha, 1000, |_| Ok(())).is_err());
    store.complete(name, &json!({"completed":true})).unwrap();
    assert!(store.complete(name, &json!({"completed":true})).is_err());
    // A prepared but unpublished result makes the entire private store refuse
    // further operation. There is no guess about whether to replay a mutation.
    assert!(Store::new(&path, owner).is_ok());
    files::atomic(
        &path.join(format!("{name}.result.json.new")),
        b"{}",
        0o600,
        Some(owner),
        false,
    )
    .unwrap();
    assert!(Store::new(&path, owner).is_err());
    drop(store);
    for name in [
        format!("{name}.consumed"),
        format!("{name}.result.json"),
        format!("{name}.result.json.new"),
        "review.lock".to_owned(),
    ] {
        std::fs::remove_file(path.join(name)).unwrap();
    }
    std::fs::remove_dir(path).unwrap();
}
