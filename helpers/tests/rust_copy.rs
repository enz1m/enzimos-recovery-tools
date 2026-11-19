// SPDX-License-Identifier: MIT
mod common;
use enzimos_platform::{files, mount_identity};
use enzimos_recovery_tools::{
    endpoints::{self, Endpoint},
    manager_plan, rescue_copy,
};
use serde_json::json;
use std::{os::fd::AsFd, path::Path};
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn panel(root: &Path) -> Endpoint {
    let uid = unsafe { libc::geteuid() };
    let directory = files::create_directory(root, 0o700, uid).unwrap();
    let unique = mount_identity::id(directory.as_fd(), true).unwrap();
    Endpoint {
        spec: json!({}),
        external: None,
        directory,
        unique,
        root_path: root.into(),
    }
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (getegid, geteuid).")]
fn rescue_copy_independently_verifies_bytes_preserves_names_and_keeps_incomplete_markers() {
    let temp = common::fixture();
    let uid = unsafe { libc::geteuid() };
    let gid = unsafe { libc::getegid() };
    let source = panel(&temp.path().join("source"));
    let destination = panel(&temp.path().join("destination"));
    for p in ["home", "home/admin", "home/admin/docs"] {
        files::create_directory(&source.root_path.join(p), 0o700, uid).unwrap();
    }
    for p in ["home", "home/output"] {
        files::create_directory(&destination.root_path.join(p), 0o700, uid).unwrap();
    }
    let body = vec![0x7f; 3 * 1024 * 1024];
    for (name, data) in [
        ("binary", body.as_slice()),
        ("line\nname", b"unchanged".as_slice()),
        ("empty", b"".as_slice()),
    ] {
        files::atomic_bounded(
            &source.root_path.join("home/admin/docs").join(name),
            data,
            0o600,
            Some(uid),
            false,
            4 * 1024 * 1024,
        )
        .unwrap();
    }
    let scan = endpoints::scan(&source, &json!(["/home/admin/docs"]), true).unwrap();
    let target = destination.open("/home/output", true).unwrap();
    use std::os::unix::fs::MetadataExt;
    let m = target.metadata().unwrap();
    let total = scan
        .records
        .iter()
        .filter(|r| r["kind"] == "file")
        .map(|r| r["identity"][3].as_u64().unwrap())
        .sum::<u64>();
    let record = json!({"owner":uid,"gid":gid,"operation":"copy","parent":"/home/output","parent_identity":[m.dev(),m.ino()],"bytes":total,"records":scan.records,"roots":scan.roots,"skipped":scan.skipped});
    let token = files::random_hex(16).unwrap();
    let mut emitted = 0;
    assert!(manager_plan::same_tree(&source, &destination));
    let result = rescue_copy::execute(&source, &destination, &record, &token, |_| {
        emitted += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(result["completed"], true);
    assert!(emitted > 0);
    let output = destination.root_path.join("home/output");
    for (name, data) in [
        ("binary", body.as_slice()),
        ("line\nname", b"unchanged".as_slice()),
        ("empty", b"".as_slice()),
    ] {
        assert_eq!(std::fs::read(output.join("docs").join(name)).unwrap(), data);
        assert_eq!(
            std::fs::read(source.root_path.join("home/admin/docs").join(name)).unwrap(),
            data
        );
    }
    assert!(
        !output
            .join(format!(".enzimos-incomplete-{token}.txt"))
            .exists()
    );
    assert!(
        output
            .join(format!(".enzimos-copy-report-{token}.json"))
            .exists()
    );
    let other = files::random_hex(16).unwrap();
    assert!(rescue_copy::execute(&source, &destination, &record, &other, |_| Ok(())).is_err());
    assert!(
        output
            .join(format!(".enzimos-incomplete-{other}.txt"))
            .exists()
    );
    assert_eq!(std::fs::read(output.join("docs/binary")).unwrap(), body);
    // The original wizard layout retains the full /home/admin/... tree, with
    // ancestors created only inside this new, empty backup namespace.
    let root = rescue_copy::mkdir(&target, "fresh", uid, gid).unwrap();
    let m = root.metadata().unwrap();
    let mut legacy = record.clone();
    legacy["parent"] = json!("/home/output/fresh");
    legacy["parent_identity"] = json!([m.dev(), m.ino()]);
    let roots = scan.roots;
    let mut rows = legacy["records"].as_array().unwrap().clone();
    enzimos_recovery_tools::file_rescue::layout(&mut rows, &roots, false).unwrap();
    legacy["records"] = json!(rows);
    let token = files::random_hex(16).unwrap();
    rescue_copy::execute_legacy(&source, &destination, &legacy, &token, false, |v| {
        assert!(v["progress"]["files"].is_u64());
        assert_eq!(v["progress"]["total_files"], 3);
        Ok(())
    })
    .unwrap();
    let tree = output.join("fresh");
    assert_eq!(
        std::fs::read(tree.join("home/admin/docs/binary")).unwrap(),
        body
    );
    assert!(!tree.join("INCOMPLETE.txt").exists());
    let report: serde_json::Value =
        serde_json::from_slice(&std::fs::read(tree.join("COPY-REPORT.json")).unwrap()).unwrap();
    assert_eq!(report["files"].as_array().unwrap().len(), 3);
    assert!(
        report["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|v| v["bytes"].is_u64())
    );
    assert!(
        rescue_copy::execute_legacy(
            &source,
            &destination,
            &legacy,
            &files::random_hex(16).unwrap(),
            false,
            |_| Ok(())
        )
        .is_err()
    );
    assert!(tree.join("INCOMPLETE.txt").exists());
}
