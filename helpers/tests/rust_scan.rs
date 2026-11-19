// SPDX-License-Identifier: MIT
mod common;
use enzimos_platform::{files, mount_identity};
use enzimos_recovery_tools::endpoints::{self, Endpoint};
use serde_json::json;
use std::os::fd::AsFd;
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn pinned_panel_scan_skips_copy_links_and_snapshots_and_refuses_changed_sources() {
    let temp = common::fixture();
    let path = temp.path().join("fixture");
    let owner = unsafe { libc::geteuid() };
    let held = files::create_directory(&path, 0o700, owner).unwrap();
    for dir in [
        "home",
        "home/admin",
        "home/admin/docs",
        "home/admin/.snapshots",
    ] {
        files::create_directory(&path.join(dir), 0o700, owner).unwrap();
    }
    let original = path.join("home/admin/docs/file");
    files::atomic(&original, b"original", 0o600, Some(owner), false).unwrap();
    std::os::unix::fs::symlink("/etc", path.join("home/admin/link")).unwrap();
    let unique = mount_identity::id(held.as_fd(), true).unwrap();
    let panel = Endpoint {
        spec: json!({}),
        external: None,
        directory: held,
        unique,
        root_path: path.clone(),
    };
    let scan = endpoints::scan(
        &panel,
        &json!(["/home/admin", "/home/admin/docs", "/home/admin/docs/file"]),
        true,
    )
    .unwrap();
    assert_eq!(scan.roots.len(), 1);
    assert_eq!(scan.records.len(), 3);
    assert_eq!(scan.skipped.len(), 2);
    endpoints::verify(&panel, &scan.records).unwrap();
    assert!(endpoints::scan(&panel, &json!(["/home/admin"]), false).is_err());
    let link = endpoints::scan(&panel, &json!(["/home/admin/link"]), false).unwrap();
    assert_eq!(link.records[0]["kind"], "link");
    endpoints::verify(&panel, &link.records).unwrap();
    assert!(endpoints::roots(&panel, &json!(["/home"]), false).is_err());
    assert!(endpoints::roots(&panel, &json!(["/"]), true).is_err());
    files::atomic(&original, b"changed", 0o600, Some(owner), true).unwrap();
    assert!(endpoints::verify(&panel, &scan.records).is_err());
    drop(panel);
    std::fs::remove_file(original).unwrap();
    std::fs::remove_file(path.join("home/admin/link")).unwrap();
    for dir in [
        "home/admin/docs",
        "home/admin/.snapshots",
        "home/admin",
        "home",
    ] {
        std::fs::remove_dir(path.join(dir)).unwrap();
    }
    std::fs::remove_dir(path).unwrap();
}
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn delete_scan_admits_copy_reports_but_not_other_recovery_records() {
    let dir = common::fixture();
    let path = dir.path().to_path_buf();
    let owner = unsafe { libc::geteuid() };
    let held = files::create_directory(&path.join("root"), 0o700, owner).unwrap();
    let root = path.join("root");
    std::fs::create_dir_all(root.join("home/admin/received")).unwrap();
    let received = root.join("home/admin/received");
    std::fs::write(received.join("photo"), b"data").unwrap();
    std::fs::write(received.join(".enzimos-copy-report-0123.json"), b"{}").unwrap();
    std::fs::write(received.join(".enzimos-incomplete-0123.txt"), b"note").unwrap();
    let unique = mount_identity::id(held.as_fd(), true).unwrap();
    let panel = Endpoint {
        spec: json!({}),
        external: None,
        directory: held,
        unique,
        root_path: root.clone(),
    };
    let selection = json!(["/home/admin/received"]);
    let scan = endpoints::scan(&panel, &selection, false).unwrap();
    assert_eq!(scan.records.len(), 4);
    let copy = endpoints::scan(&panel, &selection, true).unwrap();
    assert_eq!((copy.records.len(), copy.skipped.len()), (2, 2));
    std::fs::remove_file(received.join(".enzimos-incomplete-0123.txt")).unwrap();
    std::fs::create_dir(received.join(".enzimos-incomplete-0123.txt")).unwrap();
    assert!(endpoints::scan(&panel, &selection, false).is_err());
    std::fs::remove_dir(received.join(".enzimos-incomplete-0123.txt")).unwrap();
    std::fs::create_dir(received.join(".enzimos-delete-0123-0")).unwrap();
    assert!(endpoints::scan(&panel, &selection, false).is_err());
}
