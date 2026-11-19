// SPDX-License-Identifier: MIT
mod common;
use enzimos_platform::files;
use enzimos_recovery_tools::{file_paths, quarantine};
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn replacing_a_selected_name_during_capture_never_deletes_the_unreviewed_inode() {
    let temp = common::fixture();
    let path = temp.path().join("fixture");
    let uid = unsafe { libc::geteuid() };
    let parent = files::create_directory(&path, 0o700, uid).unwrap();
    let file = path.join("selected");
    files::atomic(&file, b"reviewed", 0o600, Some(uid), false).unwrap();
    let expected = file_paths::identity(&std::fs::metadata(&file).unwrap()).unwrap();
    let token = files::random_hex(16).unwrap();
    let result = quarantine::remove(
        &parent,
        std::ffi::OsStr::new("selected"),
        &expected,
        false,
        &token,
        0,
        || {
            std::fs::rename(&file, path.join("reviewed-original")).unwrap();
            files::atomic(&file, b"unreviewed replacement", 0o600, Some(uid), false).unwrap();
            Ok(())
        },
    );
    assert!(result.is_err());
    assert_eq!(
        std::fs::read(path.join("reviewed-original")).unwrap(),
        b"reviewed"
    );
    let holding = path.join(format!(".enzimos-delete-{token}-0"));
    assert_eq!(
        std::fs::read(holding.join("item")).unwrap(),
        b"unreviewed replacement"
    );
    std::fs::remove_file(holding.join("item")).unwrap();
    std::fs::remove_dir(holding).unwrap();
    std::fs::remove_file(path.join("reviewed-original")).unwrap();
    files::atomic(&file, b"reviewed", 0o600, Some(uid), false).unwrap();
    let expected = file_paths::identity(&std::fs::metadata(&file).unwrap()).unwrap();
    quarantine::remove(
        &parent,
        std::ffi::OsStr::new("selected"),
        &expected,
        false,
        &token,
        1,
        || Ok(()),
    )
    .unwrap();
    assert!(!file.exists());
    drop(parent);
    std::fs::remove_dir(path).unwrap();
}
#[test]
fn failed_capture_removes_the_empty_holding_directory() {
    let dir = common::fixture();
    let file = dir.path().join("selected");
    std::fs::write(&file, b"reviewed").unwrap();
    let expected = file_paths::identity(&std::fs::metadata(&file).unwrap()).unwrap();
    let parent = std::fs::File::open(dir.path()).unwrap();
    let token = files::random_hex(16).unwrap();
    let result = quarantine::remove(
        &parent,
        std::ffi::OsStr::new("selected"),
        &expected,
        false,
        &token,
        0,
        || {
            std::fs::remove_file(&file).unwrap();
            Ok(())
        },
    );
    assert!(result.unwrap_err().0.contains("holding directory removed"));
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn no_replace_fallback_moves_files_and_folders_without_replacing() {
    let dir = common::fixture();
    let parent = std::fs::File::open(dir.path()).unwrap();
    let path = |n: &str| dir.path().join(n);
    std::fs::write(path("file"), b"one").unwrap();
    std::fs::write(path("taken"), b"keep").unwrap();
    std::fs::create_dir(path("folder")).unwrap();
    std::fs::write(path("folder/inner"), b"two").unwrap();
    for link in [true, false] {
        assert!(file_paths::move_new_fallback(&parent, c"file", &parent, c"taken", link).is_err());
        assert!(
            file_paths::move_new_fallback(&parent, c"folder", &parent, c"taken", link).is_err()
        );
    }
    assert_eq!(std::fs::read(path("taken")).unwrap(), b"keep");
    file_paths::move_new_fallback(&parent, c"file", &parent, c"linked", true).unwrap();
    file_paths::move_new_fallback(&parent, c"linked", &parent, c"renamed", false).unwrap();
    assert!(!path("file").exists() && !path("linked").exists());
    assert_eq!(std::fs::read(path("renamed")).unwrap(), b"one");
    std::fs::create_dir(path("holding")).unwrap();
    let holding = std::fs::File::open(path("holding")).unwrap();
    file_paths::move_new_fallback(&parent, c"folder", &holding, c"item", true).unwrap();
    assert_eq!(std::fs::read(path("holding/item/inner")).unwrap(), b"two");
    assert!(!path("folder").exists());
    std::fs::create_dir(path("empty")).unwrap();
    file_paths::rename_new(&parent, "empty", "moved", false).unwrap();
    assert!(file_paths::rename_new(&parent, "moved", "renamed", false).is_err());
    assert!(path("moved").is_dir());
}
