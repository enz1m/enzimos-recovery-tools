// SPDX-License-Identifier: MIT
mod common;
use enzimos_platform::files;
use enzimos_recovery_tools::file_paths;
#[test]
#[allow(unsafe_code, reason = "Linux syscall ABI (geteuid).")]
fn file_panels_refuse_escape_links_reserved_names_and_overwrites() {
    for path in [
        "/home/../etc",
        "/var/.snapshots/1",
        "/dev/sda",
        "relative",
        "/etc/\0secret",
    ] {
        assert!(file_paths::source(path).is_err());
    }
    for path in ["../escape", "/etc", "nested/../../escape"] {
        assert!(file_paths::destination(path).is_err());
    }
    for name in [
        "",
        ".",
        "..",
        ".snapshots",
        ".enzimos-incomplete-x",
        "two/parts",
        "bad\n",
    ] {
        assert!(file_paths::name(name).is_err());
    }
    let temp = common::fixture();
    let path = temp.path().join("fixture");
    let owner = unsafe { libc::geteuid() };
    let held = files::create_directory(&path, 0o700, owner).unwrap();
    files::atomic(&path.join("original"), b"one", 0o600, Some(owner), false).unwrap();
    files::atomic(&path.join("existing"), b"two", 0o600, Some(owner), false).unwrap();
    assert!(file_paths::rename_new(&held, "original", "existing", true).is_err());
    assert_eq!(std::fs::read(path.join("existing")).unwrap(), b"two");
    assert_eq!(std::fs::read(path.join("original")).unwrap(), b"one");
    file_paths::rename_new(&held, "original", "new", true).unwrap();
    assert_eq!(std::fs::read(path.join("new")).unwrap(), b"one");
    std::os::unix::fs::symlink("/etc", path.join("link")).unwrap();
    assert!(file_paths::open_destination(&held, "link").is_err());
    let listing = file_paths::listing(&held, "", Some(0), false).unwrap();
    assert_eq!(listing["total"], 2);
    assert_eq!(
        file_paths::listing(&held, "", Some(0), false).unwrap(),
        listing
    );
    std::fs::remove_file(path.join("link")).unwrap();
    std::fs::remove_file(path.join("new")).unwrap();
    std::fs::remove_file(path.join("existing")).unwrap();
    drop(held);
    std::fs::remove_dir(path).unwrap();
}
