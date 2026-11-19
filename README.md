# enzimOS Recovery Tools

These Linux helpers provide the native operations used by
[enzimOS Recovery](https://github.com/enz1m/recovery). They handle administrator
authentication, file rescue, snapshot recovery, backup restore and recovery
session startup.

| Binary | Purpose |
| --- | --- |
| `enzimos-recovery-auth` | Opens a private administrator-authenticated channel. |
| `enzimos-recovery-helper` | Handles snapshot review, recovery, diagnostics and file operations. |
| `enzimos-recovery-backup` | Recovers personal files from encrypted Restic backups on external drives, SMB shares or HTTPS REST servers. |
| `enzimos-recovery-cli` | Provides a console interface for recovery. |
| `enzimos-recovery-open-terminal` | Opens the recovery console under the authenticated account. |
| `enzimos-recovery-session-state` | Checks recovery records at boot and reports work that needs confirmation. |

## Build and test

Use Linux, Rust 1.95 or newer, a C toolchain, pkg-config and the OpenSSL
development libraries. Cargo fetches the pinned public
[enzimOS Packages](https://github.com/enz1m/enzimos-packages) crates.

```sh
cargo build --release --locked --manifest-path helpers/Cargo.toml --bins
cargo test --locked --manifest-path helpers/Cargo.toml --all-targets
```

The tests use synthetic backup data, temporary files and private protocol
fixtures. Filesystem tests create protected temporary directories under
`$HOME`. Set `ENZIMOS_TEST_TMPDIR` to an existing user-owned directory with
protected ancestors if your test environment uses a shared home location.

## Package integration

[`packaging/rust/runtime.json`](packaging/rust/runtime.json) and the accompanying
Arch recipe describe the six binaries installed under
`/usr/lib/enzimos-recovery/`. The runtime keeps the existing
`enzimos-rust-recovery-ui` package identity for enzimOS Build Tools.

An installed recovery system also needs the recovery environment and its
systemd, sudo and PAM configuration. Run privileged recovery workflows inside a
disposable enzimOS guest.

## License

[MIT](LICENSE)
