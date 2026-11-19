// SPDX-License-Identifier: MIT

pub(super) fn fixture() -> tempfile::TempDir {
    let parent = std::env::var_os("ENZIMOS_TEST_TMPDIR")
        .or_else(|| std::env::var_os("HOME"))
        .expect("set ENZIMOS_TEST_TMPDIR to a private test directory");
    // The recovery filesystem checks require every ancestor to be protected.
    tempfile::Builder::new()
        .prefix("enzimos-recovery-test-")
        .tempdir_in(parent)
        .expect("create a temporary fixture beneath the private test directory")
}
