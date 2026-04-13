# CLAUDE.md — Seestar Tool

Rust desktop application for managing firmware on ZWO Seestar smart telescopes.
Built with egui (GUI) and ratatui (TUI).

---

## Building

```bash
cargo build           # debug
cargo build --release # release (stripped, opt-level 3)
```

Linux requires system GUI libraries — see README for the `apt-get` list.

---

## Running checks

CI runs these in order; all must pass before merging:

```bash
cargo fmt -- --check   # formatting (enforced, not just style)
cargo clippy -- -D warnings  # all clippy warnings are errors
cargo build
cargo test
```

Run `cargo fmt` (no `--check`) to fix formatting in place.

---

## Lints

The following are **hard errors** (see `[lints.rust]` in Cargo.toml):

- `dead_code`
- `unused_imports`
- `unused_mut`
- `unused_parens`

`clippy::all` is set to warn, and CI promotes every warning to an error via `-D warnings`.
Do not suppress lints with `#[allow(...)]` unless there is a concrete, documented reason.

---

## Code style

- **No external test fixtures** — all test data is constructed in-memory with builder helpers.
- **No `unwrap()` in production code paths** — use `?` and `anyhow::Result`.
- **`unwrap()` is fine inside tests** — panics on assertion failure is the right behavior there.
- Public functions in each module are documented with `///` doc comments. Private helpers do not need docs unless the logic is non-obvious.
- Module-level doc comments (`//!`) describe the module's responsibility and call out the Python reference file it mirrors (if any).

---

## Source layout

| File | Responsibility |
|---|---|
| [src/apk.rs](src/apk.rs) | APK/XAPK unpacking, AXML version parsing, PEM extraction from APKs |
| [src/firmware.rs](src/firmware.rs) | iscope extraction, validation, OTA upload, scope model detection |
| [src/apkpure.rs](src/apkpure.rs) | APKPure scraping and download |
| [src/pem.rs](src/pem.rs) | PEM key scanning and extraction from raw bytes |
| [src/task.rs](src/task.rs) | Shared message types (`TaskMsg`) for background task channels |
| [src/runner.rs](src/runner.rs) | Background task orchestration (firmware install, download, PEM extract) |
| [src/gui.rs](src/gui.rs) | egui front-end |
| [src/tui.rs](src/tui.rs) | ratatui terminal UI |
| [src/main.rs](src/main.rs) | Entry point, CLI flag parsing |

---

## Unit tests

### Requirements for all new features

Every new function with non-trivial logic **must** have unit tests. The bar is:

1. **Happy path** — the function returns the expected result on valid input.
2. **Error paths** — every early-return `Err(...)` branch must be exercised with a test that asserts on the error message or error kind.
3. **Boundary conditions** — off-by-one sizes, empty inputs, minimum/maximum values.

Tests that are not yet written are not optional; do not submit a feature without them.

### Where tests live

Tests go at the **bottom of the same source file** as the code they test, inside:

```rust
#[cfg(test)]
mod tests {
    use super::*;
    // ...
}
```

Do not create separate test files. This keeps the test helpers close to the code they exercise and avoids a proliferating `tests/` directory.

### Naming convention

Test functions are named `<function_being_tested>_<what_is_asserted>`:

```rust
#[test]
fn validate_iscope_rejects_empty_data() { ... }

#[test]
fn is_xapk_false_for_plain_apk() { ... }

#[test]
fn open_apk_returns_error_for_missing_iscope_entry() { ... }
```

Snake case throughout. No `test_` prefix — the `#[test]` attribute is sufficient.

### Building test data in-memory

Tests **never** load files from disk except through a `TempFile` RAII helper (see below).
Instead, construct the minimal data structure needed for each case using a local builder
helper. Examples already in the codebase:

- `make_zip(&[("path", bytes)])` → in-memory ZIP
- `make_fake_iscope(elf_class)` → real tar.bz2 with a minimal fake ELF
- `build_axml(version)` → binary AndroidManifest.xml chunk

Write a new builder helper if the existing ones do not cover the format you need. Keep helpers
in the same `mod tests` block, not at the top level.

### TempFile for disk-required paths

When the function under test requires a filesystem path (e.g., `open_apk` takes `&str`),
use the `TempFile` RAII helper that already exists in each module's test block:

```rust
struct TempFile(std::path::PathBuf);
impl TempFile {
    fn write(name: &str, data: &[u8]) -> Self { ... }
    fn path_str(&self) -> &str { ... }
}
impl Drop for TempFile {
    fn drop(&mut self) { let _ = std::fs::remove_file(&self.0); }
}
```

Copy this pattern into any new module's test block if needed. The RAII cleanup prevents
leftover temp files from polluting the test environment.

### Testability by design — inner functions

When a production function has a hard-coded constant (e.g., a minimum file size) that would
force tests to allocate impractically large buffers, extract an `_inner` variant that accepts
the constant as a parameter and have the public function call it with the real constant:

```rust
fn validate_iscope_data_inner(data: &[u8], model: ScopeModel, min_bytes: usize) -> Result<()> { ... }

#[cfg(test)]
fn validate_iscope_data(data: &[u8], model: ScopeModel) -> Result<()> {
    validate_iscope_data_inner(data, model, ISCOPE_MIN_BYTES)
}
```

Tests call `validate_iscope_data_inner` with a small `min_bytes`; production code always
goes through the wrapper that enforces the real constant.

### Coverage

Coverage is measured with [`cargo llvm-cov`](https://github.com/taiki-e/cargo-llvm-cov):

```bash
# Summary only (fast):
cargo llvm-cov --summary-only

# HTML report:
cargo llvm-cov --open
```

**UI and entry-point files are excluded from coverage expectations.**
`gui.rs` and `main.rs` contain no `mod tests` block and are not expected to have unit test
coverage — egui rendering requires a real GPU context that cannot be exercised in a
headless test run.

`runner.rs` is structurally low (~17–20% line coverage) because it orchestrates
async background tasks that spawn tokio threads and communicate over channels. This is
expected and not a target for improvement via unit tests; integration-level testing would
be required to improve it.

**Coverage targets for core logic modules** (everything except `gui.rs`, `main.rs`,
`runner.rs`):

| Module | Minimum acceptable line coverage |
|---|---|
| `apk.rs` | 95% |
| `firmware.rs` | 90% |
| `pem.rs` | 95% |
| `apkpure.rs` | 80% |
| `task.rs` | 100% (trivial) |

The overall project line coverage (excluding UI and runner) should stay above **85%**.
New code that drops any module below its threshold requires additional tests before merging.

`tui.rs` has a `mod tests` block that covers state-machine logic; the ratatui rendering
path is not exercised and that is acceptable — test the logic, not the terminal drawing.

### No async in tests

All test functions are synchronous. Functions that do I/O (TCP, HTTP) should accept an
address/port parameter so tests can bind a real `TcpListener` on `127.0.0.1:0` and
exercise the full protocol without mocks. See `serve_once` / `serve_api_once` helpers in
[src/firmware.rs](src/firmware.rs) for the established pattern.

### Asserting on error messages

When testing error paths, assert on the message content, not just that an error occurred:

```rust
let err = some_function(bad_input).unwrap_err();
assert!(err.to_string().contains("bzip2"), "got: {}", err);
```

This catches regressions where an error is returned for the wrong reason.

---

## Versioning

Version numbers follow calendar versioning: `YYYY.M.PATCH` (e.g., `2026.4.0`).
Bump the patch component for fixes and minor changes; bump the month component for
significant feature releases. Update `version` in `Cargo.toml`.

---

## Releases

See [RELEASE.md](RELEASE.md) for the release checklist and CI/CD workflow details.
