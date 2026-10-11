# Development

Use the toolchain in `rust-toolchain.toml`. Run the commands in the root README before
submitting changes. `Cargo.lock` is committed for reproducible application builds.

CI builds, lints, and tests on Linux, macOS, and Windows. It checks formatting and runs
the dependency-license gate on Linux. The initial foundation has no behavioral test
suite; Cargo test currently checks that all targets and documentation tests compile.

When behavior is introduced, add tests for encryption round trips and tampering,
authentication denial and lock expiry, canceled biometric prompts and passphrase
fallback, sync conflicts and offline changes, sharing/revocation, non-destructive GPG
import, and recovery on a fresh installation. Use synthetic fixtures, never real secrets.

Platform verification must cover Chromium and Firefox native messaging, iOS/Android
autofill, and OS authentication on actual supported environments. A successful Rust
build alone does not establish those capabilities.

The license gate examines all resolved Cargo package license declarations against a
small explicit allowlist. Unknown or compound expressions fail for human review.
This is a metadata gate, not a source-code or legal audit. Review bundled assets,
platform code, notices, and dependency provenance separately. Do not add GPL code.
