# Development

Use the toolchain in `rust-toolchain.toml`. Run the commands in the root README before
submitting changes. `Cargo.lock` is committed for reproducible application builds.

CI builds, lints, and runs behavioral Rust tests on Linux, macOS, and Windows.
It checks formatting and dependency licenses, exercises the distroless API/mirror,
and runs browser, provisioning, and website OTP reference-vector checks on Linux.

Rust tests cover encryption/tampering, persistence, CLI record workflows, account and
group authorization, session revocation, browser-approval grants, schema migration,
snapshot conflicts, and mirror history. Python browser checks cover setup, permissions,
CLI/WASM compatibility, and screenshots. See the root README and [web UI guide](web-ui.md)
for commands. The `API contracts` job validates the group-key delivery
OpenAPI document, schema fixtures, and per-operation test mappings; see the
[test actions](testing/group-key-delivery.md). The browser CI job also checks captured actual delivery requests/responses.
Use synthetic fixtures, never real secrets.

Add focused tests as behavior changes. Delivery, tampering, rotation, migration, and native/WASM interoperability tests are
implemented; expand crash-boundary and multi-process race coverage as part of hardening. See the
[roadmap acceptance criteria](roadmap.md). Native authentication and clean-host recovery
tests remain outstanding because those integrations/workflows are unfinished.

Platform verification must cover Chromium and Firefox native messaging, iOS/Android
autofill, and OS authentication on actual supported environments. A successful Rust
build alone does not establish those capabilities.

The license gate examines all resolved Cargo package license declarations against a
small explicit allowlist. Unknown or compound expressions fail for human review.
This is a metadata gate, not a source-code or legal audit. Review bundled assets,
platform code, notices, and dependency provenance separately. Do not add GPL code.
