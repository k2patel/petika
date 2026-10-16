# Clients

The implemented web client lives in `web/`. The Rust server serves its JavaScript/CSS
interface, while a dedicated worker uses `petika-web` WASM bindings for local encryption.
See the [web UI guide](../docs/web-ui.md) for features, build steps, and limitations.
The native CLI lives in `crates/petika-cli` and supports offline storage and managed
account synchronization.

Chromium/Firefox extensions and iOS/Android apps are not implemented. The desktop
integration crate is a placeholder for native messaging and OS authentication.

Planned clients should reuse the Rust core and native platform bindings for autofill
and biometrics. Browser-specific glue must work without npm. Native UI stacks and
packaging remain open decisions. See the [roadmap](../docs/roadmap.md).
