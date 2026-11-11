# Clients

The implemented web client lives in `web/`. The Rust server serves its JavaScript/CSS
interface, while a dedicated worker uses `petika-web` WASM bindings for local encryption.
See the [web UI guide](../docs/web-ui.md) for features, build steps, and limitations.
The native CLI lives in `crates/petika-cli` and supports offline storage and managed
account synchronization.

An experimental [Chromium toolbar extension](extension/README.md) supports explicit
login and TOTP filling with local WASM decryption. Firefox and iOS/Android clients
are not implemented. The desktop
integration crate is a placeholder for native messaging and OS authentication.

The Google Play Console entry uses **Petika** with Android package name
`com.aummaashree.petika`, sponsored by **Aum Maa Shree LLC**. Use this package
name as the future Android app's `applicationId`. See the
[documented app identity](../docs/branding.md#sponsorship-and-android-app-identity).

The registered iOS App Store name is **Petika Password Manager**, with bundle
ID `com.aummaashree.petika`. See the
[iOS app identity](../docs/branding.md#ios-app-identity) for registration status.

Planned clients should reuse the Rust core and native platform bindings for autofill
and biometrics. Browser-specific glue must work without npm. Native UI stacks and
packaging remain open decisions. See the [roadmap](../docs/roadmap.md).
