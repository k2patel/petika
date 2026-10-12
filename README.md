# Petika · पेटिका

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/petika-icon-dark.png">
  <img src="assets/brand/petika-icon-light.png" alt="Petika — open chest with rising binary digits" width="140">
</picture>

**Your secrets. Your infrastructure.**

An open-source, self-hosted password manager written in Rust. Petika means a small box in Sanskrit.

**Status: experimental implementation. Use synthetic data only.**
The Rust CLI supports encrypted local storage, password generation, GPG imports, and
[managed-account browser login with encrypted pull/push](docs/cli-accounts.md).
Setup offers standard or experimental hybrid post-quantum encryption. The API stores
ciphertext with revision checks and a one-way encrypted Git mirror; entry names and
folder hierarchy stay inside the encrypted snapshot.

[Deploy from source, distroless Docker, Kubernetes, or Podman kube play](docs/deployment.md).
The [web UI](docs/web-ui.md) includes local accounts, users/groups, encrypted collections,
website OTP, profile settings, and system/light/dark themes. [First-run setup](docs/setup.md)
can be completed through the browser or environment variables. [Versioned schemas](docs/schema.md)
provide a migration path for upgrades.

Browser autofill, mobile apps, biometric unlock, full native GPG key management,
optional OpenID Connect, and automatic per-user sharing-key delivery are still planned.
Group collections currently require sharing an unlock passphrase through a separate channel.

## Development

Install Rust through [rustup](https://rustup.rs/) and Python 3 for the license check.
The repository pins its Rust toolchain, including rustfmt and Clippy.

```sh
cargo build --workspace --locked
cargo run -p petika -- --help
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/check_licenses.py
```

Petika is not published to Cargo yet. Future distribution will use Cargo and native
binaries, with no npm dependency or distribution.

## Repository

- `crates/`: shared Rust core, CLI, API server, and desktop integration.
- `clients/`: planned browser and mobile client boundaries.
- `deploy/`: self-hosting and deployment requirements.
- `docs/`: architecture, requirements, operations, and development documentation.

Start with the [documentation index](docs/README.md),
[requirements](docs/requirements.md), and [architecture](docs/architecture.md).

## License and provenance

[MIT](LICENSE), copyright 2026 K2patel. Petika starts from original code in this
repository. It does not contain or translate the GPL implementation of `pass`.
Existing GPG stores can be imported locally using the native CLI and GnuPG.
See [contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).
