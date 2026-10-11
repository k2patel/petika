# Petika · पेटिका

An open-source, self-hosted password manager written in Rust. Petika means a small box in Sanskrit.

**Status: repository foundation only. Do not store real secrets in this code.**
The CLI supports help and version output. The server deliberately exits with an error;
there is no working vault, encryption, login, sync, sharing, or autofill yet.

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
Compatibility with existing stores will be implemented through a local GPG importer.
See [contributing](CONTRIBUTING.md) and [security reporting](SECURITY.md).
