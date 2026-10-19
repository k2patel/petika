# Petika · पेटिका

<picture>
  <source media="(prefers-color-scheme: dark)" srcset="assets/brand/petika-icon-dark.png">
  <img src="assets/brand/petika-icon-light.png" alt="Petika — Indian-patterned open chest with rising Devanagari binary digits" width="140">
</picture>

**Your secrets. Your infrastructure.**

Petika is an open-source, self-hosted password manager built in Rust. Its name means
“small box” in Sanskrit. Keep passwords, website verification codes, and shared
collections on infrastructure you control, with encryption performed on your device.

**Experimental and unaudited. Use synthetic data only for now.**
Petika is not yet published to crates.io, and no public prebuilt container image is published.
Build from this repository. There is no npm build or runtime dependency.

## Start here

**Trying Petika from GitHub?** Read [Use the preview before browser-store releases](docs/preview-installation.md)
for web-only access, unpacked Chrome installation, updates, and the Chrome/Firefox
signing and store-release plans. No browser extension is needed for the web app.

- **Everyday users:** [Sign in, save passwords, set up TOTP, install the extension preview, and keep backups](docs/user-guide.md).
- **Administrators:** [Install the server, onboard users, prepare S3 buckets/SSH storage, and operate backups/recovery](docs/administrator-guide.md).
- **Developers:** [Build and verify changes](docs/development.md).

Install Petika on your own server; there is no hosted signup service. Test the web
app at `http://localhost:8080`, or use a custom HTTPS domain for remote access.
For encrypted Git backups, choose your own private repository on GitHub, GitLab,
Codeberg, or a Git server you operate; see [Git hosting choices](docs/deployment.md#choose-your-git-host).

## What works today

- **Rust CLI:** local encrypted storage, password generation, GPG password-store import,
  browser-approved managed-account login, and encrypted collection pull/push.
- **Web UI:** create, search, edit, and delete entries; generate/reveal/copy passwords;
  import/export encrypted collections; automatic locking; system/light/dark themes.
- **Managed accounts:** first-administrator setup, sign-in, profiles, password changes,
  user administration, disabling accounts, and group read/edit permissions.
- **Website OTP:** encrypted TOTP seeds, live verification codes, and code copying.
- **Chromium preview:** unpacked toolbar extension with local unlock and explicit login/TOTP
  filling; exact website permissions and client revocation. Not a browser-store release.
- **Off-site backups:** user/operator S3 and SSH server push, plus user-scoped API pull keys.
- **Encryption choices:** standard or experimental hybrid post-quantum encryption at
  collection creation. Neither mode is a guarantee against all future attacks.
- **Encrypted Git mirror:** durable API revision checks and a one-way ciphertext mirror.
  Entry names, secrets, and folder hierarchy stay inside the encrypted snapshot.
- **Deployment:** source builds, non-root distroless containers, Kubernetes manifests,
  and Podman kube play configuration.
- **Setup and upgrades:** browser wizard or environment provisioning, setup mode controls,
  versioned persistence, migration backups, and rejection of unsupported newer schemas.

## Run from source

Install [Rust through rustup](https://rustup.rs/), Python 3, and OpenSSL for the example
setup-token command. The repository pins Rust 1.90.0. GnuPG is needed only for native
GPG imports.

```sh
git clone https://github.com/k2patel/petika.git
cd petika
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114 --locked
sh scripts/build_web.sh
cargo build --release --locked -p petika -p petika-server
```

For a fresh local development instance:

```sh
umask 077
mkdir -p "$HOME/.config/petika"
# Generate once; do not overwrite an existing deployment's token.
openssl rand -hex 32 > "$HOME/.config/petika/api-token"
PETIKA_COOKIE_SECURE=false \
PETIKA_TOKEN_FILE="$HOME/.config/petika/api-token" \
PETIKA_DATA_DIR="$HOME/.local/share/petika-api" \
PETIKA_GIT_MIRROR="$HOME/.local/share/petika-mirror" \
./target/release/petika-server
```

Open **http://127.0.0.1:8080**. Enter the token from that file in the first-run wizard,
create your administrator account, then create or import an encrypted collection.
The account password and collection unlock passphrase serve separate purposes.

The HTTP cookie override above is for local development only. Remote deployments
need HTTPS and the default secure-cookie setting. See [deployment](docs/deployment.md)
for secret-file ownership, persistent volumes, and reverse-proxy considerations.

## Use the CLI

The native Rust executable supports `~/.petikarc`, `show` with hidden local unlock,
and Enter-to-TOTP with an expiry countdown. See the [CLI guide](docs/cli-accounts.md)
for configuration, offline commands, compiled installation, and managed sync.

In another terminal, sign in to the local instance:

```sh
./target/release/petika login --server http://127.0.0.1:8080
# Open the printed URL and approve the code shown in your terminal.
./target/release/petika whoami
./target/release/petika collections
./target/release/petika --store personal.petika pull
./target/release/petika --store personal.petika list
./target/release/petika logout
```

`pull` refuses to replace an existing file by default. `push --revision N` uploads
ciphertext only if the remote revision still matches `N`. Use the revision returned
by your pull; reconcile conflicts before trying another upload. Group operations use
`--collection ID`. Local storage commands continue to work offline without login.

CLI sessions expire after eight hours. Their bearer credential is stored in a local
file, with owner-only permissions on Unix; OS credential-manager integration is not
implemented. See [managed CLI accounts](docs/cli-accounts.md) for session storage,
revocation, Windows permissions, and complete examples.

## Container and unattended setup

```sh
docker build -t petika:dev .
```

The final image is **distroless**, runs as UID 65532, and includes the server, CLI, and
built web UI. It has no shell, package manager, Git executable, or GnuPG.

Follow the [Docker, Kubernetes, and Podman guide](docs/deployment.md) to run it with
persistent storage and a mounted setup token. The supplied manifests use one server
replica; multi-replica operation is not supported.

Set `PETIKA_SETUP_MODE=auto`, `PETIKA_ADMIN_USERNAME`, and
`PETIKA_ADMIN_PASSWORD_FILE` for unattended administrator creation. Optionally supply
`PETIKA_INITIAL_SNAPSHOT_FILE` to provision an existing encrypted collection.
`manual` selects browser setup; `disabled` requires an already initialized instance.
Existing accounts are never reset by bootstrap variables on restart.
See the [complete setup reference](docs/setup.md).

## Security boundaries and remaining work

The server stores encrypted collections but receives account passwords for authentication
and retains account/group metadata. Collection passphrases stay on the client.
The browser must trust the application code delivered by your server.

Legacy groups use a separately shared passphrase. Explicitly migrated groups use verified
per-user encrypted packages. Removing membership blocks API access; fresh-key rotation
excludes removed recipients from new ciphertext, but cannot retract old ciphertext,
known keys, or copied secrets. Independent security review remains unfinished.

The Git mirror hides entry names and folder structure, but exposes ciphertext sizes,
revision history, and timing. Remote Git pushes remain an operator task. Keep independent
backups of server data, mirrors, configuration, and client recovery material.

**Per-user group access and explicit key rotation are implemented experimentally.**
See the [group-access guide](docs/group-access.md), [identity format](docs/identity-format.md),
and [roadmap](docs/roadmap.md) for workflows, limits, and remaining hardening.

Still planned:

- Chromium/Firefox extensions and cross-site autofill.
- Mobile apps and configurable biometric unlock.
- Full GPG key creation, export, expiry, and revocation management in the UI.
- Optional OpenID Connect, account MFA/passkeys, recovery, and audit trails.
- OS-backed CLI credential storage and identity replacement UI.
- Independent security review and broader deployment/recovery validation.

Website TOTP generates codes for saved external logins; it is not MFA for Petika login.

## Development and verification

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked
python3 scripts/check_licenses.py
node scripts/test_otp.mjs
python3 scripts/test_setup.py
```

Node is used only for the optional OTP reference-vector test, without npm packages.
The [web UI guide](docs/web-ui.md#verification) explains Python Playwright tests for
browser approval, CLI/web interoperability, permissions, themes, and mobile layouts.
CI checks Rust on Linux, macOS, and Windows, plus web workflows and the distroless image.

## Repository and documentation

| Path | Contents |
| --- | --- |
| `crates/petika-core` | Shared encryption and local storage |
| `crates/petika-cli` | Native CLI and managed-account transport |
| `crates/petika-server` | API, accounts, authorization, and Git mirroring |
| `crates/petika-web` | Rust encryption compiled to WebAssembly |
| `crates/petika-desktop` | Desktop integration scaffold |
| `clients/web` | Web UI, shared CSS, and browser worker |
| `deploy` | Kubernetes and Podman manifests |
| `assets/brand` | Light/dark branding assets |
| `docs` | Architecture, setup, security boundaries, and operations |

Start with the [documentation index](docs/README.md), [schema upgrade guide](docs/schema.md),
[contributing guide](CONTRIBUTING.md), and [security reporting policy](SECURITY.md).

## License and provenance

Petika's original code is licensed under [MIT](LICENSE), copyright 2026 K2patel.
Third-party dependencies retain their own licenses; the container includes generated
third-party notices. Petika does not contain or translate the GPL implementation of
`pass`. GPG import invokes separately installed GnuPG, which retains its own license.

### Per-user group access

Enrolled members can unlock migrated groups with their own verified recipient identity.
Editors deliver encrypted access packages and explicitly rotate keys after membership
removal. Standard and experimental X-Wing draft-06 modes are supported. See the
[group-access guide](docs/group-access.md) for CLI/browser setup, verification, migration,
rotation, and recovery.
