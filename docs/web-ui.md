# Petika web UI

The Rust server serves the web app at `/`. Encryption runs in a dedicated browser
worker using the same Rust core as the CLI, compiled to WebAssembly. The UI uses
plain JavaScript and shared CSS tokens; there is no npm build or runtime dependency.

## Run locally

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114 --locked
sh scripts/build_web.sh
cargo build --workspace --locked
PETIKA_TOKEN_FILE=/path/to/token PETIKA_COOKIE_SECURE=false ./target/debug/petika-server
```

Open `http://127.0.0.1:8080`. Use `PETIKA_COOKIE_SECURE=false` only for local HTTP.
For remote access, terminate HTTPS and retain the default Secure cookie setting.
`PETIKA_WEB_DIR` defaults to `clients/web`; the container sets it to the packaged assets.
Generated WASM/bindings are build artifacts, not checked into Git.

## Working flows

- First-administrator setup, local account sign-in/sign-out, profile and password changes.
- Browser approval of [managed CLI sessions](cli-accounts.md), with explicit consent and reauthentication.
- Standard or experimental hybrid collection creation, passphrase unlock, and inactivity lock.
- Item search/filter, create/edit/delete, password generation, explicit reveal/copy, and website links.
- Website TOTP setup from a Base32 key or `otpauth://totp/` URI, live countdown, and code copying.
  Supports SHA-1/256/512, 6/8 digits, and 30/60-second periods. Tested against RFC 6238.
- Encrypted snapshot import into an uninitialized collection and encrypted export from any collection.
- API revision checks, local encrypted drafts, conflict reporting, retry, and Git mirror status.
- Administrator-managed users, disable/enable, groups, and explicit read/edit membership.
- Shared system/light/dark appearance and responsive navigation; no external fonts, analytics,
  favicons, or third-party scripts are fetched.

The demo is opt-in, uses synthetic records, and never syncs or persists its secrets.

## Identity and group boundaries

Account passwords are sent only to the same-origin server over HTTPS and stored as
Argon2id hashes. Collection unlock passphrases never go to the server. Session cookies
are HttpOnly, SameSite=Strict, Secure by default, and expire after eight hours. Sessions
are in memory; restart signs everyone out. Mutating browser API calls require a
same-origin custom header and JSON content type; no CORS permission is granted.
Login attempts have a process-wide rate limit; deploy behind a reverse proxy with
additional timeouts and rate limits. This is still an unaudited experimental release.

Each user has a separate personal collection. Every group has a separate encrypted
collection with an opaque identifier. Administrator status does not implicitly grant
read access; membership is checked on every request. Read-only members cannot submit
updates. Disabled users lose server access and active sessions. An administrator can
change group membership, so administration is still a trusted role.

Legacy groups use a separately shared passphrase. [Recipient-enabled groups](group-access.md)
use verified identity packages and support explicit fresh-key rotation after membership
changes. Removing a member immediately blocks API access; rotation excludes its old keys
from new ciphertext, but cannot erase previously downloaded data or copied secrets.
Rewrapping a passphrase does not rotate the underlying key.

The browser persists encrypted snapshots, identity bundles, transaction drafts, public
highest-seen epochs, and appearance/lock preferences in localStorage. Storage can be disabled or run out; errors instruct the user to export.
A conflict never silently overwrites a newer server revision. Secrets appear in browser
memory while unlocked. Worker termination and DOM clearing reduce their lifetime but
cannot guarantee erasure of all browser/clipboard/OS copies. Clipboard contents are not
automatically erased. Use a trusted browser and trusted server-delivered application code.

## Remaining integrations

Cross-site autofill requires the Chromium/Firefox extension; the web page cannot fill
another website. GPG import uses the native CLI today. Full GPG key management, biometric
unlock, passkeys, optional OpenID Connect, account recovery, audit trails, and identity replacement UI are not implemented. Their screens explicitly state current limits.
Website TOTP is for saved external logins; it does not add MFA to Petika account sign-in.

## Verification

```sh
cargo test --workspace --locked
node scripts/test_otp.mjs
python3 scripts/test_setup.py
python3 -m venv /tmp/petika-browser-tests
/tmp/petika-browser-tests/bin/pip install playwright==1.60.0
/tmp/petika-browser-tests/bin/playwright install chromium
/tmp/petika-browser-tests/bin/python scripts/test_web_ui.py
```

The Python browser test starts an isolated server, exercises real setup and permission
failures, checks CLI/WASM compatibility, and captures light/dark/mobile screenshots.
See [design references](web-design.md) and [unattended setup](setup.md).
