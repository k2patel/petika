# Rust CLI client

Petika builds into a native `petika` executable. Rust is needed to build it, not
to run the resulting binary. Build separately for each operating system/architecture;
this repository does not yet publish signed CLI installers.

```sh
cargo build --release --locked -p petika
./target/release/petika --help
# Optional: build and install into Cargo's bin directory (~/.cargo/bin by default).
cargo install --path crates/petika-cli --locked
```

## Local vault and password display

```sh
petika init
petika insert Email/example --username alice --url https://example.com
petika ls
petika show Email/example
```

`show` asks for the collection passphrase using a hidden terminal prompt. After
successful decryption it prints the password. A wrong passphrase prints no password
or verification code. There is no background unlock cache: each command unlocks
locally and drops the unlocked vault when it exits. This passphrase is separate
from your server account password. Configured recipient identities use the existing
identity-unlock flow for recipient-enabled local stores.

If the entry has TOTP configured, press **Enter** after the password is shown to
see its current code and a live **expires in Ns** countdown. The code is cleared
from the current terminal line at expiry; press Enter for another code, or type
`q` followed by Enter to finish. **Ctrl+C** exits during the countdown. Previous
terminal scrollback or captured output may still contain revealed secrets.

```sh
# Hidden setup-key prompt; accept a Base32 key or otpauth://totp/ link.
petika otp set Email/example
# Explicit replacement of an existing setup:
petika otp set Email/example --replace
# Print password, current code and remaining seconds once, without waiting:
petika show Email/example --totp
# Remove the encrypted setup key (does not disable MFA on the website):
petika otp remove Email/example --yes
```

TOTP supports SHA-1/SHA-256/SHA-512, six/eight digits, and 30/60-second periods,
matching the web client. It uses the local system clock; keep that clock accurate.
The setup key is encrypted in the existing entry, never saved in the rc file.
Complete MFA enrollment/changes on the website separately. Existing web-created
TOTP entries work without re-entering their setup keys.

For pipes, `show` prints the password without an interactive TOTP prompt; request
`--totp` explicitly for a one-time code and remaining lifetime. For password-only
machine output, retain `get NAME --reveal`. The existing `get NAME` stays metadata
only. Automation may use `--passphrase-stdin`, `put --password-stdin`, and
`otp set --secret-stdin`; supply unlock material first and the entry secret on the
next line. Never put secrets in arguments or shell history.

The `ls`, `insert`, and `rm` aliases correspond to `list`, `put`, and `remove`.
Removal still requires `--yes`. Slash-separated names such as `Email/example`
provide familiar password-store naming. Petika retains its encrypted collection
format; these command aliases do not imply GPG-file compatibility. Existing GPG
password stores can be [imported locally](import.md). The workflow is inspired by
[password-store](https://www.passwordstore.org/), not copied shell code.

## Live API password retrieval

```sh
petika login --server https://petika.example.com
petika show Email/example --collection personal
petika show Email/example --collection COLLECTION_ID --totp
```

With `--collection`, `show` authenticates with the saved API session and fetches the
current encrypted snapshot before prompting for a local collection passphrase.
It does not read or write `--store`, create an encrypted vault cache, or fall back
to stale local data on an API failure. A read-only collection grant is sufficient.
Password/TOTP display works as above; the unlock passphrase is never sent to the API.

This first live operation supports collection-passphrase unlocking. Configured
recipient identities are rejected explicitly; use `keys pull` and local `show`
for that workflow until live recipient-key delivery is integrated. Without
`--collection`, `show` remains a local command. Mutations still require explicit
pull/edit/push with revision checks; automatic managed mutations are pending.

## Unix configuration: ~/.petikarc

An optional `~/.petikarc` supplies non-secret defaults. A [sample rc file](examples/petikarc)
is included for copying and editing. Create it as a regular text
file; use `chmod 600 ~/.petikarc` on Unix. Group/world-writable configuration is
rejected. Example:

```text
# One key = value per line. Quoted strings use JSON-style escaping.
store = "~/.local/share/petika/store.petika"
session_file = "~/.local/share/petika/session.json"
server = "https://petika.example.com"
# Optional, only when using recipient identity unlock for group stores:
# identity_file = "~/.local/share/petika/identity.json"
```

Command-line options override rc values, which override built-in paths. `server`
is the default for `login`; subsequent API commands use the server bound to the
saved session, so editing the rc cannot redirect an existing bearer token.
`--config PATH` selects a different rc file; `--no-config` ignores configuration.
A missing default file is fine; an explicitly named missing file is an error.

`~/` expands to the home directory. Other relative paths resolve beside the rc
file. Blank lines and full-line `#` comments are allowed. Unknown/duplicate keys
are errors. There is no shell evaluation, environment substitution, `source`, or
command execution. Never store account passwords, vault passphrases, bearer
credentials, or TOTP keys here. On Windows the optional rc is read from
`%USERPROFILE%/.petikarc`; existing default data paths remain unchanged when no rc
is present. Restrict its ACLs on Windows.

## Managed accounts and sync

The CLI signs in with your Petika-managed account. The browser confirms your identity;
collection encryption and decryption still happen locally. No npm or external HTTP
executable is required.

```sh
petika login --server https://petika.example.org
# Open the printed URL, enter the terminal code, confirm your account password,
# choose “Approve this CLI”, and confirm. The CLI completes automatically.
petika whoami
petika collections
petika status
petika --store personal.petika pull
petika --store personal.petika generate 'Example login'
petika --store personal.petika push --revision 1
petika logout
```

Use the revision printed by `pull`, not necessarily `1`. `status` reports the current
server revision and mirror state. `push --revision 0` initializes an empty remote
collection from an existing local store. Never substitute a newer revision merely to
force a conflicted upload: first pull to a separate file and reconcile the changes.
There is no automatic merge or background CLI sync in this release.

`pull` refuses an existing local file unless you explicitly pass `--replace`. It
verifies the downloaded ciphertext with your local collection passphrase before
writing. A wrong passphrase leaves the existing file untouched. `push` also verifies
the local file before uploading only its ciphertext. Offline `list`, `get`, `put`,
`generate`, and other local commands continue to work without a server session.

For groups, use `--collection ID` on `pull`, `push`, or `status`, with an ID from
`collections`. The default is your personal collection. Read-only memberships permit
downloads but not uploads. Group decryption still needs the separately shared group
passphrase; browser approval does not deliver encryption keys.

## Session storage and revocation

A versioned `session.json` beside the default user-data store contains the server
origin and bearer credential. Override it with `--session-file PATH` for separate
accounts or servers. It contains no account password or collection passphrase, but
**the bearer credential is sensitive and is not encrypted at rest**. On Unix the file
is owner-only (0600) and checked on access. On Windows use a private user-profile
location with restricted inherited ACLs; this release does not configure Windows ACLs
or integrate an OS credential manager. Do not put this file in Git or shared storage.
The session path must differ from the encrypted store path.

Sessions expire after eight hours. Logout revokes the CLI session and clears its local
file. `logout --local` clears only the local file when the server is unavailable; the
server token remains valid until expiry or revocation. Changing the account password
in the web UI or disabling the account revokes CLI sessions. Server restart also ends
all sessions and pending approvals. There are no refresh tokens. Use `logout --local`
then `login` when replacing an expired session.

HTTPS with certificate validation is required, except literal loopback addresses or
`localhost` for local development. Redirects are not followed. There is no insecure
TLS bypass. Private-CA trust configuration is not implemented yet.

## Approval protocol

This is a Petika-specific device approval protocol, inspired by the separation of
user and device codes in [RFC 8628](https://www.rfc-editor.org/rfc/rfc8628.html), not
an OAuth or OpenID Connect implementation. Optional OIDC remains future work.

- The CLI gets a random 256-bit device secret and separate 40-bit human code.
- The browser URL contains neither code; the user manually types the terminal code.
- Approval requires a browser session, account-password reauthentication, and an
  explicit decision. Denial is selected initially. Never approve someone else's code.
- Requests expire after ten minutes, can be answered once, and can be redeemed once.
- Polling is limited to every five seconds. Requests are capped at 30/minute and 100
  pending per process; password reauthentication uses the shared login rate limit.
- Redemption verifies that the approving browser session is still valid. The issued
  CLI bearer session has the same account privileges and current group permissions.

The browser shows the privilege being granted before approval. Device-code phishing
remains possible if someone persuades a user to approve their request. These controls
are not a claim of phishing resistance. Deploy behind HTTPS and proxy rate limits.
