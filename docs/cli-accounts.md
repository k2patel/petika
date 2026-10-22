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

## Live API operations

Use `--collection personal` or a collection ID on `list`/`ls`, `get`, `show`,
`put`/`insert`, `generate`, `remove`/`rm`, and `otp set/remove`:

```sh
petika login --server https://petika.example.com
petika ls --collection personal
petika show Email/example --collection personal --totp
petika put Email/example --collection personal --username alice
petika generate Email/new --collection personal
petika otp set Email/example --collection personal
petika otp remove Email/example --collection personal --yes
petika rm Email/new --collection personal --yes
# Recipient-enabled group, using an enrolled/restored and verified identity:
petika --identity-file ~/.local/share/petika/identity.json show Team/example --collection COLLECTION_ID
```

Each operation authenticates with the saved API session and fetches the current
whole encrypted snapshot. Unlocking and editing happen locally. Reads do not cache
vault contents, read/write `--store`, or fall back to stale local data on API failure.
Read-only collection grants permit reads; edits require write access. The collection
must already exist and have a snapshot; initial creation remains the existing web
or explicit initialization/push workflow.

Legacy collections prompt for a collection passphrase. Recipient collections require
`--identity-file` (or its rc default) and prompt for the identity passphrase. Origin,
account, deployment, identity, trust-bundle revision, issuer trust/signature and
observed key epoch are checked before revealing data. There is no recovery-passphrase
fallback for recipient collections. Use the existing `keys enroll`, `keys restore`,
`keys verify`, and delivery workflow to establish access first.

Writes submit ciphertext with the fetched revision. Recipient writes also include
expected key epoch and membership generation; collections needing rotation reject
edits. Successful API acceptance does not mean remote Git replication has finished.
Without `--collection`, these commands retain their local/offline behavior.

### Conflicts and interrupted writes

Before sending an edit, the CLI saves a private `petika-draft-*` directory beside
its session file. It contains `snapshot.petika`, non-secret origin/collection/revision
metadata in `context.json`, and (for recipient collections) `snapshot.access.json`
with the encrypted key package and public issuer identity. No plaintext password,
TOTP setup key, API token or unlock passphrase is stored in the draft.

A valid success acknowledgement removes that draft. A conflict, failed request or
missing/unexpected acknowledgement retains it and prints its location. No automatic
retry, ciphertext merge or force overwrite follows. An interrupted request may have
been accepted; inspect the live API state before making another edit. A crash after
acceptance but before cleanup can likewise leave a redundant draft.

Inspect the preserved edit locally, omitting `--collection`:

```sh
petika --store /path/to/petika-draft-XXXX/snapshot.petika show Email/example
# For recipient drafts, also provide the original --identity-file.
```

Compare with `show --collection ...`, then explicitly reapply the intended change
against current API state. Do not upload the entire stale draft with a newer revision:
that could overwrite someone else's edits. Keep drafts until resolved; they contain
old ciphertext just as backups do. This is snapshot-level conflict protection;
independent entry edits can still conflict until the per-entry format is implemented.

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

## Experimental migration staging

With a CLI compiled using `experimental-entry-format`, enrolled users can stage
and review a migration from a live legacy personal or group snapshot:

```sh
petika entries migrate-stage --authority-identity identity.json \
  --recovery-policy replace --draft migration.json
petika entries migrate-review --authority-identity identity.json --draft migration.json
```

Both commands default to `--collection personal`; pass `--collection GROUP_ID` for
a group. The session needs edit access. Every enabled recipient must be enrolled,
and the staging identity must match the authenticated user's current enrollment.
Other recipients must already be independently verified contacts. Personal capture
uses the owner's enrollment and snapshot; group capture verifies the entire paginated
roster and rechecks source revision/membership before accepting the read.

Staging prompts for the source recovery passphrase, local identity passphrase, and
then a new recovery passphrase twice for `replace`. Choose `omit` explicitly to
create no new recovery wrapper. Review prompts for source recovery and identity
passphrases only. `--passphrase-stdin` reads those values as successive lines;
never put passphrases in arguments or configuration. Recipient-only source unlock
is not supported by these commands yet.

The protected draft contains the original ciphertext and signed new candidate,
plus the API origin/account binding. It never overwrites an existing draft. Review
fetches current API state and rejects changed source revisions, membership,
recipients, account or server while retaining the file. Its summary shows opaque
recipient IDs/fingerprints, source counters, recovery policy and checkpoint digest;
it hides entry names, passwords and TOTP values. Account sessions can expire between
stage and review; sign in to the same account/server again without replacing the draft.

The local file is capped at 16 MiB including its origin/account envelope, so its
effective candidate capacity is slightly below the core draft limit. Staging/review
perform GET requests only and never change API ciphertext, format or trust pins.
Review is against a captured read, not a freshness guarantee; the server rechecks
source and recipient state atomically during submission. Keep a verified full backup
separately. Initial shared-vault authority requires an enrolled administrator with
edit access; the personal owner can migrate their own vault without administrator rights.

After reviewing the recipients, recovery policy and backup readiness:

```sh
petika entries migrate-submit --collection personal \
  --authority-identity identity.json --draft migration.json \
  --pin entry-pin.json --cache entry-cache --confirm
```

`--confirm` authorizes this exact migration and initial local trust acceptance.
For a new pin, prompts are source recovery passphrase, identity passphrase, then
**new** recovery passphrase if the draft uses `replace`. The CLI verifies every
source/target field and opens the new recovery wrapper locally. It cannot prove
that every other recipient has retained a working device/identity; confirm those
recovery arrangements separately. Source recipient-only unlock is still pending.

The command rechecks API origin/account/collection, current local contact trust
and live source metadata before a new submission. It never rebases stale drafts
or replaces another local pin.
Ciphertexts, wrappers and the original signed draft are durably cached; an exact
writer/operation/digest/cursor receipt is required before publishing a new pin.
The receipt is retained beside the draft as `migration.accepted.json`. The command
prints the cached anchor path for subsequent `entries list`, `sync`, or editing
with `--recipient-identity`, `--pin` and `--cache`.

If the response is lost or the CLI is interrupted, repeat the **same command and
draft**. An active entry vault is queried for the original receipt; missing or
mismatched receipts stop acceptance without resubmission. A new pin still requires
full local source/candidate verification from the retained draft, so no post-cutover
legacy snapshot read is needed. Once that exact pin exists, retries ask only for
the identity passphrase and require current read access. An advanced/different pin
is preserved and rejected by this migration command; use normal history/epoch sync.
`migrate-review` is a pre-cutover live-source check, not the reconciliation command.

Conflicting cache or receipt files stop local acceptance; preserve and investigate
them instead of deleting trust state. A pin is created only after artifacts and
receipt are saved. Remote Git replication is reported separately and is not proven
by the migration receipt. This remains an experimental workflow with incomplete
full-server/recipient recovery evidence; it does not enable a deployment.

### Offline client recovery check

`petika entries verify-backup --anchor ANCHOR --pin PIN --cache CACHE
--recipient-identity IDENTITY` verifies every live entry in a retained client kit
without contacting the API or changing the pin. Use `--recovery WRAPPER` instead
for an explicit recovery-passphrase check. It prints only counts, revision and epoch.
A cache containing only an index fails if live ciphertexts are missing. See the
[full recovery procedure](recovery.md#experimental-entry-format-recovery) for server
journal verification and independent client-pin preservation.

## Managed accounts and sync

The opt-in per-entry format has a separate [experimental CLI rotation workflow](research/entry-history-transport.md#cli-rotation-and-adjacent-epoch-acceptance).
It stages and reviews encrypted rotations, reconciles receipts, and requires explicit
confirmation before clients advance their trusted epoch. It does not migrate existing vaults.

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

For groups, use `--collection ID` with an ID from `collections`. Legacy `pull`,
`push`, and `status` default to the personal collection; live entry commands require
an explicit `--collection` to select API mode. Read-only memberships permit reads
but not writes. Legacy groups use a separately shared collection passphrase;
recipient-enabled groups use verified identity/key-package access. Browser approval
authenticates API access and does not itself deliver decryption keys.

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
