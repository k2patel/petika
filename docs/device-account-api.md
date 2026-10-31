# Candidate account device API

The [Git-authoritative target](decisions/0006-git-authoritative-sync.md) can reuse this experimental device admission foundation. Password plus any one authorized device key remains the planned online access policy; this API does not yet issue temporary upstream Git credentials or enforce direct Git publication authorization.

Status: experimental implementation for [draft ADR 0005](decisions/0005-independent-device-keys.md).
Both the server Cargo feature `experimental-device-keys` and runtime variable
`PETIKA_EXPERIMENTAL_DEVICE_KEYS=1` are required. Otherwise every endpoint below returns
404. `/v1/config` reports `device_key_api_enabled`. This is not deployed or enabled in
the production runtime.

This milestone publishes an account's signed device inventory and supports additions.
It does not grant collection access, deliver collection keys, bind login sessions to
devices, replace existing encrypted identity bundles, migrate vaults or add biometric UI.
Removal is rejected until device-session revocation and rotation-required collection
state are integrated. Existing per-user identity and vault formats remain unchanged.

## Authorization and requests

Every operation requires an active own-account browser session or an approved CLI
session. Static service bearer tokens are rejected, including when a session cookie is
also present. There is no administrator override or caller-selected account path.
Authorization and disabled-account state are rechecked under the accounts database lock,
which stays held through publication. Existing per-user key and shared reauthentication
rate limits apply. Writes also require the current account password, exact JSON content
type and `X-Petika-Request: 1`; explicit cross-site Fetch Metadata is rejected. Responses
use `Cache-Control: no-store` and do not grant CORS. Use authenticated HTTPS outside tests.

| Method and path | Request / result |
| --- | --- |
| `GET /v1/device-keys` | `{bootstrap, roster}` with the immutable bootstrap and current signed head |
| `POST /v1/device-keys/bootstrap` | `{current_password, bootstrap}` → `{bootstrap, roster}` |
| `POST /v1/device-keys/publications` | `{current_password, operation_id, expected_parent, roster}` → `{receipt}` |
| `GET /v1/device-keys/receipts/<operation_id>` | `{receipt}`; 404 if absent from the retained verified journal |
| `GET /v1/device-keys/history/<after_digest>` | `{rosters, head_digest, head_generation}`; at most 16 adjacent successors |

Successful requests return 200, including exact retries. Errors use the existing key API
`{code,message}` envelope: 400 malformed input, 401 missing/expired/disabled session or
wrong password, 403 wrong scope/authority, CSRF failure or attempted removal, 404 absent
resource, 405 wrong method, 409 conflicting state, 413 excessive body, 415 wrong media
type, 429 rate limit, 503 unavailable/corrupt committed storage. A publication error after
atomic replacement can have an uncertain outcome: retain the exact signed candidate and
operation ID, look up its receipt and retry that same operation.

JSON request objects reject unknown and duplicate fields. HTTP bodies are bounded to
1 MiB + 16 KiB; bootstrap files/parsers to 32 KiB. Existing roster, journal, counter and
signature bounds still apply. Password input buffers are cleared when released; only
public signed bootstrap/roster metadata and operation IDs are persisted here.

## Establishing the first authority

The client generates a separate authority and signs an **empty generation-one** roster.
Its already unlocked legacy identity signs a `DeviceAuthorityBootstrap` after explicit
confirmation of the new authority fingerprint. Initial devices must pass the existing
enrollment ceremony and be published as subsequent additions; bootstrap cannot bypass
possession checks by embedding a pre-enrolled device.

Strict bootstrap fields are `bootstrap_version` (=1), `source_bundle_revision`,
`legacy_identity` (existing public identity record), `initial_roster`, and `signature`.
The new authority must belong to the same deployment/account and use a different signing
key. The source revision is in 1…2^53−1. The initial roster has generation 1, empty parent,
no devices and no revoked IDs, and must carry a valid new-authority signature.

The legacy Ed25519 signature covers this canonical byte sequence. `field` means a
four-byte unsigned big-endian byte length followed by those bytes; integers are unsigned
big-endian, and fingerprint/digest/ID strings are lowercase hexadecimal ASCII.

1. `field("petika:device-authority-bootstrap:experimental-v1")`
2. Four-byte bootstrap version
3. `field(deployment_id)`, `field(user_id)`
4. Eight-byte source bundle revision, eight-byte legacy identity version
5. `field(legacy_identity.fingerprint)`
6. `field(initial_roster.authority.fingerprint)`
7. `field(initial_roster.digest())`

Both embedded signed records are validated before this signature. The server compares
the complete legacy identity and source revision with its current enrolled account
state before first initialization. Once initialized, the authority cannot be replaced
through this API, password changes, or legacy identity replacement. Exact bootstrap
retries return the current head without overwriting either file, even if the legacy
identity subsequently changes.

This proves continuity with the **currently enrolled** legacy identity, not independent
human trust. Existing legacy identity replacement still uses its existing account
reauthentication policy. A compromised directory/account during initial setup must not
become trusted merely because it supplies internally consistent records. Clients must
retain and verify independent legacy/authority fingerprints and trusted roster digests.
The bootstrap signature does not authorize collection migration.

## Publication and client reconciliation

The authority client verifies the expiring two-key enrollment proof and independently
confirmed device fingerprint, then signs one adjacent addition. The server verifies its
fixed authority, scope, full signature, exact predecessor and single-device transition.
The authority is trusted to perform the ceremony; the server cannot independently infer
decryption possession or user approval from a roster signature.

Publication and the retry record use the [native journal](device-roster-journal.md).
Operation IDs are random 32-byte lowercase hex strings. An exact historical retry returns
the original receipt even after later additions, without changing the current head.
Conflicting ID reuse, stale candidates and attempts to remove devices fail without a
state rewrite. The journal remains capped at 128 publications / 8 MiB; no compaction occurs.

Clients fetch history from their retained digest and verify each adjacent signature and
transition. Continue from the final returned digest if another page is needed. An unknown
or conflicting history pin returns 409, never a replacement trust root. Server head hints
and unsigned receipts are not independent trust anchors. Verify a receipt against the
retained candidate, reconcile signed history, and persist the updated client pin before
discarding drafts. A coherent old server backup cannot prove that no newer history exists.

## Storage and interruption behavior

For accounts path `accounts.json`, files live under
`accounts.json.device-keys/<immutable-user-id>/{bootstrap,roster}.json`. They use existing
native exclusive file locks and restrictive file permissions. Lock order is accounts
database → bootstrap → roster journal; collection operations must not be called while
holding those locks.

Initialization creates the journal first, then creates the immutable bootstrap record.
An interruption between files can resume only with an identical verified empty baseline
and a bootstrap still matching the current legacy enrollment. A different baseline,
later journal history, corruption or missing journal beneath an already committed
bootstrap never triggers reinitialization. Publication itself remains one atomic journal
replacement. Restoring/deleting every record can erase local knowledge of prior enrollment;
independent client pins remain necessary.

These extra files are **not integrated into the supported account export/restore,
replication or recovery-kit workflows**. Synthetic/disposable testing is the supported
scope until those paths and durable client custody are implemented and reviewed. The
feature must remain disabled for real vault migration.

## Validation and next step

Independent Python bootstrap bytes/signatures, native account tests, real loopback HTTP
tests, history pagination, existing enrollment/journal tests, feature gates and WASM
compilation are covered by local validation and CI configuration. Tests use generated
accounts and public synthetic fixtures, never real credentials.

Next: durable client authority/device custody and draft/receipt reconciliation, followed
by device-bound sessions, collection rotation/package delivery, migration and recovery.
