# 0002: Per-user group-key delivery

Date: 2026-10-15.
Status: implementation proposal for the next milestone; local recipient identity
generation/storage is implemented in the shared core (see [format](../identity-format.md)).
Enrollment APIs, trust-pin workflows, and group-key delivery are not implemented. This
is not an audited protocol or stable wire-format commitment.

## Outcome and scope

An enrolled group member unlocks a local recipient identity once, then receives group
access through an encrypted package addressed to that identity. Members no longer
exchange group passphrases. An authorized, unlocked editor creates packages; the server
stores and relays ciphertext and enforces current membership.

This decision covers enrollment, identity verification, delivery, recovery, and mode
compatibility. Automatic removal rotation is the following milestone. Delivery alone
must not be presented as cryptographic revocation.

## Existing implementation constraints

- `petika-core::UnlockedStore` holds both a data key and `secret_material`. Standard
  mode uses the same random 32-byte value for both. Hybrid mode uses a 32-byte X-Wing
  seed as secret material and decapsulates the envelope's KEM ciphertext for the data key.
- Envelope v1 has one passphrase wrapper and no collection/recipient/epoch binding.
  Changing its passphrase rewraps secret material; it does not rotate encryption keys.
- Accounts schema v1 contains users and membership, but no recipient identities or keys.
  Group permissions have read/edit flags; administration alone grants no decryption access.
- Snapshot updates compare revisions. Accounts and snapshot files are separately locked;
  a delivery transaction needs a defined lock order and membership recheck.
- CLI browser approval grants API access only. Web encryption runs in a WASM worker.
  Existing clients reject unknown envelope fields and versions.

## Trust and limits

Protect group keys from an observer of server storage/network ciphertext and prevent
an unverified directory key replacement from silently receiving a grant. HTTPS, trusted
client software, local device security, and a trusted first identity-verification channel
remain required. The web client must trust server-delivered code; this design does not
protect an unlocked browser from malicious JavaScript served by that server.

The server remains authoritative for membership and availability. Administrators can
change the roster, but cannot construct packages without group secret material. An
editor must verify a newly encountered recipient before releasing access. Once verified,
current membership permits automatic delivery to that pinned identity. This is not
cryptographically authenticated group governance or protection against every malicious
administrator action.

Read-only is an API permission, not a cryptographic inability to edit or redistribute
plaintext. Any recipient can copy learned secrets. A compromised recipient private key
can decrypt captured packages; this scheme provides no forward secrecy for those packages.
Clients retain highest-seen versions, but a new device or restored trust backup cannot
independently prove that the server has shown the latest history.

## Recipient identity and enrollment

Use one versioned recipient identity per user per Petika deployment, shared by that
user's devices. Generate independent encryption and signing keys on the client using
OS/browser cryptographic randomness. Include an X25519 public key for standard delivery,
an X-Wing public key for hybrid delivery, and an Ed25519 public verification key.
Never reuse collection secret material as an identity key.

Bind the public identity to a persistent random deployment ID, immutable user ID,
identity version, and explicit suite identifiers. Derive the identity fingerprint as
SHA-256 of a domain-separated, canonical encoding of that complete public record.
Display the full fingerprint in grouped form; usernames are labels, not identities.
The server origin is also pinned locally; moving a deployment requires deliberate
reassociation rather than silently accepting another host.

Enrollment requires an authenticated session and explicit reauthentication. The client
uploads a signed public record and a separately encrypted private identity bundle.
A self-signature proves signing-key possession only; verify encryption-key consistency
locally and include an encryption/decryption self-check before publishing. Initial
registration uses create-if-absent; concurrent enrollments must conflict, never overwrite.
Reauthentication does not send the local identity passphrase.

Protect the private bundle with a distinct local unlock passphrase using the existing
Argon2id parameter policy and XChaCha20-Poly1305, fresh salt/nonce, and identity-specific
associated data. Its plaintext contains the private keys, public-record fingerprint,
and verified contact pins. Use a dedicated versioned format, not a password `Entry`.
The server may store this encrypted bundle for multi-device retrieval; never its
passphrase, wrapping key, or plaintext. Password strength still bounds resistance to
an offline attack on a copied bundle.

The CLI stores ciphertext with the existing owner-only/atomic storage protections.
The browser persists ciphertext only and keeps unlocked keys in its worker. Locking,
signing out, or worker failure clears the unlocked identity state. OS credential storage
and biometrics remain separate backlog items.

## Verification and key changes

Before the first grant, the issuer compares the recipient fingerprint through an
independent trusted channel, then saves the verified binding. The recipient similarly
verifies the issuer before accepting a first package. No silent trust-on-first-use or
"verified" label based solely on the server directory. Unverified recipients remain
pending; automation resumes after verification without exchanging group passphrases.

Pin both immutable IDs and the full fingerprint. A key/version change suspends delivery
until explicitly verified. An old-key signature can show continuity but does not by
itself override this rule, especially after suspected compromise. Name changes do not
change identity. Pins synchronize only in the user's encrypted identity bundle, using
compare-and-swap updates; a conflict must preserve both local and remote changes.

Routine new-device enrollment downloads and unlocks the existing encrypted bundle and
checks that its derived public keys match the pinned identity. It does not generate a
replacement identity. With no trusted local pin, compare the fingerprint using an
existing device or the recovery export before trusting the server's record.

## Package contract and cryptography

Use single-shot HPKE base mode for encryption and a detached Ed25519 signature for
issuer authentication. Base mode alone does not identify the sender. Proposed suites:

| Collection mode | Package encryption |
| --- | --- |
| Standard | RFC 9180 DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, ChaCha20Poly1305 |
| Hybrid post-quantum | RFC 9180 base-mode key schedule with the X-Wing draft-06 KEM adapter, HKDF-SHA256, ChaCha20Poly1305 |

Pin the hybrid profile to draft-06, matching the current crate; do not call it the
latest standard or substitute a newer draft under the same suite ID. Use a maintained
HPKE implementation, not a new hand-written key schedule or KEM combiner. Validate the
hybrid adapter against the pinned specification and independent vectors before enabling
it. If the adapter/dependency is unavailable or fails validation, hybrid delivery remains
unavailable; never fall back to standard delivery. Ed25519 authentication is classical,
so this is not end-to-end post-quantum authentication.

The package is a versioned record with these authenticated fields:

| Field | Purpose |
| --- | --- |
| `package_version`, `suite` | Exact parsing and algorithm selection |
| `deployment_id`, `collection_id` | Prevent cross-deployment/collection substitution |
| `collection_mode`, `key_epoch` | Prevent mode substitution and stale-key use |
| `membership_generation` | Bind the issuance transaction to its checked roster |
| `recipient_user_id`, `recipient_identity_version`, `recipient_fingerprint` | Bind the intended identity |
| `issuer_user_id`, `issuer_identity_version`, `issuer_fingerprint` | Identify the verified signer |
| `package_id` | Random 256-bit idempotency/replay identifier |
| `enc`, `ciphertext`, `signature` | KEM encapsulation, encrypted payload, issuer signature |

Encode authenticated headers in a specified fixed field order with length-prefixed
byte strings and unsigned fixed-width integers. JSON is only the transport wrapper;
never sign a serializer's incidental object-key order. Reject duplicate/unknown fields,
invalid lengths, unsupported suites, and noncanonical encodings. Cap each package at
16 KiB before parsing/cryptography; define separate bounded pagination for package lists.

Use distinct domain labels for identity fingerprints, enrollment signatures, HPKE
`info`, package AAD, and package signatures. HPKE `info` and AAD bind the full canonical
header; the signature covers that header, `enc`, and ciphertext. Publish byte-exact
encoding/domain fixtures before implementation integration.

The encrypted payload carries a tagged, exactly 32-byte collection secret:

- Standard: the collection's data key.
- Hybrid: the collection's X-Wing seed, not a replacement standard data key.

On receipt, match the expected deployment, collection, identity, mode, and epoch; verify
the pinned issuer signature; then decapsulate/decrypt and authenticate the collection
snapshot with the resulting material. Preserve the hybrid KEM ciphertext and derive its
data key as today. Never expose raw secret material through a web worker message or
public CLI output. Core APIs return an unlocked session or an opaque package, not keys.

## Collection binding and compatibility

Introduce an opt-in envelope v2 for recipient-enabled groups. Bind deployment ID,
collection ID, mode, and key epoch into both snapshot-data and recovery-wrapper AAD.
Migration requires a current editor to unlock v1 and re-encrypt the records under that
context, preserving the mode and existing secret material for the delivery milestone.
This re-encryption adds context; it is not fresh-key rotation or exclusion of previous
passphrase holders. Epoch 1 marks adoption of the new format, not cryptographic freshness.

Keep a passphrase recovery wrapper during migration, with the passphrase retained by
the owner outside the server. New recipients use their packages. Future rotation must
replace the secret material and update every remaining access path, including recovery
wrappers, so an old wrapper cannot unlock the new epoch.

Existing v1 personal/group stores remain readable and unchanged until explicit migration.
Older clients must reject v2 without modifying files. The server must reject v1 uploads
into a migrated collection, regardless of a matching snapshot revision. No automatic
mode conversion, destructive bulk migration, or silent downgrade.

Add a sequential account schema migration for the deployment ID, public identities,
encrypted identity bundles, and membership generations. Record new collection/package
schema versions separately. Preserve original backups and immutable historical snapshots;
update the [schema guide](../schema.md) when formats actually ship.

## Delivery state and authorization

| State | Client behavior |
| --- | --- |
| Recipient not enrolled | Show pending enrollment; do not manufacture keys server-side |
| Identity not verified or changed | Require verification before sending/accepting grants |
| No authorized unlocked editor | Show pending delivery; retry when one unlocks |
| Current valid package | Unlock locally after identity unlock |
| Removed/disabled user | Deny directory/package/snapshot access; flag rotation requirement |
| Wrong mode/epoch/signature or conflicting update | Reject and preserve the local draft |

Only a current active editor may publish packages, and only for current active members.
Administration alone and read-only membership do not authorize package issuance. Bootstrap
requires an editor who can already unlock the collection with its passphrase. A group
with only readers needs an explicit administrator membership change to obtain an editor.
Recipients retrieve only their own packages; editors can inspect delivery status needed
to fill missing grants. Minimize directory visibility to identities relevant to sharing.

All grant publications compare snapshot revision, key epoch, membership generation,
and recipient identity version. Acquire the account lock before the collection lock,
re-read identity/membership/disabled status inside that boundary, and reject conflicts.
Membership and identity changes use the same ordering. Do not hold these locks while
performing client crypto or network work.

Persist a recipient-enabled collection's snapshot, active epoch, and grant set together
in one versioned collection state, using journal-before-current-pointer replacement.
Recovery ignores uncommitted journal tails. Retried identical package IDs are idempotent;
reuse with different bytes is rejected. Legacy snapshot endpoints must participate in
the same authorization/version checks, not offer a bypass.

A subsequent roster generation does not by itself invalidate every remaining member's
package. Validate against the current roster, recipient key, and active epoch; the signed
issuance generation is historical evidence, not a replacement for current authorization.
Removed users lose API access immediately; until fresh-key rotation ships, their cached
keys can still decrypt later ciphertext encrypted with the same secret material. Expose
this limit explicitly rather than reporting them as cryptographically excluded.

## Recovery and key loss

Provide an encrypted export of the identity bundle, public fingerprint, verified pins,
and versions, and verify a synthetic restore on a second client. Retain its unlock
passphrase separately. Account-password changes/resets do not rewrap or recover identity
keys; the server must not claim otherwise. Changing the identity passphrase rewraps the
same identity and uses bundle revision checks.

If all devices and recovery material are lost, create a new identity only through an
explicit replacement flow. Suspend old-identity deliveries, require fresh fingerprint
verification, and ask an unlocked editor to reissue each accessible group grant. An
administrator cannot recover a group key without another authorized holder or recovery
wrapper. If no such material survives, the collection is unrecoverable.

Compromised identity replacement also requires subsequent group-key rotation; deleting
a directory record cannot invalidate captured packages. Account deletion/recreation must
use a new immutable ID. Logout removes session access, not copies on other devices;
per-device cryptographic revocation is outside this per-user identity milestone.

Keep recipient directories and packages out of public/shared Git mirrors, preserving
the current generic mirror metadata boundary. Back up full server state and encrypted
identity bundles separately. A ciphertext-only mirror requires the recovery passphrase
or a separately retained matching package and recipient private identity.

## Implementation order and acceptance

1. Add core identity generation, encrypted bundles, fingerprints, canonical encodings,
   package sealing/opening, and v2 context binding with native/WASM fixtures.
2. Add schema migration, directory/bundle APIs, membership generations, and atomic grant
   publication/retrieval. Exercise every API path with unauthorized and read-only users.
3. Integrate enrollment, verification, delivery status, and unlock into CLI and web.
4. Exercise independent users/devices and recovery exports before marking delivery done.

Tests must cover two users opening the same group without a shared passphrase, both
modes, native/WASM interoperability, unrelated recipients, substituted directory keys,
forged issuers, every bound-field mutation, malformed/oversized records, key/version
changes, disabled users, membership races, interrupted commits, retry idempotency,
conflicting bundle edits, v1 preservation, old-client rejection, downgrade rejection,
and wrong/missing recovery material. Pin protocol vectors rather than merely round-trip
testing the same implementation. Logs and error messages must contain no secret material.

Before adopting dependencies, check Rust 1.90/WASM compatibility, permissive licenses,
and upstream vectors. Freeze exact encoding and algorithm adapters with those tests.
Automatic fresh-key rotation, PQ signatures, transparency/consensus over membership,
and per-device identities require separate decisions. This document completes the design
checklist item; the remaining implementation items stay unchecked.

## Sources

- [RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html): HPKE base-mode composition,
  application context, and replay/downgrade limits. HPKE's name does not itself imply PQ security.
- [X-Wing draft-06, section 5.6](https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-06.html#section-5.6):
  pinned experimental HPKE KEM interface; it does not support authenticated KEM mode.
- [RustCrypto X-Wing documentation](https://docs.rs/x-wing/0.1.1/x_wing/): repository
  dependency's draft version and implementation limitations.
- [RFC 8032](https://www.rfc-editor.org/rfc/rfc8032.html): Ed25519 signatures.

The application identity, authorization, storage, and recovery policies above are Petika
proposals, not guarantees supplied by these specifications.
