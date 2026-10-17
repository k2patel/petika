# Local recipient identity format

Implemented in `petika-core::identity`. This format underpins the implemented
[CLI/browser recipient workflows](group-access.md). Existing legacy collections remain
unchanged until explicit migration. Local verified contact pins
are now implemented in encrypted bundle v2. The format is experimental.

## API and lifecycle

- `UnlockedIdentity::generate(deployment_id, user_id, identity_version)` generates three
  independent seeds: X25519, X-Wing draft-06, and Ed25519. IDs are 64 lowercase hex digits;
  versions are 1 through 2^53-1.
- `public_identity()` returns public keys, IDs, version, fingerprint, and self-signature.
  `PublicIdentity::validate()` checks framing and self-signature, not the user's real-world
  identity. Key consistency and local X25519/X-Wing exchange checks run on generation/restore.
- `seal(passphrase)` exports an encrypted backup with a fresh salt and nonce. Calling it
  with another passphrase rewraps the same identity; it does not rotate keys or invalidate
  old backups. Passphrases require at least 12 characters and at most 4096 UTF-8 bytes.
- `open(bytes, passphrase, expected_fingerprint)` requires an independently retained
  fingerprint and authenticates/decrypts the bundle. Every recovered seed must reproduce
  its public key and signature. A server-provided fingerprint alone is not verification.
- On native targets, `IdentityFile::lock` holds an exclusive advisory lock. `save(..., true)`
  refuses existing files, `save(..., false)` explicitly replaces the same identity atomically, and
  `open` bounds the file read. Unix files are owner-only; Windows inherits private ACLs.

Unlocked identities have no `Debug`, `Clone`, or plaintext `Serialize` implementation.
Private seed owners and plaintext buffers zeroize on drop; this does not guarantee erasure
of compiler, allocator, browser, or OS copies. No raw-key export API is exposed.

## Public encoding

Binary fields use canonical padded base64. Fingerprints are lowercase SHA-256 hex.
The canonical fingerprint transcript is the concatenation of:

1. Length-prefixed UTF-8 `petika:recipient-identity:v1`.
2. Length-prefixed ASCII deployment ID, then user ID (64 hex characters each).
3. Identity version as an unsigned 64-bit big-endian integer.
4. Length-prefixed suite `x25519`, then its length-prefixed 32-byte public key.
5. Length-prefixed suite `xwing-draft06`, then its length-prefixed 1216-byte public key.
6. Length-prefixed suite `ed25519`, then its length-prefixed 32-byte public key.

All lengths are unsigned 32-bit big-endian byte counts. JSON ordering is irrelevant.
The Ed25519 enrollment signature signs three length-prefixed fields: domain
`petika:recipient-enrollment:v1`, the complete transcript above, and the ASCII fingerprint.
A self-signature demonstrates signing-key possession; independent contact verification
is required by the local trust API described below; encrypted bundles can be synchronized through revision-checked server APIs.
CLI/web synchronization and verification flows remain pending.

## Verified contacts and key changes

All contact operations require an expected immutable user ID and a signed public record
from the same deployment. Self-contacts, cross-deployment records, wrong user IDs, and
invalid signatures fail before changing stored trust. No username or display-name match
can establish trust.

- `observe_contact(user_id, record)` returns `Unverified`, `Verified`, `Changed`,
  `Rollback`, or `Suspended`. Reading a new record never creates a trusted pin.
- `verify_contact(user_id, record, confirmed_fingerprint, expected_pin)` requires the
  exact fingerprint confirmed through an independent channel. `expected_pin` is a clone
  of the local pin shown at the start of verification, or `None` for a new contact.
  A mismatched current pin produces `ContactConflict` and preserves the existing pin.
- `require_verified_contact(user_id, record)` rejects every status except `Verified`.
  Package creation and opening use this gate. It does not confer server membership.
- `contact_pin(user_id)` exposes read-only pin metadata for verification and display.

An observed valid changed or older record suspends the current pin and advances its local
revision. Repeated observations do not keep incrementing it. Returning to the originally
pinned record stays suspended until explicit re-verification. The trusted fingerprint
is never replaced by an observation. Unverified high version numbers do not advance the
trusted version; this avoids poisoning it with an attacker-supplied future version.

A replacement must have a strictly higher identity version. A different fingerprint at
the same version and any lower version are rejected even during explicit verification.
The exact existing identity may be re-verified to clear a false-alarm suspension.
Identical verification of an already active pin is idempotent. There is no implicit
"forget contact" or rollback reset. Revision exhaustion fails closed for re-verification.

The core cannot establish whether a human actually checked a trusted channel: callers
must never automatically echo the directory's fingerprint as confirmation. Persist
suspensions and verified changes before using them beyond the current session. Native
callers must hold `IdentityFile`'s exclusive lock across open, contact changes, and save.
The in-memory pin comparison does not resolve concurrent full-bundle edits on different
devices; server bundle CAS/conflict handling remains a separate pending API task.

## Encrypted backup and migration

New exports contain `backup_version: 2`, `public_identity`, and `encrypted_bundle`.
The bundle has `bundle_version: 2`, `identity_fingerprint`, `salt` (16 bytes), `nonce`
(24 bytes), `ciphertext`, and the exact KDF identifier `argon2id-v19-m65536-t3-p1`.
The two version fields must match. Unknown/duplicate fields, KDF policies, unsupported
versions, and noncanonical base64 fail closed. Input is bounded to 128 KiB and decoded
ciphertext to 64 KiB before KDF.

Argon2id v19 derives a 32-byte wrapping key using 64 MiB memory, 3 iterations, and 1 lane.
XChaCha20-Poly1305 encrypts strict JSON with `identity` (the three private seed arrays and
owner fingerprint) and `contacts`. Each contact has `user_id`, `identity_version`,
`fingerprint`, `suspended`, and a local `revision`. Contacts are sorted by user ID,
unique, exclude the owner, and are limited to 128. Versions/revisions must fit 1 through
2^53-1; IDs/fingerprints must be 64 lowercase hex characters. Contact metadata is never
included in the public identity or unencrypted bundle headers.

V2 associated data is length-prefixed domain `petika:recipient-private-bundle:v2`,
unsigned 32-bit big-endian bundle version 2, length-prefixed ASCII fingerprint, and
length-prefixed KDF identifier. Every byte count uses unsigned 32-bit big-endian encoding.
Salt/nonce/ciphertext tampering fails authentication. Version relabeling cannot strip pins.

V1 remains readable with its original domain ending in `:v1`, integer version 1, and
flat private identity JSON. Loading v1 creates an empty contact list in memory without
rewriting the source. New exports always write v2. Native replacement of a v1 file first
preserves its exact encrypted bytes in `<path>.v1.backup` with the same private-file
protections. A matching existing backup is reused; a conflicting backup blocks the
replacement. Both original and backup remain intact on that failure. Earlier clients
reject v2; no automatic downgrade is provided.

This local migration does not change the account, collection envelope, or journal schema.
A deliberately restored older backup can lose newer trust decisions; offline restore has
no trusted global version oracle. Keep the latest encrypted identity backup and fingerprint
separately from its passphrase. Account-password resets cannot recover identity keys.
Server enrollment, replacement, directory lookup, and bundle synchronization remain
described in the [API contract](api/group-key-delivery.md).

## Verification and provenance

Core tests cover independent key generation, public key/fingerprint vectors, authenticated
but mismatched private material, wrong passphrases/identity pins, ciphertext/header
tampering, unsupported formats, bounded input, rewrapping/recovery, file locking,
non-overwriting creation, symlinks, and Unix permissions. Contact tests cover explicit
first verification, encrypted pin persistence, changed-key suspension, rollback and
same-version substitution rejection, stale verification conflicts, cross-user/deployment
records, contact bounds, v1 migration backups, and version relabeling rejection.

`tests/fixtures/identity-backup-v1.json` was produced with the v1 implementation at
commit `bf1a1b3`, using synthetic data and passphrase `synthetic identity unlock phrase`.
It exercises compatibility with actual pre-contact ciphertext rather than re-creating
an old format using the new serializer.

`tests/fixtures/identity-v1.json` combines public synthetic inputs from RFC 7748 section
6.1, RFC 8032 section 7.1, and the first X-Wing draft-06 vector bundled with RustCrypto
`x-wing` 0.1.1. The fingerprint was computed independently using Python `hashlib.sha256`
and big-endian `struct` encoding. The X-Wing vector is reused under its MIT license;
preserve the upstream notice in `tests/fixtures/X-WING-LICENSE-MIT`.

Run `cargo test -p petika-core --locked`; the normal workspace CI includes these tests.
Native/WASM workflow tests additionally run both delivery modes. A compile alone is not
a workflow test; see [test actions](testing/group-key-delivery.md).
