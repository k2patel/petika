# Local recipient identity format

Implemented in `petika-core::identity`. This is the client-core foundation for group-key
delivery, not an enrollment API or a user-facing CLI/web enrollment workflow. Existing
collections, accounts, and synchronization are unchanged. The format is experimental.

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
  refuses existing files, `save(..., false)` explicitly replaces them atomically, and
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
and trust-pin synchronization remain the next implementation step.

## Encrypted backup

The strict JSON wrapper contains `backup_version: 1`, `public_identity`, and
`encrypted_bundle`. The latter contains `bundle_version: 1`, `identity_fingerprint`,
`salt` (16 bytes), `nonce` (24 bytes), `ciphertext`, and the exact KDF identifier
`argon2id-v19-m65536-t3-p1`. Unknown/duplicate fields, versions, KDF policies, or noncanonical
base64 fail closed. Input is bounded to 128 KiB and decoded ciphertext to 64 KiB before KDF.

Argon2id v19 derives a 32-byte wrapping key using 64 MiB memory, 3 iterations, and 1 lane.
XChaCha20-Poly1305 encrypts the private JSON containing three 32-byte seed arrays and the
public identity fingerprint. Associated data consists of length-prefixed domain
`petika:recipient-private-bundle:v1`, unsigned 32-bit big-endian bundle version 1,
length-prefixed ASCII fingerprint, and length-prefixed KDF identifier. Salt/nonce tampering
fails authentication. All parameter validation happens before expensive derivation.

Verified contacts are not stored yet; adding them requires explicit format compatibility
handling. Server bundle revisions, enrollment, replacement, and directory APIs remain
proposed in the [API contract](api/group-key-delivery.md). Account password resets cannot
unlock this local identity. Keep the encrypted backup, its passphrase, and the verified
fingerprint available through independent recovery storage.

## Verification and provenance

Core tests cover independent key generation, public key/fingerprint vectors, authenticated
but mismatched private material, wrong passphrases/identity pins, ciphertext/header
tampering, unsupported formats, bounded input, rewrapping/recovery, file locking,
non-overwriting creation, symlinks, and Unix permissions.

`tests/fixtures/identity-v1.json` combines public synthetic inputs from RFC 7748 section
6.1, RFC 8032 section 7.1, and the first X-Wing draft-06 vector bundled with RustCrypto
`x-wing` 0.1.1. The fingerprint was computed independently using Python `hashlib.sha256`
and big-endian `struct` encoding. The X-Wing vector is reused under its MIT license;
preserve the upstream notice in `tests/fixtures/X-WING-LICENSE-MIT`.

Run `cargo test -p petika-core --locked`; the normal workspace CI includes these tests.
A successful WASM compile establishes build compatibility, not a tested browser identity
workflow or delivery protocol. See [test actions](testing/group-key-delivery.md).
