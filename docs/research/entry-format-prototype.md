# Experimental entry-format core prototype

Implemented behind the **off-by-default** Cargo feature `experimental-entry-format`
on `petika-core`. This is an unaudited cryptographic prototype, not an enabled vault
format. No CLI/server/web route consumes it, no migration exists, and existing
Standard/Hybrid envelopes and recipient packages are unchanged.

```sh
cargo test --locked -p petika-core --features experimental-entry-format
cargo clippy --locked -p petika-core --features experimental-entry-format --all-targets -- -D warnings
```

## Implemented boundary

`entry_format::RootKey` owns a zeroizing random 32-byte root and a fixed context.
`Header` binds format, suite, deployment, collection, epoch/salt, entry/index kind,
opaque object ID and positive revision. `seal` always generates a fresh nonce;
`open` requires the independently expected header and exact-byte envelope digest.
The caller must obtain that digest from an authenticated index. A public hash by
itself does not authenticate an object or establish freshness.

The low-level primitive still treats plaintext as opaque bytes. The opt-in
[index validation layer](entry-index.md) now validates decrypted folder graphs,
entry references, tombstones and head continuity. It does not implement API
transactions or migration. Entry payload schemas remain the caller's responsibility.

| Prototype limit | Value |
| --- | --- |
| Entry plaintext | 256 KiB |
| Index plaintext | 2 MiB |
| Serialized recovery wrapper | 4 KiB |
| Object envelope input | Base64 expansion of plaintext limit + 16-byte tag, plus 4 KiB header budget |
| Context IDs / entry IDs / wrapper IDs | Exactly 64 lowercase hex ASCII characters |
| Epoch and object revision | 1 through 2^53−1 |
| Epoch salt / AEAD nonce | 32 / 24 bytes, canonical padded base64 |
| Recovery KDF | Argon2id v19, 64 MiB, 3 iterations, 1 lane, 32-byte output |
| Recovery passphrase creation | 12–4096 UTF-8 bytes; strength remains user-dependent |

Unknown/duplicate fields, unsupported profiles, noncanonical base64, invalid lengths
and parameter substitutions are rejected. Raw input bounds precede JSON decoding;
wrapper ciphertext length is checked before Argon2 work. Index-count, transaction,
receipt and history-catch-up budgets are still unimplemented review gates.

## Exact prototype encoding

`field(x)` = `u32be(byte_length(x)) || x`. Text is UTF-8; IDs are hex ASCII, not raw
hex-decoded bytes. Context prefix is `field(deployment_id) || field(collection_id) ||
u64be(key_epoch)`. The suite is `xchacha20poly1305-hkdf-sha256-v1`.

HKDF-SHA256 uses the raw 32-byte epoch salt and root as input key material. Expand
produces 32 bytes, with info:

```text
field("petika:entry-format:kdf:v1") || u32be(1) || field(suite) ||
context_prefix || field(kind) || field(object_id)
```

Kind is `entry` or `index`; the singleton index's object ID is the empty string.
AEAD associated data is:

```text
field("petika:entry-format:aead:v1") || field(hkdf_info) ||
field(raw_epoch_salt) || u64be(object_revision)
```

The envelope has exactly `header`, `nonce`, `ciphertext`. `header` has exactly
`entry_format_version`, `suite`, `context`, `kind`, `object_id`, `revision`.
Context has exactly `deployment_id`, `collection_id`, `key_epoch`, `epoch_salt`.
The digest is SHA-256 of the exact stored envelope bytes; JSON whitespace/order is
not normalized for hashing. Existing ciphertext must be retained byte-for-byte.

### Explicit recovery wrapper

This is a new prototype wrapper; it is not an extension of key-package v1.
Profile: `argon2id-v19-xchacha20poly1305-entry-root-v1`. Wrapper version: 1.
Payload: ASCII `petika:entry-root:v1`, one zero byte, then exactly 32 root-key bytes.
Every creation uses a random wrapper ID, 16-byte Argon2 salt and 24-byte AEAD nonce.
The associated data is:

```text
field("petika:entry-format:recovery:v1") || u32be(wrapper_version) ||
field(profile) || field(suite) || context_prefix || field(raw_epoch_salt) ||
field(wrapper_id) || field(raw_argon2_salt) ||
u32be(memory_kib) || u32be(iterations) || u32be(lanes) || field(payload_tag)
```

The strict wrapper JSON has exactly `wrapper_version`, `profile`, `suite`, `context`,
`wrapper_id`, `salt`, `memory_kib`, `iterations`, `lanes`, `nonce`, `ciphertext`.
There is no server wrapper, implicit recipient fallback or algorithm negotiation. Unwrap
requires an expected context rather than trusting the wrapper's claimed location.
A future client must additionally verify the authenticated active-wrapper set after
unlock; that collection-level policy is not implemented here.

## Epoch checkpoints and recipient extension

Roots remain fixed to exact contexts; there is no implicit epoch switch. The
[checkpoint and recipient extension](entry-checkpoints.md) now supplies explicit
identity-signed epoch transitions, independently pinned authority/checkpoint
bootstrap, active-wrapper verification and a new recipient package family.

These are opt-in core APIs only. Native pin persistence and adjacent-head
continuity are available in the [index extension](entry-index.md); client UX and
migration remain pending. A checkpoint authority must verify
candidate data before signing it. The extension documents authority-loss recovery,
profile restrictions and the remaining fork/freshness limitations.

## Independent fixtures and validation scope

`scripts/generate_entry_vectors.py` uses cryptography 46.0.3 HKDF-SHA256 and PyNaCl
1.6.2's libsodium XChaCha20-Poly1305/Argon2id. It does not call Rust or implement a
new cipher. Install `scripts/requirements-entry-vectors.txt` in an isolated test
virtual environment, then run `python scripts/generate_entry_vectors.py --check`.
The committed `entry-format-v1.json` fixture contains synthetic keys only.

Rust checks exact info/AAD/derived keys, decrypts Python ciphertext, reproduces its
object ciphertext with test-only fixed nonces, and unwraps the Python recovery vector.
Other tests cover fresh production nonces, object/key-domain separation, wrong
password/context, header/ciphertext/nonce tampering with recomputed public hashes,
strict parsing/limits and rejection by the current vault parser.

CI explicitly tests this feature on native platforms and checks WASM compilation.
Running the vectors in a WASM runtime remains pending. The full 46-scenario
[acceptance plan](../testing/encrypted-entry-format.md) remains a rollout gate;
these primitive tests do not satisfy its API, migration, index or recovery scenarios.
This work is not an independent security review or a FIPS validation.
