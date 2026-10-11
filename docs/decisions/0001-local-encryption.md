# 0001: Local encrypted storage before network sync

Status: accepted for the experimental local milestone, not a stable storage contract.

## Architecture

The user selected API-authoritative synchronization with a one-way encrypted Git mirror.
The mirror will be a separate data repository, never the Petika source repository.
Build and test local encryption first. No remote login, sharing, or sync is implied by
this milestone. The local snapshot format will need migration before per-record sharing.

## Threat model and choices

Protect a copied, locked store against plaintext disclosure and undetected modification.
Do not claim protection from malware running as the user, a compromised OS, terminal
capture, hostile filesystem races, or a malicious binary. File size and ciphertext length
remain observable. Valid older snapshots can be replayed; rollback detection needs the
future revision protocol. Passphrase strength limits resistance to offline guessing.

Use RustCrypto Argon2id v19 (64 MiB memory, 3 iterations, 1 lane, 32-byte output) with a
fresh 16-byte salt to derive a wrapping key. In standard mode, generate a separate random 256-bit data key.
Wrap that key with XChaCha20-Poly1305 and a fresh 24-byte nonce. Encrypt the entire local
record map with that data key and an independent fresh 24-byte nonce on every save.
All randomness uses the OS CSPRNG. Use separate fixed associated-data domains for key
wrapping and contents, including the format version. Reject any unsupported version,
KDF parameters, wrong nonce/key length, or excessive size before attempting decryption.

The outer JSON envelope contains only format/KDF metadata, salt, nonces, and ciphertext.
Names, usernames, URLs, notes, and passwords are inside the authenticated ciphertext.
Bound files at 16 MiB and serialized plaintext at 2 MiB. No plaintext temporary files.
Never derive encryption material directly from biometrics.

## Local persistence and unlock

Use an exclusive advisory sidecar file lock for the complete read-modify-write operation.
Write ciphertext to a same-directory temporary file, flush, then atomically replace.
Create new stores without overwriting an existing file. On Unix, enforce owner-only file
permissions and sync the containing directory. Reject symlink store/lock files. The OS
account must control the containing directory; Windows protection inherits its ACLs.
Do not rewrite directory permissions on a caller-specified existing directory.

For this CLI milestone every command unlocks using a hidden passphrase prompt and drops
keys on exit. There is no unlocked daemon or biometric integration yet. New passphrases
must be at least 12 characters. A deliberate `--passphrase-stdin` option supports pipes;
passphrases and entry passwords are never accepted as command-line arguments. Secret
buffers and record fields use zeroize; this does not guarantee removal of all compiler,
allocator, OS, or terminal copies. Disabling biometrics is not modeled as disabling locks.

## Validation and limitations

Test wrong passphrases, ciphertext/key/header tampering, version rejection, bounded reads,
round trips, metadata confidentiality, exclusive locking, duplicate/missing records,
atomic replacement, permissions, passphrase changes, and CLI failure behavior.
The format is experimental and unaudited. Recovery, enrollment, sharing, hardware key
storage, migration, and the network protocol remain separate design/implementation steps.

References: [Argon2](https://docs.rs/argon2/0.5.3/argon2/),
[XChaCha20-Poly1305](https://docs.rs/chacha20poly1305/0.10.1/chacha20poly1305/),
[atomic temporary-file persistence](https://docs.rs/tempfile/latest/tempfile/struct.NamedTempFile.html).

## Experimental hybrid mode

Initial setup also offers `hybrid-post-quantum`. RustCrypto X-Wing combines ML-KEM-768
and X25519. A random private seed is passphrase-wrapped with Argon2id and
XChaCha20-Poly1305; encapsulation provides the snapshot data key. The public KEM
ciphertext is stored in the envelope. Mode-specific associated data binds both layers
to the chosen mode, rejecting mode substitution. Both modes support local GPG import.

The X-Wing crate reports no independent implementation audit. This mode is experimental,
not a claim of unbreakable encryption. Weak passphrases remain vulnerable to offline
guessing in either mode. Post-quantum account enrollment and sharing are not implemented.
See [X-Wing implementation documentation](https://docs.rs/x-wing/0.1.1/x_wing/).

## Mirror privacy

The server journals each accepted ciphertext revision, then mirrors it asynchronously
using Rust gix. A bare repository contains one generic `snapshot.json` per committed
tree; record names and hierarchy are encrypted inside it. Revision counts, ciphertext
size, and commit times remain visible. Git is not required in the runtime image.
