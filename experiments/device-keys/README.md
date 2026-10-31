# Independent device-key model

Executable evidence for [draft ADR 0005](../../docs/decisions/0005-independent-device-keys.md).
This standalone workspace accepts no arguments, files, network data or real account
credentials. It generates all test keys in memory and prints only pass/fail summaries.
Nothing depends on it from the application workspace or release images.

```sh
cargo test --manifest-path experiments/device-keys/Cargo.toml --locked
cargo run --manifest-path experiments/device-keys/Cargo.toml --locked
cargo clippy --manifest-path experiments/device-keys/Cargo.toml --all-targets --locked -- -D warnings
```

The model gives two devices in the **same account** different X25519, experimental
X-Wing draft-06 and Ed25519 keys. A separate signing authority approves an exact signed
roster after confirmation and encryption/signing possession checks. It then encrypts
one synthetic collection once, wrapping the random secret separately for each device
using HPKE. After removal it creates a fresh secret and ciphertext for the remaining
device. The retired private keys fail to decrypt even when bypassing roster checks;
old ciphertext and old packages remain readable with a historical pin, as expected.

Tests also cover expiry, wrong fingerprints, forged possession/signatures, encryption
key substitution, replay, concurrent enrollment/revocation, stale/forged roster state,
wrong collection/epoch, modified ciphertext/package/signature and profile substitution.
Both delivery profiles run; the imported production X-Wing adapter's vector tests run
in this workspace too. The checked-in lockfile pins the isolated dependencies.

This is an in-process **software model**, not Petika multi-device support or a new wire
format. JSON tuples are a local typed signing transcript, not an untrusted-input parser.
The authority keeps pending challenges locally; those secret fields are never a server
message. `Pin` bootstraps from independently retained synthetic values in the harness.
Callers supply the expected collection/epoch; no global freshness oracle is implied.
The demo selects a fresh epoch explicitly and has no production storage coordinator.

The single personal-collection authority also acts as issuer in this experiment.
Production must preserve independent group permissions and collection checkpoint
authority, verify per-account roster CAS, and atomically commit rotation. There is no
enrollment UI, account API, persistent hardware wrapper, secure clock, recovery custody
system, disk-failure handling or independently reviewed serialization here. The
biometric probe remains separate. Production Standard/Hybrid vault-format integration
and per-device revocation claims remain gated on the ADR's review/migration work.
