# Synthetic AES-GCM provider experiment

This standalone Rust workspace evaluates AWS-LC APIs without adding dependencies to
Petika's release workspace or changing vault formats. Never give it production data.
It accepts no keys or files and prints no key, nonce, plaintext or ciphertext bytes.

Run with Rust 1.90 and the native build prerequisites required by AWS-LC:

```sh
cargo test --manifest-path experiments/crypto-provider/Cargo.toml --locked
cargo run --manifest-path experiments/crypto-provider/Cargo.toml --locked
cargo test --manifest-path experiments/crypto-provider/Cargo.toml --locked --no-default-features --features fips
```

Default builds are ordinary provider capability tests. `fips` requests the upstream
FIPS provider; it is not a certification claim and never falls back to a non-FIPS
build on failure. Keep the lockfile and inspect the exact resolved module version.
The explicit 1.17.0 wrapper pin is an experimental candidate, not a security update policy.

The probe uses provider-generated randomness and the provider's randomized-nonce API.
Tests reject modified ciphertext, tags, nonce, context, wrong keys and truncated tags.
They are integration checks, not a cryptographic audit or exhaustive algorithm vectors.
The sample imports synthetic key bytes and does not prove approved key-generation,
zeroization, service indicators or production multi-writer nonce policy.

See the [validation mapping](../../docs/research/aws-lc-provider-spike.md) for results
and limits. A production profile additionally needs provider self-test/error handling,
approved-service checks, bounded key usage, migration and independent review.
