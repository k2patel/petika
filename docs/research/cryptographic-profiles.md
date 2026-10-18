# Cryptographic profile assessment and device-delivery draft

Date: 2026-10-18. Baseline: `bc48aa1`. Status: initial source/code assessment and
review draft. No new cryptographic implementation or external review completed.
Follow-up: [implemented synthetic AES-GCM spike and evidence](aws-lc-provider-spike.md).
The initial assessment below remains the baseline; production integration is still pending.

Direction: [ADR 0004](../decisions/0004-cryptographic-profile-direction.md).

## Profile separation

| Component | Existing behavior | Intended development |
| --- | --- | --- |
| Content encryption | XChaCha20-Poly1305 in Standard and experimental Hybrid | Retain; separately evaluate an AES-256-GCM profile |
| Collection secret | Standard random data key; Hybrid X-Wing seed with envelope KEM ciphertext | Preserve exact existing interpretation; new formats tag secret type explicitly |
| Recipient delivery | HPKE X25519 or X-Wing draft-06, with ChaCha20Poly1305 and Ed25519 outer signatures | New device-addressed ML-KEM-based profile; signatures and enrollment authorization reviewed separately |
| Local key protection | Argon2id/passphrase-encrypted identity bundle | Additional platform-bound device protection after capability testing |
| Recovery | Collection passphrase wrapper and encrypted identity exports | Explicit recovery access paths with compatible profile policy |

Content cipher and delivery KEM need separate authenticated identifiers. A new
ML-KEM delivery package can protect an existing collection secret without changing
the content cipher, but retaining old packages/wrappers retains their attack paths.
A content-cipher change requires a new authenticated envelope version and re-encryption.

## AES-256-GCM module feasibility

Initial candidate: AWS-LC through `aws-lc-rs` for native Rust. NIST lists the static
AWS-LC 3 module under active FIPS 140-3 certificate 5314, with approved-mode and
installation/configuration caveats. Upstream release notes associate the v1.17.x
Rust wrapper with FIPS v3. Follow-up runtime inspection found that our resolved module
is 3.6.0, whereas this certificate policy names 3.1.0; see the spike evidence above.
This is a shortlist, not a dependency selection or proof
that a Petika binary uses the validated configuration.
[NIST certificate 5314](https://csrc.nist.gov/projects/cryptographic-module-validation-program/certificate/5314),
[upstream release notes](https://github.com/aws/aws-lc-rs/releases).

The wrapper's FIPS feature is insufficient evidence by itself: upstream warns that
module versions can advance, including versions submitted for certification. Pin
and inspect the complete dependency/build chain against the certificate and security
policy rather than selecting `latest`.
[Upstream module-version guidance](https://github.com/aws/aws-lc-rs/blob/main/aws-lc-rs/README.md).

Before selecting the provider, record:

- Exact Rust wrapper, FFI/module revision, source hashes, certificate status and
  security-policy revision; permitted compilation/linking and initialization procedure.
- Covered CPU/OS environments for each native target, approved service indicators,
  startup/self-test behavior and failure handling. Browser/WASM coverage is unproven.
- AES-GCM IV generation requirements, per-key usage limits, approved randomness,
  key derivation/import rules and secret handling outside the module boundary.
- Rust 1.90 compatibility, build tools, licensing, reproducibility and distribution.
- Which operations remain outside the validated boundary: current Argon2id,
  XChaCha20, X-Wing, signatures, local device wrappers, TLS and backup tooling all
  need separate assessment. A validated TLS server cannot validate client vault crypto.

Do not copy XChaCha's random 192-bit nonce policy into AES-GCM. Design IV allocation
against the selected module's requirements, including concurrent writers, crashes,
restored counters and cloned devices. Investigate fresh per-write data keys versus
coordinated nonce allocation; choose only after a reviewed multi-writer analysis.

Outcome: native feasibility is promising; validated Petika operation, browser coverage,
module security-policy mapping and the nonce/key lifecycle remain unverified. No AES
provider is added to the application dependencies in this assessment.

## ML-KEM device-delivery profile: review draft

ML-KEM is standardized in FIPS 203. Its role is to establish a shared secret used by
an authenticated encryption construction, not directly encrypt arbitrary vault data.
The IETF PQ/hybrid HPKE document observed during this assessment is draft-05, not a
final RFC. RFC 9180 alone does not standardize an arbitrary new ML-KEM adapter.
[FIPS 203](https://csrc.nist.gov/pubs/fips/203/final),
[IETF PQ HPKE draft](https://datatracker.ietf.org/doc/draft-ietf-hpke-pq/),
[RFC 9180](https://www.rfc-editor.org/rfc/rfc9180.html).

Candidate for evaluation: ML-KEM-768-based delivery, comparing pure ML-KEM with a
specified traditional/PQ hybrid. Parameter selection is provisional; stronger sets,
performance and module availability require assessment. Do not invent a KEM combiner,
copy the existing draft-06 adapter under a new label, or silently substitute Kyber
pre-standard encodings. Pin any experimental specification and vectors exactly.

Proposed contract for review:

1. Each device has distinct recipient encryption keys; device authorization is
   separately authenticated and versioned. Define authority and quorum before coding.
2. An unlocked, authorized issuer verifies the recipient device and its current
   authorization, then seals a typed collection secret using a reviewed KEM/KDF/AEAD
   profile. The package does not authorize access to additional collections.
3. Authenticate deployment/user/device IDs, device fingerprint/version, collection,
   content suite, delivery suite, key epoch, authorization generation, issuer identity,
   format version and unique package ID. Freeze canonical bytes and bounds in fixtures.
4. Authenticate the issuer and its authority separately. Keeping Ed25519 would leave
   classical authentication: do not label that end-to-end PQ security. Evaluate a
   standardized PQ signature profile and its lifecycle, size and compatibility costs.
5. Reject altered headers, invalid ciphertext, wrong recipient/epoch, unsupported
   profiles, replayed authorization and downgrade attempts. Use maintained libraries
   and upstream known-answer tests; do not implement new KEM mathematics.
6. Preserve existing package v1 decoding and strict rejection of unknown formats.
   New device-addressed packages need a new version and deliberate migration.

Fresh ML-KEM encapsulations do not provide forward secrecy against later compromise
of a static recipient decapsulation key. Rotation limits future delivery only after
new collection secrets and recipient keys are adopted. Enrollment signatures do not
alone solve server rollback/equivocation or bootstrap freshness on a recovered device.

Review artifacts still required: exact algorithms and libraries, external specification
revision, byte encoding, vectors, threat model, device-authority protocol, error behavior,
compatibility/migration report and independent design/implementation assessment.

## Initial review of all key-access paths

This inventory records code/design observations, not a completed penetration test.

| Access path | Evidence / current protection | Finding and required follow-up |
| --- | --- | --- |
| Collection recovery wrapper | [crypto.rs](../../crates/petika-core/src/crypto.rs): Argon2id-derived key wraps collection secret using XChaCha20-Poly1305 | Copied wrappers permit offline passphrase guesses; PQ delivery cannot fix weak recovery phrases. Define recovery entropy policy and review every retained epoch. |
| Recipient package | [packages.rs](../../crates/petika-core/src/identity/packages.rs), [wire format](../key-package-format.md) | Standard delivery is classical; Hybrid is pinned experimental X-Wing; both use classical Ed25519 authentication. No blanket PQ claim. |
| Private identity bundle/export | [identity.rs](../../crates/petika-core/src/identity.rs): passphrase-protected private keys and trust data | Unlocking this bundle exposes all grants addressed to that identity. Include exports and old copies in rotation/compromise analysis. |
| Device biometric wrapper | [research proposal](multi-device-biometric-keys.md); not implemented | Verify cryptographic binding to user verification, fallback, hardware provenance and exported-wrapper exposure. A classical public-key wrapper can create a classical path to a Hybrid secret. |
| Browser unlock | Existing WASM worker and server-delivered application | A malicious client can steal unlocked secrets; PRF does not cure malicious script delivery. No PRF outputs in server requests or logs. |
| Trusted-person / organization recovery | Planned in [ADR 0003](../decisions/0003-security-and-recovery-baseline.md) | Define scope, custody, enrollment and revocation; review every recovery recipient's protection. Approval workflow is not threshold cryptography. |
| Backups and Git mirror | [recovery](../recovery.md), [off-site backups](../offsite-backups.md) | Inner vault wrappers survive outer backup encryption. Recovery must inspect historical packages, passphrases and restored authorization state. Outer encryption alone does not upgrade the inner profile. |
| Push destination credentials | [push.rs](../../crates/petika-server/src/accounts/backups/push.rs) | Separate server master-key domain; it protects destination credentials, not vault contents. Full backup handling still needs independent custody and restore review. |
| Account/API credentials | Server account/session/API authorization | Permit retrieval or management of ciphertext, not vault decryption by themselves. Keep account reset distinct from vault-key recovery. |

For each implemented/new wrapper, attach an evidence record containing secret type,
where ciphertext copies exist, suite/provider, entropy/KDF, authenticated context,
nonce/usage rules, who can invoke it, export/fallback behavior, rotation/recovery,
platform, test evidence and reviewer. Classify unexamined paths as unknown, not secure.

If a policy requires PQ confidentiality, do not create a parallel classical recipient
package for the same secret and still advertise PQ protection. Scope claims precisely
when old backups or recovery copies remain. Strong symmetric recovery secrets are not
inherently disqualified merely because their wrapper does not use ML-KEM.

## Ordered implementation gates

- [x] Record accepted direction and inspect existing cipher/package/wrapper paths.
- [x] Identify a native validated-module candidate and current ML-KEM standards boundary.
- [ ] Complete the certificate/security-policy/build matrix and synthetic AES-GCM
  capability tests; do not change production ciphertext.
- [ ] Resolve device authorization and select an exact reviewed delivery construction;
  freeze vectors and the new package contract before integration.
- [ ] Prototype independent device recipients in both current content modes; test
  tampering, substitution, revocation/rotation, interrupted migration and old restores.
- [ ] Complete independent protocol review, remediate findings and retest.
- [ ] Integrate explicit opt-in migration with preserved backups, platform capability
  checks and labels matching the evidence. No silent provider or suite fallback.

These gates implement the accepted direction while keeping unreviewed cryptography
out of the production path. This document does not claim external review, FIPS
validation of Petika, or a production-ready PQ profile.
