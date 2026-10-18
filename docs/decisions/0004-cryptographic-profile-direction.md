# 0004 Cryptographic profiles and complete key-access review

Date: 2026-10-18. Status: accepted direction; new profiles are not implemented or
independently reviewed. Baseline: `bc48aa1`.

## Decision

1. Retain XChaCha20-Poly1305 for the existing vault format. Preserve current decoding,
   suite identifiers and restore compatibility; no automatic cipher conversion.
2. Evaluate AES-256-GCM through a validated cryptographic module for a separately
   versioned compliance-oriented profile. Algorithm selection alone is not validation.
3. Develop an ML-KEM-based device-key delivery profile with independent protocol
   review before production use. Existing experimental Hybrid remains experimental.
4. Review every device, identity, passphrase, recovery and backup access path. A
   stronger delivery package cannot protect a vault secret exposed through another path.

Keep content encryption, recipient delivery, signatures, local device protection and
recovery policy separately identified and authenticated. Do not encode all these
choices in a single ambiguous Standard/Hybrid switch. Future UI labels must reflect
implemented profiles and verified platform capabilities, not this planning decision.

## Implementation boundary

Follow the [profile assessment and draft](../research/cryptographic-profiles.md).
Its ML-KEM parameter selection and package design are proposals, not frozen wire formats.
The [multi-device research](../research/multi-device-biometric-keys.md) still requires
an enrollment-authority decision and platform experiments. Do not allocate production
suite identifiers or replace existing grants until those contracts are reviewed.

A new profile must reject downgrades, preserve original backups, authenticate all
context, and fail closed when required providers are unavailable. Migration requires
fresh secrets where old wrappers exposed the same material; merely rewrapping a known
secret does not undo compromise. Historical copies retain their original protection.

No change to account passwords, live deployments or existing ciphertext is authorized
implicitly by profile selection. Supported migrations must be explicit, recoverable
and tested. Production support remains subject to the security alignment release gates.
