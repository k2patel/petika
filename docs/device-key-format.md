# Candidate independent device-record and roster encoding

Date: 2026-10-31. **Experimental candidate, pending protocol review.** Implements the
record/roster portion of [draft ADR 0005](decisions/0005-independent-device-keys.md)
behind `petika-core/experimental-device-keys`, disabled by default. This is separate
from the accepted per-user identity, entry checkpoints and existing account API.
There is no production device enrollment or migration in this change.

## Encoding rules

Transport is UTF-8 JSON. Unknown/duplicate fields, missing fields, nulls, wrong types,
trailing JSON and unsupported versions fail. Key order and whitespace are not signed.
Use the bounded `parse` methods at untrusted input boundaries; direct serde decoding
does not validate cryptographic semantics. Every public consumer must validate records.

`F(x)` is four-byte unsigned big-endian byte length followed by the exact bytes `x`.
`U32` and `U64` are unsigned big-endian integers. Domain/suite names and IDs below are
ASCII with no NUL terminator. IDs, fingerprints and digests are exactly 64 lowercase
hexadecimal characters. They enter transcripts as **ASCII hex**, not decoded bytes.
Cryptographic keys and signatures use canonical padded standard Base64 in JSON; their
**decoded bytes** enter transcripts. No alternate padding, URL alphabet or whitespace.

| Limit | Value |
| --- | --- |
| Device JSON input | 8,192 bytes |
| Authority JSON input | 2,048 bytes |
| Roster JSON input | 1,048,576 bytes |
| Active devices | 64 |
| Revoked device-ID tombstones | 4,096 |
| Roster generation | 1 through 2^53−1 |

Limits are protocol limits, not configurable KDF/resource parameters. Hitting the
tombstone limit requires a future reviewed compaction/authority-transition design;
silently discarding revocation history is prohibited. No such transition exists yet.

## Device record

Required JSON fields: `record_version` (=1), `deployment_id`, `user_id`, `device_id`,
`standard_public_key`, `hybrid_public_key`, `signing_public_key`, `fingerprint`, `signature`.
Device IDs are fresh random 32-byte values encoded as lowercase hex. Keys are independently
generated X25519, X-Wing draft-06 and Ed25519; no key-version field exists because a key
change must enroll a new device ID. Labels do not appear in the signed record.

The transcript is exactly this concatenation:

```text
F("petika:device-record:experimental-v1") || U32(1)
|| F(deployment_id) || F(user_id) || F(device_id)
|| F("x25519")       || F(decoded standard_public_key: 32 bytes)
|| F("xwing-draft06")|| F(decoded hybrid_public_key: 1216 bytes)
|| F("ed25519")      || F(decoded signing_public_key: 32 bytes)
```

`fingerprint = lowercase_hex(SHA256(transcript))`.
`signature` is Ed25519 over:

```text
F("petika:device-self-signature:experimental-v1")
|| F(transcript) || F(fingerprint)
```

Reject malformed/noncontributory or noncanonical X25519 public coordinates (both the
standalone key and the trailing X25519 component of X-Wing). Validate the X-Wing public
key using the pinned draft-06 implementation. Reject malformed/weak Ed25519 public keys
and use strict signature verification. Public-key validation and a self-signature do
**not** prove encryption-key possession; the enrollment challenge protocol remains separate.

## Account device authority

Required JSON fields: `authority_version` (=1), `deployment_id`, `user_id`,
`signing_public_key`, `fingerprint`. The transcript is:

```text
F("petika:device-authority:experimental-v1") || U32(1)
|| F(deployment_id) || F(user_id)
|| F("ed25519") || F(decoded signing_public_key: 32 bytes)
```

The fingerprint is lowercase-hex SHA-256 of that transcript. This public record has
no self-signature; a roster signature proves authority-key possession, and external
confirmation establishes trust. The device authority is a separate key from ordinary
device signing keys and from the existing collection checkpoint authority.

## Signed roster

Required JSON fields: `roster_version` (=1), `authority` (the complete authority record),
`generation`, `parent_digest`, `devices` (complete device records), `revoked_device_ids`,
`signature`. Account/deployment come from the embedded authority. Every device must
match both. Active records are strictly ascending by device ID; tombstones are separately
strictly ascending. Reject duplicates, overlapping active/revoked IDs, any reused active
Standard/Hybrid/signing public key and any device signer equal to the authority signer.
This check cannot establish hardware uniqueness or detect all historical key reuse.

Generation 1 has an empty parent digest, zero tombstones and at most one initial device.
Every later generation has a 64-character parent digest. The unsigned transcript is:

```text
F("petika:device-roster:experimental-v1") || U32(1)
|| F(authority transcript) || F(authority fingerprint)
|| U64(generation) || F(parent_digest)
|| U32(number of active devices)
|| for each active record in order:
     F(device transcript) || F(device fingerprint) || F(decoded device signature: 64 bytes)
|| U32(number of revoked IDs)
|| for each revoked ID in order: F(device_id)
```

The authority's Ed25519 signature signs this transcript. The roster digest is
`lowercase_hex(SHA256(transcript || F(decoded roster signature: 64 bytes)))`.
All signatures, counts and order are bound. Signing a roster does not by itself prove
the caller obtained user approval, verified encryption possession or had API permission.
`DeviceAuthorityKey::sign_roster` is deliberately a low-level client primitive.

## Trusted transitions

Bootstrap requires independently confirmed authority fingerprint **and** roster digest.
It can start at a later snapshot only with that independent evidence. Validation against
the embedded self-described authority alone is not trust. `TrustedDeviceRoster` cannot
be deserialized from untrusted JSON and does not yet implement disk persistence.

An exact validated digest is an idempotent retry. Otherwise require the same complete
authority record, generation +1 and exact prior digest, then exactly one of:

- **Add:** one new device ID, unchanged retained device records and unchanged tombstones.
  The new ID must never have been revoked in the retained history.
- **Remove:** one removed device, unchanged retained records, and precisely that ID added
  to the tombstones. No other tombstone change is allowed.

Reject simultaneous add/remove, multi-device changes, empty changes, in-place key changes,
authority changes, skipped history, erased/extra tombstones, stale/forked parents and
counter overflow. Check everything before mutating the pin. A later enrollment must
restart if the roster used to create its challenge changed in the meantime.

This authenticates transitions relative to retained evidence; it cannot detect a newer
roster hidden by a malicious server when all independent newer evidence has been lost.
Removing a device from the roster does not rotate collection secrets or erase old data.

## Fixtures, validation and next boundary

`scripts/generate_device_key_vectors.py` independently constructs all transcripts,
fingerprints and Ed25519 signatures with Python hashlib/cryptography, without invoking
Rust. It uses explicit public test labels and existing upstream X-Wing public vectors.
The fixture stores only public records, signatures and canonical bytes. Rust tests check
exact bytes/digests, signatures and an add/remove chain, plus malformed inputs, bounds,
duplicate keys, signed invalid transitions and pin preservation on errors.

The candidate encoding is pinned by these fixtures, not accepted for production by them.
The [candidate enrollment ceremony](device-enrollment-format.md) now defines signed
requests, two encrypted challenges and a signed possession proof using these records.
The [native publication journal](device-roster-journal.md) adds durable CAS and retry receipts.
Next work is authenticated account integration, device-package delivery and migration. Independent protocol
review, hardware lifecycle and client/server integration remain required. Account password
reset, existing identities and production vault readers/writers are unaffected.
