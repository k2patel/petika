# Candidate device enrollment challenge and proof

Date: 2026-10-31. Experimental, disabled by default behind `experimental-device-keys`.
Extends the [candidate device-record format](device-key-format.md) under
[draft ADR 0005](decisions/0005-independent-device-keys.md). This is client-side core
logic; it does not provide account APIs, sessions, biometric prompts, collection
access, server publication, or production enrollment.

## Ceremony and trust boundary

1. The new device independently bootstraps the account authority and current roster,
   generates fresh recipient/signing keys, and signs an enrollment request.
2. The authority client checks the exact current roster, request signature, expiry,
   eligibility and independently confirmed device fingerprint. It creates two independent
   random 32-byte challenges, encrypts one to each recipient key, and signs the complete
   public challenge. Original challenge plaintexts are then discarded; a zeroizing
   expected-response hash remains in client-only `PendingEnrollment` state.
3. The new device verifies the authority signature and independently confirmed authority
   fingerprint, the exact current roster, complete own record and time window. It opens
   **both** HPKE packets, hashes the secrets with the signed challenge digest and signs
   that response. Missing either encryption key cannot produce a valid proof.
4. The authority rechecks the current roster, fingerprint and time, verifies the device's
   proof signature, exact request/challenge digests and expected response (constant-time
   comparison). It prepares one signed adjacent roster adding only that device.
5. Approval consumes that pending ceremony and clears its expected response. It returns
   a candidate without advancing the caller's trusted pin. Preserve the exact candidate
   for submission retries; publish using server CAS, verify its receipt, then advance the
   local pin. Drop pending state to cancel. Failed verification leaves pending state usable
   until expiry; clients must rate-limit attempts and discard abandoned ceremonies.

The caller supplies trusted Unix time in whole seconds. Both ends enforce
`issued_at <= now < expires_at`, lifetime 1–300 seconds, and timestamps at most 2^53−1.
Generated requests use 300 seconds. Clock rollback resistance is a platform/integration
requirement, not established by this library. Password reset and a server directory
alone never substitute for either independently confirmed fingerprint.

Multiple pending requests may target one baseline. Once a newer trusted roster is
observed they fail. This in-memory primitive cannot prevent two disconnected authority
copies from signing competing candidates; durable CAS and retained pins must reconcile
them. Recreating a challenge from the same request requires a new explicit approval,
produces new secrets and is not a retry of the old proof. No cross-process nonce ledger
or persistence of pending private state is implemented.

## Encoding

Use `F`, `U32`, `U64`, canonical padded Base64, lowercase-hex IDs and strict JSON rules
from [device-key format](device-key-format.md). All domains below are exact ASCII with
no terminator, except the explicitly NUL-terminated encrypted payload tag.

| Input | Maximum JSON bytes | Parse result |
| --- | --- | --- |
| `EnrollmentRequest` | 16,384 | Framing, device record and request signature validated |
| `EnrollmentChallenge` | 24,576 | Framing, request and embedded authority signature validated |
| `EnrollmentProof` | 2,048 | Framing only; requires retained challenge for verification |

Embedded authority signatures establish consistency, not independent trust. The operational
methods always bind them to `TrustedDeviceRoster`. Unknown, duplicate, null, missing,
oversized and unsupported-version fields fail. None of these records carries private
keys or raw challenge plaintext; no such field is accepted in a server message.

### Request

JSON fields: `request_version` (=1), `authority`, `device`, `roster_generation`,
`roster_digest`, `nonce` (fresh random 32 bytes as 64 lowercase hex characters),
`issued_at`, `expires_at`, `signature`. Both complete public records use their existing
candidate encodings. The transcript is:

```text
F("petika:device-enrollment-request:experimental-v1") || U32(1)
|| F(authority transcript) || F(authority fingerprint)
|| F(device transcript) || F(device fingerprint) || F(decoded device self-signature)
|| U64(roster_generation) || F(roster_digest) || F(nonce)
|| U64(issued_at) || U64(expires_at)
```

The device signs this transcript with Ed25519. The request digest is SHA-256 of
`transcript || F(decoded request signature)`, represented as lowercase hex.
Require matching deployment/account, room for another active device and next generation,
an unused/nonrevoked device ID, no reuse of active encryption/signing keys, and a device
signer distinct from the authority signer.

### HPKE and signed challenge

Packet JSON contains `enc` and `ciphertext`, both Base64. Required profiles are
`standard` (X25519 KEM 0x0020, 32-byte encapsulation) and
`experimental-xwing-draft06` (existing pinned experimental KEM 0x647a, 1,120-byte encapsulation).
Both use HPKE Base mode, HKDF-SHA256 (0x0001) and ChaCha20-Poly1305 (0x0003).

```text
binding = F(request_digest) || F(profile)
info = F("petika:device-enrollment-hpke-info:experimental-v1") || F(binding)
aad  = F("petika:device-enrollment-hpke-aad:experimental-v1") || F(binding)
payload = ASCII("petika:device-possession:experimental-v1") || 0x00 || random_32_bytes
```

Each packet has its own randomness and secret. Ciphertext length is payload length +16.
No fallback, suite negotiation or authentication-only proof is accepted.

Challenge JSON fields: `challenge_version` (=1), `request`, `standard`, `hybrid`,
`signature`. Its transcript is:

```text
F("petika:device-enrollment-challenge:experimental-v1") || U32(1) || F(request_digest)
|| F("standard") || F(decoded standard enc) || F(decoded standard ciphertext)
|| F("experimental-xwing-draft06") || F(decoded hybrid enc) || F(decoded hybrid ciphertext)
```

The authority signs this transcript. The challenge digest is lowercase-hex SHA-256 of
`transcript || F(decoded authority signature)`. Both ciphertexts and their order are bound.

### Proof and candidate

```text
response = SHA256(
  F("petika:device-enrollment-response:experimental-v1")
  || F(challenge_digest) || F(standard challenge plaintext: 32 bytes)
  || F(hybrid challenge plaintext: 32 bytes))
```

Proof JSON fields: `proof_version` (=1), `request_digest`, `challenge_digest`,
`response` (Base64, 32 decoded bytes), `signature`. The device signs:

```text
F("petika:device-enrollment-proof:experimental-v1") || U32(1)
|| F(request_digest) || F(challenge_digest) || F(decoded response)
```

Successful approval returns the existing signed roster format, with generation +1,
the exact baseline digest as parent, the candidate added in sorted order and all other
records/tombstones preserved. It is not an API authorization receipt or permission to
read any collection. The lower-level roster-signing primitive remains available for
controlled bootstrap/removal; it cannot assert that a ceremony occurred.

## Evidence and remaining work

Independent Python fixtures reproduce request/challenge/proof transcript bytes,
signatures and HPKE ciphertexts. Standard uses independent X25519 DH and HPKE schedule;
Hybrid uses existing upstream X-Wing KAT encapsulation/shared secret with the independent
HPKE schedule. Fixture inputs are explicit public test labels. Rust opens both packets,
matches the proof byte-for-byte, and produces the expected signed roster.

Tests reject signed responses with either missing secret, packet corruption even if
re-signed by the authority, wrong fingerprints/authority/device, mixed ceremonies,
expiry/future requests, replay, stale roster and intervening revocation. Failed checks
preserve pending state and the baseline; success clears the expected response without
prematurely advancing the pin. Public wire fields and secret local state remain separate.

Durable CAS/receipts, authenticated account transport, recovery, device packages,
biometric-protected persistence, migration, independent review and platform lifecycle
validation remain open. This candidate protocol is not enabled in production.
