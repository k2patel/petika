# Candidate authorized temporary Git SSH-key registration

Date: 2026-10-31. Implemented behind `experimental-device-keys`, the device API runtime
gate and `PETIKA_EXPERIMENTAL_GIT_KEY_LEASES=1`. No production deployment, real provider
key mutation or product biometric-enforcement claim. A subsequent
[native coordinator](native-git-lease-client.md) adds a tested isolated-agent seam; product
custody and Git execution remain open.
Extends [cleanup wiring](git-key-lease-cleanup.md) and
[ADR 0006](decisions/0006-git-authoritative-sync.md). Independent review remains required.

## Authorization and repository policy

An active account session, current password reauthentication, an already admitted device
and a new SSH key's proof of possession are required. Static service bearers are rejected
by the device route. The session ID comes from server session state; callers never choose
it. A self-signed unadmitted device record cannot request a grant. Account administrators
have no override for another account's assigned repository.

Protected host configuration adds optional `owner_user_id` (immutable Petika user ID),
`allow_write` (default false) and `max_lease_seconds` (default 3600, range 60–3600).
Omitting `owner_user_id` permits cleanup only, never issuance. Requests must exactly match
an assigned configured provider/origin/repository and its permission/lifetime policy.
Write access requires explicit operator opt-in; host write grants can be broad and are
not entry/branch ACLs. Initial assignment is to one private account, not shared-vault
membership. The repository must not mix ciphertext belonging to unrelated permission
groups; the owner mapping does not filter Git objects. Shared repository authorization still needs its separate reviewed contract.

Use HTTPS GitHub/Gitea key APIs with the existing protected management credential.
The new public SSH key is `ssh-ed25519`; its independent private seed stays on the client.
Do not reuse the device/authority signing key as an SSH credential. Client ephemeral SSH
custody and Git execution remain integration work; the native coordinator now supplies
an isolated-agent protocol without a private-key file.

## API and flow

All paths share the device API's cookie/approved-CLI session checks, JSON content type,
`X-Petika-Request: 1`, cross-site rejection and no-store responses. Request bodies are
bounded to 16 KiB and typed objects reject duplicate/unknown fields.

| Method / path | Contract |
| --- | --- |
| `GET /v1/device-keys/git-leases/context` | Authenticated non-bearer session ID and user/deployment context; no management configuration required |
| `GET /v1/device-keys/git-leases/operations/<operation_id>` | Own-session lookup with exact original public challenge, for lost challenge/registration replies |
| `POST /v1/device-keys/git-leases/challenges` | `{current_password, operation_id, device_id, repository, ssh_public_key, read_only, ttl}` → `{challenge}` |
| `POST /v1/device-keys/git-leases` | `{current_password, proof}` → verified active lease/public SSH descriptor |
| `GET /v1/device-keys/git-leases/<lease_id>` | Own-session status, operation ID, exact public challenge, expiry and error; no grant or private key |
| `POST /v1/device-keys/git-leases/<lease_id>/complete` | Strict `{}` → durable cleanup intent for that one lease |

`repository` is the configured `{provider, management_origin, repository}` descriptor.
`ssh_public_key` in the challenge request is canonical base64 of a raw 32-byte Ed25519
verification key. Server-generated output converts it into standard OpenSSH public-key
wire framing. Only public keys and signatures are accepted; no private-key upload.
`operation_id`, device IDs, lease IDs, session IDs, fingerprints and roster digests are
64-character lowercase hex. TTL is 60–3600 seconds, additionally bounded by host policy
and the remaining authenticated session lifetime.

1. Server authenticates/reauthenticates, loads the account's anchored roster, checks
   device admission and configured repository policy, and durably prepares the cleanup
   lease plus exact challenge before responding. No host create request occurs yet.
2. Client verifies its independently trusted current roster, confirms the exact remote
   origin/repository and checks its own device/key bindings. It signs the challenge
   digest with both its admitted device signer and its new independent SSH signer. The
   client must compare the operation/session IDs, key, permission and requested TTL with
   its retained request before signing; a server-provided challenge is not user consent.
3. Server reauthenticates and rechecks the exact current session, user/deployment,
   current signed roster, permission, TTL and persisted challenge. It keeps account and
   roster locks through admission and bounded host creation so disable/roster changes
   cannot race that admission. This serializes competing operations and may yield Busy
   errors; it is not a high-throughput distributed transaction implementation.
4. Server verifies complete host inventory, reserves `registering` durably, then makes
   at most one host POST for that lease. A 201 response alone is insufficient: inventory
   must confirm exactly one matching marker/fingerprint with the requested permission.
5. Client retains its operation/challenge and private SSH key. It uses status/exact retry
   to reconcile uncertain results, and completes or cancels the lease when done. Completion
   persists revocation before acknowledgement; the worker performs removal and verifies
   absence. Logout, expiry and restart cleanup remain connected.

Authorization is for ciphertext transport. Neither signature proves fresh biometric
execution or unlocks vault contents. The mandatory per-secret biometric broker boundary
remains separate; a successful lease must never be displayed as a biometric vault unlock.

## Candidate bytes and signatures

`GitLeaseChallenge` has version 1 and strict fields listed by the canonical sequence:

1. `field("petika:git-ssh-lease:experimental-v1")`; four-byte unsigned big-endian version.
2. `field` of each ASCII string, in order: `lease_id`, `operation_id`, `deployment_id`,
   `user_id`, `session_id`, `device_id`, `device_fingerprint`, `roster_digest`,
   `management_origin`, `repository`.
3. `field` of the decoded raw 32-byte `ssh_public_key`; one byte `read_only` (0 or 1).
4. Eight-byte unsigned big-endian `issued_at`, `challenge_expires_at`, `lease_expires_at`.

`field` means four-byte unsigned big-endian byte length followed by the value. Digest is
lowercase SHA-256 hex over those canonical bytes. Timestamps are positive and JS-safe
(through 2^53−1), with challenge lifetime at most 60 seconds and lease lifetime at most
one hour. The request's opaque lease ID is a fresh server nonce, not a client-selected ID.

Proof is `{challenge, device_signature, ssh_signature}`. Signatures are canonical base64
Ed25519 signatures over `field(domain) || field(challenge_digest_hex)`. Domains are
`petika:git-ssh-lease-device-proof:experimental-v1` and
`petika:git-ssh-lease-key-proof:experimental-v1`, respectively. The two signers have distinct
roles; signing and SSH keys must not reuse known device/authority signing public keys.
The server also matches the exact persisted challenge, not just a valid self-signature.

OpenSSH public wire bytes are `field("ssh-ed25519") || field(raw_public_key)`; the cleanup
fingerprint is lowercase SHA-256 hex of those bytes. The host descriptor is
`ssh-ed25519 <canonical-base64-wire>`. No private SSH serialization is defined here.
Independent Python fixtures in `tests/fixtures/git-lease-v1.json` under petika-core
validate canonical bytes, both signatures, digest and OpenSSH framing without Rust.

## Retries, races and failure states

Lease metadata now optionally retains the exact public authorization challenge; legacy
cleanup records without it cannot authorize registration. Idempotency is scoped to the
server session and caller operation ID. A new operation cannot reuse a previously tracked
SSH public key for that repository, including removed leases; use a fresh transport key. Identical challenge retries return the original
challenge; changed key/device/remote/permission/TTL or roster under that operation fail.
A returned old challenge is not a renewed authorization window: after expiry, query status
or cancel; a new attempt needs a fresh operation and appropriate key custody.

Only `pending_registration` may make its first host create call. `registering` is reserved
before that call. After a timeout, malformed reply or failed persistence, absence in an
inventory does not prove the in-flight POST cannot still complete. Therefore another POST
is prohibited for that lease. A retry can adopt an already present exact owned key after
fresh request validation; otherwise it stays uncertain until cancellation/expiry cleanup.
The cleanup worker keeps scanning tombstones for delayed registrations.

Reused proofs cannot move to another session, device, roster, repository, public key or
permission. A changed roster requires a new ceremony. Revoking/removed leases cannot be
reissued. Duplicate or wrong-permission owned keys queue cleanup rather than yielding a
grant; ownership collisions fail closed without deleting unrelated material. Registration
that finishes after the lease/session deadline is queued for revocation, not acknowledged
as active. Ordinary deploy-key deletion still depends on a working host/worker; no hard
remote TTL or cancellation of an accepted Git push is claimed.

Status and completion require the owning current session and remain available even if
host credential configuration becomes unavailable. Queue/ledger corruption is an error,
never reinitialization. No signing key, SSH private key, account password or backend
management credential is persisted in lease authorization records.

## Validation and remaining work

Checks cover independent two-signature fixtures, live client proof generation, request
bounds, wrong password/device/scope/write permission, session substitution, stale rosters,
proof expiry, idempotency, intent-before-POST, lost create replies across restart, prohibition
of a second unknown POST, cleanup after completion and permission mismatch. Fake local
GitHub/Gitea HTTP servers exercise create/list/delete and a create-side-effect followed
by a 503 response. Actual hosted permissions, SSH use and platform key custody remain
untested. Existing account, identity, entry and cleanup regressions remain required.

Next: protected platform custody and pinned-host Git execution beyond the
[native lease coordinator](native-git-lease-client.md), hosted disposable-repository trials,
status/QR UI and cryptographic device-removal/rotation. Operator assignment changes and
feature shutdown must explicitly drain/revoke existing leases; stopping cleanup does not
make remote deploy keys expire. No production flag was enabled by this implementation.

Recorded validation: [2026-10-31 registration evidence](testing/git-key-registration-2026-10-31.json).
