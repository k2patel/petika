# Candidate native Git lease coordinator

Date: 2026-10-31. `petika-desktop` feature `experimental-git-client`, off by default.
This is a tested native library seam, not a product CLI, browser bridge, or vault unlock.
It extends the [registration contract](git-key-registration.md) and
[cleanup worker](git-key-lease-cleanup.md). No live host credentials or repositories
were used, and no production feature was enabled.

## Boundaries and callers

The caller supplies an independently verified current device roster, an admitted
`DeviceIdentity`, an authenticated approved-CLI session, the intended host/repository,
permission and TTL, and a trusted `DraftCustody` implementation. `HttpService::context`
returns the authenticated non-bearer session ID with user/deployment IDs. Compare the
account/deployment with local trusted pins before creating the operation; this endpoint
does not establish a new device or roster trust anchor. The server owns the session ID.

`HttpService` keeps its bearer token in zeroizing memory and requests the current account
password through a callback separately for challenge and registration. Neither is stored
in the operation draft. Production endpoints require a canonical HTTPS origin without
userinfo, path, query or fragment. Redirects and proxies are disabled, calls have a
10-second deadline, and request/response payloads are bounded to 16 KiB. Loopback HTTP
is enabled only in unit-test compilation. A 404 means absence only for an operation
lookup; authentication and network errors cannot be interpreted as an absent lease.

There is no production `DraftCustody` implementation or password-only fallback. Its
contract requires authenticated encryption, protected wrapping-key custody and purpose
separation with `petika:native-git-lease-draft:experimental-v1`. The only software
wrapping key is inside tests. The Apple synthetic broker does not yet protect real
`DeviceIdentity` material or these drafts. A production adapter, trusted native IPC,
platform lifecycle tests and independent review remain required. Rust trait compliance
alone does not establish an OS security boundary or prove fresh biometric approval.

Transport admission and ciphertext sync do not decrypt vault secrets. Every secret
operation still requires its own fresh biometric-only broker action under
[ADR 0006](decisions/0006-git-authoritative-sync.md). A valid device signature is not
biometric evidence, and this coordinator supplies no secret-access bypass.

## Durable operation flow

| Phase | Durable data / permitted next step |
| --- | --- |
| `prepared` | Fresh random operation ID and independent Ed25519 seed/public key, exact scope and creation time; persisted before HTTP |
| `challenge_requested` | Record before challenge request; on retry look up the same operation before resending |
| `challenge_accepted` | Exact accepted challenge; only this challenge may be authorized |
| `authorized` | Both device and SSH proofs stored, no registration sent yet |
| `registration_started` | Persist before registration; reconcile remote status before any retry |
| `active` | Exact matching remote active status observed |
| `transfer_started` | Persist before exposing an isolated agent to one transport job; no repeat transfer from this phase |
| `cleanup_pending` | Persist before completion/cancellation call, retain encrypted seed for recovery |
| `removed` | Remote removal observed; seed and proof omitted from the new encrypted draft |

The native client compares every retained challenge field: account/deployment, session,
operation, device/fingerprint, independently pinned roster digest, management origin,
repository, SSH public key, read permission and exact requested TTL. Issuance must fall
within the operation's original 60-second request window. Canonical wire validation and
proof verification enforce the challenge lifetime. This prevents a server-provided
challenge from silently broadening a locally retained request.

A lost challenge response is recovered through
`GET /v1/device-keys/git-leases/operations/<operation_id>`. Status includes the exact
original public challenge. Lookup and completion are restricted to the owning live
session/account/deployment and work without management credential configuration.
A new session cannot adopt the old session's lease; existing session-event cleanup
revokes it. GET `/v1/device-keys/git-leases/context` also works without host credentials.
Neither endpoint authorizes creation or changes vault state.

Before registration, the client queries remote status. Only the exact pending intent
can be submitted. `registering` remains uncertain; it is not blindly submitted again.
A lost successful registration response can adopt the exact `active` status only when
the durable local phase records that registration began. An `active` local operation
cannot regress to pending issuance. These checks complement the server's sole-POST
reservation; they do not replace it or provide general rollback-resistant local storage.

All draft reads/writes use the native exclusive `StoreFile` lock, owner-only files,
bounded input and atomic replacement with sync. Serialization and decryption buffers
are zeroized. Any seal/write failure poisons the instance, including uncertain outcomes
after replacement; drop/reopen and reconcile rather than continuing in memory. Reopen
validates the seed/public key, scope, phase and challenge/proof relationships. The
custodian must authenticate its output, and the caller must use a trusted local directory.
For local development use the ignored `.secrets/git-leases/` directory and
`<operation_id>.git-lease-draft` names; draft files and their lock suffix are also ignored
repository-wide. Never put a real credential or encrypted private-key draft into Git.

## Temporary SSH agent and transfer seam

On Unix, `Operation::transfer` records `transfer_started`, rechecks the owning session's
active status and expiry, then launches a new `/usr/bin/ssh-agent -D` with an empty
environment and a private temporary socket directory. It sends one constrained Ed25519
identity directly over the Unix socket using
[RFC 9987 sections 5.2.3 and 5.2.7](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.2.3).
The packet contains the independent transport seed, never a device/authority signer.
Private buffers are zeroized; no SSH private-key file is written. Only the socket path
and standard public descriptor reach the trusted transport callback.

The agent lifetime is capped by the remaining lease time, conservatively reduced by
monotonic elapsed time. Normal completion/error kills and waits for that agent before
requesting remote cleanup; unrelated agents and keys are untouched. A parent crash may
leave the isolated agent process until externally collected, but its key has a local
lifetime constraint. Local agent expiry does not enforce expiry on a remote deploy key.
Remote deletion still depends on the worker/provider; strict remote TTL requires a
certificate or lease-checking gateway. Caller-supplied `now` must come from the native
controller's trusted UTC clock, never a browser request.

The callback is a **trusted extension seam**. It must enforce independently verified SSH
host-key pins, no forwarding or credential fallback, bounded subprocesses and ciphertext-only
Git protocol rules. This milestone does not supply a production Git runner or host-key
pin verifier. The agent test signs generated authentication data; it is not an actual
SSH login, Git fetch/push, or hosted-permission test. No system agent is reused.

After either a successful or failed job, cleanup intent is durable before the server
call. A failed cleanup acknowledgement retains the draft and forbids another transfer.
A crash/uncertain push requires Git head/candidate reconciliation before a new operation;
there is no automatic push replay, merge, rebase, or force push. A panic/crash leaves the
persisted transfer marker and server expiry/restart cleanup rather than claiming immediate
completion. A successful completion response means cleanup queued, not deletion confirmed.
Poll cleanup until `removed` is observed before forgetting the seed. Old backups may
still contain encrypted seed copies; this is not a secure-erasure claim.

An absent lookup after a lost challenge response does not prove an in-flight server
request cannot finish. Cancellation retains the encrypted intent for later reconciliation;
the server's orphan intent expiry handles that case. Do not silently generate a second
operation/key while the first is unresolved.

## Validation and next wiring

Nine native tests cover encrypted reopen, all retained bindings, wrong device, expired
proof/lease, lost replies, unknown registration, no transfer replay, custody failure,
tampered ciphertext, bounded HTTP/CSRF/public-only requests, repeated password callbacks,
real system-agent Ed25519 signatures, local agent key expiry, cleanup after job failure
and scoped process/socket removal. Account tests additionally cover own-session operation
lookup, non-bearer context and cross-session denial. See
[recorded evidence](testing/native-git-lease-client-2026-10-31.json).

Next: protected platform custody for actual device identities and drafts; a pinned-host
Git runner and two-client conditional-update/reconciliation tests; disposable hosted
permission trials; browser/QR/status UI. Production biometric enforcement, shared-vault
authorization, cryptographic device removal/rotation and explicit Git-authority migration
remain separate release gates.
