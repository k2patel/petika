# Candidate native Git lease coordinator

Date: 2026-10-31. `petika-desktop` feature `experimental-git-client`, off by default.
This is a tested native library with pinned-host SSH fetch, not a product CLI, browser
bridge, or vault unlock.
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

## Temporary SSH agent and pinned-host fetch

On Unix, public `Operation::fetch` uses an internal transfer lifecycle that records `transfer_started`, rechecks the owning session's
active status and expiry, then launches a new `/usr/bin/ssh-agent -D` with an empty
environment and a private temporary socket directory. It sends one constrained Ed25519
identity directly over the Unix socket using
[RFC 9987 sections 5.2.3 and 5.2.7](https://www.rfc-editor.org/rfc/rfc9987.html#section-5.2.3).
The packet contains the independent transport seed, never a device/authority signer.
Private buffers are zeroized; no SSH private-key file is written. Only the socket path
and standard public descriptor reach the internal Git runner. The generic callback seam
is now crate-private; callers use the typed fetch API.

The agent lifetime is capped by the remaining lease time, conservatively reduced by
monotonic elapsed time. Normal completion/error kills and waits for that agent before
requesting remote cleanup; unrelated agents and keys are untouched. A parent crash may
leave the isolated agent process until externally collected, but its key has a local
lifetime constraint. Local agent expiry does not enforce expiry on a remote deploy key.
Remote deletion still depends on the worker/provider; strict remote TTL requires a
certificate or lease-checking gateway. Caller-supplied `now` must come from the native
controller's trusted UTC clock, never a browser request.

`Scope.ssh_remote` retains the independently confirmed SSH hostname, port, username,
exact lease repository and canonical Ed25519 host public key before admission. The SSH
repository must match the lease's owner/repo. Older drafts without this optional field
can still reconcile/clean up, but cannot fetch. The endpoint cannot be substituted by
a server challenge. Management origins also reject embedded credentials, paths, query
and fragment before retention or transmission.

The runner uses a fresh known-hosts file containing only that host pin, strict checking,
an explicit public identity and the isolated agent. It ignores user/system SSH config,
disables password/PIN/keyboard-interactive/host-based/GSSAPI fallbacks and forwarding,
and does not reuse a control socket or learn/replace a host key. A changed host key fails;
there is no TOFU or `ssh-keyscan` trust ceremony. The controller must obtain the pin
independently before creating this scope. See [OpenSSH configuration](https://man.openbsd.org/ssh_config).

Git runs with an empty inherited environment, disabled global/system configuration,
no credential helpers/hooks/fsmonitor, SSH as its only allowed protocol, no tags or
submodule recursion, and an empty template. It fetches one validated branch into a new
bare repository at `refs/petika/fetched`, with depth 128 and SHA-1 object format, then
runs strict structural fsck and resolves a commit tip. It never checks out remote files,
executes their filters, merges, rebases or publishes. The returned `FetchedGit` owns that
temporary quarantine and removes it on drop; it does not update a shared cache or trusted
vault pins. Single-branch fetch is not a repository read ACL. See [Git fetch](https://git-scm.com/docs/git-fetch)
and [Git configuration](https://git-scm.com/docs/git-config).

A correct SSH pin and structural Git checks **do not authenticate vault contents**.
The application must independently verify the signed history, account/collection,
recipient policy, epoch and retained rollback pins before using fetched data. This
milestone adds no vault decryption or secret access and does not complete G01/G02.
A remote may supply arbitrary unverified objects; no ciphertext schema is trusted here.

Each job has a monotonic deadline capped at 30 seconds and the remaining lease time,
bounded stdout/stderr capture (8 KiB each), and its own process group, killed/waited on
completion or error. Children inherit a 16 MiB file-size resource limit. Polling checks
reject symlinks, more than 4096 filesystem entries, or observed aggregate files over
64 MiB. These checks tolerate Git's atomic lock/pack renames and run again at completion.
The aggregate budget can overshoot between polls; this is not a hard memory/CPU/disk
sandbox. Production process isolation and hostile-pack stress tests remain gates.
Raw remote stderr is not forwarded to users.

The candidate currently supports native Unix tools at `/usr/bin/git`, `/usr/bin/ssh`
and `/usr/bin/ssh-agent`, one Ed25519 host pin, SHA-1 Git repositories and the standard
`ssh://user@host:port/owner/repo.git` shape. HTTPS Git transport, host certificates,
alternate repository-path mappings, SHA-256 repositories and other platform adapters
remain work; unsupported cases must not silently fall back to unpinned transport.

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

The original nine native tests cover encrypted reopen, all retained bindings, wrong device, expired
proof/lease, lost replies, unknown registration, no transfer replay, custody failure,
tampered ciphertext, bounded HTTP/CSRF/public-only requests, repeated password callbacks,
real system-agent Ed25519 signatures, local agent key expiry, cleanup after job failure
and scoped process/socket removal. Account tests additionally cover own-session operation
lookup, non-bearer context and cross-session denial. See
[recorded evidence](testing/native-git-lease-client-2026-10-31.json).

The expanded suite has 15 passing tests, including one explicitly run local-sshd test
(normally ignored unless the required system tools/loopback permission are available).
Actual Git-over-SSH transfers generated authenticated ciphertext to a disposable bare
repository. Wrong host pin and wrong client key deny fetch and queue cleanup. Additional
checks cover retained endpoint reopen, repository/branch injection, inherited poisoned
Git configuration, shell quoting, real subprocess timeout, quotas and symlink denial.
The local test server uses a private generated configuration with StrictModes disabled
because its `/private/tmp` ancestor is writable; no system SSH service/configuration is
changed. Host-provider key deletion still uses the separate fake-host tests, not a live
provider. See [SSH fetch evidence](testing/pinned-ssh-fetch-2026-10-31.json).

Next: protected platform custody for actual device identities and drafts; signed Git
publication verification and exact-parent conditional push, including two-client
conflicts, branch deletion/recreation and lost acknowledgements; disposable hosted
permission trials; browser/QR/status UI. Production biometric enforcement, shared-vault
authorization, cryptographic device removal/rotation and explicit Git-authority migration
remain separate release gates.
