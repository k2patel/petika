# Experimental temporary Git SSH-key cleanup engine

Date: 2026-10-31. Implemented native engine in
`crates/petika-server/src/git_key_leases.rs`, behind `experimental-device-keys`.
GitHub/Gitea HTTP inventory/deletion adapters, an opt-in scheduler and durable account
session cleanup hooks are now wired. Authorized key registration is now implemented in the [registration contract](git-key-registration.md);
cryptographic device removal and native SSH custody remain pending. No real host keys have been registered or deleted by these tests.

## Ownership and complete inventory

Every temporary key registration must first persist a `prepare` intent with random
lease ID, configured repository/management origin, public-key fingerprint, device ID,
opaque non-bearer session reference and expiry. TTL is bounded to one hour. No private
SSH key or API credential belongs in the ledger. The remote key title is the exact
`petika-lease:v1:<lease-id>` marker. Adapters normalize the fingerprint to lowercase
SHA-256 hex over the public-key wire bytes.

Cleanup examines every retained lease, including removed tombstones. A key is owned only
if its repository, exact marker and fingerprint match the protected local ledger.
A prefix alone is not ownership; unrelated/permanent keys, including unknown prefixed
keys, remain untouched. A marker collision with different key material is a visible
failure. Unknown remote keys need explicit operator review; this engine does not silently
adopt them or erase them after loss of a ledger. Back up this metadata independently.

The host adapter must return complete paginated inventory and enforce deadlines,
authenticated host identity, scoped management permissions, stable non-reused remote
key IDs and safe ID encoding. Duplicate/empty IDs, incomplete pages and excessive counts
fail closed before deletion. Provider routing and credentialed redirects must not permit
scope substitution. The engine is tested with a deterministic in-memory host, and the HTTP adapters with
local fake GitHub/Gitea JSON endpoints. Actual hosted permissions and policy remain untested.

## Lifecycle

1. `prepare` durably records intent before remote registration. This permits discovery
   after a registration succeeds but its reply is lost.
2. `sweep(now, host)` visits all retained leases. Before remote deletion it persists
   revocation intent for expired leases. All matching managed copies are deleted.
3. Session end/completed operation calls `request_cleanup(Session(...))`; device removal
   calls `Device(...)`; an authorized revoke-all command uses `All`. The controller must
   authorize the selector and stop new registration for cancelled sessions/devices.
4. Cleanup confirms absence with a second complete inventory. A delete success response
   alone is insufficient. Failed keys retain error state and bounded exponential retry
   times; the next lease is still processed. Failures never resurrect or recreate keys.
5. Restart opens the same locked ledger and retries. Removed tombstones are still scanned:
   a delayed in-flight registration after cancellation is discovered and removed later.
   The worker cannot promise instantaneous denial during that delay.

`sweep` returning success means its ledger updates completed, not that all remote keys
are gone. Controllers must inspect each lease's `state`, `last_error` and `retry_at` and
surface pending/failed cleanup. Errors are fixed enum codes, never provider diagnostics
or credentials. Revocation intent remains durable across uncertain remote outcomes.

## Persistence and limits

`StoreFile` supplies exclusive locking, owner-only file creation, atomic replacement and
sync. Hold only the lease lock during a sweep, never account/journal locks across network
calls. The worker processes at most 32 leases per pass, retains a round-robin `cursor` in the
ledger across restarts and uses a 30-second host budget with 10-second request deadlines.
Large inventories can exhaust a pass and remain pending. Adaptive provider rate limiting
and per-repository inventory coalescing remain future work.

Strict bounded JSON has version 1 and up to 4,096 retained leases / 4 MiB. Corrupt or
ambiguous schema fails closed. No read failure resets state. Tombstones are not silently
pruned; quota exhaustion rejects new registrations before remote creation. Compaction
requires a separate late-registration/receipt retention design. Local filesystem control
is a trust boundary; the ledger is not a signed remote authorization proof.

## Expiry and security limits

Deleting ordinary deploy keys is cleanup-dependent expiry. Server outage, host outage,
permission loss, rate limits or clock problems can delay revocation. Strict TTL requires
a remote-enforced SSH certificate or a gateway checking the lease on every operation.
Deletion does not promise cancellation of an established SSH session or accepted Git push.
Host write grants may be broad; this engine does not impose branch/entry policy on them.
Vault keys and mandatory per-secret biometrics are independent of transport-key cleanup.

## Validation and next work

Engine and wiring tests cover every managed duplicate, preservation of unrelated/prefixed
keys, expiry, scoped session/device/all revocation, failure isolation, restart retries,
late registration after removal, uncertain deletion, incomplete inventory, fingerprint
collision, dishonest deletion acknowledgement, corruption and exclusive locking.
These are engine tests, not hosted GitHub/Gitea or real SSH integration evidence.

Next: authorized key registration tied to admitted devices/sessions and operation completion,
cryptographic device-removal integration, explicit status UI, unknown-key auditing, adaptive
rate limiting and actual-host validation. Never enable temporary key issuance before its
matching cleanup paths pass validation. See [architecture](architecture.md) and
[work plan](implementation-plan-git-biometric.md).

## Runtime configuration and adapters

The Cargo feature `experimental-device-keys` and runtime
`PETIKA_EXPERIMENTAL_GIT_KEY_LEASES=1` enable the cleanup wiring. Set
`PETIKA_GIT_KEY_HOSTS_FILE` to a protected operator configuration file. No setting is
enabled in production by this change. This opt-in starts cleanup only; it does not add
an endpoint for registering temporary keys or obtaining device-secret access.

Configuration JSON version 1 contains `hosts`, at most 32 entries. Each entry has:

| Field | Contract |
| --- | --- |
| `repository.provider` | `github` or `gitea`; generic managed SSH is not yet implemented |
| `repository.management_origin` | Exact allowlisted HTTPS API origin, e.g. `https://api.github.com/` or the Gitea origin; no embedded credential, query or fragment |
| `repository.repository` | `owner/repository`, matching the lease scope exactly |
| `api_prefix` | Empty for GitHub.com, `/api/v3` for a compatible GitHub Enterprise endpoint, `/api/v1` for Gitea |
| `token` | Protected management credential with repository-key list/delete authority; never put a real value in this repository |
| `auth_scheme` | `bearer` (default) or `token`, matching the host credential type; Gitea API personal tokens commonly use `token` |

On Unix the file must be a regular non-symlink file owned by the server UID, mode 0400
or 0600. Read-only mounts of regular private files work without a sidecar lock beside
the configuration. Install a private regular-file copy when the secret provider exposes
symlinks. Other platforms require equivalent operator-managed file access protections.
Input size is bounded to 64 KiB. Configuration and token buffers are cleared on release
where supported; HTTP library/OS copies are not an absolute zeroization guarantee.

The adapters use pinned configured repository scope and HTTPS certificate verification,
no environment proxy or redirects, a 1 MiB response cap and complete pagination through
an empty page. They continue even when a host returns fewer than 100 entries per page.
Duplicate IDs, malformed keys, non-success responses and pagination exhaustion fail
closed. Deletion accepts 200/204/404 only, and the engine subsequently verifies absence.
No credentials appear in arguments, durable lease state, provider diagnostics or logs.
Configuration reloads each pass so operators can rotate management credentials.

## Scheduler and event wiring

Startup validates configuration and acquires an exclusive worker lifetime lock before
queuing cleanup of every previous-process lease. Account sessions are process-local;
therefore their old transport access must not survive a server restart. This is a
single-server/session-owner configuration, not support for distributed account sessions
or multiple independent API replicas. A second cleanup worker on the same directory
fails startup before revoking the first worker's leases.

The worker runs every five seconds under the maintenance/backup gate. It first drains
up to 128 durable events from `git-key-events.json`, then sweeps its lease budget.
Session logout, session revocation, observed expiry, account disablement and password
change queue non-bearer session IDs before removing affected in-memory sessions. A
password change preserves the caller's selected current session. Queue persistence
failure fails the account operation; logout does not report success or clear its cookie
when queueing failed. Because the queue precedes account publication, a later account
storage failure may conservatively revoke transport access even if the account change
fails. Retry/re-authentication must remain explicit.

The queue is strict versioned JSON with at most 4,096 deduplicated session/device events.
Revocation intent is committed to the lease ledger before an event is removed; replay
is harmless after an uncertain queue write. Corrupt state is retained and reported,
never reset. Queue locks are released before network calls, so logout does not wait on
a host inventory/deletion request. Lease locks may remain held for a bounded pass.
The backup gate can delay capture during that pass. No account lock is held by the
worker while calling a host.

A typed `enqueue_device` hook is available for future authorized cryptographic device
removal. That removal API is still blocked pending session/package/rotation integration;
the existing client-session revocation route is the currently connected control.
Registration must use the server's non-bearer session ID and verify current admission;
no caller-selected bearer token may be placed in lease metadata. Operation-completion
cleanup is a future registration/sync-controller call to the same session/lease lifecycle.

Any persisted remote failure makes the worker report a generic pending-cleanup diagnostic;
per-lease `last_error` and `retry_at` remain in the private ledger. There is no status UI
in this milestone. Timed deletion still depends on a live authorized worker and reachable
host; strict remote TTL requires the certificate/gateway design described above.

Validation evidence: [2026-10-31 wiring checks](testing/git-key-cleanup-wiring-2026-10-31.json).

## Registration extension

[Authorized registration](git-key-registration.md) now persists the exact device/SSH
challenge before host creation, reserves `registering` before its sole create attempt,
and connects explicit per-lease completion to cleanup. Wrong permissions on an owned
authorization cause revocation. Backend host policy adds `owner_user_id`, `allow_write`
and `max_lease_seconds`; absent owner assignment remains cleanup-only. Native SSH use
and actual-host validation remain open; no live keys were changed.

The subsequent [native client coordinator](native-git-lease-client.md) durably records
transfer/cleanup intent, reconciles its own operation ID after lost replies and retains
an encrypted private-key draft until removal is observed. Its isolated-agent seam is
tested with generated data; production custody and pinned-host Git execution remain open.
