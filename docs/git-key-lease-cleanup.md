# Experimental temporary Git SSH-key cleanup engine

Date: 2026-10-31. Implemented native engine in
`crates/petika-server/src/git_key_leases.rs`, behind `experimental-device-keys`.
Registration/network adapters, scheduler and account logout/device-removal wiring remain
pending. No real host keys have been registered or deleted by these tests.

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
scope substitution. The engine interface is tested with a deterministic in-memory host;
actual HTTP schemas and host policy have not been validated here.

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
calls. Production workers require bounded work budgets and per-host rate limiting;
per-repository inventory coalescing and fairness remain integration work.

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

Nine targeted tests cover every managed duplicate, preservation of unrelated/prefixed
keys, expiry, scoped session/device/all revocation, failure isolation, restart retries,
late registration after removal, uncertain deletion, incomplete inventory, fingerprint
collision, dishonest deletion acknowledgement, corruption and exclusive locking.
These are engine tests, not hosted GitHub/Gitea or real SSH integration evidence.

Next: connect authorized registration and the durable worker scheduler, implement and
validate actual host adapters, make logout/removal queue cleanup atomically, expose status
and audit unknown keys, and test deadline/rate-limit/partial-page/restart behavior against
real disposable repositories. Never enable temporary key issuance without cleanup wiring.
See [architecture](architecture.md) and [work plan](implementation-plan-git-biometric.md).
