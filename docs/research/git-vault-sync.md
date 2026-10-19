# Git-backed encrypted vault synchronization

Status: requirements clarified on 2026-10-18; implementation in progress. The
entry-granular format and selectable Git triggers remain unimplemented.

## User-requested behavior

Git is part of the normal vault workflow, with a configurable GitHub/Gitea remote.
Users choose synchronization on changes, on a schedule, or manually. A vault's
logical folder structure and entries are encrypted and replicated. Normal edits
should update only the affected encrypted entries and necessary metadata, rather
than replacing the entire encrypted collection.

All clients use the Petika API for managed vault reads and writes. The API is the
single write authority, and the Petika service is the sole writer to the vault's
Git backend. Clients never push directly to Git. Normal synchronization is outbound;
importing remote history is an explicit recovery operation, not two-way sync.
GitHub Actions is not required: the service can trigger replication after an
accepted save or on the configured schedule.

```text
Web / extension / CLI (encrypt and decrypt locally)
                     |
                     v
Petika API (authorize, check revisions, durably accept changes)
                     |
                     v
Serialized Git writer -> GitHub / Gitea remote
```

API authentication permits access; local vault unlocking permits decryption. A
client does not need Git credentials. Optional local caches/offline drafts must
return through the same revision-checked API before becoming accepted changes.

## Existing implementation

The API accepts revision-checked whole-collection encrypted snapshots and maintains
local Git history. The homelab `deploy/homelab/mirror.sh` sidecar pushes that history
every 60 seconds using fast-forward-only pushes. The remote has collection-specific
branches. This is outbound recovery replication, not a configurable two-way Git
backend. CLI `--collection` reads and writes use the API with local passphrase or
recipient-identity unlock; writes preserve encrypted drafts on conflicts or uncertain
acknowledgements. Commands without `--collection` remain local; pull/push is explicit.

### Implementation gap checklist

- [x] API-authorized, revision-checked snapshot writes and durable journal.
- [x] Local Git mirror serialization and fast-forward-only homelab remote pushes.
- [x] Live CLI passphrase-based `show --collection`, with no stale local fallback.
- [x] Live recipient-identity unlock and managed CLI snapshot mutation transactions,
  with encrypted draft preservation and no automatic stale-write retry.
- [ ] Entry/index format, authenticated deletion and migration/restore validation.
- [ ] Per-entry revisions with atomic shared-index changes and preserved stale drafts.
- [ ] Provider-neutral remote configuration and selectable replication triggers.
- [ ] Durable remote replication status, retry handling and divergence reporting.
- [ ] Validate single-writer enforcement and crash consistency end to end; do not
  infer multi-replica support from local file locks.

See the [full software diagram](../architecture.md#full-software-diagram) for
current components and planned boundaries.

Re-encrypting a whole snapshot changes ciphertext broadly. Git object transfer does
not make this an efficient per-entry update format. Do not describe the existing
snapshot mirror as incremental encrypted-entry synchronization.

## Proposed storage model

The [entry format and transaction specification](encrypted-entry-format.md) and
[acceptance matrix](../testing/encrypted-entry-format.md) now detail this proposal.
They are not implemented or independently reviewed. The first version retains a
collection-wide encrypted-index CAS: per-entry files reduce ciphertext churn, but
do not yet eliminate conflicts between different-entry edits.

- Keep stable opaque identifiers for collections, folders, and entries. Never use
  plaintext website names, usernames, or folder names as Git paths.
- Encrypt each entry independently with fresh nonces on writes. An authenticated,
  encrypted index describes the logical folder tree and entry revisions; Git's
  physical directories need not expose that tree.
- Authenticate collection ID, entry ID, format version, revision and key epoch as
  part of the format. Specify rollback and substitution defenses before coding.
- A normal edit changes its entry ciphertext and required index/commit metadata.
  Unchanged entries retain their ciphertext. Deletions need explicit authenticated
  records so an offline client cannot silently resurrect a removed entry.
- Folder changes affect the index. Key rotation or a format migration may require
  many/all entries to be rewritten; do not promise entry-only updates in those cases.
- Git can still reveal object counts, approximate sizes and change timing. Hiding
  plaintext folder names is not complete metadata privacy.

## Sync controls and service responsibilities

Expose remote, branch, sync mode (on changes / scheduled / manual), interval,
last successful remote commit, pending changes, errors and Retry. Distinguish local
save, API acceptance and successful remote replication in the UI and CLI.

A durable queue should coalesce replication work, retry transient failures and
survive restarts without dropping accepted revisions. API acceptance and enqueueing
must be crash-consistent. A Git outage leaves accepted saves durable and visibly
pending replication, rather than reporting them as remotely synced.
Serialize writes per repository/branch, including across service replicas and
retries; use idempotent operations and preserve accepted revision ordering.
The server can push encrypted objects without vault-decryption keys. Git credentials
remain separate from vault keys and API tokens. Repository writers must be authorized;
if several users share a repository, Git access itself is not per-user vault ACLs.
A repo-scoped credential granting read access can expose all ciphertext in that repo.

Concurrent clients can still edit the same entry. Require an expected revision on
every mutation and reject stale writes before acceptance; never silently overwrite
or merge ciphertext. Preserve the client's draft so it can fetch the latest state
and explicitly resolve the edit after unlocking. Independent entry edits should
not conflict unnecessarily; changes to the encrypted shared index require their own
transaction/revision checks. Define those checks in the format and API protocol.

Push fast-forward-only. Unexpected external remote commits stop replication and
surface an actionable error; never auto-merge or force-push. Restrict remote write
credentials to the service. Explicit recovery/import must validate authenticity,
key epochs, membership and rollback policy before restoring authoritative state.

GitHub Actions could optionally orchestrate work after events or on a schedule,
but a runner still needs authenticated access to the source. No workflow needs a
vault passphrase merely to replicate ciphertext. Scheduling must not be treated as
an exact-time durability guarantee.

## Delivery sequence

1. Implement the agreed API-authoritative protocol: managed CLI operations use the
   API, with explicit local/offline behavior. Define revision checks, repository
   ownership, serialized writes and durable replication status. Existing local CLI
   commands must not silently change meaning during migration.
2. Specify and review the encrypted entry/index format and a reversible migration
   from current snapshots. Retain the current restore path until a new round-trip
   recovery test passes.
3. Implement and test entry-level changes, encrypted folder metadata, deletions,
   conflicts, interrupted writes, key rotation, access revocation and offline clients.
4. Add provider-neutral Git transport, durable queues, selectable triggers and status.
   Keep snapshot/full-server backup requirements distinct from synchronization.

See [current architecture](../architecture.md), [recovery](../recovery.md), and
[CLI behavior](../cli-accounts.md) for what is implemented today.
