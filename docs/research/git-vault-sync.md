# Git-backed encrypted vault synchronization

Status: requirements clarified on 2026-10-18; design proposal, not implemented.

## User-requested behavior

Git is part of the normal vault workflow, with a configurable GitHub/Gitea remote.
Users choose synchronization on changes, on a schedule, or manually. A vault's
logical folder structure and entries are encrypted and replicated. Normal edits
should update only the affected encrypted entries and necessary metadata, rather
than replacing the entire encrypted collection.

Whether changes from other Git clients must be imported is still an open decision.
Do not assume that outbound backup replication and two-way synchronization are the
same feature. GitHub Actions is also not assumed to be the required scheduler:
"on changes" can be handled by the Petika service or CLI after an accepted save.

## Existing implementation

The API accepts revision-checked whole-collection encrypted snapshots and maintains
local Git history. The homelab `deploy/homelab/mirror.sh` sidecar pushes that history
every 60 seconds using fast-forward-only pushes. The remote has collection-specific
branches. This is outbound recovery replication, not a configurable two-way Git
backend. CLI pull/push is explicit; local show does not fetch live API data.

Re-encrypting a whole snapshot changes ciphertext broadly. Git object transfer does
not make this an efficient per-entry update format. Do not describe the existing
snapshot mirror as incremental encrypted-entry synchronization.

## Proposed storage model

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

A durable queue should coalesce edits, retry transient failures and survive restarts.
The server can push encrypted objects without vault-decryption keys. Git credentials
remain separate from vault keys and API tokens. Repository writers must be authorized;
if several users share a repository, Git access itself is not per-user vault ACLs.
A repo-scoped credential granting read access can expose all ciphertext in that repo.

For two-way sync, define the source of truth and synchronization protocol first:
fetch before publishing, track a common base, detect changes per entry, retain both
versions on conflicts, and never force-push away remote history. The server cannot
merge plaintext fields without decryption keys; resolution belongs in an unlocked
client. Specify commit authenticity, recovery/key-wrapper distribution, membership
changes, stale clients and key epochs before allowing remote imports.

GitHub Actions could optionally orchestrate work after events or on a schedule,
but a runner still needs authenticated access to the source. No workflow needs a
vault passphrase merely to replicate ciphertext. Scheduling must not be treated as
an exact-time durability guarantee.

## Delivery sequence

1. Resolve outbound-only versus two-way behavior, repository ownership, and which
   component accepts authoritative writes. Specify live CLI reads versus explicit
   offline/local operations alongside this decision.
2. Specify and review the encrypted entry/index format and a reversible migration
   from current snapshots. Retain the current restore path until a new round-trip
   recovery test passes.
3. Implement and test entry-level changes, encrypted folder metadata, deletions,
   conflicts, interrupted writes, key rotation, access revocation and offline clients.
4. Add provider-neutral Git transport, durable queues, selectable triggers and status.
   Keep snapshot/full-server backup requirements distinct from synchronization.

See [current architecture](../architecture.md), [recovery](../recovery.md), and
[CLI behavior](../cli-accounts.md) for what is implemented today.
