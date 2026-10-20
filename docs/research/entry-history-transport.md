# Experimental history transport contract

Status: core wire contract, durable journal with entry deltas, account-authorized
HTTP routes, and native CLI index-history sync implemented behind
`experimental-entry-format`. HTTP additionally requires `PETIKA_EXPERIMENTAL_ENTRIES=1`.
Migration, entry edit/submission CLI, wrapper/epoch changes, entry Git replication,
and production deployment remain unavailable. Do not populate a fake entry journal
from whole-vault snapshots: their formats and trust contexts differ.

## Request and response

`HistoryRequest` contains version 1, exact collection/epoch `context`, an `after`
cursor (`revision`, canonical head `digest`), optional `target` cursor, and `limit`
from 1 to 32. The initial `after` must come from the client's local pin. Subsequent
pages retain the first response's target. Strict request parsing is limited to
4 KiB. Counters, IDs and contexts use existing canonical format rules.

`HistoryPage` contains version 1, the same context and `after`, a `target`, and an
array of `{head, envelope}` items. `envelope` preserves the exact encrypted-index
JSON text; do not parse/reserialize it before verifying its hash. Response parsing
rejects raw input above 32 MiB, unknown/duplicate fields, changed request context,
changed pinned targets, invalid cursors, broken parent links, nonadjacent revisions,
wrong envelope hashes and invalid empty pages. The sum of compact head bytes and
raw envelope bytes is capped at 16 MiB; count is bounded by the request limit.
The raw wire cap includes JSON escaping overhead.

A response can contain fewer items than requested to respect the byte budget.
It must make progress unless `after == target`. The last item cannot pass the
target; at the target revision its digest must equal the pinned target digest.
`next_request` derives the next cursor and retains the target. Call it for progress
only after the page has been authenticated and durably accepted. A target first
reported by the server is a pagination boundary, not an independent freshness pin.

## Client acceptance

`HistoryPage::verify` authenticates/decrypts each index using the existing adjacent
history validator. It requires the supplied previous index to match `after` and
its root key. Public metadata validation alone does not authenticate index contents.

`CheckpointStore::accept_history_response` additionally requires the previous
index to equal the locked local head and persists the final verified head before
returning. Invalid pages and stale retries leave the pin unchanged. Empty pages
return `None` and never move the pin. They mean only that the server reported the
requested cursor as its target; they do not prove no newer state exists.

The HTTP transport must enforce the raw response cap while reading, before
buffering the complete body. This API validates already buffered bytes and does
not implement an HTTP reader. WASM callers must provide their own durable pin
storage; native callers use the existing atomic storage protocol. After uncertain
write outcomes, reload/reconcile the pin rather than resetting trust.

## Server builder

`petika_server::entry_history::build_page` takes a validated request, a captured
current cursor and a committed-record reader. It checks base, target and current
against that read view, retrieves adjacent records up to the count/byte budget,
and returns a validated bounded JSON response. A missing or pruned record is an
error, not permission to skip forward. Later pages retain their original target
even if the current head advances in the same epoch. Epoch changes require the
separate rotation/handoff protocol.

The caller must authorize collection access before using the builder, bind the
requested context to that collection, enforce bounded record reads, and provide
a stable committed read view. The builder itself is not an authorization boundary
or journal implementation. Server data remains ciphertext-only; the builder cannot
validate encrypted index semantics. A malicious server can withhold newer data,
so clients must not turn a reported target into a global-freshness claim.

Tests exercise server construction through strict wire parsing and durable client
acceptance over multiple pages/restart, fixed targets during concurrent advancement,
stale replay, missing records, wrong cursor/context, tampered envelopes, empty
skipping responses, duplicate fields and size/count limits. CI runs tests and
Clippy with the feature enabled; default builds have no new endpoint.

## Committed journal

`petika_server::entry_journal::Journal` holds an exclusive root lock for its entire
lifetime. Opening a second handle fails. Records are immutable, content-addressed
JSON containing an encrypted index/head, changed entry ciphertexts and delete
preconditions, a parent-record address, and a writer-scoped operation receipt.
Unchanged entry ciphertexts are referenced through committed ancestry, never resealed
or copied into the next record. The record is an immutable transaction bundle;
there is no separately published entry-object directory. Record publication uses file sync, atomic rename, and directory
sync before the committed root pointer is replaced using the same protocol. Only
the root's verified ancestry is readable; no directory scan promotes orphan records.

Append compares the complete expected cursor, requires adjacent same-context heads,
and prohibits access-set or membership changes pending the rotation transaction.
The journal computes a request digest over the expected cursor, writer, operation
and candidate index plus entry deltas, including exact envelope text. Empty-delta
requests retain the original index-only digest encoding for existing journal records.
Exact retries return the original
receipt; changed submissions under the same writer/operation are rejected. Historical
records and receipts are retained, bounded by 1,024 records and 64 MiB of serialized
committed records. Quota exhaustion rejects the next append, without pruning.
Each individual record also inherits the storage layer's 16 MiB serialized limit.
This small in-memory journal is experimental, not an unlimited production backend.

After an uncertain root publication the handle refuses further writes/history reads;
drop and reopen it to reconcile the root before retrying. Metadata accessors on that
handle may still describe its last known state and must not be used as reconciliation.
The storage directory and its ancestors must be provisioned durably before use.
Process-exit tests cover all eight write/sync/rename/directory-sync boundaries for
record and root publication. These demonstrate process-crash recovery, not physical
power-loss behavior or all T08/T09 release criteria. Restart also verifies every
reachable record hash, parent link and receipt before serving history. Missing or
corrupt committed ancestors fail closed.

`Journal::transact` checks bounded public index/entry envelopes, revisions, contexts,
duplicate IDs, expected previous entry revision/digest and permanent tombstones.
`Journal::entry` resolves an ID and exact digest at a committed cursor, including old
reader roots. It rejects deleted, absent, mismatched and mixed-root ciphertexts.
It cannot validate encrypted names, index completeness or encrypted tombstones;
unlocked clients must verify these. No snapshot is imported or converted.

## Account HTTP boundary

All entry routes use POST JSON with the existing session/CLI authentication,
`X-Petika-Request: 1` and same-origin request checks. There is no single-account
bootstrap-bearer access. Routes require an already initialized journal at
`collections/{id}/entries`; initialization and migration are not exposed.
An existing `snapshot.json` rejects entry requests, preventing implicit cutover.
Conversely, a committed entry root rejects legacy snapshot/delivery requests with
426 after authorization, including in default server builds. Collection `status`
advertises `entry-v1`, supported capabilities, runtime gate state and unavailable
migration/replication. Capability support does not grant write permission.

| Suffix under `/v1/collections/{id}/` | Request | Response |
| --- | --- | --- |
| `entry-history` | `HistoryRequest` (4 KiB) | Bounded `HistoryPage` |
| `entry-object` | `{context,root,id,digest}` (4 KiB) | Exact encrypted envelope |
| `entry-receipt` | `{context,operation}` (4 KiB) | Current writer's receipt |
| `entry-transactions` | `{version:1,operation,expected,object,changes}` (12 MiB) | `{receipt,replication:"unavailable"}` |

`changes` contains at most 256 tagged puts/deletes. A put is
`{action:"put",id,expected,revision,envelope}`; expected is null for creation or
`{revision,digest}` for replacement. Delete is
`{action:"delete",id,expected:{revision,digest}}`. Deleted IDs are permanently
reserved (4,096 total live/deleted IDs). The committed delete records preserve the
prior digest/revision and deletion collection revision; clients must require the
matching authenticated index tombstone with final entry revision = prior + 1.

The server checks access before reading journal state, then acquires the journal
lock, authenticates again, and holds the account database lock through the operation.
Writes require edit permission, unchanged membership generation, and no required
group rotation. Context must bind both deployment and collection. Receipt lookup
is writer-scoped and requires current read access. Non-access validation/storage
failures use a generic 409 response: preserve drafts and reconcile receipts; no
rollback or retry under a new operation ID is implied. The server caps request
reads before buffering them in full. Nothing reports remote Git completion.

## CLI confirmation and resumable index sync

Compile the CLI with `--features experimental-entry-format`. `petika entries trust`
requires a local signed checkpoint, its independently compared digest and authority
fingerprint, the matching encrypted `HistoryObject`, a recovery wrapper and an
explicit `--confirm`. It creates a new pin and never replaces an existing one.
It does not establish global freshness, prove absence of forks, or perform migration.
Recovery-wrapper passphrases remain local. Unlock checks the pinned root commitment
and requires the exact recovery wrapper in the authenticated active wrapper set;
another valid wrapper for the same key is not a fallback. Recipient-wrapper CLI
unlock is pending.

```sh
petika entries trust --checkpoint checkpoint.json \
  --checkpoint-digest '<independently-confirmed-digest>' \
  --authority-fingerprint '<independently-confirmed-fingerprint>' --confirm \
  --index anchor.json --recovery recovery.json --pin pin.json --cache encrypted-index-cache

petika entries sync --collection personal --anchor anchor.json \
  --recovery recovery.json --pin pin.json --cache encrypted-index-cache
```

Sync reads at most 32 MiB plus one rejection byte from the HTTP reader, verifies each
page, caches its immutable encrypted indexes **before** advancing the durable pin,
and keeps the first response's target throughout that run. After a lost response,
restart from the saved pin and corresponding cached index. An empty page leaves
the pin unchanged. Missing or corrupt pinned cache requires restoring the exact
encrypted index from backup; the command never resets trust. Keep the anchor,
recovery wrapper, pin and cache backed up, and provision their directories durably.
This command synchronizes authenticated index history only, not entry payloads,
wrappers, drafts or remote Git state. A retained server journal alone is not a
complete offsite recovery path.

Remaining release gates include migration/cutover and compatibility scenarios,
encrypted edit drafts and receipt-confirmed CLI submission, wrapper/epoch
transactions, ordered Git replication/restore, physical durability/disk-full testing,
and broader native/WASM interoperability. Default enablement remains off.
