# Experimental history transport contract

Status: core wire contract, native client acceptance adapter and server page builder
implemented behind `experimental-entry-format`. A committed index-history journal
is now implemented as a storage primitive. No HTTP route, entry payload transaction,
CLI sync command, migration or production deployment is enabled by this change.
The existing snapshot API remains unchanged. Do not populate a fake entry journal
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

## Server builder and remaining integration

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

## Committed index journal

`petika_server::entry_journal::Journal` holds an exclusive root lock for its entire
lifetime. Opening a second handle fails. Records are immutable, content-addressed
JSON containing an encrypted index/head, a parent-record address, and a writer-scoped
operation receipt. Record publication uses file sync, atomic rename, and directory
sync before the committed root pointer is replaced using the same protocol. Only
the root's verified ancestry is readable; no directory scan promotes orphan records.

Append compares the complete expected cursor, requires adjacent same-context heads,
and prohibits access-set or membership changes pending the rotation transaction.
The journal computes a request digest over the expected cursor, writer, operation
and candidate index, including exact envelope text. Exact retries return the original
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

This primitive does **not** accept entry payload deltas, validate encrypted index
contents, persist wrapper changes, authorize accounts, or replicate Git. Its opaque
index bytes must still be decrypted/authenticated by clients. No snapshot is imported
or converted. It is not yet the complete entry transaction backend required by T01–T14.

Next gate: entry-object storage and public delta/precondition validation under the
same atomic publication, followed by account-authorized HTTP routing and bounded
CLI transport. Migration and confirmation/recovery UX remain pending. No client Git
writes or ciphertext merge behavior will be added.
