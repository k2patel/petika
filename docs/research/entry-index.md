# Experimental index validation and local pins

Status: opt-in core prototype, not independently reviewed or connected to clients,
API transactions, Git publication or existing vault migration.

`entry_format::index` now opens an encrypted index against a public `Head`, hashes
exact envelope bytes and validates the decrypted schema before returning an opaque
`VerifiedIndex`. A verified index authenticates content, not freshness. First trust
requires matching an independently pinned signed checkpoint. Subsequent ordinary
heads must extend the locally accepted head by exactly one revision and its digest.

The schema uses arrays with explicit duplicate-ID checks. The empty folder ID is
the implicit root. Names are exact UTF-8, 1–4096 bytes, without NUL; slash is literal,
not a path separator. Folder/entry siblings cannot share an exact name. There is
no normalization or case folding. All folder, live-entry and tombstone IDs are
unique across the index; folders must have existing parents, no cycles and at most
128 named ancestors including themselves. Total records are limited to 10,000,
and decrypted JSON remains limited to 2 MiB. Unknown/duplicate struct fields fail.

Ordinary updates retain context, root commitment, membership and wrapper set.
Changed ciphertext increments the entry revision once; unchanged ciphertext keeps
its revision even on rename/move. New entries start at one. Deleted entries produce
an exact tombstone with the previous ciphertext digest, next entry revision and
current deletion commit. Tombstones cannot be removed, rewritten or resurrected.
Epoch transitions use separate authority proofs; they do not yet prove preservation
of the previous epoch's entries/tombstones. That is a migration integration gate.

`verify_objects` checks exact live-object coverage and decrypts every referenced
envelope. Opening the index alone cannot detect unavailable blobs. Deleted historical
payloads are not required for current restore. Entry payload schemas remain the
caller's responsibility. Decrypted index structs intentionally omit Debug, but
names are ordinary Rust strings and are not guaranteed zeroized on drop.

## Head digest encoding

Using the existing `field(bytes) = u32be(length) || bytes` convention:

```text
field("petika:entry-head:v1") || u32be(1) ||
field(deployment_id) || field(collection_id) || u64be(key_epoch) ||
field(raw_epoch_salt) || field(suite) || field(parent_digest) ||
field(index_digest) || field(wrapper_set_digest) ||
u64be(revision) || u64be(membership_generation)
```

SHA-256 of these bytes becomes lowercase hex. Revision one has an empty parent;
all later revisions require a digest. The index repeats head context, suite,
revision, parent and membership, with explicit wrapper references whose set digest
must match. It does not embed its own ciphertext digest, avoiding a hash cycle.
Independent stdlib Python vectors now cover genesis, a successor and the maximum
counter. CI regenerates them; Rust checks the resulting head digests.

## Native checkpoint store

`CheckpointStore` holds the existing `StoreFile` exclusive lock across read,
verification and write. Initialization requires an already trusted checkpoint and
its verified index, and cannot overwrite a file. Public metadata only is persisted:
signed checkpoint plus highest accepted head. No names, entry plaintext or keys.

Ordinary updates require the caller's decrypted previous index to match the stored
head exactly, then validate the next index before atomic replacement. Epoch updates
verify the authority transition using the **stored** highest revision, and match
the newly decrypted index to its new checkpoint. Missing/corrupt files fail closed;
there is no automatic trust reset. Unix files must be private regular files;
writes sync a same-directory temporary file, rename, then sync the directory.

The protected local filesystem is a trust boundary. An attacker who can replace
local state, or restoring an old device backup, can roll back that anchor. This is
not hardware monotonic storage or universal fork detection. Callers must persist
before exposing accepted results; a write error after rename has an uncertain
outcome and requires reopening/reconciliation, never blind reset or retry.

Tests cover malformed authenticated indexes, duplicate IDs, missing parents,
cycles, sibling collisions, missing/tampered objects, entry revision consistency,
rename, deletion, tombstone retention, exclusive locking, no-overwrite bootstrap,
stale update rejection, restart persistence, an abandoned temporary file and
corrupt-file refusal. The abandoned-file test simulates pre-rename interruption;
it is not power-loss testing. The shared storage unit tests additionally inject
errors after temporary write, file sync, rename and directory sync for creation
and replacement, verifying complete old/new records when reopened. Production integration, bounded
network catch-up integration, epoch content continuity and real process/power-loss
tests remain required.

## Bounded same-epoch catch-up

`history::verify_page` accepts 1–32 borrowed heads/envelopes, with a 16 MiB total
budget (compact serialized head plus exact envelope bytes). It validates budgets
before decryption, then verifies every adjacent index and semantic delta. Only
the previous and current decrypted indexes are retained internally. Empty pages,
skips, reordered heads, forks, altered ciphertext and epoch changes are rejected.

`CheckpointStore::catch_up` first checks the starting index against the local pin
and the root against the signed checkpoint. It writes only the final head after
all page checks succeed. A bad tail leaves the file unchanged. The returned index
can anchor the next page, including after reloading its encrypted envelope on
restart. A write error still requires reconciliation because rename may have
completed. No API response is itself a freshness anchor.

This is a core verification API, not an HTTP endpoint or client sync command.
Transport must enforce request/body size limits before allocation; the core budget
cannot undo an oversized response already buffered by its caller. Epoch catch-up
remains explicit via authority transitions and requires further content-continuity
work. Tests exercise page limits, skipped heads, invalid tails, atomic acceptance,
stale retries and restart continuation.
