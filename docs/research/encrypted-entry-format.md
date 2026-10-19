# Encrypted entry format and atomic API transactions

Status: **proposed, not implemented or independently reviewed**, 2026-10-18.
The API-authoritative workflow is agreed; the format below is a review candidate.
No existing vault, wrapper, API route or Git tree changes as a result of this document.
Acceptance criteria are in [the validation plan](../testing/encrypted-entry-format.md).
An [opt-in core primitive prototype](entry-format-prototype.md) now implements
strict object headers, entry/index AEAD and an explicit recovery wrapper. The full
format and migration remain unimplemented; the prototype encoding is experimental.
An [identity-authorized checkpoint/recipient extension](entry-checkpoints.md) now
implements explicit epoch proofs; persisted pins and full index/history continuity
remain integration gates.

## Scope and invariants

Clients encrypt, decrypt and edit. The API authenticates users, checks collection
permissions and expected state, and accepts transactions. Petika is the sole Git
writer. Git is an outbound history/replication backend; recovery is explicit.

A successful edit changes one entry object, the encrypted index and transaction
metadata. Unchanged entry objects remain byte-identical, including their nonces.
Folder-only changes need not rewrite entry payloads. Rotation can rewrite every
object. Full-server backup remains necessary for accounts and configuration.

Do not advertise independent-entry concurrency in the first version: a complete
**encrypted index is the atomic collection root**. Two clients editing different
entries from the same root can still conflict. Per-entry counters detect what
changed; they do not authorize replacement of a stale index. A later design may
partition the index, but must solve authenticated completeness and atomic folder
operations before removing collection-wide compare-and-swap.

## Proposed objects and layout

Keep format version separate from account schema, HTTP version, key-package version,
and legacy snapshot schema. Reserve `entry_format_version = 1` as a proposal only;
do not overload the current envelope v1/v2 parsers or label this an accepted v3.

```text
head.json                       public commit descriptor
index.enc                       authenticated encrypted index
access/<opaque-wrapper-id>.json  encrypted root-key wrappers, public context only
entries/<opaque-entry-id>.enc    independent authenticated encrypted records
```

This is a logical committed Git tree/export layout, not a mutable-directory API
storage implementation. Native storage must publish a consistent root pointer as
described below. No plaintext path names, usernames, websites or OTP data in filenames,
commit messages, API paths or diagnostics. Object IDs are 32 CSPRNG bytes encoded as
64 lowercase hex characters; folder IDs follow the same rule. Never derive IDs
from names, URLs or user passwords. IDs survive rename/move and ordinary rotation.

| Object | Public fields | Encrypted content |
| --- | --- | --- |
| Head | Format, data suite, deployment/collection IDs, epoch, epoch salt, commit revision, parent digest, index-envelope digest, active-access-set digest, head digest | None |
| Index envelope | Context, kind `index`, revision, nonce, ciphertext | Entries, folders, tombstones, wrapper references and authenticated commit context |
| Entry envelope | Context, kind `entry`, entry ID, entry revision, nonce, ciphertext | Existing username/password/URL/notes/optional OTP fields |
| Access descriptor/wrappers | Explicit wrapper version/profile, context, wrapper ID, bounded KDF/KEM parameters and ciphertext | Versioned root-key material |

Index plaintext contains:

- The same deployment, collection, epoch, data suite, commit revision, parent digest
  and active-access-set digest as the head.
- A folder map: opaque folder ID, parent ID (or root), and exact display name.
- A live-entry map: opaque entry ID, exact display name, folder ID, entry revision
  and SHA-256 digest of the complete serialized entry envelope.
- A tombstone map: deleted entry ID, final entry revision, deletion commit revision
  and prior live-envelope digest. Deleted IDs are never reused in this format.
- Explicit schema version and a root-folder identifier; no unknown implicit defaults.

Validate unique IDs, unique logical paths, existing parents, no folder cycles, no
live/tombstone overlap, positive bounded counters and complete live-object coverage.
Each live entry appears exactly once. Name/path equality must be identical across
native and WASM clients; preserve exact existing names without Unicode normalization
or case folding during migration. Freeze naming and serialization rules before code.

Tombstones remain in the encrypted index indefinitely in the first version. No
automatic compaction: removing them requires an explicit stale-client horizon and
restore policy. Historical Git commits retain removed ciphertext. Current HEAD need
not contain deleted payloads, and the previous digest in a tombstone does not make
that old payload a required dependency for restoring the current state.

Metadata still leaks: entry counts, stable opaque IDs, sizes, revisions, changes,
wrapper metadata and timing. The encrypted folder tree hides names and parentage,
not all access patterns. Account/group names and membership are existing server
metadata outside this vault format.

## Candidate cryptographic construction

Retain XChaCha20-Poly1305 for entry/index payload protection. Candidate suite name:
`xchacha20poly1305-hkdf-sha256-v1`. This is a Petika profile proposal, not a standard,
a compliance claim, or a substitute for cryptographic review.

Generate a fresh random 32-byte collection root key for each new format epoch.
Do not reinterpret an existing Hybrid X-Wing seed as this root key. Derive a
32-byte key for each object using HKDF-SHA256: Extract with an explicit random
32-byte epoch salt, then Expand with purpose/context-specific `info`. Index and
entry keys have separate domains; entry IDs distinguish entry keys. The epoch salt
is public and bound into wrapper context, object headers and the encrypted index.
This use of context binding follows [RFC 5869](https://www.rfc-editor.org/rfc/rfc5869.html);
exact profile bytes and independent vectors remain a release gate.

Use a fresh CSPRNG 24-byte nonce whenever an object is encrypted, including retries
that produce changed ciphertext. Never reuse a nonce intentionally or derive it
from a revision counter. Random nonces are supported by the extended nonce design
of [XChaCha20-Poly1305](https://doc.libsodium.org/secret-key_cryptography/aead/chacha20-poly1305/xchacha20-poly1305_construction).
An exact idempotent retransmission reuses existing ciphertext bytes, not a new
cryptographic operation. Unchanged objects are copied, not resealed.

Candidate canonical encoding follows the existing package convention:
`field(x) = u32be(byte_length(x)) || x`; text is UTF-8; IDs are lowercase hex ASCII;
versions are u32be; counters are u64be capped at 2^53−1. Object kind is explicit.
HKDF info includes, in order: versioned KDF domain, suite, deployment, collection,
epoch, object kind and object ID (empty for the single index). AAD includes a
separate versioned AEAD domain, those fields, epoch salt and object revision.
For the index, object revision equals the proposed commit revision; for entries it
is an independent strictly increasing counter. Nonces are AEAD inputs and included
in the hashed envelope. The suite fixes key, nonce and tag sizes.

Use strict JSON transport with canonical padded base64 for binary values. Reject
duplicate/unknown fields, noncanonical encodings, invalid counters and excessive
sizes before allocation/decryption. Hash **exact stored envelope bytes**; do not
parse and reserialize before computing a stored-envelope digest. Canonical head
and access-set digests use length-prefixed fields, not arbitrary JSON text ordering.
The access set is sorted by unique wrapper ID, with each wrapper's exact-byte digest.
Head digest covers all head fields except itself under a distinct versioned domain.

The client must authenticate the index before revealing any entry; check its head
bindings and validate every displayed entry's digest, header and AEAD. Listing
names needs only the verified index; full restore must validate every referenced
object. Missing objects are errors, never implicit deletion. Index counts and total
sizes must be bounded to prevent attacker-controlled work amplification.

### Wrapper and profile gate

Every enabled unlock path exposes the same epoch root key: recovery passphrase,
recipient/device packages and any explicitly configured organizational recovery.
Changing the data format cannot silently add a server-held decryption key or weaken
an existing profile. Wrapper headers/AAD must bind the new root-key payload type,
data suite, epoch salt, deployment, collection, epoch and wrapper profile/version.
The authenticated index binds the full active wrapper set; verify it after unlock.
No fallback to a different suite, old epoch, or unrequested recovery method.

Existing key-package v1 carries mode-specific material and authenticates the
snapshot envelope contract. **It cannot be copied unchanged into this format.**
Specify a new payload/profile binding and vectors, and assess recovery wrappers,
before enabling migration. Standard and experimental Hybrid collections keep their
current formats until their respective migration paths pass review. Do not silently
convert Hybrid to Standard. Reviewed ML-KEM device delivery and a validated-module
AES profile remain separate work; this proposal grants neither production status.

## API transaction contract

Proposed route family: `/v1/collections/{id}/entry-state` and
`/v1/collections/{id}/entry-transactions`. These routes do not exist today.
Discovery must advertise the format and read/write capabilities; older clients must
receive an explicit upgrade-required error, not a synthetic empty legacy snapshot.

Reads return one immutable head descriptor plus encrypted index/access references.
Fetch entry objects using that root and their exact digests, not an unversioned
"latest" path. Authorization is checked on each fetch. Pin an immutable read view
or return a retryable expired-view error; never combine objects from different roots.

Each mutation includes:

1. Random 256-bit operation ID, expected head digest/revision, expected key epoch,
   expected access-set digest and expected membership generation.
2. Proposed head/index/access changes; put/delete entry deltas containing expected
   prior entry revision/digest (or explicit absence for creation).
3. Proposed commit revision = current + 1; changed entry revisions = previous + 1,
   new entries = 1. Deletes produce a tombstone at previous entry revision + 1.
   Re-creation is a new ID after explicit user intent, not tombstone removal.

The API holds the single writer lock, rechecks authorization and all preconditions,
checks bounds/digests, verifies the proposed public delta and publishes atomically.
The server cannot verify encrypted names or index semantics. An unlocked client must
validate them; an authorized malicious writer can still submit unreadable ciphertext.
A server head hash is an integrity reference, not proof that the server decrypted or
cryptographically approved a transaction. Never disclose decryption keys for validation.

A fresh transaction either advances the whole root once or does nothing. A stale
head/index, entry, access set, epoch or membership returns a conflict. Do not rebase
ciphertext. Preserve the local encrypted draft; fetch and decrypt the new index and
ask the user to reapply the intended change. The first release retains today's
explicit conflict handling, even when edits affect different entry IDs.

Scope operation receipts by authenticated writer and collection. The same operation
ID and exact request digest return the original result only after current access is
checked; a different digest under the same ID is rejected. Atomically persist the
receipt with acceptance. Retain receipts for the lifetime of this experimental
format (quota-limited); no arbitrary retry expiry or silent receipt GC. After losing
an acknowledgement, query the receipt before any new submission. A status query
must not expose another user's transaction or disclose revoked collection contents.

Return accepted head/revision, operation ID/digest and replication-pending status.
Validate the acknowledgement against the candidate before deleting the local draft.
API acceptance and remote Git success are distinct statuses.

## Persistence and Git ordering

Start with the existing single-instance-per-data-directory restriction. File locks
are not a multi-host distributed lock. Multiple replicas need a separately reviewed
transactional coordinator; do not claim support with a local lock alone.

Stage immutable encrypted objects, index and candidate commit/receipt in a private
transaction directory. Flush objects and directories, then atomically replace and
sync the committed root pointer under the writer lock. Only the committed pointer
and its ancestor chain authorize visible state and mirror work. Orphan staging
records never become accepted merely because they exist. Recovery after restart
walks committed ancestry; cleanup must not delete reachable objects or active reads.

The committed transaction chain is the durable replication queue. The Git writer
replays every accepted revision in order and records an atomic local checkpoint.
Coalescing remote network pushes may send several commits together, but cannot drop
intermediate accepted history. A crash between Git commit and checkpoint must be
idempotently recoverable. Each commit tree has only the current logical layout;
ordinary edits must preserve unchanged entry blob IDs.

Remote pushes remain fast-forward-only. Divergence stops replication and surfaces
an error; neither clients nor the service merge/force-push ciphertext. Git outages
do not roll back durable API saves. Expose accepted/local-mirrored/remote-confirmed
revisions separately. Schedules change remote timing, not API durability semantics.

## Replay, revocation and recovery limits

Index AEAD and entry digests reject substitution, mix-and-match and omitted live
objects relative to an authenticated root. Clients persist their highest observed
epoch/revision and head digest per deployment/collection. Reject lower heads and
different digests at the same revision. To advance across skipped revisions, verify
an authenticated index/parent chain from the saved checkpoint, not just a larger
server-supplied counter. Define chain retention and bounded catch-up before release.

A fresh/restored client with no trusted checkpoint cannot distinguish a complete
valid old history from current state. Recovery kits should carry a verified root
checkpoint; Git commit IDs alone are not independent trusted witnesses. A malicious
server can fork histories between isolated clients. This design does not solve
fork detection without out-of-band comparison or an independently trusted log.

Revocation requires fresh epoch material and new allowed-recipient/recovery wrappers;
re-encrypt the index and all live entries atomically. A stale writer must not publish
under the old epoch. Retained Git history and downloaded material remain readable
to anyone who already had old keys. Rotation does not erase disclosed secrets.

## Migration and rollback

1. Inventory client capabilities and *all* active wrappers/recovery paths. Produce a
   verified full backup and retain exact original snapshots/history. Require an
   unlocked authorized editor; the server cannot migrate plaintext independently.
2. Fetch/pin the source revision, membership and wrapper state. Build a complete
   candidate under a fresh root key and explicit new-format epoch/context (existing epoch + 1 for bound collections; 1
   for previously unbound collections). Preserve
   every entry field, including optional OTP and exact names. Do not automatically
   split slash-containing names into folders: preserve literal names until an
   explicit folder import rule is reviewed and selected.
3. Independently decrypt/compare every staged entry and wrapper recovery path;
   validate the index and perform a restore into an isolated client. Partial success
   is not cutover. Explicitly handle users whose new wrappers cannot be delivered.
4. Publish the entire format switch with source-revision/membership CAS. If anyone
   edited the source, preserve staging and restart from current data. Old API writes
   must fail after cutover; never run writable old/new representations in parallel.
5. Before cutover, abort by discarding uncommitted staging; source remains unchanged.
   After cutover, do not silently reset the pointer. Restore a matched pre-migration
   backup only with explicit reconciliation of post-cutover writes, or implement a
   reviewed client-side reverse export to a separate collection. Mark such a restore
   explicitly for checkpoint verification; no automatic anti-rollback bypass.

Migration is therefore reversible **before** cutover; lossless rollback **after**
new writes requires additional reconciliation, not merely restoring an old binary.
Do not advertise an implemented downgrade/export path yet.

## Gates before implementation and rollout

- Freeze byte-exact KDF/AAD/head/index/wrapper schemas and serialization; get a
  cryptographic review and independent native/WASM fixtures. Primitive references
  support the building blocks, not the security of this composed format.
- Specify authenticated continuity across epoch changes without assuming the client
  retains every old root key; a new-key index alone cannot prove all intervening
  history. Block rollout until this checkpoint/transition proof is reviewed.
- Fix resource budgets for entry/index/transaction bytes, entry/tombstone counts,
  receipts, ancestry catch-up and staging; tie quotas to pre-allocation checks.
- Specify wrapper migration and device/recovery compatibility for each supported
  profile, including new/old clients and unavailable recipients.
- Implement the [acceptance matrix](../testing/encrypted-entry-format.md) first in
  core/API test harnesses, then clients and Git/restore integration. No silent
  migration or default enablement while a release-blocking scenario is failing.

Related: [sync requirements](git-vault-sync.md), [current architecture](../architecture.md),
[current key packages](../key-package-format.md), [schema migration](../schema.md),
[cryptographic profile direction](../decisions/0004-cryptographic-profile-direction.md).
