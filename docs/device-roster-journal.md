# Candidate durable device-roster publication journal

Date: 2026-10-31. Native-only reference implementation under
`petika-core/experimental-device-keys`, disabled by default. It connects the
[candidate enrollment proof](device-enrollment-format.md) to durable signed-roster
publication. It is not yet used by the Petika server or account APIs.

## Workflow

1. Independently confirm the authority fingerprint and initial roster digest. Retain
   them outside the journal as its initialization anchor. The baseline can be a later
   independently verified snapshot; loading server-provided metadata is not confirmation.
2. `DeviceRosterJournal::lock(path, authority_fingerprint, initial_digest)` acquires an
   exclusive native lock, retained for the handle lifetime. `initialize(&trusted)` creates
   the journal only if absent and only if the baseline matches both retained values.
3. Complete the enrollment ceremony against the latest trusted roster and retain its
   exact signed candidate. Do not advance a separate client pin before publication.
4. `publish(operation_id, expected_parent, &candidate)` verifies the candidate and the
   complete retained journal. For a new operation it requires exact current-parent CAS,
   generation +1 and the established adjacent single-device add/remove rules.
5. Atomically replace the journal with the signed successor and its operation record
   together. Return a receipt derived from that stored operation. Publish no usable
   keys, private pending challenges, account sessions or collection contents.
6. After an interrupted acknowledgement, reopen with the same initialization anchor
   and `lookup(operation_id)` or retry the exact candidate. An already committed operation
   returns its original receipt even if later updates have advanced the head. Verify the
   receipt against the retained operation ID/candidate; advancing a local pin is separate.

Operation IDs are caller-generated random 32-byte values as lowercase hex. One ID may
identify only one canonical candidate and parent. Changing either under the same ID
fails. A stale competing candidate under a fresh ID also fails without rewriting state.
Returning a historical receipt never rolls the journal back to that operation's roster.

The journal accepts any valid authorized single-device add/remove transition. Enrollment
proofs are enforced in the authority client before it signs an addition; the publication
layer cannot infer human approval or decryption possession from a signature alone.

## Persistence and limits

One strict JSON record contains `version` (=1), the full signed `baseline`, and an ordered
`publications` array of `{ operation_id, roster }`. Its maximum size is 8 MiB and its
maximum publication count is 128. Exhaustion fails without pruning existing history or
receipts. Compaction/checkpoint replacement needs a separate reviewed design.

Every read validates the independently anchored baseline, each signature, strictly
adjacent transition and unique operation ID. Unknown, duplicate and malformed JSON,
invalid versions, excessive counts/size, corrupt signatures and inconsistent history
fail. No read error triggers reinitialization. Creation uses no-clobber semantics.

The existing `StoreFile` helper provides exclusive locking, restrictive Unix file modes,
temporary-file write/sync, atomic replacement and Unix parent-directory sync. Native
platform filesystem guarantees still matter. Tests inject failures after temporary write,
file sync, replacement and directory sync. Before replacement the old file remains; after
replacement the complete operation can be found on reopen and exact retry reconciles it.
These are deterministic interruption checks, not a physical power-loss/disk-full certification.

Only public signed metadata and operational retry IDs are stored. Account/device inventory
can still be private metadata, so the file uses owner-only access. Local filesystem control
is a trust boundary for operational metadata; roster signatures do not sign operation IDs.
Retain trusted anchors and newest pins independently. A coherent old complete journal or
prefix is valid history: the journal cannot know a newer state was hidden or lost without
external newer evidence. A separately retained newer pin rejects that rollback.

## Receipt contract

Receipts have strict JSON fields `receipt_version` (=1), `operation_id`,
`authority_fingerprint`, `previous_digest`, `roster_digest`, and `generation` (2 through
2^53−1). Other fields are 64-character lowercase hex values. Input is bounded to 2,048
bytes. The receipt binds the caller's operation to one signed candidate and parent.

`verify_candidate` checks this correspondence and the candidate's signature. The receipt
is not independently signed and cannot prove that a remote server committed anything.
Authenticate the eventual transport, check membership/session authorization, and reconcile
against durable server state. Never advance trust based on an unsigned receipt alone or
copy a receipt's digest into a confirmation prompt as if independently verified.

## Validation and next boundary

Tests cover end-to-end proof → candidate → publication → reopen → receipt, later-head
historical retries, competing candidates, operation-ID reuse, forged receipt fields,
exclusive locking, wrong initialization anchors, owner-only Unix mode, all four write
boundaries, corrupted/truncated/duplicate journals, and rollback against a retained
newer pin. Candidate checks and both independent fixture generators remain in CI.

Next: authenticated account API integration, durable client draft/receipt reconciliation,
session revocation and rotation-required state, device-package delivery and migration.
The native journal is not compiled into WASM; browser persistence needs its own reviewed
transaction/storage adapter. No production account or vault format changes occur here.
