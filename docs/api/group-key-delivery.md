# Group-key delivery API contract

Status: **six identity operations implemented; four collection operations planned**. The machine-readable contract is
[group-key-delivery.openapi.json](group-key-delivery.openapi.json), OpenAPI 3.0.3.
The [design decision](../decisions/0002-per-user-group-key-delivery.md) defines the
cryptographic and trust model. This contract does not redefine existing endpoint errors.

## Common rules

Use existing managed cookie or CLI bearer sessions. Legacy static snapshot tokens do
not authorize key operations. Mutations require `Content-Type: application/json` and
`X-Petika-Request: 1`; reject cross-site Fetch Metadata and do not enable CORS. All
responses use JSON, `Cache-Control: no-store`, and `X-Content-Type-Options: nosniff`.
Never log request bodies, passwords, cookies, bearer credentials, or decrypted material.

IDs/fingerprints are 64 lowercase hex characters. Counters are nonnegative JSON integers
bounded by 2^53-1 for browser interoperability; identity versions and active epochs start
at 1. Epoch 0 means a legacy collection. All byte strings use canonical padded base64;
decode and check exact algorithm lengths before crypto. Unknown/duplicate fields and
unsupported versions fail closed. OpenAPI describes shape; it cannot establish signature,
canonical-byte, authorization, or cross-field validity.

Errors have `{ "code": "conflict", "message": "State changed; refresh and retry" }` shape.
Use 400 for invalid data/crypto framing, 401 for absent/invalid/revoked sessions (including
disabled users), 403 for known resource permission failures or request-origin failures,
404 for absent or invisible resources, 409 for stale expected state or conflicting
idempotency keys, 413 for size limits, 429 for throttling, and 503 for storage failures.
Do not expose another user's existence, keys, or current revision in an error. Unsupported
methods return 405; unsupported mutation media types return 415. Reauthentication failure
is 401 and does not mutate existing identity state.

## Operations and invariants

| Method/path | Authorization and result | Conflict/negative requirements |
| --- | --- | --- |
| GET `/v1/keys/deployment` | Managed session reads persistent deployment ID, 200 | Required before generating a deployment-bound identity |
| GET `/v1/keys/identity` | Own public identity plus encrypted private bundle, 200; 404 if unenrolled | Never return another user's bundle or plaintext |
| POST `/v1/keys/identity` | Own enrollment with `current_password`, public record, encrypted bundle, expected revision 0; 201 and bundle revision 1 | Concurrent enrollment: one success, one 409; deployment/user IDs must match caller |
| PUT `/v1/keys/identity/bundle` | Own encrypted bundle update; compare expected bundle revision, increment once; 200 | Cannot change public identity/fingerprint; stale edits preserve both copies |
| POST `/v1/keys/identity/replace` | Own explicit replacement with reauthentication and expected identity/bundle versions; 200 | New identity version must be previous + 1; old grants stop being served; concurrent replacement fails |
| GET `/v1/keys/users/{user_id}` | Self or active co-member public identity only; 200 | Unrelated/admin-only access receives 404; no encrypted private bundle |
| GET `/v1/collections/{collection_id}/key-access` | Active member reads own delivery status; editors can inspect active roster delivery status; 200 | Unenrolled is a state, not successful delivery; verification status is local and never asserted by the server |
| GET `/v1/collections/{collection_id}/key-packages` | Active member receives only packages for own current identity and active epoch; 200 | No matches returns empty page, not another identity's packages; disabled/removed users denied |
| POST `/v1/collections/{collection_id}/key-packages` | Active editor publishes signed grants to current active members; 200 | Compare snapshot revision, epoch, membership generation, recipient and issuer identity versions under locks |
| POST `/v1/collections/{collection_id}/recipient-migration` | Active editor atomically commits envelope v2 and initial grants; 200 | Only legacy epoch 0 to epoch 1; mode must match existing collection; legacy snapshot upload cannot undo migration |

Publication requires issuer ID/key to match the authenticated editor and each recipient
to match the current directory. The server validates public signature and framing, not
encrypted secrets or whether the issuer verified fingerprints. Clients enforce trust
pins and authenticate decrypted snapshots. The initial migration must include the
issuer's own usable grant; other unenrolled/unverified members remain visibly pending.

The supplied encrypted snapshot is an opaque serialized envelope subject to server
framing validation. Its v2 byte-level encoding will be frozen with core protocol fixtures;
this API contract must not be mistaken for a completed cryptographic wire specification.

## Concurrency, limits, and retry behavior

Acquire account then collection locks and recheck membership, disabled status, identity
versions, expected snapshot revision, epoch, and membership generation. Commit grant-set
changes and migration through the same durable collection journal/current pointer.
Each successful state change increments the snapshot/state revision, including package-only
changes; adjust legacy snapshot clients to tolerate unchanged ciphertext at a new revision.
No response may acknowledge a state that has not reached durable storage.

A repeated package ID with identical authenticated bytes returns the original committed
result without a new revision, after checking current caller authorization, identity, and
epoch. A reused ID with different bytes is 409. For a mixed batch, either every package is
new or every package is an identical replay from the same transaction; otherwise 409.
Replay detection precedes the old revision comparison, but never bypasses current access
checks. Migration retries use the same package batch and exact snapshot bytes; mismatched
snapshot bytes are 409. Persist enough transaction metadata to recognize retries after restart.

Identity bundle versions 1 and 2 have the same outer API fields; version 2 protects
verified contact pins in its encrypted payload. New clients write version 2. Bundle
updates must reject a 2-to-1 downgrade even with a matching revision, and a replacement
identity starts with a version 2 bundle. Local pin revisions are separate from server
bundle revisions and never replace server CAS.

Identity mutations use bundle revision CAS; after a lost response fetch the own identity
state to reconcile. Do not retry enrollment/replacement by silently generating new keys.

Limits: 16 KiB serialized package, 100 packages per batch/page, 128 KiB identity request,
2 MiB package-publication request, and 20 MiB migration request including at most 16 MiB
of serialized encrypted snapshot. Enforce actual request bytes before allocating/parsing;
JSON schema string lengths alone are not sufficient. Bound decoded key fields to their
algorithm lengths and bundles to 64 KiB ciphertext. Paginate with opaque cursors bound to
caller, collection, and state revision; stale cursors return 409. Empty `next_cursor` ends
a page. Do not permit cursor-based access to another member's packages.

Identity enrollment/replacement shares the existing reauthentication rate limiter;
new key endpoints also require bounded per-user request rates before release. Concrete
rate thresholds belong to implementation configuration and must have boundary tests.

Membership edits and disabling/re-enabling a user increment affected group membership
generations. Identity replacement invalidates delivery to the old identity and updates
affected group generations. Removing/disabling a recipient or replacing its key marks
rotation required. Re-enabling/re-adding never clears that flag. This milestone must not
claim fresh-key exclusion until the separate rotation transaction is implemented.

## Verification

[Development test actions](../testing/group-key-delivery.md) map every step and operation
to positive, denial, race, and recovery cases. The contract CI job validates OpenAPI and
schema fixtures now. Runtime API conformance tests are required with each endpoint's
implementation; they are not present yet.

Identity operations use a 128 KiB request limit and 120 requests per user per minute.
Password confirmation shares the existing 20-per-minute account authentication budget.
Replacement requires bundle v2; updates cannot downgrade v2 to v1. Identity enrollment
and replacement advance affected membership generations; replacement also marks rotation
required. No group packages or cryptographic rotation are implemented yet.
