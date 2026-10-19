# Encrypted entry format: acceptance and failure-injection plan

Status: **full scenarios specified, not yet implemented/executed**, 2026-10-18.
Six [prototype primitive tests](../research/entry-format-prototype.md) now cover
parts of E01/E04/E07/E08/E09 and K01/K02; they do not complete those scenario rows. These are release
criteria for the [candidate format](../research/encrypted-entry-format.md), not
claims about today's snapshot implementation. Existing CLI tests do not satisfy
these criteria merely because they exercise snapshot CAS or encrypted drafts.

## Test harness and evidence

Use synthetic secrets only. Build deterministic fixtures with fixed test-only
randomness and an independent reference encoder/KDF/AEAD implementation. Production
randomness must remain OS-backed; never ship fixture seeds/nonces. Run the same
valid/invalid vectors in native Rust and WASM. Save expected canonical bytes, exact
ciphertext hashes, decoded contents and rejection classes, plus source/version of
the reference implementation. Do not count round trips using one implementation
as independent interoperability evidence.

The API harness needs two independently unlocked clients, a real persistence
backend, injected writer/crash barriers and restart. The Git harness uses local
bare remotes, denies network/push access on demand, and introduces an external
remote commit. Restore into an empty isolated data directory with a separate client.
Capture accepted roots/operation receipts, reachable object hashes, Git trees and
status transitions. Never capture real secrets, bearer tokens or private keys.

Every row below is required before default enablement unless marked a documented
limitation. A check passes only when both the expected result and the forbidden
side effect are asserted. Map IDs to named automated tests in a later implementation
PR; leave the plan's status unchanged until those tests actually exist and pass.

## Core format and cryptography

| ID | Scenario | Required assertion |
| --- | --- | --- |
| E01 | Native seals, independent reference and WASM open; reverse directions too | Exact KDF info/AAD/header/hash agreement; all fields preserved, including OTP and Unicode names |
| E02 | Edit one password in a three-entry vault | Only target envelope, index and head change; other envelope bytes and Git blob IDs identical |
| E03 | Rename/move entry and rename folder | Only index/head change; payload bytes stable; no dangling parents, duplicate paths or cycles |
| E04 | Flip each public context/AAD field, nonce, tag or ciphertext bit | Authentication/format rejection before plaintext display; no fallback profile |
| E05 | Substitute a valid entry from another ID, collection, deployment, epoch or revision | Rejected by context plus authenticated index digest binding |
| E06 | Omit a live entry, return an old entry or mix roots during read | Error/retry, never silently treat as deletion or reveal the mismatched entry |
| E07 | Duplicate/unknown JSON fields, noncanonical base64, oversized lengths, bad counters, unsupported suites | Bounded pre-allocation rejection, no file/network mutation; same native/WASM decision |
| E08 | Re-encrypt the same object twice using instrumented randomness | Distinct nonces/ciphertexts; replay exact ciphertext only for exact retry; RNG failure aborts save |
| E09 | Use index key for an entry or swap entry IDs/key domains | Authentication fails; independent vectors confirm purpose separation |
| E10 | Scan filenames, tree names, public descriptors, requests and logs | No fixture names, passwords, URLs, usernames, notes or OTP setup values; documented metadata remains observable |
| E11 | Malformed decrypted index: cycles, duplicate IDs, live/tombstone overlap, wrong head/access binding | Reject whole view before listing/revealing; valid AEAD alone is insufficient |

## Transactions, durability and Git

| ID | Scenario | Required assertion |
| --- | --- | --- |
| T01 | Two editors change the same entry from one root | Exactly one initial acceptance; loser has encrypted draft; no overwrite or automatic retry |
| T02 | Two editors change different entries from one root | Initial global-index CAS still rejects one; explicit refetch/reapply retains both edits; do not claim conflict-free parallel writes |
| T03 | Create colliding ID; create existing path; update deleted ID; stale delete | ID/expected-state checks reject publicly invalid deltas; unlocked client rejects encrypted path collisions; no tombstone resurrection |
| T04 | Delete entry, then stale offline client reconnects | Authenticated tombstone retained; old ID cannot be reintroduced; intentional recreation uses new ID |
| T05 | Replay same operation ID and bytes; reuse ID with different bytes | First replay returns original receipt without extra revision/commit; changed payload rejected |
| T06 | Accept transaction, drop connection before response, restart | Receipt identifies exact accepted root; draft retained until verified; no duplicate acceptance or false failure rollback |
| T07 | Read-only, disabled, expired-session, revoked user attempts write or receipt lookup | No mutation; no receipt/content leak after loss of access; recheck after waiting for writer lock |
| T08 | Crash before/after each object flush, directory flush and root-pointer replacement | Restart sees old complete root or new complete root; never mixed state; orphan staging invisible |
| T09 | Disk full, permission failure, oversized transaction or quota exhaustion | No successful acknowledgment before durable state; original committed root recoverable |
| T10 | Git writer crashes before/after commit and checkpoint | Replay yields exactly ordered accepted history, no duplicate logical revision or dropped intermediate commit |
| T11 | Remote unavailable for several API writes, then restored | API saves remain durable; status pending/error; ordered commits eventually pushed and remote-confirmed revision advances |
| T12 | Another actor adds a remote commit or remote is ahead | Push stops with divergence status; no merge, reset or force push; API history retained |
| T13 | Restart with old uncommitted staging and active snapshot readers | GC retains every reachable/reader-pinned object; no staging promotion or mixed-version reads |
| T14 | Start second server writer on same data directory | Startup denied under current deployment contract; no multi-host support inferred |
| T15 | Receipt exists but response has wrong operation/root/epoch/membership fields | CLI retains draft and reports uncertainty; never announces remote Git completion |

## Wrappers, rotation and trusted checkpoints

| ID | Scenario | Required assertion |
| --- | --- | --- |
| K01 | Unlock using each explicitly supported recovery/device/recipient wrapper | Same root and verified index; correct suite/payload type; no old-package reinterpretation |
| K02 | Wrong password, unverified/changed issuer, forged package, foreign origin/account/deployment | No plaintext or write; trust suspension persisted where required |
| K03 | Membership changes or epoch rotates after fetch but before commit | Old write rejected; draft retained; no package issuance for revoked identity |
| K04 | Rotate with multiple entries and allowed/revoked recipients | All live objects and active wrappers move atomically to fresh epoch; authorized clients restore; revoked old key cannot decrypt new state |
| K05 | Replace wrapper set, insert weaker recovery wrapper or downgrade data suite | Authenticated index/access-set mismatch or explicit policy rejection; no hidden fallback |
| K06 | Previously observed client receives lower revision/epoch or same revision with different digest | Reject without resetting trusted checkpoint; preserve evidence for explicit recovery |
| K07 | Skip revisions, cross an epoch, or receive discontinuous parent history | Verify bounded authenticated continuity to saved checkpoint; no trust in a bare larger counter; epoch-transition proof must be specified first |
| K08 | Fresh client receives a complete valid old history without an independent checkpoint | Document inability to prove freshness; never label it rollback-proof (known limitation) |
| K09 | Two isolated clients are served distinct valid forks | Document missing independent witness; do not claim universal fork detection (known limitation) |
| K10 | Inspect old Git history after rotation | Old keys can still open old ciphertext; test/document that revocation cannot erase previous disclosure |

## Migration and restore

| ID | Scenario | Required assertion |
| --- | --- | --- |
| M01 | Migrate supported legacy personal/group fixtures with empty/nonempty stores and OTP | Exact decrypted field/name equivalence; every target entry/index and enabled wrapper independently opens |
| M02 | Slash names, Unicode, case variants and folder-like names | No normalization, silent splitting, collision or dropped record; folder mapping explicitly defined |
| M03 | Source edit, membership change, revocation or rotation during staging | Cutover CAS fails; source edit survives; candidate remains uncommitted and can be rebuilt |
| M04 | Interrupt migration at each staging/cutover boundary | Before cutover old format remains authoritative; after cutover new root is complete; repeat attempt cannot overwrite source backup |
| M05 | Old client writes after cutover; unsupported profile/wrapper migration requested | Explicit rejection before mutation; no empty-vault illusion, downgrade or partial migration |
| M06 | Restore latest committed Git tree in isolated unlocked client | All live entries/folders/tombstones verified; no reliance on deleted payloads or server plaintext keys |
| M07 | Full-server disaster restore with accounts, configuration, wrappers and checkpoints | Correct compatible release and access state restored; Git-only restore is not claimed to restore accounts |
| M08 | Restore pre-migration backup after new-format writes exist | Explicit reconciliation required; no silent loss of newer writes or automatic checkpoint reset |
| M09 | Reverse export requested | Not offered until a separate validated export exists; never imply binary rollback is a lossless data conversion |
| M10 | Recipient unavailable or recovery wrapper missing during staging | Migration blocked or explicit reviewed delivery policy; no silent removal of an unlock/recovery path |

## Implementation order

1. Freeze schemas, byte encoding, limits, wrapper/profile migration and epoch continuity.
   Resolve review findings in the specification before generating golden fixtures.
2. Implement E/K core vectors in isolation behind an experimental format boundary.
   Keep legacy parsers and writes unchanged.
3. Implement transaction/persistence T cases against the API, including crash barriers.
4. Implement migration M cases and native/WASM/extension/CLI compatibility checks.
5. Demonstrate restore and remote-outage/divergence behavior, then consider explicit
   opt-in deployment. Default rollout requires all release-blocking rows passing.
