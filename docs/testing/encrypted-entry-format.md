# Encrypted entry format: acceptance and failure-injection plan

Status: **partially implemented behind experimental gates**. Primitive vectors,
checkpoint/recipient verification, durable pins, journal transactions, authenticated
HTTP, CLI drafts/history, and Git replication now have the evidence listed below.
Migration and complete K/T/M scenario coverage remain pending. These are release
criteria for the [candidate format](../research/encrypted-entry-format.md), not
claims about today's snapshot implementation. Existing CLI tests do not satisfy
these criteria merely because they exercise snapshot CAS or encrypted drafts.

The experimental committed **index-history** journal now has the following
automated evidence, without completing the full transaction scenarios below:

- `entry_journal::tests::process_termination_never_promotes_orphan_records` exits
  a child process at eight record/root persistence boundaries and reopens the
  journal. This now includes a changed entry ciphertext, without simulating
  physical power loss or completing all transaction durability criteria (T08).
- `retries_conflicts_lock_and_recovery` and
  `changed_request_quota_and_uncertain_publication_fail_closed` cover index CAS,
  exact retries, changed operation requests, scoped receipts, exclusive handles,
  quota rejection and reconciliation after an uncertain root publication.
- `corrupted_committed_ancestry_is_never_replaced_by_staging` rejects corrupt
  reachable records; `committed_journal_pages_authenticate_after_restart` verifies
  real encrypted index history through the bounded transport after restart.

Additional experimental evidence now covers entry deltas and HTTP/CLI integration:

- `entry_transactions_preserve_other_ciphertexts_and_tombstones` uses real encrypted
  multi-entry fixtures to check preservation, exact-root reads, stale edits, operation
  replays, deletion/resurrection rejection and restart. It does not verify Git blob IDs.
- `account_entry_api_binds_access_context_receipts_and_legacy_boundary` checks read-only
  access, revocation, scoped receipts, collection/deployment binding, membership changes,
  bounded reads and exclusion of legacy state. The account lock is asserted held.
- `real_http_entry_routes_require_runtime_gate_session_and_request_headers` starts the
  real server and checks opt-in gating, session/CSRF requirements, legacy write rejection,
  capabilities and request bounds.
- CLI `confirmed_entry_history_resumes_after_partial_sync_without_resetting_pin`
  runs separate CLI processes, rejects an inactive but otherwise valid recovery
  wrapper, confirms a new anchor, refuses replacement, accepts one
  page then loses a response, resumes at the durable cursor and checks empty-page behavior.
- The eight-boundary process-exit test now includes a real encrypted entry payload
  committed with its index/receipt, asserting pre-publication invisibility and complete
  post-publication recovery.
- `storage::failure_tests::drop_releases_lock_without_waiting_for_inherited_descriptors`
  covers explicit guard release while a duplicate open file description remains alive,
  preventing spawned children from temporarily prolonging a dropped journal lock.

Further transaction/replication evidence:

- CLI `encrypted_entry_drafts_reconcile_lost_receipts_and_reject_conflicts` stages
  ciphertext-only replacements, preserves notes/OTP, loses an acceptance response,
  rejects a stale second draft, resumes through a receipt without a second write,
  rejects a forged acknowledgement and reconciles a deletion. Drafts remain on disk.
- `receipt_absence_must_be_explicit_and_unambiguous` rejects missing, duplicated or
  unknown receipt lookup fields; explicit null is the only absence response.
- `entry_git_replication_preserves_blobs_recovers_checkpoints_and_stops_divergence`
  checks unchanged blob IDs, ordered outage catch-up, missing-checkpoint recovery,
  decrypted live-object restore from a local bare remote, and an external remote
  commit. Divergence does not change the remote or prevent further API acceptance.
- `entry_replication::tests::process_termination_replays_ordered_commits_without_duplicate_revisions`
  exits a real child after commit publication, repository sync and checkpoint
  publication; restart replays exactly the accepted logical revisions.

Core epoch bundle evidence:

- `complete_epoch_bundle_unlocks_and_advances_exact_local_pin` verifies complete
  nonempty and empty-vault rotations, recovery and recipient unlock, old-key
  rejection of new ciphertext, continued access to old ciphertext, pin restart
  and replay rejection.
- `incomplete_or_substituted_epoch_bundle_leaves_pin_unchanged` rejects missing or
  duplicate entries/wrappers, wrong preconditions, old ciphertext, changed cursors,
  bad transitions and a stale candidate after local progress, preserving pin bytes.
- `signed_rotation_cannot_hide_content_changes_or_invalid_wrappers` rejects even
  authority-signed candidates containing renamed entries, changed passwords,
  weakened recovery parameters or inconsistent recipient issuer metadata.
- `epoch_wire_and_receipts_bind_the_complete_request` checks strict parsing,
  wire/count limits and complete writer/request/cursor receipt binding, including
  exact wrapper bytes and separation from ordinary edit receipts.

Server epoch evidence:

- `epoch_journal_replays_complete_rotation_and_preserves_old_reads` checks complete
  replacement, missing data/wrapper rejection, operation retry, old exact-root reads,
  epoch-bounded history and adjacent transition retrieval after restart. Unanchored
  journals cannot rotate.
- `epoch_process_exit_never_exposes_mixed_keys_wrappers_or_entries` exits child
  processes at all eight publication boundaries and verifies that checkpoint,
  wrappers, live ciphertexts and receipt recover together; retry accepts only once.
- `epoch_uncertain_publication_requires_reopen_and_receipt_tampering_is_rejected`
  rejects use of an uncertain handle, reconciles after reopening, and rejects a
  rewritten receipt even when its enclosing record hash is recomputed.
- `epoch_api_enforces_authority_roster_membership_and_reconciles_after_revocation`
  checks read-only and non-authority editor denial, missing/revoked delivery rejection, stale membership,
  old-context receipt reconciliation, revoked-reader denial and subsequent ordinary
  writes using the committed membership generation without clearing account flags.
- `epoch_git_tree_contains_exact_wrappers_and_signed_transition` checks exact active
  wrappers/checkpoints and transition bytes in ordered local Git history.
- The real HTTP test also checks rotation/transition runtime gates, authentication
  and same-origin request headers. Explicit migration coverage is listed below;
  there is no general-purpose unauthenticated journal initializer.

- `rotation_drafts_reconcile_lost_ack_and_clients_verify_before_advancing` runs
  actual CLI subprocesses against a mock API for both explicit recovery policies.
  It checks wrong credentials, unverified recipients, encrypted draft retention,
  payload/TOTP preservation, no-overwrite, lost acknowledgements, forged receipts,
  cache conflicts, receipt-only retries, invalid transitions and review without
  pin advancement. A separate recipient verifies and accepts the new epoch, then
  unlocks using cached wrappers and the original collection anchor.
- `epoch_lookup_requires_explicit_transaction_or_null` rejects ambiguous lookup
  responses. Roster tests enforce current access and membership generation;
  the real HTTP route checks include roster authentication/runtime gates.

Local migration preservation evidence (partial M01/M02/M05 only):

- `legacy_modes_preserve_empty_and_literal_named_records` opens real legacy
  Standard/Hybrid ciphertext, with bound/unbound and empty/nonempty variants,
  preserves slash names and distinct Unicode/case variants, and opens the candidate
  recovery wrapper. This does not prove delivery to all recipients.
- `validly_encrypted_content_changes_and_missing_objects_fail_migration` rejects
  validly encrypted/signed changes to each field, lost OTP, removed/renamed records,
  unknown payload fields and missing/substituted objects; the source remains intact.
- `migration_rejects_epoch_reuse_skips_and_profile_changes` rejects nonadjacent
  bound epochs and changes between Standard and experimental Hybrid profiles.
- `migration_cannot_invent_folders_tombstones_or_history` rejects authenticated
  candidates that introduce a folder tree, deleted-record history or later revisions.

Encrypted migration staging evidence:

- `migration_drafts_restore_from_disk_in_both_profiles_and_recovery_policies`
  serializes real drafts to protected no-overwrite files, reopens recipient and
  recovery wrappers, verifies content in Standard/Hybrid and bound/unbound cases,
  and scans serialized bytes for fixture plaintext/passwords. Original encrypted
  source bytes remain exact.
- `migration_draft_binds_source_roster_policy_and_every_ciphertext` rejects stale
  external bindings, altered source/operation/roster/policy/entries, wrong credentials
  or authority, and omitted wrappers. A re-signed incomplete draft passes public
  framing checks but fails full unlocked verification, as required.
- `migration_staging_rejects_unverified_recipients_wrong_source_and_ambiguous_wire`
  rejects unverified/duplicate recipients, wrong source credentials/digest,
  unknown/duplicate/missing fields and oversized serialized input.
- `empty_migration_draft_has_a_complete_recoverable_index` verifies an empty
  collection still has a signed index and working new recovery wrapper.

Authority handover, real-device restore and physical power-loss/disk-full
scenarios remain outside this core-test coverage; shared CLI restore evidence is below. No full T-series row is
marked complete solely from these partial synthetic scenarios.

CLI migration evidence:

- `migration_cli_captures_live_source_and_retains_stale_drafts_without_writes`
  exercises actual CLI subprocesses with Standard/Hybrid snapshots and both recovery
  policies. The mock API asserts GET-only traffic and paginated roster use; tests
  reject read-only access, capture races, identity mismatch, wrong credentials,
  changed source revision/membership and foreign origin. Submission also rejects
  a recipient whose local contact pin was suspended after staging. Drafts remain unchanged
  after failures and re-review; neither the legacy local store nor a pin is created.
- `personal_migration_uses_own_enrollment_without_group_access_endpoint` confirms
  personal stage/review uses the enrolled owner and generation 1, without requesting
  the group-only key-access endpoint. These are synthetic HTTP tests, not live cutover.

- `migration_submit_reconciles_lost_ack_and_initializes_only_verified_pins` runs CLI
  subprocesses in Standard/Hybrid modes with omitted/replaced recovery. It terminates
  the CLI after API acceptance but before acknowledgement, then reconciles the same
  operation without another migration POST. It rejects stale sources, wrong new
  recovery passwords, absent/bad receipts and conflicting local artifacts without
  creating a pin. Read-only receipt retry works; an accepted pin needs only identity
  unlock, supports recipient-backed listing and is never replaced when corrupt.
- The core empty-draft test verifies the migration receipt digest matches its
  domain-separated wire tuple and rejects wrong writers, operations, digests and cursors.

Server migration evidence:

- `migration_api_cas_authority_retained_source_and_exact_retry` covers personal
  owners (including non-admins), shared admin/edit authority, wrong sessions,
  changed source revision/hash, membership mismatch and incomplete recipient rosters.
  It verifies exact receipt retry, refusal to replace active journals or reuse an
  operation with changed content, retained source bytes and direct legacy-write refusal.
- `migration_process_exit_exposes_only_complete_format_switch` terminates a child
  process at each of eight immutable-record/root publication boundaries, reopens the
  journal, checks complete checkpoint/wrapper/entry/receipt visibility and retries
  the exact operation. Source ciphertext remains unchanged at every boundary.
- Existing real HTTP route tests include migration runtime gating, authenticated
  request headers, malformed bodies, a successful shared-vault cutover and exact
  retry, retained snapshot bytes, post-cutover history reads and legacy GET/PUT
  rejection. The clean-directory drill below adds real CLI/server migration and restore.

Full recovery evidence:

- `scripts/test_entry_recovery.py` runs real experimental server/CLI binaries in both
  Standard and Hybrid profiles, migrates and rotates a vault, captures the stopped
  server and separate client kit, removes the original directories and restores on
  a clean path. It checks account continuity, receipts, exact mirrored index/epoch
  state, identity/recovery unlock and every cached live entry.
- The offline `petika-entry-recovery` checker rejects running-server access, damaged
  journal records and missing/older roots against independently retained reports.
  `entries verify-backup` rejects missing ciphertext and wrong identity credentials
  without changing the pin. Restoring a pre-migration server cannot reset a newer
  client pin. The full drill runs in the Web UI/provisioning CI job.
- This full-server drill is authority-only, local filesystem evidence. The Git/user
  export and shared-recipient drills below add ciphertext recovery coverage. Real-device
  readiness, post-backup write reconciliation and production/off-site recovery
  objectives remain open.

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

### Exact-pin ciphertext recovery

The real-server `scripts/test_entry_recovery.py` drill also recovers current Git trees
using recipient identity and explicitly selected recovery wrapper, and version-2
recipient-scoped API exports using the native CLI through `user_backup.py`. It checks
all recovered caches offline, rejects an older Git commit, symbolic commit selector,
wrong identity, existing output directory, changed export owner, missing and altered
ciphertexts, and verifies the retained pin remains byte-identical. Both Standard and
experimental Hybrid profiles are exercised. Server migration tests check separate
owner/editor packages and rejection after group access is removed. These checks do
not establish multi-device readiness or reconciliation of newer writes.

### Shared-recipient recovery evidence

`scripts/test_entry_shared_recovery.py` uses real native API/CLI binaries with an owner
and read-only group member in both profiles. It checks:

- Mutual contact verification and recipient checkpoint confirmation against values
  retained by the authority; no pin is created without explicit confirmation.
- Owner/recipient exports select their own packages. Fresh-cache recovery authenticates
  every entry, including a fixture containing TOTP, without printing secret contents.
- Read-only recipients review an adjacent rotation without changing their pin, then
  explicitly accept it. A second simulated device restores the retained identity/pin
  without an API session, authority key, recovery wrapper or old cache.
- Cross-user exports and older exports against newer pins fail without output or pin
  changes. Membership removal removes the group from the backup index and rejects
  exports. Subsequent rotation contains only the remaining owner's recipient package.
- A removed identity cannot unlock the owner's new package even with a separately
  confirmed new checkpoint. Historical retained exports remain decryptable, as expected.
- Final owner and recipient historical recovery works with the server stopped and
  original client directories deleted.

CI runs this alongside the full-server drill. Simulated device directories share one
user's enrolled identity; independently enrolled device keys, hardware/biometric paths,
cross-platform restore and production custody are not covered. Recipient identity
replacement has a separate scenario below.

### Newer-write reconciliation assessment

The full recovery drill now captures a stopped-server backup after migration, submits
another same-epoch entry write, then rotates. `petika-entry-recovery --compare` checks
an exact retained report, an older report whose head/checkpoint is in the newer journal,
a conflicting historical digest, an older restore faced with newer retained evidence,
and a missing collection. The drill compares the data inventory before/after successful
and conflicting assessments and rejects comparison against a running server. Both
Standard and experimental Hybrid profiles run this path.

Operator comparison unit tests reject duplicate collection IDs, foreign deployments,
unknown report fields, invalid/path-like collection IDs and zero epochs, and distinguish
same-revision conflicts from missing later history. A successful structural comparison
is not a decryption/freshness proof. This does not implement journal replay, account-state
reconciliation or recovery from a client cache alone.

### Complete successor-backup staging

The real Standard/Hybrid recovery drill now restores via `backup_recovery.py reconcile`
with a separately retained manifest hash and old/new reports. It checks source inventory
preservation, exact restored account bytes, write and rotation receipt continuity, client
pin preservation, and rejection of login for an account disabled after the baseline.
Wrong hashes/releases, conflicting baseline reports, stale candidates, wrong expected
heads and existing outputs fail. Backup safety tests inject publication failure and
verify no completion marker is left and the source stays unchanged. These tests do not
establish partial replay, identity-change reconciliation, power-loss durability
or real-device restore readiness.

### Group revocation across complete-server reconciliation

The shared-recipient drill now captures a complete baseline before membership removal,
removes the read-only member and rotates, captures a complete successor, and reconciles
against both independently retained reports and the successor manifest hash. It verifies
source inventory and exact account bytes, deletes the original server/client directories,
and starts the reconciled server on an isolated loopback port in both profiles.

The remaining owner receives the same scoped export and rotation receipt and can decrypt.
The removed member's old CLI grant is invalid after restart. A freshly approved CLI
session authenticates their account, but collection listing and roster/epoch/receipt
reads enforce removal. Their existing user backup key still
identifies them, but excludes the group and rejects its export. Fresh account login also
cannot list/read the group. Retained client pins remain unchanged. This covers membership
removal followed by rotation; authority identity replacement, independently enrolled
devices and production cutover remain separate scenarios.

### Editor-to-reader downgrade across complete-server reconciliation

Run `python3 scripts/test_entry_shared_recovery.py --role-downgrade` with the same
experimental binaries. CI runs this separately for Standard and Hybrid delivery.
The recipient begins with edit permission and stages an encrypted transaction. After
the administrator removes edit permission, submission returns 403 while the transaction's
expected head still matches the server. The accepted head remains unchanged; the reader
can still export their own encrypted package.

The authority rotates with both members retained. After complete-successor reconciliation
and removal of the original server/client directories, the restored group preserves the
reader role. Fresh browser and CLI sessions reject the retained transaction. The retained
identity/pin copy explicitly accepts the rotated epoch, then recovers and decrypts every
live entry from its own scoped export. A fresh CLI write fails without publishing a draft
or changing the accepted pin/server head. The pending encrypted draft remains unchanged.
This uses synthetic directories sharing one enrolled identity, not independent device keys.

### Replacement identity across complete-server reconciliation

Build the synthetic fixture with `cargo build --locked -p petika-core --example
recovery_identity_fixture`, then run `python3 scripts/test_entry_shared_recovery.py
--identity-replacement`. CI runs both delivery profiles. The fixture uses a known test
passphrase and must never generate production identities.

After capturing the baseline, the reader replaces their identity through the authenticated
API using the expected identity/bundle versions and account password. Replaying that
replacement conflicts without modifying the new identity. Until rotation supplies a
current package, export fails closed (currently HTTP 503). The reader restores the new
identity using its separately known fingerprint and independently verifies the vault
authority again. The authority explicitly verifies the replacement fingerprint and
rotates with the reader still a member.

The reconciled server preserves the exact replacement identity/bundle, group state and
rotation receipt. Its scoped export targets the new identity version. The old key cannot
accept the new epoch, and this failure leaves the pin unchanged. Explicit acceptance with
the replacement key succeeds and the exported live entries decrypt. Testing the retired
key against the exact new pin also fails, separating key rejection from rollback rejection.
Historical retained ciphertext remains decryptable with the retired key. These are
synthetic software identities, not hardware enrollment, biometric recovery, authority
identity replacement or production cutover evidence.

### Baseline plus journal/access delta recovery

`python3 scripts/test_entry_recovery.py --delta-recovery` uses the real CLI/server in both
Standard and Hybrid profiles. After a full baseline it accepts a new entry, disables an
account and rotates the vault. It captures only a recovery delta, verifies unchanged journal
records were omitted, then removes the original server and client directory. No newer full
backup is created. Reconstruction uses the old full backup, delta, independent manifest
hash and retained head reports.

The restored server must preserve the disabled account status, accept the authorized owner,
serve the write/rotation receipts and decrypt at the retained client pin. Wrong baseline,
hash, release, conflicting/incorrect head evidence and missing current-account blobs are
rejected without publishing an output. Source inventories stay unchanged. Existing corruption
and rollback tests also exercise the reconstructed candidate. `scripts/test_backup_delta.py`
covers source mutation, missing/corrupt fragments, path and symlink rejection, deletions,
file-to-directory transitions, no overwrite and failed publication without a completion marker.
Filesystem tests mock the native audit; the two-profile drill supplies actual journal validation.

### Large chunked exports and separate-host recovery

`python3 scripts/test_entry_chunks.py` creates 64 large entries plus an initial entry through
the real CLI/API in each profile. Aggregate ciphertext exceeds 16 MiB. It captures a
version-3 bundle, deletes the old client/cache, decrypts every recovered entry, and checks
missing/corrupt chunks, wrong heads, interrupted capture, output reuse and unchanged pins.
`scripts/test_chunk_backup.py` separately exercises downloader/bundle failures with synthetic
transport responses; server scope/revocation checks also cover the chunk endpoint.

To retain only synthetic encrypted kits for another host, run:

```sh
python3 scripts/test_entry_chunks.py --retain-kit /private/new-synthetic-kits
python3 scripts/drill_cross_platform_recovery.py \
  --kits /private/new-synthetic-kits \
  --image registry.example.com/your-project/petika:EXACT_COMMIT-recovery-qa \
  --registry-namespace petika --registry-secret your-registry-pull-secret \
  --output /private/cross-platform-evidence.json
```

The QA image must be built with `PETIKA_EXPERIMENTAL_ENTRY_FORMAT=1`; the ordinary deployed
image stays at its default. The optional Gitea `recovery-qa.yml` workflow builds that image
only when explicitly dispatched. The runner creates and deletes a unique namespace, copies
only the selected registry pull credential, uses ephemeral storage and mounts no production
data. It records source/target architectures, target release/digest, per-profile ciphertext
sizes, decrypted counts, pin preservation and wrong-passphrase rejection. This demonstrates
software-key restore between hosts/platforms, not hardware enrollment, biometrics or recovery
of production data. Review recorded results before marking R07 complete.
