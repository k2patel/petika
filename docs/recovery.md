# Sync, backup, and recovery

The API is authoritative; Git is a one-way ciphertext mirror. A full disaster restore
and recovery of a historical collection are different operations. The operator tool
[`scripts/backup_recovery.py`](../scripts/backup_recovery.py) supports both using Python 3
and Git. Historical recovery also requires the matching native `petika` CLI.

## What to retain

| Material | Full server backup | Ciphertext Git mirror |
| --- | --- | --- |
| Current snapshots and accepted revision journals | Yes | Accepted ciphertext history |
| Account IDs, password hashes, groups, permissions, deployment ID | Yes | No |
| Encrypted identity bundles, recipient grants, retry receipts | Yes | No |
| Local identity/contact/epoch files and their passphrases | Separate client backup | No |
| Group recovery passphrase for each retained epoch | Separate secure custody | No |
| Runtime configuration, tokens, TLS material, exact release/image digest | Operator-supplied config directory | No |

A full backup contains sensitive server metadata and credentials, even though collection
secrets remain encrypted. Store it on encrypted, access-controlled storage, independently
of the ciphertext-only Gitea repository. Never push full backups to that repository.
Keep client recovery material and independently recorded identity fingerprints separately.
An encrypted identity without its passphrase is not recoverable. A v2 Git snapshot can be
opened with that epoch's group recovery passphrase; the mirror has no recipient grants.

## Experimental entry-format recovery

Entry-format collections require the matching experimental build. Full backups already
copy the entire journal, immutable records, committed root, epoch wrappers, migration
source, account database and configuration. A valid inventory proves byte preservation;
it does not prove that a client can unlock the collection or that the backup is current.
Do not delete the retained legacy snapshot after migration.

Build the matching operator checker separately if it is not present in the deployed
image (the runtime image does not include this extra binary):

```sh
cargo build --locked -p petika -p petika-server --features experimental-entry-format
```

While the server is stopped, record its entry heads in a separately retained, protected
file before creating the full backup:

```sh
umask 077
target/debug/petika-entry-recovery /stopped/petika/data > /private/entry-heads.json
```

Use a new report filename and preserve older reports. Check the command's exit status
before retaining that report. It acquires the server's
instance lock, opens each committed journal, validates its complete ancestry, receipts,
checkpoint/wrapper state and account/deployment/collection binding, and compares the
retained migration snapshot with its signed source. It does not start a server, migrate
accounts, decrypt entries or reconstruct missing state. Lock sidecars may be created.
An empty report means no committed entry roots were found, not proof that none were lost.

After the ordinary full restore and inventory verification below, compare against the
independently retained report **before** starting the isolated instance:

```sh
target/debug/petika-entry-recovery /recovery/petika/data \
  --expect /private/entry-heads.json
```

Missing/older roots, account/context mismatches, damaged records or changed retained
migration sources stop verification. The report contains public IDs and cursors, not
vault keys. Keep it independently: a replacement of both report and backup cannot be
detected by this comparison. Never regenerate the expected report from the restore to
make a mismatch pass.

### Retain and verify each client kit

Separately back up the protected local identity bundle (including verified contacts),
its passphrase, the exact local pin, original anchor and complete cache. The cache needs
all live entry ciphertexts, current epoch state and recipient/recovery wrappers, plus
retained drafts/receipts needed for reconciliation. Keep recovery passphrases separately.
A synchronized index alone does not guarantee every entry object is cached. Preserve
newer client pins before inspecting an older server restore; never overwrite them with
pins from that older backup. Account/API sessions are replaceable: sign in again when
connecting to the restored server rather than relying on restored login credentials.

Verify a copied client kit without an API connection:

```sh
petika --no-config entries verify-backup --anchor /private/client-kit/anchor.json \
  --pin /private/client-kit/pin.json --cache /private/client-kit/cache \
  --recipient-identity /private/client-kit/identity.json
```

Use the actual original anchor path printed by migration or handoff. Alternatively,
replace `--recipient-identity` with `--recovery /private/client-kit/cache/recovery-WRAPPER_ID.json`
and enter that epoch's recovery passphrase. Run the checks for every recovery route
you intend to rely on. The command authenticates the pinned index and decrypts/parses
**every live entry** without printing names, passwords or TOTP values. Missing, changed
or wrong-context objects fail; the pin is never initialized or reset. Identity unlock
may reseal contact state using the existing protected-bundle handling. Success proves
that selected kit and unlock path work, not global freshness or other users' readiness.

The disposable `python3 scripts/test_entry_recovery.py` drill covers both Standard and
experimental Hybrid migration, rotation, full-server and separately retained client-kit
restore, recovery/identity unlock, receipt continuity, missing/corrupt data and rejection
of a pre-migration server by a newer client pin. It uses local servers and synthetic
secrets; it does not establish a production recovery time or physical power-loss guarantee.

### Compare a restore with evidence of newer writes

Keep the isolated server stopped. Preserve the original backup, later client kits,
accepted drafts/receipts, and any newer complete server backups before investigating.
With the matching experimental operator binary, compare the restored journal against
a recovery report retained independently from the backup being evaluated:

```sh
petika-entry-recovery /private/restored/data \
  --compare /private/retained/newer-entry-report.json > /private/comparison.json
```

`--compare` holds the server-instance lock throughout verification and comparison. It
prints a public JSON assessment: no vault plaintext or usable keys. Exit **0** means
all reported entry heads/checkpoints match; **2** means the comparison succeeded but
requires reconciliation; **1** means invalid evidence or failed structural validation.
A nonzero exit must not be treated as permission to start the server. Existing `--expect`
continues to require an exact retained report. Neither mode authorizes deployment.

| Collection status | Meaning and next step |
| --- | --- |
| `matches` | Same head, epoch and checkpoint. Still compare client pins and decrypt. |
| `retained-head-in-local-history` | The validated local journal contains the exact retained head and checkpoint, followed by later records. Preserve those records; verify newer client evidence before cutover. |
| `newer-retained-head` | Retained evidence names a later revision that this restore lacks. Obtain a newer complete journal with receipts and matching account/membership state; do not reset client pins. |
| `conflicting-history` | The same revision or claimed historical checkpoint differs. Isolate both copies; do not merge encrypted files or force-push Git. |
| `missing-collection` | A retained collection is absent from the restored entry roots. Locate its complete backup. |
| `not-in-retained-report` | The restore contains a collection absent from the report. Obtain independent evidence for it. |

A report is protected external evidence, not a signed client acceptance, global freshness
proof or complete account-state comparison. A higher retained revision is an unresolved
claim until its history is available. Even a structurally verified descendant must be
decrypted against independently retained client trust. An empty matching report says
nothing about vaults absent from both copies. Structural inspection may create lock
sidecars; it does not rewrite journals, receipts, account records or client pins.

This is **comparison and triage**, not automatic write replay. Prefer a complete newer
backup and validate it separately. Client caches and Git trees alone do not restore
server receipt continuity, membership changes or account state. Do not replay stale
writes, re-run migration, drop history, or manufacture a replacement pin to make an old
restore pass. Partial import/replay with account/access reconciliation remains unfinished;
keep a restore with unresolved newer evidence isolated.

### Stage a complete successor backup

If a complete newer backup survives, `backup_recovery.py reconcile` can stage it into a
new private directory. Preserve the earlier restore. Retain the newer backup's exact
`manifest.json` SHA-256 through an independent trusted channel at capture time, along
with its compatible release and entry recovery report. Computing a hash from an
untrusted candidate alone does not establish its authenticity or freshness.

```sh
python3 scripts/backup_recovery.py reconcile /private/newer-backup \
  --release RECORDED_RELEASE \
  --baseline-report /private/evidence/older-entry-report.json \
  --expected-report /private/evidence/newer-entry-report.json \
  --expected-manifest-sha256 INDEPENDENTLY_RETAINED_MANIFEST_SHA256 \
  --recovery-tool target/debug/petika-entry-recovery \
  --output /private/reconciled-candidate
```

The command verifies the selected manifest and full inventory, restores a temporary
candidate with the matching release, checks every expected entry head, and proves
that every older retained collection is present in the candidate's journal history.
At least one retained collection must have advanced. New collections are accepted
only when included in the exact newer report. Conflicting/missing history, stale
candidates, empty evidence and existing destinations fail without replacing anything.

All accounts, membership/access state, receipts, journals, mirror state and configuration
come from the **same selected complete backup**. No older accounts are combined with
newer ciphertext, and no fragment is replayed. The retained manifest hash identifies
that capture's entire inventory; it does not prove that the capture contains every
subsequent revocation or write. Establish the authoritative capture independently.
If later access changes are known but absent, keep the candidate isolated.

Evidence files are limited to 16 MiB each; each native audit has a 120-second timeout.

`RECONCILIATION.json` is fsynced in temporary storage and linked into the output last. It records the manifest/report hashes, ancestry
assessment and next checks. An interrupted or failed copy can leave an incomplete output
without this marker: do not start it; retain the source and retry into another directory.
The command does not produce `RESTORE.json` or switch a deployment. Source backups,
older restores and client pins remain unchanged. Auditing may add lock sidecars to the
candidate. Protect the candidate because it includes server credentials and configuration.

Before cutover, verify retained client pins and decrypt using the recovery workflow,
start the candidate in isolation, test permitted and revoked access, and reconcile known
write/rotation receipts. The synthetic Standard/Hybrid drill verifies both receipts and
that an account disabled after the baseline remains disabled after this staged restore.
The shared-vault drill additionally reconciles a pre-revocation baseline with a complete
post-revocation backup, deletes the original server/client directories, and starts the
isolated restored server. It verifies exact group/account state, owner exports and the
rotation receipt. Old CLI sessions are not restored. The removed member's persisted
backup key still identifies their account but cannot list/export the group; fresh browser and CLI
sessions also cannot list/read the group. Historical copies remain decryptable. Identity
replacement across full-server reconciliation still needs dedicated validation. If no
complete successor backup survives, safe partial-journal import/replay with account/access
reconciliation remains unsupported.

### Recover entry ciphertexts from Git or a user export

Opt-in entry-format builds support offline recovery into a **new encrypted cache**.
Retain the client pin and identity (or recovery passphrase) independently. Recovery
requires the backup head to equal that pin exactly: older and newer heads fail without
rollback, advancement or trust reset. Preserve historical pins separately if you need
historical recovery. These commands do not reconstruct accounts, API journals or receipts.

For Git, obtain a complete local clone and choose a full lowercase commit hash:

```sh
petika --no-config entries recover-git --repository /private/backup.git \
  --commit FULL_COMMIT_HASH --pin /private/client-kit/pin.json \
  --recipient-identity /private/client-kit/identity.json --output /private/recovered-cache
```

Alternatively, replace `--recipient-identity` with `--recovery-wrapper-id WRAPPER_ID`
and enter the explicitly selected epoch recovery passphrase. Shallow clones, unexpected
files, missing objects and mismatched pins are rejected. Git is read locally; the command
does not push, merge or resolve divergent history. Aggregate ciphertext recovery is
currently limited to 16 MiB.

User backup API exports now support migrated collections in entry-enabled builds. Each
version-2 collection contains the encrypted index and live entries, signed checkpoint,
**only that user's recipient package**, and authenticated wrapper IDs/digests. It excludes
other users' packages, recovery wrappers, account databases and receipts. Current account,
membership and identity checks still apply. The surrounding bundle stays version 1 and
may contain both legacy and entry collections. Default builds still refuse entry exports.

```sh
python3 scripts/user_backup.py --recover-from /private/user-backup \
  --collection COLLECTION_ID --pin /private/client-kit/pin.json \
  --recipient-identity /private/client-kit/identity.json --output /private/recovered-cache
```

The script verifies the bundle manifest, then invokes `entries recover-backup` to verify
local trust, unlock the user's package and decrypt/parse every live entry. A manifest
alone provides no cryptographic trust. Both recovery commands publish ciphertext only,
print the new anchor path and leave the pin/server unchanged. Use the printed anchor,
retained pin, new cache and `--handoff /private/recovered-cache/handoff.json` with the
recipient identity in `entries verify-backup` and subsequent offline entry commands.
Recovery-key mode instead writes `recovery-WRAPPER_ID.json` for `--recovery`.

`RECOVERY.json` is written last as a completion marker. Authentication failures publish
no directory; storage failures can leave an incomplete directory without that marker.
Keep the source backup and retry into a new directory. Existing destinations are never
overwritten. Larger streaming exports, real-device restore evidence and reconciliation
of writes newer than a backup remain pending. Full-server restoration still requires a
full-server backup and independently retained client trust.

### Shared-vault restore and revocation checks

Run `python3 scripts/test_entry_shared_recovery.py` with the same experimental native
build used above. It exercises an owner and a read-only recipient in both Standard and
experimental Hybrid profiles: mutual contact verification, independent checkpoint
confirmation, scoped exports, explicit rotation acceptance and fresh-cache recovery.
A second simulated recipient device receives only a retained encrypted identity and
pin; it receives no account session, authority key, recovery wrapper or old entry cache.
Offline recovery checks run after stopping the original server and deleting the original
client directories. A reconciled server is then started separately for access validation.

Removing a recipient blocks further group exports. Rotate the vault root afterward to
exclude them from future key delivery. The drill checks both controls and verifies that
the removed recipient cannot unlock the owner's package at the new checkpoint. **Revocation
cannot erase ciphertext or keys already retained by that person.** Their historical
exports still decrypt with the matching historical pin and identity; the current pin
continues to reject older backups. Existing passwords already disclosed may need changing
at the corresponding websites/services.

This is synthetic local-filesystem evidence, not a claim that every real device is ready.
The simulated devices reuse one user's enrolled identity, rather than independently
enrolled hardware keys. Actual device loss/replacement, identity replacement, biometric
unlock, cross-platform key custody, and production recovery objectives remain separate
release checks. Preserve independently verified pins and encrypted identity backups for
each recipient, and test the recovery routes you intend to rely on.

## Full offline backup

Stop **all** processes writing the data and mirror directories before copying, including
server replicas and any mirror maintenance jobs. `--offline` is the operator's attestation;
the tool cannot stop or lock an arbitrary deployment. It compares source inventories before
and after copying, but that is not a substitute for stopping writers or taking a consistent
storage snapshot. Back up the entire data directory, including journals, grants, deployment
identity, and schema migration backups. Do not select individual JSON files.

Prepare a private configuration directory containing the deployed environment/configuration,
secret files, and an inventory of external dependencies. Preserve the exact compatible image
digest or binary release and web assets. Do not include symlinks: materialize Kubernetes
Secret/configuration files into this private directory. Keep passphrases separately.

```sh
umask 077
python3 scripts/backup_recovery.py create --offline \
  --data /stopped/petika/data --mirror /stopped/petika/mirror \
  --config /private/petika-config --release 'sha256:EXACT_IMAGE_DIGEST' \
  --output /backups/petika/2026-10-18
python3 scripts/backup_recovery.py verify /backups/petika/2026-10-18
```

Use an output directory that does not exist. The tool records file sizes, SHA-256 hashes,
empty directories, creation time, and release in `manifest.json`. It rejects overlapping
source/destination paths, links, and special files. All copied files are owner-readable/writable
and directories owner-only on POSIX. A failed copy has no completed manifest; preserve the
original sources and use a new destination for retry. Run with a private, trusted directory
and no concurrent modifications. The backup format does not retain executable bits, ACLs,
or ownership; it is for data/configuration, not executable installation.

Copy the completed directory off-host, then verify the **destination** copy. SHA-256 checks
detect accidental damage and omissions, not malicious replacement of both manifest and files.
Use trusted storage/access controls and independently retained backup records. The tool never
starts services, changes a deployment, or deletes backups.

### Retention and recovery targets

Baseline operator policy: retain 7 daily full backups, 4 weekly backups, and 12 monthly
backups; keep at least one verified copy off-site under independent credentials. Retain the
ciphertext Git history without rewriting it. Retain epoch recovery passphrases for as long
as their historical ciphertext is needed. Removing a member cannot revoke historical copies.

Take a full backup before every upgrade, identity replacement, and significant permission
change. A daily full backup gives a **target** metadata recovery point of 24 hours; the
one-minute Git push interval is only a ciphertext replication target, not a guaranteed RPO.
Monitor failed pushes and backup ages. Measure recovery time during your own deployment drill;
no production RTO is established by the local tests.

Only retire a backup after its replacement has verified at both locations and a retained
backup has passed a recovery drill. Pruning is deliberately manual: do not delete your last
known-good backup or rewrite the live mirror to meet a retention count.

## Restore a full server onto a clean host

Keep the old deployment stopped and preserve its volumes for investigation. Verify your
chosen backup and explicitly record its date: restoring it also restores old permissions,
password hashes, identity versions, and revision counters. Revision checks cannot detect an
operator rolling back the whole server database. Reconcile changes made after the backup
before allowing clients to reconnect.

```sh
python3 scripts/backup_recovery.py restore /backups/petika/2026-10-18 \
  --release 'sha256:EXACT_IMAGE_DIGEST' --output /recovery/petika
```

The destination must not exist. The tool verifies the full inventory before copying and
checks the restored files again. `RESTORE.json` is written only after successful verification;
never start from an incomplete staging directory. Install the matching release separately.

1. Mount restored `data` and `mirror` directories into an isolated instance. Configure it
   from the retained `config` files; adjust file ownership to the container runtime UID
   (65532 for the current image), keeping owner-only access. Use
   `fsGroupChangePolicy: OnRootMismatch`, as in the production manifest; recursive
   fsGroup changes on remount can add group access and make Petika reject restored files.
   Initialize each empty PVC using the same maintenance-pod security context **before**
   restoring private files. Keep the initialized PVC root ownership/permissions; restore
   into private subdirectories beneath it. Replacing the PVC root with a mode-0700
   directory can trigger recursive permission changes even with `OnRootMismatch`. Do not expose it publicly yet.
2. Use `PETIKA_SETUP_MODE=disabled`; restored accounts must load without creating a new
   deployment identity. Temporarily set an isolated `PETIKA_ENDPOINT` and listener. Leave
   remote mirror replication off until history has been compared with the remote backup.
3. On a fresh client, sign in again. Browser and CLI sessions are memory-only and do not
   survive server restart. Restore the encrypted recipient identity using its independently
   retained fingerprint, then pull and decrypt each critical collection:

   ```sh
   petika --session-file /private/new-session.json login --server https://recovery.example
   petika --session-file /private/new-session.json --identity-file /private/new-identity.json \
     keys restore --fingerprint INDEPENDENTLY_RECORDED_FINGERPRINT
   petika --session-file /private/new-session.json --identity-file /private/new-identity.json \
     --store /private/recovered.petika keys pull --collection COLLECTION_ID
   petika --identity-file /private/new-identity.json --store /private/recovered.petika list
   ```

4. Verify group permissions, rotation-required state, current epochs, and representative
   entries. Keep existing clients' epoch/contact files: they can expose trust rollback.
   Do not delete them to suppress a rollback error. Compare with independently retained
   fingerprints, membership records, and post-backup changes.
5. If the remote mirror is ahead, preserve both histories. Do not force-push an older
   local mirror. Recover missing history locally and reconcile through authenticated
   writes, or start a separately retained recovery backup repository. Only after review,
   restore the canonical endpoint/TLS, route traffic, and enable replication.

For the homelab, use a separate recovery namespace/PVC pair for validation. The distroless
server has no shell or `tar`: use an operator-controlled maintenance pod mounting the stopped
PVCs or storage-native consistent snapshots. The Git sidecar has only the mirror volume;
it cannot create a complete server backup. This tool does not stop the live cluster or
provision off-site storage automatically.

## Recover a historical Git snapshot locally

Clone the **full bare repository** from the private backup using your credential helper;
never put a token in a URL or command argument. Gitea stores managed histories as
`collections/<opaque collection ID>` and legacy history as `legacy`.

```sh
umask 077
git clone --bare https://git.example/owner/petika-vault-backup.git /private/backup.git
python3 scripts/backup_recovery.py history /private/backup.git \
  --branch collections/COLLECTION_ID
python3 scripts/backup_recovery.py recover /private/backup.git \
  --commit FULL_COMMIT_ID --cli /usr/local/bin/petika \
  --output /private/historical.petika
petika --store /private/historical.petika list
```

Select the exact full commit ID deliberately. The tool checks Git object integrity,
rejects shallow clones and missing/out-of-order revisions, reads the bounded `snapshot.json`, and invokes the native CLI to
fully authenticate/decrypt it before publishing a new owner-only encrypted file. Entry
names are suppressed during verification; plaintext is never written by this tool.
`--passphrase-stdin` is available for secure scripted input. Wrong/missing keys, corrupt
ciphertext, missing objects, and existing destinations fail without publishing a file.
For migrated/rotated collections, supply the recovery passphrase for the selected epoch.
It supports Standard and experimental hybrid snapshots, envelopes v1 and v2.

This recovers a local historical copy; it does not rewind a live server. An authentic older
snapshot is still authentic: Git hashes and encryption cannot establish that it is current.
Keep the original backup immutable, and record the selected commit and recovery reason.

### Publish recovered contents safely

For a legacy/passphrase collection, first inspect the recovered file, obtain the **current**
server revision with `petika status`, and push using that revision:

```sh
petika --session-file /private/session.json status --collection COLLECTION_ID
petika --session-file /private/session.json --store /private/historical.petika \
  push --collection COLLECTION_ID --revision CURRENT_REVISION
```

This creates a new current revision. If another client writes first, the push fails; pull
into a different file and reconcile explicitly. Never overwrite server JSON or copy an old
journal over current data to restore one collection.

For recipient-enabled v2 collections, a historical envelope may have an old key epoch.
Do not upload it through legacy `push`, downgrade the collection, or restore stale grants.
Pull the current collection with `keys pull`, unlock the historical file separately using
its epoch recovery passphrase, and re-enter the selected recovered entries through the
current client; publish with `keys push --revision CURRENT_REVISION`. This encrypts with
current access state and enforces revision/epoch checks. Automated historical merging and
a restore UI are not implemented; full account disaster recovery uses the matched full
backup procedure above.

## Validation

```sh
python3 scripts/test_backup_recovery.py
python3 scripts/test_backup_recovery.py --drill
```

The drill requires built `target/debug/petika` and `petika-server` binaries plus Git. It
provisions synthetic accounts and groups in both encryption modes, migrates and rotates,
backs up, **deletes the original server and client directories**, and restores into a new
server process and fresh client. It checks account identity, identity-bundle restore,
recipient grants, local v1/v2 historical recovery, wrong keys, incomplete mirrors, damaged
ciphertext, refusal to overwrite files, and historical publication with stale-write rejection.
Unit checks cover missing/changed/extra backup files, release mismatch, links, and overlap.
These tests are wired into CI. They establish clean-directory recovery, not an off-site-storage
or exhaustive power-loss drill. Use the separate cluster drill below to validate Kubernetes
PVC restoration across nodes. Independent crypto review remains open.


## Isolated Kubernetes drill

[`scripts/drill_kubernetes_recovery.py`](../scripts/drill_kubernetes_recovery.py) creates a
unique temporary namespace, three synthetic PVCs, and digest-pinned Petika pods. It provisions
accounts and rotated collections in both encryption modes, stops the original server, makes
and verifies a full offline backup, deletes the original PVC and client files, and restores
to a fresh PVC on a different node. A fresh client restores its identity using a retained
fingerprint and decrypts both collections. Setup is disabled on the restored server.

Prerequisites: `kubectl` with namespace/PVC/PV/pod permissions, a matching local native CLI,
two schedulable nodes with distinct `kubernetes.io/hostname` labels, a dynamically provisioned
storage class with Immediate binding, and an existing registry pull Secret. The script copies that pull Secret into
the temporary namespace in memory; it never copies production data or other credentials.
The helper image must provide Python 3; its resolved image ID is recorded in the report.

```sh
python3 scripts/drill_kubernetes_recovery.py \
  --context YOUR_KUBERNETES_CONTEXT \
  --image registry.example.com/YOUR_NAMESPACE/petika@sha256:EXACT_IMAGE_DIGEST \
  --source-node SOURCE_NODE --restore-node RESTORE_NODE --storage-class YOUR_STORAGE_CLASS \
  --registry-secret-namespace petika --registry-secret YOUR_REGISTRY_SECRET \
  --report output/kubernetes-recovery.json
```

The script creates no Service or Ingress; client traffic uses loopback-only port forwarding.
It mounts only newly created synthetic PVCs. For each new PVC it verifies the bound PV's
generated PV name plus claim namespace, name, and UID before changing that **test PV only** to a `Delete` reclaim
policy. It removes the temporary namespace and waits for its PVs to disappear, including
on test failure, except when unexpected volume ownership requires manual inspection.
In that case it retains the namespace to avoid deleting a pre-existing volume. If interrupted
forcibly or cleanup fails, use the recorded namespace/PV
names to inspect and finish cleanup; never apply cleanup to the production namespace.

The JSON report records the pinned application image, helper image ID, nodes, synthetic
volumes, checks, elapsed times, and cleanup result. This is a same-storage-system drill;
it does not establish survival of NFS loss or an off-site recovery objective. Run a separate
off-site restore after independent retained storage has been configured. Cluster drills
are explicitly operator-run and are not part of GitHub CI.

The [2026-10-18 result](testing/kubernetes-recovery-2026-10-18.json) passed on the homelab:
Standard and Hybrid rotated collections were decrypted by a fresh client after the original
PVC and client files were removed. Restore plus validation took 56.73 seconds; the entire
synthetic drill including provisioning and cleanup took 229.3 seconds. All temporary
namespaces and PVs were removed. These measurements describe this small synthetic fixture,
not a production recovery-time commitment.

See [off-site backups](offsite-backups.md) for separate user/operator S3 and SSH
profiles, read-only user backup keys, encrypted transfer and download verification.
