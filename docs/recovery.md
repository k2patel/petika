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
  --context kubernetes-admin@homelab \
  --image git.k2patel.in/k2patel/petika@sha256:EXACT_IMAGE_DIGEST \
  --source-node desk --restore-node vashu --storage-class nfs-csi \
  --registry-secret-namespace petika --registry-secret gitea-registry \
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
