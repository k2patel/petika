# Off-site backups

Petika supports S3-compatible and SSH/SFTP destination profiles in **Settings →
Off-site backups**. Each user manages their own profiles. Administrators can also
manage separate **Operator full-server destinations**. A profile contains only a
name, storage type and repository URL; saving one does not schedule a transfer.
Download the profile to the backup machine.

User backup API keys are generated in the same dialog after account-password
confirmation. The raw key is shown once; Petika stores its SHA-256 hash. Keys are
read-only, expire within 365 days, and can be revoked. Disabling the account or
changing its password invalidates its keys. A key can download only that user's
personal collection, current group collections, encrypted recipient identity,
and recipient grants. Administrator keys have no membership bypass. Revocation
cannot retract copies already downloaded.

Full-server archives include account data, all collections, configuration, and Git
history. Only the operator can create these, using the offline procedure in
[recovery.md](recovery.md). User API backups are current collection snapshots, not
full-server disaster recovery or Git-history archives. Multiple collections are
captured sequentially, not as a transactional point-in-time snapshot.

## Configure a backup machine outside the homelab

Install Python 3.9+ and restic (tested with 0.19.1). Copy this repository's `scripts`
directory to the machine. Use a separate repository and password for each user
and for full-server backups. Keep the repository password, recovery passphrases,
and repository ID independently of the homelab and the repository itself.

Supported profile repository URLs:

- S3: `s3:https://s3.example.net/bucket/petika`
- SSH: `sftp://backup@backup.example.net//srv/backups/petika`

Use a provider outside the homelab. Put S3 credentials in the runner's protected
environment (`AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY`), or configure an SSH
identity and independently verified host key in the runner's SSH configuration.
SSH runs with batch mode and strict host-key checking. Never embed credentials in
profiles. See [restic's repository configuration](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html).

Create owner-only files for the repository password and the user API key
(`chmod 600`), using a password manager or private editor rather than shell
arguments/history. For each downloaded destination profile, initialize once:

```sh
python3 scripts/offsite_backup.py --profile-file destination.json \
  --password-file /private/path/repository-password init --receipt repository.json
```

Retain the full `repository_id` from this receipt independently. Subsequent
commands require `--repository-id FULL_ID`; this detects accidental repository
substitution. Repeat setup for both S3 and SSH if both copies are desired.

## Capture and publish

A user runner downloads encrypted data with its user-scoped API key:

```sh
python3 scripts/user_backup.py --server https://petika.example.net \
  --api-key-file /private/path/backup-key --output /private/staging/user-2026-10-18
```

The API uses `/v1/backup/index` and `/v1/backup/collections/ID` with a Bearer key.
Keys cannot authenticate ordinary account, administrator, or write endpoints.
HTTPS is required except for loopback; redirects are rejected. The current
homelab HTTP address requires HTTPS configuration or a protected loopback tunnel
before a remote runner can use it.

For full-server backups, first create and verify an offline bundle using
`backup_recovery.py create` as described in the recovery runbook. It includes
`data/backups.json`, which stores key hashes and destination profiles.

Publish either kind of bundle to each destination:

```sh
python3 scripts/offsite_backup.py --profile-file destination.json \
  --password-file /private/path/repository-password --repository-id FULL_ID \
  publish /private/staging/user-2026-10-18 --host alice-backups \
  --receipt /private/receipts/s3-2026-10-18.json
```

A receipt is issued only after downloading the uploaded snapshot without a cache
and verifying its files against the source manifest. Keep receipts outside the
homelab. Use unique staging directories and receipt filenames. Schedule these
commands in your external runner and alert on nonzero exits; Petika does not run
an internal transfer scheduler. A failed verification may leave an uploaded
snapshot, but produces no success receipt. Local repository mode is only for
tests and does not provide off-site protection.

## Recover and check retention

```sh
python3 scripts/offsite_backup.py --profile-file destination.json \
  --password-file /private/path/repository-password --repository-id FULL_ID \
  fetch --snapshot FULL_SNAPSHOT_ID --output /private/recovered-bundle
```

For server bundles, follow the full restore procedure in `recovery.md`. For user
bundles, inspect `index.json` for collection IDs and authenticate a selected
snapshot with its collection recovery passphrase:

```sh
python3 scripts/user_backup.py --recover-from /private/recovered-bundle \
  --collection COLLECTION_ID --cli /path/to/petika --output /private/recovered.petika
```

This authenticates the encrypted collection using the native CLI before publishing
it into a new file. It never writes to the server. Keep the encrypted identity
and grants in the bundle as well; the recovery command uses the collection's
recovery passphrase. Recovery fails safely if that passphrase is incorrect.

Use the same repository arguments with `check` to download and authenticate all
repository data. Use `retention-plan --host alice-backups` to preview 7 daily,
4 weekly, 12 monthly and at least 2 recent snapshots. This is a dry run and never
prunes. Approve deletion separately after verifying independent copies and a
recovery drill. Restoring an old full-server archive also restores historical
account/key state: revoke obsolete backup keys before exposing a restored server.
