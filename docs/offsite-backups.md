# Off-site backups

**S3 and SSH/SFTP are server-push destinations. The backup API is pull-only.**
Configure both kinds of push destinations in **Settings → Off-site backups**.
Each user owns their destinations and encrypted credentials. Administrators have
separate **Operator full-server destinations**. No external runner is required
for push jobs. Only API pull clients run externally.

## Enable server push

Use the `push-runtime` Docker target. It includes Python, restic 0.19.1 and OpenSSH;
the default `runtime` target remains distroless and does not run push jobs. The
Gitea image workflow builds `push-runtime` with the source commit as its release ID.

```sh
docker build --target push-runtime --build-arg PETIKA_RELEASE=YOUR_COMMIT -t petika:push .
```

For native deployments, install Python 3.9+, restic 0.19.1 and an OpenSSH client,
then set these server environment variables:

- `PETIKA_BACKUP_SCRIPT`: absolute path to `scripts/server_backup.py`.
- `PETIKA_BACKUP_RELEASE`: exact compatible binary/image release for full restores.
- `PETIKA_BACKUP_PYTHON` and `PETIKA_BACKUP_RESTIC`: optional executable paths.
- `PETIKA_BACKUP_WORK_DIR`: optional private staging filesystem outside the data
  and mirror directories. Allow room for the captured bundle and downloaded
  verification copy; the default is the operating system temporary directory.
- `PETIKA_BACKUP_MASTER_KEY_FILE`: optional protected file containing exactly
  32 random bytes. If omitted, Petika generates `data/backup-master.key` with
  owner-only permissions when credentials are first saved. Mounting the key from
  a separately managed server secret protects against theft of only the data volume.

Keep one server writer per data directory. Petika holds an instance lock and
serializes its API and local mirror writers during capture. External programs
must not mutate these directories. The homelab Git push sidecar mounts the mirror
read-only. During capture, API requests return a retryable HTTP 503 while health checks
remain available. Network transfer runs after the writers resume. Allow enough
staging capacity for your data volume; capture has a five-minute timeout.

The server polls due jobs every five seconds and runs one at a time. Schedules
are intervals of 1–720 hours. **Back up now** queues a job, including for a disabled
schedule. Last attempt, last verified success, repository ID and snapshot ID are
persisted. A restart retries an interrupted job after its two-hour lease expires.
A failed job has a generic status, never provider diagnostics that may expose secrets.
The worker does not automatically prune repository history.

## Configure push destinations in Settings

For each destination, enter its name, repository URL, schedule, repository password,
and provider credentials. Use independent storage outside the homelab:

- S3: `s3:https://s3.example.net/bucket/petika`, access key, secret key, optional
  session token and region. Renew expiring session tokens before they expire.
- SSH: `sftp://backup@backup.example.net//srv/backups/petika`, a dedicated OpenSSH
  private key without an interactive passphrase, and an independently verified
  `known_hosts` entry. Host-key checking is mandatory. Jobs use only the saved
  identity and host keys, with no ambient SSH agent or SSH configuration.

For a new repository, select **Initialize a new encrypted repository on first
run**. For an existing repository, supply its full ID and current password.
Initialization never replaces an existing repository. The first completed attempt
retains the initialized repository ID even if the subsequent upload fails. If the
server crashes between initialization and recording the ID, obtain that ID using
restic with the retained password and enter it in Settings before retrying.

Save a copy of each repository password independently of the homelab. The server
needs these passwords to encrypt backups; collection recovery passphrases remain
separate and are never required by the push worker.

Credentials are encrypted with XChaCha20-Poly1305 and bound to their owner and
destination. APIs return only `credentials_configured`, never saved credentials
or ciphertext. Leave all credential fields blank when editing to preserve them;
provide the complete set to replace them. Changing the repository URL or storage
type clears existing credentials and verification state. Running jobs cannot be
edited or removed until they finish. Deleting a destination removes its local
credentials, not the remote backups. Server administrators who control the master
key and process can decrypt provider credentials; this is server-managed encryption,
not protection from the server operator.

A push job captures and verifies a bundle, encrypts/uploads it with restic, then
downloads it without using a cache and verifies its files. Only that final check
marks the job **verified**. A failed verification may leave a remote snapshot.

User jobs include only currently authorized personal/group snapshots, encrypted
recipient identity and that user's recipient grants. Disabled users cannot start
new jobs. Permission changes after capture cannot retract a copy already captured
or uploaded. User bundles contain no account database or full Git history.

Operator jobs include all server data, the local Git mirror, the API token,
credential-encryption master key, and supported server settings. Keep infrastructure
manifests, TLS/proxy secrets and other deployment configuration in your independent
infrastructure backup. The complete bundle is encrypted by restic before upload.

## API pull backups

Petika generates user-scoped, read-only API keys after password confirmation. The
key is shown once; only its SHA-256 hash is stored. Keys expire within 365 days,
can be revoked, and are invalidated by password changes or account disabling.
Group membership is rechecked on every request; administrator keys do not bypass
membership. These keys cannot access server push credentials or full-server archives.

External software can use `GET /v1/backup/index` and
`GET /v1/backup/collections/ID` with `Authorization: Bearer KEY`. The bundled client:

```sh
python3 scripts/user_backup.py --server https://petika.example.net \
  --api-key-file /private/path/backup-key --output /private/staging/user-backup
```

The key file must be owner-only (`chmod 600`). HTTPS is required except on loopback;
redirects are rejected. API pulls capture collections sequentially rather than as
one transactional snapshot. The current homelab HTTP endpoint needs HTTPS or a
protected loopback tunnel for remote API pull clients.

## Recover independently of the server

Retain the repository URL, full repository ID, repository password, provider
credentials and latest verified snapshot ID outside the homelab. Download the
credential-free profile from Settings and put the password in an owner-only file.
Supply S3 credentials through the recovery machine's protected environment, or
configure its SSH identity and verified host keys. See
[restic repository configuration](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html).

```sh
python3 scripts/offsite_backup.py --profile-file destination.json \
  --password-file /private/path/repository-password --repository-id FULL_ID \
  fetch --snapshot FULL_SNAPSHOT_ID --output /private/recovered-bundle
```

For server bundles, follow [recovery.md](recovery.md). Restore `config/token`,
`config/backup-master.key`, and the recorded server settings to their configured
locations. Start isolated and disable the push worker until account/key state and
schedules have been reviewed; restored historical state can re-enable old keys/jobs.

For user bundles, inspect `index.json` for collection IDs and authenticate a
selected snapshot using its collection recovery passphrase:

```sh
python3 scripts/user_backup.py --recover-from /private/recovered-bundle \
  --collection COLLECTION_ID --cli /path/to/petika --output /private/recovered.petika
```

This authenticates before publishing into a new local file, without server writes.
Use the same repository arguments with `check` to read/authenticate all repository
data, or `retention-plan --host petika-OWNER_ID` (`petika-operator` for full-server
jobs) to preview 7 daily, 4 weekly, 12 monthly and at least 2 recent snapshots.
The retention plan is a dry run. Approve deletion separately after validating
independent copies and recovery. Provider transport tests require real endpoints;
local adapter tests verify scheduling, credential isolation and encrypted recovery.
