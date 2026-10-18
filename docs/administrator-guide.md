# Install and administer Petika

This guide covers server installation, user onboarding, bucket/SSH preparation,
backup operations, upgrades, and recovery. Give everyday users the
[user guide](user-guide.md). Petika remains experimental and unaudited; these
procedures do not establish production readiness or compliance certification.

## Choose an installation

| Requirement | Installation |
| --- | --- |
| Local development | [Source build](deployment.md#build-from-source) with Rust, built WASM, and localhost HTTP |
| Server without push jobs | [Default container runtime](deployment.md#docker); encrypted API and web app |
| Scheduled S3 or SSH backups | `push-runtime` container target, or configured native push worker |
| Kubernetes | [Deployment manifests](deployment.md#kubernetes), one replica, persistent data/mirror volumes |
| Existing homelab | [Homelab overlay](../deploy/homelab/README.md) and `scripts/deploy_homelab.py` |

There is no public ready-to-install binary/container release. Build a reviewed
source revision; the homelab's private registry is not a public download source.
For scheduled push backups:

```sh
git clone https://github.com/k2patel/petika.git
cd petika
git rev-parse HEAD
# Replace SOURCE_COMMIT with the exact checked-out commit printed above.
docker build --target push-runtime --build-arg PETIKA_RELEASE=SOURCE_COMMIT \
  -t petika:SOURCE_COMMIT .
```

Use the [container guide](deployment.md) for UID ownership, mounted secret files,
volumes, and runtime flags. The small `/tmp` example there is for the default
runtime; push jobs need staging space for a captured bundle and a downloaded
verification copy. Mount a sufficiently sized private work directory and set
`PETIKA_BACKUP_WORK_DIR`; keep it outside the data and mirror directories.

Retain the exact image digest or native release for restore. Keep one writer per
data directory. Persist the complete data directory and mirror; restarting a
container without its volumes is not an upgrade.

## Bootstrap the administrator and configure HTTPS

Prepare a protected random setup/API token and an initial administrator password
using the [setup guide](setup.md). Prefer mounted secret files over literal passwords
in manifests or shell commands. A typical initial environment is:

```ini
PETIKA_SETUP_MODE=auto
PETIKA_ADMIN_USERNAME=admin
PETIKA_ADMIN_PASSWORD_FILE=/run/secrets/admin-password
PETIKA_TOKEN_FILE=/run/secrets/token
PETIKA_ENDPOINT=https://petika.example.com
PETIKA_COOKIE_SECURE=true
```

The homelab overlay defaults to `admin` for new installations. Generic manual setup
lets you choose the username. Changing bootstrap variables does not rename an
existing account or reset its password: the earlier homelab account remains `owner`.
The file `/run/secrets/admin-password` supplies a password, not a username.

Point your DNS name to the reverse proxy, install its certificate, and follow the
[Nginx/Caddy guide](reverse-proxy.md). Host the app at `/`, not a subpath. Keep the
browser-facing `PETIKA_ENDPOINT` correct or the app will redirect elsewhere.
Secure cookies remain enabled even when Nginx forwards HTTP to the backend.

For this homelab, the public URL is **https://petika.k2patel.in** and Nginx can use
`http://10.10.12.115:80` as its upstream. `HTTPS=both` currently keeps the bundled
IP TLS listener too. These are deployment-specific values, not universal defaults.

After startup, verify HTTPS `/readyz`, `/config.json`, sign-in, and a synthetic
collection save/reload/unlock. After initial provisioning, remove bootstrap password
sources and optionally use `PETIKA_SETUP_MODE=disabled`. Keep the API token needed
by the running server. Existing accounts continue working in disabled setup mode.

Before changing a public hostname, have users export browser-local identity recovery
material and pending encrypted work; browser storage does not move between origins.

## Create users and manage access

1. Sign in as an administrator. Open **Users → Add user**.
2. Assign a unique username, display name, and initial password. Give administrator
   access only to people who need server administration. Deliver credentials privately.
3. Give the user the server URL and [user guide](user-guide.md). Ask them to change
   their initial account password and set up their own collection passphrase.
4. Use **Groups** for shared collections and choose read/edit membership. Complete
   the separate verified key-delivery flow in [group access](group-access.md).
5. When removing access, disable the account/remove memberships and perform the
   required group-key rotation. Removing membership alone cannot revoke already
   downloaded secrets or historical copies.

Users manage their own active sessions under **Settings → Connected clients**.
The extension preview currently uses a session labelled CLI. User-scoped backup
API keys are managed separately in **Off-site backups**. Account disabling and
password changes invalidate backup API keys; provision replacement automation keys
as appropriate. A server restart invalidates active account sessions.

There is no implemented forgotten-vault-passphrase reset, native biometric unlock,
or universal server-held key that decrypts every collection. Administrator access
does not turn missing user recovery material into a recoverable vault.

## Provide the Chromium package to users

On a build machine, build the web WASM and package the extension for your HTTPS
origin using the [extension build guide](../clients/extension/README.md):

```sh
sh scripts/build_web.sh
python3 scripts/build_extension.py --endpoint https://petika.k2patel.in
```

Distribute the entire `output/extension-chromium` folder, optionally zipped, through
your trusted software-distribution channel. Users load that folder unpacked; they
do not build Rust themselves. Supply the source revision and the user installation
instructions. Keep the exact configured server origin with the package inventory.
The server needs commit `9e9b6dd` or newer for client/website APIs.

Requires Chrome/Chromium 127 or newer. Users can enable a five-minute inline
signup prompt from the unlocked toolbar popup; no broad website host permission
is added. Reload the extension after replacing its package.

This is an experimental Chromium preview, not a store-signed release. Manual
installation and real-site compatibility still need QA. The local integration test
uses synthetic origins and a test-only permission instead of a toolbar gesture.
See its [documented limitations](../clients/extension/README.md#not-implemented).

## Prepare an off-site S3 bucket

Create storage outside the Petika host/cluster and its failure domain. A bucket on
MinIO in the same failed homelab is not an independent disaster-recovery copy.
Petika does not create cloud accounts or administer provider IAM for you.

For AWS, create a dedicated private bucket with all Block Public Access settings
enabled and default encryption. Consider versioning to retain older object versions;
retain independent administrative credentials for recovering those versions.
[AWS bucket access guidance](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-management.html)

Example for a **new bucket in us-east-1**, using an already configured operator AWS
CLI profile. Substitute a globally unique bucket name. These commands create cloud
resources; they are not required on ordinary users' computers.

```sh
petika_bucket=replace-with-your-unique-petika-backup-bucket
aws s3api create-bucket --bucket "$petika_bucket" --region us-east-1
aws s3api put-public-access-block --bucket "$petika_bucket" \
  --public-access-block-configuration 'BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true'
aws s3api put-bucket-encryption --bucket "$petika_bucket" \
  --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
aws s3api put-bucket-versioning --bucket "$petika_bucket" \
  --versioning-configuration Status=Enabled
```

Other regions/providers have different creation requirements. Follow the provider's
instructions rather than copying an AWS command unchanged.
[AWS CLI setup](https://docs.aws.amazon.com/AmazonS3/latest/userguide/GettingStartedS3CLI.html)

Create a dedicated backup identity scoped to this bucket or repository prefix.
It needs the operations used by restic, including listing, reading, writing and
removing its repository objects/locks; validate the exact provider policy with an
initialization, upload, and independent download test. Do not use root credentials
or give the backup identity permission to change bucket policy/versioning. Retain
separate recovery credentials and configure provider-specific KMS permissions if
using a customer-managed KMS key. Provider encryption complements restic encryption;
it does not replace the repository password.

Use separate repositories and credentials for unrelated users and operator backups.
A repository folder is not an access-control boundary unless the provider policy
restricts access to that prefix. For example, use `operator` for full-server backups
and a separate user-specific prefix/repository for each user's copies.

Do not expire arbitrary live objects in a restic repository: old data packs can
still be referenced by newer snapshots. Keep history management at the repository
level. Bucket versioning costs storage; review noncurrent-version lifecycle rules
against your recovery requirements before enabling deletion. Test Object Lock or
immutable retention against repository locking/maintenance before using it on the
working repository. Independently retained copies should not be deletable using
only the credentials stored on the Petika server.

### Enter the S3 destination in Petika

Open **Settings → Off-site backups**. Select **Operator full-server destinations**
for server disaster recovery; stay in **Your backups** for the signed-in user's
currently authorized encrypted collection/identity data.

Choose **Add S3 or SSH destination**, select S3, and fill the guided fields:

| Field | Example or meaning |
| --- | --- |
| Name | `Off-site operator backup` |
| Storage endpoint | `https://s3.us-east-1.amazonaws.com` for this AWS example |
| Bucket name | The bucket you created; do not repeat it in the endpoint |
| Folder in bucket | `operator` or a separate repository prefix |
| Repository encryption password | A new password of at least 16 characters for the restic repository, retained independently |
| S3 access key / S3 secret key | The dedicated provider identity's credentials |
| S3 region / S3 session token | Provider region and temporary-credential token when applicable |
| Back up every (hours) | For example 24 hours; choose based on your recovery-point requirement |

Select **Initialize a new encrypted repository on first run** only for a new
repository. For an existing one, provide its full repository ID and current password.
Petika builds the restic URL from these fields. Advanced URL mode preserves existing
URLs and supports configurations outside the guided form.
[Restic repository configuration](https://restic.readthedocs.io/en/stable/030_preparing_a_new_repo.html)

Check **Enable scheduled server push** for recurring jobs. Save, choose **Back up now**, and use **Refresh status** until **Last verified**
shows success. Download the profile and record the repository and snapshot IDs.
Save does not prove connectivity; a verified job uploads and independently downloads
and checks the bundle, but still does not prove a full application restore.

## Prepare SSH storage

Provision a dedicated account on an independent SSH/SFTP host, a private writable
backup directory, sufficient disk space, and a dedicated public-key login. Keep the
private key in Petika's protected destination credentials; it must work without an
interactive passphrase prompt. Verify the host-key fingerprint through a trusted
channel before entering its `known_hosts` line. A network scan alone does not
establish host authenticity.

In the same destination form, select SSH/SFTP and enter **SSH host**, **SSH username**,
**SSH port**, and an absolute **Backup folder**, such as `/srv/backups/petika`.
Provide the private key, verified host keys, and a separate repository password.
For nonstandard ports, use the correct `[host]:port` known-hosts form. Follow the
same initialize/run/verify/profile-retention steps as S3. Ambient SSH agents/config
are not used by the push worker.

## Operate backups and recovery

| Task | Procedure |
| --- | --- |
| Enable push jobs | Use `push-runtime` or configure the native worker and staging space in the [backup guide](offsite-backups.md#enable-server-push). |
| Review jobs | Inspect last attempt and last verified success; investigate failures or an overdue verified backup. No external alerting is implied. |
| Rotate destination credentials | Edit and provide the complete replacement credential set. Leaving all credential fields blank preserves them. Re-run and verify. |
| Renew temporary S3 credentials | Replace them before expiry, including session token; Petika does not automatically renew them. |
| API pull automation | User generates a scoped backup API key; an external machine uses [user_backup.py](offsite-backups.md#api-pull-backups). This is separate from server push. |
| Retention | Preview the restic retention plan; pruning is not automatic. Validate independent copies before approving deletion. |
| Restore drill | Download onto an independent machine, verify, restore isolated, authenticate a synthetic collection, and record elapsed time/results. |

Retain the repository URL/ID/password, provider recovery credentials, snapshot IDs,
server backup master key, compatible release, runtime settings, and infrastructure
secrets outside the failed server. Keep collection/identity passphrases separately.
Operator bundles include server data, the mirror, token and credential master key;
TLS/proxy secrets and deployment manifests need a separate infrastructure backup.
A user's backup is not a full account/server restore, and a Git mirror is not a
substitute for the account database or identity/grant state.

Follow [independent fetch and recovery](offsite-backups.md#recover-independently-of-the-server)
and the [full recovery runbook](recovery.md#restore-a-full-server-onto-a-clean-host).
Start restored servers isolated with the matching release and push jobs disabled.
Review restored historical accounts, permissions, API keys and schedules before
reconnecting clients. Test a recovery rather than assuming a green upload is enough.

## Upgrade and troubleshoot

Before upgrading, record the running image digest, retain configuration/secrets, and
capture a consistent full backup. Stop every writer for offline capture, or use the
supported server push capture gate. Do not copy selected JSON files from a running
instance. Keep the previous image and backup together: an older binary may reject
newer account fields even when the schema number is unchanged.

Deploy the reviewed image with the same persistent volumes and endpoint. Check
rollout readiness, HTTPS `/readyz`, `/config.json`, sign-in, collection save/unlock,
client lists and backup status. On Kubernetes, useful non-secret checks are:

```sh
kubectl -n petika get pods
kubectl -n petika rollout status deployment/petika --timeout=300s
curl --fail https://petika.k2patel.in/readyz
curl --fail https://petika.k2patel.in/config.json
```

For rollback, follow the recovery runbook with compatible state; changing the image
alone is not a guaranteed database rollback. Preserve current volumes before recovery.
Do not print mounted secret files or full Secret manifests into support tickets.

| Symptom | Check |
| --- | --- |
| Redirects to an old IP/domain | Set `PETIKA_ENDPOINT` and roll out; saving a Gitea variable alone does not restart the server. |
| Sign-in does not persist | Correct public HTTPS origin, secure cookies, proxy forwarding, and browser session expiry. |
| Push unavailable | Correct image target, worker configuration and sufficient writable staging capacity. |
| Backup fails | Credentials/expiry, exact region/endpoint/path, provider permissions, SSH host key, repository ID/password, and network access from the server. |
| Destination cannot be edited | Wait for its running job to finish. |
| API client stopped after restart/password change | Reconnect the account session or issue a new backup key as applicable. |
| Restore fails compatibility checks | Use the recorded release and preserve the backup; do not bypass format validation. |
