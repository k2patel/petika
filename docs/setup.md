# First-run and unattended setup

Setup initializes once. Restarting with bootstrap variables does not replace accounts,
change passwords, reset memberships, or re-import a snapshot.

| Variable | Default | Purpose |
| --- | --- | --- |
| `PETIKA_SETUP_MODE` | `auto` | `auto`, `manual`, or `disabled` |
| `PETIKA_ADMIN_USERNAME` | unset | Initial administrator username |
| `PETIKA_ADMIN_NAME` | `Administrator` | Initial administrator display name |
| `PETIKA_ADMIN_PASSWORD` | unset | Initial account password, at least 12 characters |
| `PETIKA_ADMIN_PASSWORD_FILE` | unset | Mounted secret containing that password; preferred |
| `PETIKA_INITIAL_SNAPSHOT_FILE` | unset | Optional pre-encrypted Petika file for the initial personal collection |
| `PETIKA_TOKEN_FILE` | required | Existing API/setup bearer token file; also authorizes the manual wizard |
| `PETIKA_ENDPOINT` | unset | Canonical public HTTP(S) origin, e.g. `https://vault.example.com`; unset uses the current browser origin |
| `PETIKA_COOKIE_SECURE` | `true` | Set `false` only for local HTTP testing |
| `PETIKA_WEB_DIR` | `clients/web` | Built frontend asset directory |

`auto` uses a complete environment configuration when supplied, otherwise shows the
web wizard. Partial credentials fail startup instead of silently exposing the wizard.
Do not set both password sources. `manual` uses the wizard and ignores bootstrap
credentials. `disabled` requires an already initialized account database and fails
closed on a new instance. Invalid mode names fail startup.

Example with secret files:

```sh
PETIKA_SETUP_MODE=auto \
PETIKA_ADMIN_USERNAME=admin \
PETIKA_ADMIN_NAME='Workspace owner' \
PETIKA_ADMIN_PASSWORD_FILE=/run/secrets/admin-password \
PETIKA_INITIAL_SNAPSHOT_FILE=/run/secrets/initial.petika \
PETIKA_TOKEN_FILE=/run/secrets/token \
./target/release/petika-server
```

The encrypted initial snapshot is optional. Without it, account setup is skipped but
the user creates an encrypted collection on first sign-in. With it, both creation
wizards are skipped and the user unlocks the existing collection locally. The server
never receives its decryption passphrase. Create the file with the native CLI beforehand.
Snapshot framing is validated before provisioning; only the client can authenticate it.
The initial snapshot is written before publishing the account record. An interrupted
provision may leave an inaccessible orphan collection directory; it cannot overwrite
an existing user's collection.

After provisioning, remove bootstrap credentials from the environment/secret mount
and set `PETIKA_SETUP_MODE=disabled` if desired. Normal sign-in and administrator user
creation continue working. This setting never disables authentication.

For Kubernetes, set the username/mode directly and use `secretKeyRef` or a mounted
Secret for the password. Podman kube play supports the same environment names and
secret mounts. Never commit secret values into manifests. Keep one server replica.

[Schema and migrations](schema.md) explains the upgrade contract and backup behavior.
