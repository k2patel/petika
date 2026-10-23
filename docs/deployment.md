# Container and source deployment

Experimental web UI and local managed accounts, with personal/group encrypted collections.
Verified group-key delivery and explicit rotation are implemented; native biometrics and
mobile clients remain planned. An experimental Chromium toolbar extension
is available for local QA; see the [user guide](user-guide.md). The bearer token authorizes ciphertext
access; it cannot decrypt the store. Use synthetic data until the security design and
implementation have been independently reviewed.

For an installation walkthrough and routine operations, start with the
[administrator guide](administrator-guide.md). Ordinary users can use the web app
without installing server tools; see the [user guide](user-guide.md).

## Build from source

```sh
rustup target add wasm32-unknown-unknown
cargo install wasm-bindgen-cli --version 0.2.114 --locked
sh scripts/build_web.sh
cargo build --release --locked -p petika -p petika-server
```

Create a private token file outside the repository:

```sh
umask 077
mkdir -p "$HOME/.config/petika"
openssl rand -hex 32 > "$HOME/.config/petika/api-token"
PETIKA_COOKIE_SECURE=false \
PETIKA_TOKEN_FILE="$HOME/.config/petika/api-token" \
PETIKA_DATA_DIR="$HOME/.local/share/petika-api" \
PETIKA_GIT_MIRROR="$HOME/.local/share/petika-mirror" \
./target/release/petika-server
```

Mirroring uses the Rust gix library and requires no Git executable. Install GnuPG
on the client for imports; GnuPG retains its own license. The server never needs
GPG private keys.

## Docker

```sh
docker build -t petika:dev .
docker volume create petika-data
docker volume create petika-mirror
```

Supply the generated token using your runtime's secret support, or mount it read-only.
For a bind mount, arrange that UID 65532 inside the container can read the file; do not
make the host copy world-readable. Docker rootful Linux maps that UID directly. For
local testing with a host-owned token, `--user "$(id -u):$(id -g)"` is an alternative,
but then pre-create writable data directories owned by that same UID.

Example after preparing a UID-65532-readable secret file:

```sh
docker run --name petika --detach \
  --read-only --cap-drop ALL --security-opt no-new-privileges \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  -e PETIKA_COOKIE_SECURE=false \
  -p 127.0.0.1:8080:8080 \
  -v petika-data:/data -v petika-mirror:/mirror \
  --mount type=bind,src=/absolute/path/to/api-token,dst=/run/secrets/token,readonly \
  petika:dev
```

The final runtime uses distroless cc-debian13 as UID 65532, without a shell,
package manager, Git, or GnuPG. HTTP probes work without an in-container command.
The image includes both Rust binaries. Use `--entrypoint /usr/local/bin/petika` to run
the CLI. Run GPG imports with the native CLI on a host with GnuPG installed.
Keep the client store and GPG keys separate from server volumes.

For Nginx/Caddy and external TLS termination, see the
[reverse-proxy guide](reverse-proxy.md).

## Kubernetes

The supplied manifests use a single replica, Recreate updates, two persistent volumes,
non-root execution, a read-only root filesystem, resource limits, and health probes.
Load `petika:dev` into your local cluster or replace the image with your own registry
tag/digest. No prebuilt image has been published.

```sh
kubectl apply -f deploy/kubernetes/namespace.yaml
kubectl -n petika create secret generic petika-auth \
  --from-file=token="$HOME/.config/petika/api-token"
kubectl apply -k deploy/kubernetes
kubectl -n petika rollout status deployment/petika
kubectl -n petika port-forward service/petika 8080:8080
```

The cluster needs a default storage class or pre-provisioned volumes. fsGroup grants
initial volume access; Petika creates nested files with owner-only permissions. Keep
fsGroupChangePolicy at OnRootMismatch to avoid relaxing existing file permissions.
Do not scale beyond one replica: the current store is a filesystem-backed single-server
implementation. Expose it remotely only behind HTTPS with request timeouts, body limits, and
rate limits. No public ingress is installed automatically.

## Rootless Podman kube play

Requires a recent Podman with kube Secret volumes and PVC ownership annotations.
Podman uses its own manifest because its kube support differs from Kubernetes.

```sh
podman build -t localhost/petika:dev .
kubectl create secret generic petika-auth \
  --from-file=token="$HOME/.config/petika/api-token" \
  --dry-run=client -o yaml > "$HOME/.config/petika/podman-secret.yaml"
podman kube play "$HOME/.config/petika/podman-secret.yaml"
podman kube play deploy/podman/petika.yaml
```

Generate the secret YAML under `umask 077` and never commit it. Its base64 data is not
encryption. The secret volume is readable inside this single-container pod; the host
file stays private. Named volumes retain data across pod replacement. The manifest
binds port 8080 only to loopback. Stop with `podman kube down deploy/podman/petika.yaml`;
do not request volume deletion unless you intend to erase the data and mirror.

## Choose your Git host

The source clone URL in this guide points to the project's upstream repository.
Your Petika installation, optional source fork and encrypted-backup repository
belong to you; they do not depend on the maintainer's infrastructure.

Create a **private** repository for encrypted Git history on your chosen host.
Use its actual clone URL, for example:

| Provider | Example backup remote |
| --- | --- |
| GitHub | `https://github.com/YOUR_ACCOUNT/petika-vault-backup.git` |
| GitLab | `https://gitlab.com/YOUR_NAMESPACE/petika-vault-backup.git` |
| Codeberg | `https://codeberg.org/YOUR_ACCOUNT/petika-vault-backup.git` |
| Your Git server | Use the HTTPS or SSH clone URL supplied by your server |

Replace the account/namespace and repository name with your own. Configure the
[administrator Git settings](administrator-guide.md#configure-encrypted-git-copies-in-the-web-ui)
in the push-runtime web UI, or an operator-managed push job, with that remote and
repository-scoped write credentials.
The optional [mirror sidecar](../deploy/homelab/README.md) uses `PETIKA_BACKUP_URL`
and an HTTPS credential helper; customize its username/token handling for your
provider. A separate SSH push job needs its own protected key and verified host
keys. Neither the Git remote nor credentials belong in client vault configuration.
Keep credentials out of URLs, committed files and logs.

Git is an outbound encrypted-history copy: clients still read/write through the
Petika API. Do not let clients push competing ciphertext edits or enable automatic
two-way Git imports. Git hosting is also separate from your container registry;
build your image locally or publish it to a registry you control. A Git mirror
alone does not back up accounts and access grants; retain full-server backups too.

## Localhost or a custom domain

For local web testing, bind to loopback and open `http://localhost:8080`. Set
`PETIKA_COOKIE_SECURE=false` and leave `PETIKA_ENDPOINT` empty or set it to that
localhost URL. The Docker and Kubernetes examples above show loopback access.

For remote use, choose a domain you control (for example `petika.example.com`),
point its DNS record at your reverse proxy, and install a trusted TLS certificate.
Set `PETIKA_ENDPOINT=https://petika.example.com` with your actual hostname and
`PETIKA_COOKIE_SECURE=true`, then restart/roll out Petika. Follow the
[Nginx/Caddy guide](reverse-proxy.md) for your proxy's upstream address and ports.
The example domain is a placeholder, not a public Petika service. The extension
preview requires HTTPS; localhost HTTP testing here refers to the web app.

## Operations

`GET /healthz` checks the process; `GET /readyz` checks storage access. Authenticated
`GET /v1/status` reports API and mirror revisions. Mirror lag does not reject API writes:
accepted snapshots remain in the durable revision journal and retry every five seconds.
The legacy bearer API mirror is a bare Git repository on `/mirror/repository.git` containing only `snapshot.json`
in each committed tree. Inspect it externally with `git --git-dir=/mirror/repository.git show HEAD:snapshot.json`.
Managed collections use `/mirror/{opaque-collection-id}/repository.git`; their revisions
are available through `petika status --collection ID`. Account and group metadata is
not included in these mirrors. Entry names and folder hierarchy are encrypted; ciphertext sizes, revision counts,
and commit times remain visible. Pushing it to a remote Git server is
currently an operator task. Back up both persistent volumes and client recovery material.
A mirror on the same physical disk is not an independent disaster-recovery backup.

Rotate the API token by replacing its secret and restarting the process. This does not
rotate encryption keys or invalidate already copied ciphertext. Never upload your
passphrase or GPG private keys to the server.

References: [Podman kube play](https://docs.podman.io/en/latest/markdown/podman-kube-play.1.html),
[Kubernetes security contexts](https://kubernetes.io/docs/tasks/configure-pod-container/security-context/).


The image includes the built web UI at `/`. See [setup variables](setup.md) for unattended
administrator creation, optional encrypted snapshot provisioning, and setup lockout.
HTTP port-forward/local examples require `PETIKA_COOKIE_SECURE=false` for web login;
use the default `true` behind HTTPS in production. Account cookies are not API bearer tokens.
See [web security boundaries](web-ui.md) and [schema upgrades](schema.md).
