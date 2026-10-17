# Container and source deployment

Experimental web UI and local managed accounts, with personal/group encrypted collections.
Verified group-key delivery and explicit rotation are implemented; native biometrics and
browser extensions remain planned. The bearer token authorizes ciphertext
access; it cannot decrypt the store. Use synthetic data until the security design and
implementation have been independently reviewed.

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
