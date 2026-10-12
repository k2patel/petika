# Self-hosting

The experimental Rust server serves the web UI and API. A non-root distroless image,
Kubernetes manifests, and Podman kube play configuration are available. Follow
[deployment](deployment.md), [first-run setup](setup.md), and [schema upgrades](schema.md).
This release has not undergone a security audit.

Run a single server replica with persistent data and mirror directories. Managed
accounts are available now; optional OpenID Connect remains planned. Terminate HTTPS
for remote access and preserve Secure cookies. Back up the complete data directory,
encrypted mirror, configuration, and client recovery material before upgrading.

The guide must identify every persistent volume and required recovery artifact, show
how to restore on a fresh host, and explain offline client behavior during outages.
Never put real secrets, private keys, or deployment credentials in this repository.
