# Deployment assets

- [Kubernetes and Podman instructions](../docs/deployment.md)
- [Homelab Gitea build, HTTPS LoadBalancer, and encrypted backup](homelab/README.md)

The base Kubernetes manifests require an image and authentication Secret.
The homelab overlay adds TLS and a ciphertext-only Gitea replication sidecar.
