# Homelab deployment

The private Gitea source mirror at `https://git.k2patel.in/k2patel/petika`
pulls GitHub every ten minutes. `.gitea/workflows/image.yml` builds AMD64 images
in the existing Gitea runners using the account-level `CONTAINER_TOKEN` secret.
Images use full commit SHA tags. Deployment is performed with local kubectl;
the build runner receives no Kubernetes credentials. Dispatch the workflow after
synchronizing the mirror when an immediate build is needed.

Render `kubectl kustomize deploy/homelab`, replace `REPLACE_WITH_COMMIT` with the
built commit SHA (or deploy its registry digest), then apply to the homelab context.
Required namespace secrets: `petika-auth` (`token`, `admin-password`),
`petika-backup-auth` (`token`), `petika-tls` (`tls.crt`, `tls.key`), and
`gitea-registry` (registry pull credential). Never commit their values.
The initial administrator is `owner`; after provisioning remove the bootstrap
password and configure setup mode `disabled` as described in `docs/setup.md`.

The LoadBalancer exposes HTTPS on port 443. The initial IP is `10.10.12.115`.
Its local TLS certificate must be trusted on each testing device; HTTP on a LAN
IP cannot provide the secure browser context required for encryption and OTP.
If the IP changes, replace the certificate with a matching IP SAN certificate.

The mirror sidecar pushes ciphertext-only Git histories every minute to the
private `k2patel/petika-vault-backup` repository. Each managed collection uses
`collections/<opaque collection ID>`; the legacy API uses `legacy`.
It mounts only the mirror volume, read-only, and uses a write token scoped to
that one repository. Pushes are fast-forward only; rollback conflicts remain
visible in `kubectl -n petika logs deployment/petika -c mirror` for operator repair.
No keys, accounts, identity bundles, contact pins, or grants enter this backup.
Back up the data PVC separately and retain client identity/recovery backups;
the Git repository alone does not restore server accounts or recipient access.
Gitea and Petika share this homelab: arrange an off-site backup independently.

Check rollout and replication:

```sh
kubectl -n petika rollout status deployment/petika --timeout=300s
kubectl -n petika get service,pods,pvc
kubectl -n petika logs deployment/petika -c mirror --tail=20
```
