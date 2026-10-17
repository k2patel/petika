# Homelab deployment

See the [reverse-proxy guide](../../docs/reverse-proxy.md) for Nginx/Caddy,
external TLS termination, and HTTP/HTTPS settings.

The private Gitea source mirror at `https://git.k2patel.in/k2patel/petika`
pulls GitHub every ten minutes. `.gitea/workflows/image.yml` builds AMD64 images
in the existing Gitea runners using the account-level `CONTAINER_TOKEN` secret.
Images use full commit SHA tags. Deployment is performed with local kubectl;
the build runner receives no Kubernetes credentials. Dispatch the workflow after
synchronizing the mirror when an immediate build is needed.

Deploy a published image with local kubectl:

```sh
python3 scripts/deploy_homelab.py --image git.k2patel.in/k2patel/petika:FULL_COMMIT_SHA --apply
```

Omit `--apply` to render for review. The script reads Gitea repository Actions
variables, with environment overrides: `HTTPS=off` exposes HTTP port 80,
`HTTPS=on` exposes HTTPS port 443 with the optional TLS proxy, and `HTTPS=both`
exposes both. Petika itself always receives HTTP; TLS may terminate at any upstream
proxy. `PETIKA_COOKIE_SECURE=true` is independent and should be used whenever the
browser connects over HTTPS, including external TLS termination. For direct HTTP
testing only, set it to `false`. Initial Gitea values are `HTTPS=off` and
`PETIKA_COOKIE_SECURE=false`. `PETIKA_ENDPOINT` sets the public browser origin
(initially `http://10.10.12.115`); an empty value uses the current origin.
No kubeconfig is stored in Gitea.

Required namespace secrets: `petika-auth` (`token`, `admin-password`),
`petika-backup-auth` (`token`), `petika-tls` (`tls.crt`, `tls.key`), and
`gitea-registry` (registry pull credential). Never commit their values.
The initial administrator is `owner`; after provisioning remove the bootstrap
password and configure setup mode `disabled` as described in `docs/setup.md`.

The initial LoadBalancer IP is `10.10.12.115`. HTTP is enabled initially.
When using the optional local TLS proxy, its certificate must be trusted on each testing device; HTTP on a LAN
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
