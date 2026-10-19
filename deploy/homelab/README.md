# Customize the homelab overlay

For a new installation, start with the portable [deployment guide](../../docs/deployment.md)
and [administrator guide](../../docs/administrator-guide.md). Run Petika on your
own server or test the web app at `http://localhost:8080`. Configure a custom HTTPS
domain using the [reverse-proxy guide](../../docs/reverse-proxy.md).

This directory is a deployment-specific overlay, not a ready-to-apply public
installation. Before using it, review and replace its image registry, backup remote,
secret names, Service configuration, storage settings, and TLS certificate paths.
Do not apply it unchanged to your cluster.

## Choose your Git host and image registry

Your private encrypted-history repository can be on GitHub, GitLab, Codeberg, or
a Git server you operate. Examples of repository URLs you create yourself:

- `https://github.com/YOUR_ACCOUNT/petika-vault-backup.git`
- `https://gitlab.com/YOUR_NAMESPACE/petika-vault-backup.git`
- `https://codeberg.org/YOUR_ACCOUNT/petika-vault-backup.git`

Set the mirror container's `PETIKA_BACKUP_URL` to your repository and provide
repository-scoped write credentials through the `petika-backup-auth` Secret.
Review `askpass.sh` for the credential format and adapt it to your provider's
HTTPS authentication requirements; do not put credentials in the URL or commit them.
Git hosting and container hosting are separate choices. Build Petika yourself and
set the image to your registry path, such as
`registry.example.com/YOUR_NAMESPACE/petika:FULL_COMMIT_SHA`, or use a local image
loaded into your cluster. Replace `gitea-registry` with your own image-pull Secret
when authentication is needed.

The optional `.gitea/workflows/image.yml` is a Gitea-specific CI example. Other Git
hosts need their own build/publish workflow; GitHub, GitLab and Codeberg are not
interchangeable CI APIs. No CI runner needs Kubernetes credentials when you deploy
with local kubectl.

## Deployment helper limitations

`scripts/deploy_homelab.py` renders this overlay and can apply it with `--apply`.
Its fallback Actions-variable lookup is tied to a particular Gitea repository.
To avoid that lookup, explicitly set all three environment values below, after
customizing the overlay files:

```sh
HTTPS=off PETIKA_COOKIE_SECURE=true PETIKA_ENDPOINT=https://petika.example.com \
  python3 scripts/deploy_homelab.py \
  --image registry.example.com/YOUR_NAMESPACE/petika:FULL_COMMIT_SHA
```

This renders for review. Add `--apply` only after reviewing the resulting manifest.
Use your domain and image path. `HTTPS=off` exposes HTTP port 80 for an external
proxy; `on` exposes the optional TLS sidecar on 443; `both` exposes both. Petika
itself receives HTTP. Keep Secure cookies enabled when browsers connect over HTTPS.
For localhost-only testing, use `PETIKA_COOKIE_SECURE=false` and an empty endpoint
or `http://localhost:8080`. The overlay's port-forward is `8080:80` with HTTP enabled;
the portable base manifests use `8080:8080`.

Provision `petika-auth` (`token`, `admin-password`), `petika-backup-auth` (`token`),
your registry pull credentials, and, only for the TLS sidecar, `petika-tls`
(`tls.crt`, `tls.key`). Certificates must cover your hostname or address and be
trusted by clients. New bootstrap installs use username `admin`; changing bootstrap
settings does not rename existing accounts. Remove the bootstrap password after
provisioning; see [setup](../../docs/setup.md).

## Replication and recovery

The mirror sidecar pushes ciphertext-only Git histories every minute. Managed
collections use `collections/<opaque collection ID>` branches; the legacy API uses
`legacy`. Pushes are fast-forward only. The sidecar mounts only the mirror volume,
read-only, and should have write access only to its destination repository.

The Git copy does not include accounts, identity bundles, contact pins or grants.
Back up the complete server data and retain client recovery material separately.
If your Git server shares the same host/site, arrange an independent off-site copy.
See [backup and recovery](../../docs/recovery.md).

```sh
kubectl -n petika rollout status deployment/petika --timeout=300s
kubectl -n petika get service,pods,pvc
kubectl -n petika logs deployment/petika -c mirror --tail=20
```
