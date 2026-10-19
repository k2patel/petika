# Reverse proxy and optional HTTPS

Petika serves HTTP on `PETIKA_LISTEN` (normally `0.0.0.0:8080`). TLS can terminate
at an existing reverse proxy, an ingress controller, or the optional homelab TLS
sidecar. It does not need to terminate inside Petika.

The examples below assume the proxy runs on the same host as Petika and forwards
to `http://127.0.0.1:8080`. If it runs elsewhere, use your server's reachable
address and port. A proxy inside Kubernetes can use
`http://petika.petika.svc.cluster.local:8080` with the portable base manifests.
Use a dedicated hostname such as `petika.example.com` at the site root `/`;
subpath hosting such as `/petika/` is not supported by the current frontend.
Point that hostname to your proxy and provision a certificate trusted by clients.

## Settings

| Browser connection | `PETIKA_COOKIE_SECURE` | Example `PETIKA_ENDPOINT` |
| --- | --- | --- |
| HTTPS through your proxy | `true` | `https://petika.example.com` |
| Local HTTP testing | `false` | `http://localhost:8080` or empty |

Set these server environment variables using your container runtime or deployment
manifest, then restart/roll out the server. Petika does not infer cookie security
from `X-Forwarded-Proto`; use the browser-facing URL to choose the setting.

For HTTPS, create a DNS record for a domain you control pointing to your proxy,
obtain a certificate covering that domain, and configure Nginx or Caddy below.
Replace every `petika.example.com` with your domain. No particular Git hosting
provider or CI service is required to configure HTTPS.

The optional [homelab overlay](../deploy/homelab/README.md) also has an `HTTPS`
setting (`off`, `on`, `both`) for its Service/TLS sidecar. It is specific to that
deployment helper, not a general Petika server option. Customize the overlay
before using it; the portable [deployment guide](deployment.md) is the starting
point for a new installation.

## Public domain or endpoint address

Set `PETIKA_ENDPOINT=https://petika.example.com` for the browser-facing domain,
or `PETIKA_ENDPOINT=http://localhost:8080` for local testing. Include the scheme
and optional port, but no credentials, subpath, query, or fragment. Leave it empty
to use whichever origin served the page. This does not change `PETIKA_LISTEN`,
create DNS records, allocate an IP, or configure a TLS certificate.

The server reads this at startup and exposes only this public value at
`/config.json` with caching disabled. If a browser opens a different origin,
it moves to the configured origin before making authenticated API calls. The
frontend and API then share that origin, keeping cookies and identity state
consistent; this is not a separate cross-origin API/CORS setting.

For your deployment, set:

```ini
PETIKA_ENDPOINT=https://petika.example.com
PETIKA_COOKIE_SECURE=true
```

Changing these values needs a restart or rollout, not an image rebuild.
The hostname must resolve to the proxy that serves Petika; pointing it back to
an address which redirects elsewhere can cause a redirect loop. To test using
localhost while a canonical address is configured, temporarily deploy with
`PETIKA_ENDPOINT=''`, then restore the public setting afterward.

## Nginx

Place this configuration inside the proxy's `http` context. Replace the hostname
and certificate paths. A certificate must already exist before starting Nginx.

```nginx
limit_req_zone $binary_remote_addr zone=petika_requests:1m rate=20r/s;

server {
    listen 80;
    server_name petika.example.com;
    return 308 https://petika.example.com$request_uri;
}

server {
    listen 443 ssl;
    server_name petika.example.com;
    ssl_certificate /etc/letsencrypt/live/petika.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/petika.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    client_max_body_size 24m;
    client_body_timeout 30s;
    client_header_timeout 15s;
    send_timeout 30s;

    location / {
        limit_req zone=petika_requests burst=60 nodelay;
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Host $http_host;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_connect_timeout 5s;
        proxy_read_timeout 60s;
        proxy_send_timeout 60s;
        proxy_cache off;
    }
}
```

Run `nginx -t` before reloading. Preserve `Authorization`, `Cookie`, `Set-Cookie`,
`Content-Type`, `If-Match`, and `X-Petika-Request`; normal proxy forwarding preserves
them. Do not cache API responses or strip conditional headers. Keep the frontend,
WASM assets, and `/v1/` under the same origin; do not add permissive CORS headers.
The 24 MiB proxy cap leaves room above the application's 20 MiB migration limit.
See [Nginx proxy directives](https://nginx.org/en/docs/http/ngx_http_proxy_module.html).

## Caddy

For a hostname with working DNS and ACME reachability, Caddy can manage the public
certificate and HTTPS redirect:

```caddyfile
petika.example.com {
    request_body {
        max_size 24MB
    }
    reverse_proxy http://127.0.0.1:8080 {
        transport http {
            dial_timeout 5s
            response_header_timeout 60s
        }
    }
}
```

For a private hostname with no public certificate, add `tls internal` inside the
site block and trust Caddy's local CA on each client. Caddy normally preserves
Host and sets the forwarded headers. Validate with `caddy validate --config
/etc/caddy/Caddyfile` before reloading. Apply edge rate limits in the surrounding
proxy/firewall if required; this example does not install a Caddy rate-limit plugin.
See [Caddy reverse proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy).

## Verification and troubleshooting

1. Check upstream health: `curl --fail http://127.0.0.1:8080/readyz`.
2. Check the browser-facing path: `curl --fail https://petika.example.com/readyz`.
   With a private CA, use `--cacert /path/to/ca.crt` rather than disabling validation.
3. Open `https://petika.example.com/`, sign in, and verify the session cookie has
   `HttpOnly`, `SameSite=Strict`, and `Secure`. In the browser console,
   `window.isSecureContext` must be `true` and `crypto.subtle` must exist.
4. Create/unlock a test collection, save an entry, reload, and unlock again. Check
   the mirror sidecar logs for successful replication after a save.

A plain LAN URL such as `http://192.0.2.10:8080/` can serve the UI and API, but it is
not a browser secure context. The sample demo works there, with an explanatory
message for unavailable OTP and clipboard features. Account collection workflows
and OTP require the
HTTPS proxy or localhost. For local browser tests without any TLS proxy, leave
cookie security `false` and run:

```sh
kubectl -n petika port-forward service/petika 8080:8080
# Open http://localhost:8080/
```

If login succeeds but does not persist over HTTP, check whether Secure cookies
are enabled. Do not disable Secure cookies just because the **proxy-to-Petika**
connection is HTTP. A 413 response indicates an upload/body limit; a CSRF failure
can indicate stripped headers or frontend and API requests crossing origins.

Moving between an IP, localhost, and a hostname changes the browser origin.
Petika's browser-local encrypted identities, trust state, and pending edits do
not automatically move with it. Export encrypted identity recovery material
before switching origins. Restrict the backend listener to the trusted proxy/LAN;
Petika retains its own account authentication behind the proxy.

Related: [deployment](deployment.md), [homelab overlay](../deploy/homelab/README.md),
[setup](setup.md), and [web security boundaries](web-ui.md).
