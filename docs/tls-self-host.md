# TLS self-host

This runbook covers TLS termination for `kite-mcp-server` deployments
NOT behind Fly.io / Cloudflare. If you're using `kite-mcp-server.fly.dev`
or fronting your own deployment with Cloudflare, **you don't need this
page** — Fly.io / Cloudflare terminate TLS at their edge and forward
plain HTTP to the binary on `internal_port`.

This page is for self-host scenarios where you want HTTPS directly on
the binary:

- VPS / bare-metal with a public IP and a domain you control
- Home-lab behind a tunnel that needs end-to-end TLS
- On-prem deployments where TLS-terminating proxy isn't an option

Two paths are supported:

1. **Inline ACME** (`golang.org/x/crypto/acme/autocert`) — single binary,
   no sidecar; the server itself acquires + renews Let's Encrypt certs
   on ports 80 and 443.
2. **Reverse proxy** (Caddy / Traefik / nginx) — binary stays on plain
   HTTP, proxy terminates TLS. Recommended if you're already running a
   proxy for other services.

---

## Path 1: Inline ACME (recommended for single-service self-host)

### Prerequisites

- A public domain you control (e.g. `mcp.example.com`)
- DNS A/AAAA record pointing to the public IP of your server
- Ports 80 AND 443 reachable from the public Internet (firewall, port
  forwarding, AWS security group, etc.)
- A persistent storage path for the ACME cache (cert + account state)

### Configuration

Set two env vars before starting the binary:

```sh
TLS_AUTOCERT_DOMAIN=mcp.example.com
TLS_AUTOCERT_CACHE_DIR=/var/lib/kite-mcp/autocert
```

When `TLS_AUTOCERT_DOMAIN` is non-empty, the server flips into inline-TLS
mode:

- Binds `:443` for HTTPS with autocert-managed cert + key
- Binds `:80` to (a) answer ACME http-01 challenges and (b) 301-redirect
  everything else to `https://<TLS_AUTOCERT_DOMAIN>/`
- Issues a Let's Encrypt cert on first request to a recognised hostname
- Auto-renews the cert ~30 days before expiry
- Caches issued certs + ACME account in `TLS_AUTOCERT_CACHE_DIR`

The original `APP_PORT` env var is **ignored** in this mode — TLS needs
the privileged port 443. If you need to bind a non-standard port (e.g.
behind another proxy that terminates 443 → 8443), use Path 2 below
instead.

### Cache directory persistence

**This is critical**: `TLS_AUTOCERT_CACHE_DIR` MUST be on persistent
storage. Let's Encrypt's rate limit is **50 certificates per registered
domain per week**. Losing the cache forces re-issuance on every restart
and rapidly exhausts the budget. Recovery from rate-limit exhaustion
takes 7 days.

Recommended values per deployment shape:

| Shape | Recommended `TLS_AUTOCERT_CACHE_DIR` |
|---|---|
| systemd service | `/var/lib/kite-mcp/autocert` (created by service unit, owned by service user) |
| Docker container | `/data/autocert` mounted as a named volume |
| Kubernetes pod | a `PersistentVolumeClaim` mounted at `/data/autocert` |
| User-mode (default) | `${HOME}/.cache/kite-mcp/autocert` (auto-detected when env unset) |

### Privileged-port binding

Ports 80 and 443 are privileged on Linux (only root can bind by default).
Three production options:

1. **Run as root** (simplest, least secure). Set `User=root` in the
   systemd unit.
2. **`setcap` capability grant** (recommended). Run:

   ```sh
   sudo setcap 'cap_net_bind_service=+ep' /usr/local/bin/kite-mcp-server
   ```

   Then run the binary as a non-root user (e.g. `kite-mcp`) — it can
   bind 80 and 443 without root. Re-apply `setcap` after every binary
   replacement.

3. **systemd socket activation**. Define `kite-mcp-http.socket` and
   `kite-mcp-https.socket` units with `ListenStream=80` and `:443`,
   then have the service unit accept activation. The binary doesn't
   currently support socket activation passthrough; this path needs
   plumbing first (open an issue if you want it).

On macOS / BSD: launchd / rc.d equivalents apply.

### DNS prerequisites

The autocert manager validates ownership via http-01 challenge:

1. Let's Encrypt sends a GET to `http://<TLS_AUTOCERT_DOMAIN>/.well-known/acme-challenge/<token>`
2. Our `:80` listener responds with the matching token (autocert manages
   the token state)
3. Let's Encrypt verifies the token matches and issues the cert

This requires:

- Public DNS record (A or AAAA) for `<TLS_AUTOCERT_DOMAIN>` resolving to
  the server's public IP
- Inbound :80 reachable from Let's Encrypt's validators (their IP ranges
  rotate; allow from the world)
- No CNAME redirect / DNS-trickery that would cause Let's Encrypt to
  validate against a different host

If you need wildcard certs (e.g. `*.example.com`), DNS-01 is required.
This is **not currently implemented** — see "Path 2" below.

### Verifying the deployment

After starting the binary with `TLS_AUTOCERT_DOMAIN` set:

```sh
# First HTTPS request triggers cert acquisition (~5-10 seconds for
# Let's Encrypt to validate + issue):
curl -v https://mcp.example.com/healthz

# Subsequent requests are fast:
time curl -s https://mcp.example.com/healthz

# Verify the redirect:
curl -v http://mcp.example.com/healthz
# Expected: 301 Moved Permanently, Location: https://mcp.example.com/healthz

# Verify ACME challenge passthrough:
curl -v http://mcp.example.com/.well-known/acme-challenge/test-token
# Expected: 404 (the autocert manager doesn't have a "test-token", but
#            it ANSWERS rather than redirects — proves the path is wired)
```

### Operational gotchas

| Gotcha | Mitigation |
|---|---|
| Cert expiry | Auto-renewed at T-30 days. No human intervention needed. Monitor via `curl -kvI https://your.domain/` and check expiry in TLS handshake. |
| Lost cache → rate-limit exhaustion | Cache MUST be on persistent storage. See "Cache directory persistence" above. |
| Multiple domains needed | Comma-separated `TLS_AUTOCERT_DOMAIN` is **rejected** at startup (clearer than silently failing ACME validation). Multi-domain support requires per-domain cache layout — see "Path 2" or open an issue. |
| Wildcard cert needed | Not supported (requires DNS-01 challenge with provider-specific API). Use Path 2 with a wildcard-capable proxy. |
| ACME staging vs production | Currently uses Let's Encrypt production CA. Staging mode (looser rate limits, fake-CA certs) requires a config knob — open an issue if you need it. |
| Bare IP rejection | `TLS_AUTOCERT_DOMAIN=1.2.3.4` is rejected at startup. ACME does not issue certs for IPs. |
| Behind a TCP load balancer | The LB must pass through 80 + 443 transparently (TLS passthrough mode). If the LB terminates TLS itself, use Path 2 from the LB onwards. |

### Failure modes (logged; non-fatal where possible)

| Failure | Behaviour |
|---|---|
| Bad `TLS_AUTOCERT_DOMAIN` (comma-separated, bare IP, wildcard) | Rejected at startup with clear error. Server does not start. |
| `:80` bind fails (port in use, no privilege) | Logged as warning; HTTPS continues on `:443`. The redirect convenience is lost. ACME http-01 will fail at next renewal. |
| `:443` bind fails | Logged as error; server returns from RunServer. Operator must fix and restart. |
| Cache dir not writeable | First write fails at cert acquisition; logged with `os.PathError`. |
| Network blocks egress to Let's Encrypt | ACME validation fails; cert acquisition retries with backoff. Server is unreachable on HTTPS until egress is restored. |

---

## Path 2: Reverse proxy (Caddy / Traefik / nginx)

When you have an existing proxy or want flexibility (multiple services,
wildcard certs, custom headers, A/B routing), terminate TLS at the proxy
and run `kite-mcp-server` on plain HTTP.

In this mode:

- Leave `TLS_AUTOCERT_DOMAIN` unset
- Set `APP_PORT` to a non-privileged port (e.g. `8080`)
- Set `APP_HOST` to `127.0.0.1` (or `0.0.0.0` if the proxy is on a
  separate host on a private network)
- Set `EXTERNAL_URL` to the proxy's public HTTPS URL (e.g.
  `https://mcp.example.com`) — this is what's emitted in OAuth redirect
  URLs and dashboard links

### Caddy example

`/etc/caddy/Caddyfile`:

```caddy
mcp.example.com {
    reverse_proxy 127.0.0.1:8080
    encode gzip
}
```

Caddy auto-renews via Let's Encrypt. Restart with
`sudo systemctl reload caddy` after every config change.

### Traefik example

`docker-compose.yml`:

```yaml
services:
  traefik:
    image: traefik:v3.0
    command:
      - --providers.docker
      - --entrypoints.web.address=:80
      - --entrypoints.websecure.address=:443
      - --certificatesresolvers.le.acme.email=admin@example.com
      - --certificatesresolvers.le.acme.storage=/le/acme.json
      - --certificatesresolvers.le.acme.httpchallenge.entrypoint=web
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - le_data:/le

  kite-mcp:
    image: ghcr.io/sundeepg98/kite-mcp-server:latest
    environment:
      APP_PORT: 8080
      APP_HOST: 0.0.0.0
      EXTERNAL_URL: https://mcp.example.com
      OAUTH_JWT_SECRET: <your-secret>
      # ... rest of config
    labels:
      traefik.enable: true
      traefik.http.routers.mcp.rule: Host(`mcp.example.com`)
      traefik.http.routers.mcp.entrypoints: websecure
      traefik.http.routers.mcp.tls.certresolver: le
      traefik.http.services.mcp.loadbalancer.server.port: 8080

volumes:
  le_data:
```

### nginx example

`/etc/nginx/sites-available/kite-mcp`:

```nginx
server {
    listen 80;
    server_name mcp.example.com;
    location /.well-known/acme-challenge/ { root /var/www/certbot; }
    location / { return 301 https://$host$request_uri; }
}

server {
    listen 443 ssl http2;
    server_name mcp.example.com;
    ssl_certificate /etc/letsencrypt/live/mcp.example.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/mcp.example.com/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

Use `certbot --nginx` to acquire the cert; certbot auto-renews via cron
or systemd timer.

### When to choose Path 2 over Path 1

Choose Path 2 if any of:

- You already run a proxy for other services (no extra ops cost)
- You need wildcard certs (`*.example.com`)
- You need DNS-01 challenges (provider-specific, e.g. behind CloudFlare DNS)
- You need TLS-terminated path-routing (multiple services on one domain)
- You need HTTP/2 push, Brotli compression, or other proxy-only features
- You're running multi-region with a CDN that terminates TLS (Fastly,
  CloudFront, Cloudflare) — same pattern as Fly.io's edge

Choose Path 1 if:

- Single binary, single domain, single host
- Want minimal ops surface (no proxy to operate)
- Don't already run a proxy

---

## Behind a CDN (Cloudflare, etc.)

If you're using Cloudflare in front of Path 1 or Path 2:

- Use **Full (strict)** SSL mode in Cloudflare. This requires a valid
  cert on the origin (which Path 1 provides via Let's Encrypt).
- **Flexible** mode (Cloudflare → origin is HTTP) defeats end-to-end
  TLS and is **not recommended** for a financial-services deployment.
- If using Cloudflare's Origin CA cert (long-lived, signed by
  Cloudflare's private root), set up Path 2 with that cert as a
  pinned static cert. Path 1's autocert won't talk to Cloudflare's
  CA.

Disable Cloudflare's caching for `/mcp`, `/sse`, `/callback`,
`/auth/*`, `/dashboard/*`, and `/admin/*` — these are stateful or
dynamic.

---

## Security considerations

- **HSTS**: not currently emitted by the server. Add via reverse proxy
  if needed (Caddy auto-adds HSTS in production mode; nginx requires
  explicit `Strict-Transport-Security` header).
- **Cipher suites**: Go's default TLS cipher suites for autocert are
  conservative (TLS 1.2+ only, modern AEAD ciphers). No knob to
  customise yet.
- **Certificate transparency**: Let's Encrypt automatically logs all
  issued certs to public CT logs. Anyone can search ct.googleapis.com
  for `mcp.example.com` and see the cert was issued. This is a
  privacy consideration if your domain is otherwise unpublished.
- **Host-header reflection defence**: the `:80` redirect uses the
  ACME-validated `TLS_AUTOCERT_DOMAIN` as the redirect target Host,
  not the inbound request's Host header. An attacker pointing
  `attacker.example.com` at our IP cannot trick our redirect into
  pointing at their domain.
- **HostPolicy allowlist**: the autocert manager rejects ACME requests
  for any hostname other than `TLS_AUTOCERT_DOMAIN`. An attacker
  pointing their domain at our IP cannot burn our ACME rate-limit
  budget.

---

## Reference: env vars at a glance

| Var | Path 1 (inline ACME) | Path 2 (reverse proxy) |
|---|---|---|
| `TLS_AUTOCERT_DOMAIN` | required (e.g. `mcp.example.com`) | unset |
| `TLS_AUTOCERT_CACHE_DIR` | recommended (default: `~/.cache/kite-mcp/autocert`) | unset |
| `APP_HOST` | ignored (binds `0.0.0.0` on `:443`) | `127.0.0.1` typical |
| `APP_PORT` | ignored (uses `:443`) | non-privileged (e.g. `8080`) |
| `EXTERNAL_URL` | `https://<TLS_AUTOCERT_DOMAIN>` | `https://<your-proxy-host>` |
| `OAUTH_JWT_SECRET` | required (32+ bytes high-entropy) | required |

See `docs/config-management.md` §3 for the full env-var inventory.

---

## See also

- [`docs/self-host.md`](self-host.md) — base self-host runbook
  (Kite developer app setup, OAuth, ENABLE_TRADING)
- [`docs/config-management.md`](config-management.md) — full env-var
  inventory + Fly.io baseline
- [`docs/sebi-paths-comparison.md`](sebi-paths-comparison.md) — when
  each Path applies (1=public, 2=hosted-readonly, 3=algo-vendor)
- [Let's Encrypt documentation](https://letsencrypt.org/docs/) —
  rate limits, validation methods, CA reliability
- [`golang.org/x/crypto/acme/autocert`](https://pkg.go.dev/golang.org/x/crypto/acme/autocert) — library reference
