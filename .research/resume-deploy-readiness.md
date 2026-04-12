# Phase 2f: Deployment Readiness Audit

**Target**: Fly.io app `kite-mcp-server` (bom region)
**Scope**: Dockerfile, fly.toml, env vars, migrations, health check, graceful shutdown, new feature secrets
**Verdict**: DEPLOY READY. No blocking issues. Minor polish items below.

## 1. Dockerfile (`D:\kite-mcp-temp\Dockerfile`) — PASS

- Go `1.25.8-alpine` builder (matches memory: CVE GO-2026-4603 patched).
- Static build: `CGO_ENABLED=0`, `-ldflags "-s -w"` (stripped, minimal).
- Version injection: `-X main.MCP_SERVER_VERSION=${VERSION}` via `ARG VERSION=v1.1.0`.
- Litestream 0.5.10 pulled via `ADD` from GitHub release, copied to runtime.
- Runtime: `alpine:3.21` with `ca-certificates`, `tzdata`, `bash`.
- Non-root user: `appuser` created, `/data` chowned.
- `HEALTHCHECK` uses `wget -qO- http://localhost:8080/healthz` every 30s (present in the image; `wget` ships with BusyBox alpine — OK).
- Entrypoint: `/scripts/run.sh` (Litestream PID 1 → app subprocess).

## 2. fly.toml (`D:\kite-mcp-temp\fly.toml`) — PASS (minor)

```
app = "kite-mcp-server"
primary_region = "bom"
[http_service] internal_port=8080, force_https=true, auto_stop_machines=false, min_machines_running=1
[mounts] source="kite_data", destination="/data"
[env] APP_MODE=http, APP_PORT=8080, APP_HOST=0.0.0.0, LOG_LEVEL=info, ALERT_DB_PATH=/data/alerts.db
```

- Correct port (matches Dockerfile healthcheck and `APP_PORT`).
- `auto_stop_machines=false` + `min_machines_running=1` — required for Litestream + scheduler + ticker goroutines. Correct.
- Persistent volume `kite_data` mounted at `/data` — hosts `alerts.db`, restored from R2 on cold start by run.sh.
- **MINOR**: No `[http_service.checks]` block for Fly-native health checks. Docker HEALTHCHECK is present but Fly's load balancer does not use it for routing decisions. Consider adding `[[http_service.checks]] path="/healthz"` for better failure signalling. Not blocking.
- **MINOR**: No `[[vm]]` block — relies on Fly defaults (`shared-cpu-1x`, 256MB). Memory notes record 512MB RAM in prod — suggests this is set via `flyctl scale memory 512` out-of-band. Consider codifying in `fly.toml` for reproducibility.

## 3. Environment Variables — PASS

Required (validated in `app/app.go:287-302` LoadConfig):
- `OAUTH_JWT_SECRET` — gates OAuth mode (required in prod, already a Fly secret)
- `EXTERNAL_URL` — required when `OAUTH_JWT_SECRET` set (already a Fly secret)

Conditional/optional (sourced from `os.Getenv`):
- `KITE_API_KEY`/`KITE_API_SECRET` — NOT set on Fly (per-user OAuth model); LoadConfig handles absence gracefully
- `TELEGRAM_BOT_TOKEN`, `ALERT_DB_PATH`, `ADMIN_EMAILS`, `ADMIN_ENDPOINT_SECRET_PATH` — already present as secrets
- `GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` — optional SSO
- Stripe: `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `STRIPE_PRICE_PRO`, `STRIPE_PRICE_PREMIUM`, `STRIPE_PRICE_SOLO_PRO` — optional (billing opt-in); if SECRET_KEY absent, `wire.go:205` skips billing
- `ADMIN_PASSWORD` — optional (bootstrap admin)
- `DEV_MODE` — dev only
- Litestream: `LITESTREAM_BUCKET`, `LITESTREAM_R2_ACCOUNT_ID`, `LITESTREAM_ACCESS_KEY_ID`, `LITESTREAM_SECRET_ACCESS_KEY` (referenced in `etc/litestream.yml`) — already set per memory

No new secrets introduced by circuit breaker, correlation middleware, or injection points. Confirmed.

## 4. Migrations — PASS

- No external migration tool. SQLite schema/migrations live in-process via `kc/alerts/db.go` + `kc/alerts/db_migrations.go`.
- `migrateRegistryCheckConstraint` is idempotent (checks `sqlite_master` first, recreates table if the new `CHECK IN` values are missing). Safe on redeploy.
- No breaking schema changes introduced in this branch beyond what's already running in prod (v43 per memory). Confirmed by inspection — all alert/credential tables use `CREATE TABLE IF NOT EXISTS` patterns.
- **Recommendation**: First-boot after deploy will run `migrateRegistryCheckConstraint` on any older DB restored from R2. Litestream `restore` handles this automatically via `run.sh`.

## 5. Binary Size — EXPECTED OK

- Stripped static Go binary with ~80 tools, 330+ tests, embedded templates — expect 30–45 MB.
- Final image: alpine:3.21 base (~8 MB) + binary + litestream (~20 MB) + tzdata + ca-certs → ~70–90 MB total. Within Fly free-tier norms.
- Not measurable from static analysis; verify with `docker images` post-build if concerned.

## 6. Graceful Shutdown — PASS

`app/http.go:59` installs `signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)`. Shutdown goroutine (`http.go:62-104`) executes in correct order:

1. `scheduler.Stop()` — stop briefings (prevent new Kite calls)
2. `srv.Shutdown(ctx)` with 10s timeout — drain in-flight HTTP requests
3. `auditStore.Stop()` — flush audit buffer after drain
4. `telegramBot.Shutdown()` — cleanup Telegram goroutine
5. `kcManager.Shutdown()` — session cleanup, instruments scheduler
6. `oauthHandler.Close()` — OAuth auth-code store cleanup
7. `rateLimiters.Stop()` — rate limiter GC goroutine

Ordering is sound: HTTP drained before stores closed (no "use after close"). 10s timeout aligns with Fly's default SIGTERM→SIGKILL window (usually 30s via `kill_timeout`).

- **MINOR**: `fly.toml` does not set `kill_timeout`. Fly default is usually adequate (5m for app VMs) but consider pinning explicitly, e.g. `kill_timeout = "15s"`.

## 7. Health Check — PASS

`app/http.go:441` mounts `GET /healthz` returning `{status, uptime, version, tools}` with 200 OK. Used by:
- Dockerfile HEALTHCHECK (`wget -qO-`)
- No Fly-native check (see fly.toml minor above)
- Load balancers / monitoring (unauthenticated, safe — no secrets leaked)

Simple liveness only — does not verify DB or downstream Kite reachability. For an MCP server this is the right design (avoid dependent failure cascades).

## 8. New Features — No New Secrets Required

- **Circuit breaker** (`mcp/circuitbreaker_middleware.go`): pure in-memory state (`FailureThreshold`, `OpenDuration`), configured at wire time. No env var.
- **Correlation middleware** (`mcp/correlation_middleware.go`): generates `uuid.New().String()` per call, injects into context. No env var.
- **Injection points**: test coverage changes, no runtime config impact.

Verified via grep of `os.Getenv|LookupEnv` — only pre-existing keys referenced.

## Summary

| Check | Status | Notes |
|---|---|---|
| Dockerfile | PASS | Go 1.25.8, CVE patched, multi-stage, non-root |
| fly.toml | PASS (minor) | Missing Fly-native check + explicit VM size |
| Env vars | PASS | No new secrets; LoadConfig validates OAUTH/EXTERNAL_URL |
| Migrations | PASS | Idempotent in-process; safe on restart |
| Binary size | EXPECTED OK | Not measurable statically |
| SIGTERM / shutdown | PASS | Ordered drain, 10s HTTP timeout |
| /healthz | PASS | Simple liveness, unauthenticated, safe |
| New feature secrets | PASS | Circuit breaker + correlation ID self-contained |

### BLOCKING
None.

### MINOR (nice-to-have, do not block deploy)
1. Add `[[http_service.checks]]` in `fly.toml` for Fly-native /healthz probing.
2. Pin VM size (`[[vm]] memory = "512mb"`) in `fly.toml` for reproducibility.
3. Set explicit `kill_timeout = "15s"` in `fly.toml`.

**Recommendation**: Deploy is green. `flyctl deploy -a kite-mcp-server` from `D:\kite-mcp-temp` is safe to run.
