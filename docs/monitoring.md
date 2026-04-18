# Monitoring & Observability

What to watch, where to find it, and when to wake up.

This document catalogs every observable surface exposed by the Kite MCP
Server and maps each one to an actionable alert. Pair it with the
[Operator Playbook](operator-playbook.md) for the decision tree once an
alert fires, and with [env-vars.md](env-vars.md) for the environment
variables that gate each surface.

---

## Surfaces

### 1. `/healthz?format=json` — component health

Public, unauthenticated endpoint. Returns aggregate `status`, uptime,
build `version`, and a `components` map covering the audit store,
riskguard, Litestream replication, and Kite API connectivity.

```json
{
  "status": "ok",
  "uptime_s": 12345,
  "version": "v1.1.0",
  "components": {
    "audit": {"status": "ok", "dropped_count": 0},
    "kite_connectivity": {"status": "unknown", "note": "no active session to probe"},
    "litestream": {"status": "unknown", "note": "external binary"},
    "riskguard": {"status": "ok"}
  }
}
```

Probe from any shell:

```bash
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
```

**Alert if:**
- Top-level `status != "ok"` for more than 5 minutes.
- `components.audit.status != "ok"` at all (implies SQLite write path
  is broken — see § Common scenarios).
- `components.riskguard.status != "ok"` (kill switch or risk limits
  store unreachable).
- `uptime_s` resets unexpectedly (indicates crash restart). Expected
  value: monotonically increasing between deploys.
- `components.audit.dropped_count` climbs above ~10 in a sustained
  fashion (see [operator-playbook.md](operator-playbook.md) § 1.3 for
  thresholds).

Notes:
- `kite_connectivity` and `litestream` report `unknown` by design; the
  server does not probe them in-process.
- The endpoint is deliberately public (no auth) so external uptime
  monitors can hit it without secrets.

### 2. `server_metrics` MCP tool (admin-adjacent)

Invokable from any connected MCP client using an admin email. Returns
per-tool latency percentiles (p50 / p95 / p99), error rate, and call
count over the configured window.

Source: `mcp/observability_tool.go`.

**Alert if:**
- p95 latency > 3000 ms on any order tool (`place_order`,
  `modify_order`, `cancel_order`, `place_gtt_order`) — indicates the
  Kite API is slow or the broker adapter is retrying.
- Error rate > 5 % on any tool for longer than a 15-minute window —
  usually reveals a broken integration or a changed upstream schema.
- Call count for a single tool suddenly drops to zero during market
  hours — silent failure, possibly a feature-flag regression.

### 3. `server_version` MCP tool

Returns the git SHA, build time, region, and current uptime. Primary
use: correlating a bug report across multiple deployments or comparing
local vs. Fly.io behaviour.

Source: `mcp/observability_tool.go`.

Call this first when a user reports behaviour that does not match what
is in master — it confirms which commit is actually running.

### 4. Audit trail (SQLite `tool_calls`)

Every MCP tool call is logged asynchronously to the `tool_calls` table
via the buffered audit writer. Retention was bumped to 5 years for
SEBI compliance (previously 90 days). The dashboard surfaces this at
`/dashboard/activity` with CSV / JSON export.

Hash chaining (commit `3591cc6`) makes the table tamper-evident;
external anchoring is optional and gated on the `AUDIT_HASH_PUBLISH_*`
family of env vars — see [env-vars.md](env-vars.md) § Audit.

**Alert if:**
- Sudden 10x spike in `place_order` calls for one user within a minute
  — either the user's credentials are compromised or an LLM loop is
  runaway. Freeze with `admin_freeze_global` before investigating
  (see [operator-playbook.md](operator-playbook.md) § 6).
- Any audit write error in the logs (`buffered_audit_writer` dropped
  event / SQLite `database is locked`).
- `dropped_count` from `/healthz` exceeds the thresholds in the
  morning routine — this is a compliance gap, not an aesthetic issue.
- The hash chain fails its self-verification (logged at startup). A
  broken chain means the table was edited out-of-band.

### 5. Anomaly stats cache hit rate

The audit store caches per-user order baselines with a 15-minute TTL
to avoid hammering SQLite on every `place_order`. Hit rate is exposed
via `auditStore.StatsCacheHitRate()` and surfaces in the metrics
dashboard.

```go
hitRate := auditStore.StatsCacheHitRate()
```

**Alert if:**
- Hit rate < 70 % after one hour of steady traffic. Indicates either
  the TTL is too short for the workload, the cache is being evicted
  (memory pressure), or baselines are changing too often. Cache thrash
  translates to N+1 SQLite reads on the critical order path — at scale
  this blows the p95 latency budget on `place_order`.
- Hit rate = 100 % for days on end with new users joining — the cache
  may not be invalidating and could be serving stale baselines to the
  anomaly check.

### 6. RiskGuard metrics

Riskguard emits structured log lines for every block. The dimensions
available:

- **Reason**: `kill_switch`, `daily_count` (200/day), `duplicate`
  (30 s window), `rate_limit` (10/min), `confirmation_required`,
  `anomaly`, `off_hours`, `order_value_cap` (default ₹5 L),
  `qty_limit`, `daily_value_cap` (default ₹10 L), `auto_freeze`.
- **Per-user block history**: available on the admin dashboard and via
  `admin_risk_status` MCP tool.

**Alert if:**
- A sudden increase in blocks for a single user — inspect the audit
  trail for the same user: attack, misconfigured bot, or runaway LLM.
- **ZERO blocks for days** on a live deployment. Riskguard is almost
  certainly misconfigured (envs missing, middleware skipped). This is
  a silent safety regression — every production deploy should see the
  occasional `duplicate` or `rate_limit` hit.
- An unexpected `auto_freeze` — the circuit breaker tripped. Figure
  out why before unfreezing.

### 7. `X-Request-ID` correlation

Every inbound HTTP request is stamped with a random `X-Request-ID`
(also echoed back in the response header). The ID is propagated into
the slog context so every log line that handles the request — handler
→ MCP tool → use case → adapter → audit — carries the same ID. The
audit row records a separate `CallID` for the tool call itself; a
single request can emit multiple CallIDs when tool chaining happens.

Trace a request end-to-end:

```bash
flyctl logs -a kite-mcp-server | jq 'select(.request_id=="<id>")'
```

When a user reports "my order disappeared", the first thing to ask for
is the `X-Request-ID` from the failing response.

### 8. Fly.io platform signals

These come from the Fly dashboard or `flyctl`, not from the server
itself.

- **Machine restarts**: expected value = 0 between deploys. A restart
  outside a release window points to an OOM kill or a panic.
- **Memory usage**: capped at 512 MB (`fly.toml`). Alert at 80 %
  sustained. Memory regularly crossing 400 MB is a scale signal — see
  [operator-playbook.md](operator-playbook.md) § 7.
- **Egress bandwidth**: a sudden spike without a matching surge in
  tool calls is a potential data leak indicator. Normal trading-day
  egress stays well under 100 MB.
- **CPU**: shared 1 vCPU. Sustained > 70 % during market hours is a
  scale signal (bump to Performance-1x).

```bash
flyctl metrics -a kite-mcp-server
flyctl status -a kite-mcp-server
```

### 9. Telegram bot health

The bot handles alert delivery, morning briefings, daily P&L, and
inline trading commands (`/buy`, `/sell`, `/quick`, `/setalert`).

**Alert if:**
- Morning briefing not delivered by 09:10 AM IST on a weekday (the
  scheduler fires at 09:00 — a 10-minute grace covers normal variance).
- Daily P&L not delivered by 15:40 PM IST on a weekday (scheduled
  15:35).
- `/buy` command success rate drops below 95 % — the inline-keyboard
  confirmation flow has usually regressed.
- `TELEGRAM_BOT_TOKEN` missing after a secret rotation — feature is
  silently disabled, users do not see errors.

---

## Common alert scenarios

| Symptom | Likely cause | First response |
|---|---|---|
| `HTTP 429` from Kite API in logs | Global rate limit hit | Reduce outbound throughput; check for a runaway tool caller |
| Healthz `components.audit.status != "ok"` | SQLite file locked or Litestream replication backlog | Check `flyctl logs -a kite-mcp-server` for `litestream` errors |
| User reports widget blank | MCP client does not speak the Apps protocol | Verify host; the server falls back to text content automatically |
| Anomaly blocks spike | User attacked OR LLM running in a loop | Freeze via `admin_freeze_global`, inspect audit trail by user email |
| Telegram brief missed | Scheduler crashed or bot token rotated out | Check Fly logs for scheduler panics; restart machine |
| p95 on `place_order` > 5 s | Kite API slow, or static egress IP not whitelisted | Call `test_ip_whitelist` MCP tool |
| `dropped_count` climbing | Audit writer backpressured by slow SQLite writes | Investigate disk / Litestream; do not place orders until resolved |
| `/dashboard/activity` empty | Audit middleware not wired (regression) | Redeploy last-known-good release; investigate wire order |

---

## Logging

- Structured **slog JSON** to stdout. Fly.io captures this; run
  `flyctl logs -a kite-mcp-server` to tail.
- Correlate by `request_id` (HTTP layer) and `CallID` (audit row).
- `LOG_LEVEL` env var gates verbosity (`debug`, `info`, `warn`,
  `error`). Default `info`.
- Common filter patterns:

  ```bash
  # Errors and panics only
  flyctl logs -a kite-mcp-server | jq 'select(.level=="ERROR" or .msg|test("panic"))'

  # Everything for a single request
  flyctl logs -a kite-mcp-server | jq 'select(.request_id=="<id>")'

  # Everything for a single user
  flyctl logs -a kite-mcp-server | jq 'select(.email=="<email>")'
  ```

---

## Daily ops checklist

Run each morning (covered in [operator-playbook.md](operator-playbook.md)
§ 1):

1. `curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .`
2. Check Fly.io dashboard: machine health, error rate, memory.
3. Spot-check `/dashboard/activity` for anomalies or unexpected users.
4. If tool count / behaviour does not match expectation, invoke
   `server_version` from your MCP client to confirm the deployed SHA.

## Weekly ops checklist

1. Review SBOM changes (artifacts in the Actions tab — see
   [sbom.md](sbom.md)).
2. Review gosec SARIF for new findings.
3. Rotate `OAUTH_JWT_SECRET` if the month's staging rotation is
   overdue — procedure in [operator-playbook.md](operator-playbook.md)
   § 5.
4. Verify Litestream → R2 backup age: the most recent WAL segment
   under `s3://<LITESTREAM_BUCKET>/alerts.db/` should be under one
   minute old during trading hours.

---

## What is not alerted

Deliberately out of scope for this document:

- **SEBI compliance drift** — see [SECURITY_POSTURE.md](SECURITY_POSTURE.md).
- **Stripe billing webhooks** — handled by the billing middleware; a
  failure mode there does not affect trade execution.
- **Kite Connect upstream pricing changes** — monitor manually via the
  Zerodha developer console.
- **Per-tool unit test coverage** — a pre-commit and CI concern, not a
  runtime signal.

If you need these alerted, wire `/healthz?format=json` into an
external on-call system (PagerDuty / Grafana OnCall) with the
thresholds above.
