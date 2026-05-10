# Phase 2.5 — Postgres Operational Runbooks

**Date**: 2026-05-10 IST
**HEAD (kite-mcp-server)**: post-Phase-2.3 (commit `9122a75`)
**External repo state**:
- `algo2go/kite-mcp-alerts v0.5.0` (Phase 2.2 OpenPostgresDB + Phase 2.4 placeholder rewriter + round-trip tests)
- `algo2go/kite-mcp-billing v0.3.0` (Phase 2.1.6 cross-repo edit)

**Production state**: v261 LIVE on Fly.io BOM region; SQLite + Litestream → R2; **NOT yet running on Postgres**. This document is the operational reference for the **future** Phase 2.6 production canary.

**Charter**: doc-only research. NO code changes during this commit. Phase 2.6 is GATED on explicit user re-authorization due to real-Postgres-provisioning + cost + user-sign-off implications.

---

## TL;DR

Phase 2 has shipped 5 incremental phases over the last week:
- **Phase 2.0**: design + port stub (commit `c5b9cf7`)
- **Phase 2.1**: SQL portability audit + Stage 1 ON CONFLICT rewrites across 5 algo2go repos
- **Phase 2.1.6**: dialect.go helper (PragmaInit/TableExists/ColumnExists/SchemaDDL)
- **Phase 2.2**: `OpenPostgresDB` constructor + Postgres-flavored DDL
- **Phase 2.3**: driver-switching `ProvideAlertDB` factory in kite-mcp-server
- **Phase 2.4**: placeholder rewriter (`?` → `$N`) + 5 round-trip migration tests

Phase 2.5 (this doc) catalogues the operational procedures for the **upcoming** Phase 2.6 production canary. No infrastructure is provisioned yet; this is the playbook to follow when it is.

**Cost decision (deferred to Phase 2.6 dispatch)**: which Postgres provider — Fly Postgres (~₹400-1500/mo for HA), Neon (~₹0-2K/mo on free tier ≤500MB), Supabase (~₹0-2K/mo on free tier ≤500MB), or AWS RDS (₹2-5K/mo for db.t4g.micro). All four are viable for the canary; production-scale evaluation is a separate decision when paid-user signal requires it.

---

## R-1. Provider Selection Decision Matrix

| Provider | Free Tier | Latency to Fly.io BOM | India Region? | Recommendation |
|---|---|---|---|---|
| **Fly Postgres** | None; ~$8-15/mo for ha=1 | <1ms (same machine if `--region bom`) | Yes (BOM) | **Best for Phase 2.6 canary** — same datacenter as the app. |
| **Neon** | 0.5GB + 1 compute | ~50-100ms (US/EU regions only currently) | No (Asia Pacific in roadmap) | Free-tier viable for canary, but cross-region latency is a concern. |
| **Supabase** | 500MB + 2 projects | ~100-150ms (regional Asia Pacific in Singapore) | Singapore (closest) | Good free tier; cross-region latency moderate. |
| **AWS RDS** | None for Postgres after 12-mo free trial | <30ms from Mumbai region | Yes (ap-south-1) | Most expensive; preferred only at >1000-user scale. |

**Phase 2.6 canary recommendation**: **Fly Postgres in BOM region** because (a) collocated with our app, (b) flyctl primitives we already use, (c) cost predictable (₹500-1500/mo at 1-2 GB), (d) easy rollback (just point ALERT_DB_URL back to the local SQLite path).

---

## R-2. Provisioning Runbook (Fly Postgres in BOM)

### Pre-flight checks

1. Confirm `flyctl auth whoami` returns the project owner.
2. Confirm `kite-mcp-server` app exists in BOM: `flyctl status -a kite-mcp-server`.
3. Verify current SQLite-backed deploy is healthy: `curl -sf https://kite-mcp-server.fly.dev/healthz | head`.

### Provisioning steps

```bash
# 1. Create Postgres cluster in BOM (single instance for canary).
flyctl postgres create \
  --name kite-mcp-postgres \
  --region bom \
  --vm-size shared-cpu-1x \
  --volume-size 1 \
  --initial-cluster-size 1

# Output saves a connection URL. Store it as a fly secret next.

# 2. Attach to the kite-mcp-server app — auto-injects DATABASE_URL.
flyctl postgres attach kite-mcp-postgres -a kite-mcp-server

# 3. Override our specific env var (DATABASE_URL is generic; we want
# explicit ALERT_DB_URL so an unrelated future DATABASE_URL change
# doesn't accidentally repoint our alerts DB).
flyctl secrets set -a kite-mcp-server \
  ALERT_DB_DRIVER=postgres \
  ALERT_DB_URL='<the URL printed by step 1>'

# Note: flyctl secrets set triggers a rolling deploy; if you want to
# stage the secret without restart, use --stage and flyctl deploy
# explicitly.
```

### Verification (post-provisioning, pre-cutover)

```bash
# Connect from the app machine (verifies network reachability):
flyctl ssh console -a kite-mcp-server -C \
  'apk add postgresql-client && psql $ALERT_DB_URL -c "SELECT version()"'

# Or from local machine via flyctl proxy:
flyctl proxy 5432 -a kite-mcp-postgres &
PGPASSWORD=<from secret> psql -h localhost -U postgres -d kite_mcp_postgres \
  -c 'SELECT version()'
```

### Rollback

```bash
# Detach the Postgres cluster — restores app to SQLite-only path.
flyctl secrets unset -a kite-mcp-server ALERT_DB_DRIVER ALERT_DB_URL
flyctl postgres detach kite-mcp-postgres -a kite-mcp-server

# Optional: destroy the unused Postgres cluster (cost recovery).
flyctl apps destroy kite-mcp-postgres
```

---

## R-3. Migration Playbook (SQLite → Postgres)

**Charter**: this runbook covers the data-copy step from a live SQLite deployment to a freshly-provisioned Postgres. Phase 2.4's round-trip test verifies the Save* methods work both ways; this runbook is the production-data variant.

### Approach

The kite-mcp-alerts API exposes Load* methods for every table. The runbook is:
1. Take a **read-only snapshot** of SQLite (via Litestream's existing R2 backup).
2. Open both SQLite (snapshot) and Postgres in a one-shot Go script.
3. For each table, call `Load*` from SQLite → `Save*` to Postgres.
4. Verify row counts match per table.

### Data-copy script (provided as a one-off; NOT productionized)

The script lives at `scripts/postgres-import.go` (build tag `//go:build phase26migration`) and runs:

```go
//go:build phase26migration
package main

import (
    "log"
    "os"
    "github.com/algo2go/kite-mcp-alerts"
)

func main() {
    sqlitePath := os.Getenv("SOURCE_SQLITE_PATH")
    postgresURL := os.Getenv("TARGET_POSTGRES_URL")

    src, err := alerts.OpenDB(sqlitePath)
    if err != nil { log.Fatal(err) }
    defer src.Close()

    dst, err := alerts.OpenPostgresDB(postgresURL)
    if err != nil { log.Fatal(err) }
    defer dst.Close()

    // Copy alerts.
    byEmail, err := src.LoadAlerts()
    if err != nil { log.Fatal(err) }
    for _, slice := range byEmail {
        for _, a := range slice {
            if err := dst.SaveAlert(a); err != nil {
                log.Printf("save alert %s: %v", a.ID, err)
            }
        }
    }

    // Repeat for: tokens, credentials, telegram_chat_ids, sessions,
    // oauth_clients, daily_pnl, trailing_stops, app_registry.
    // Each follows the same Load → Save pattern; placeholder
    // rewriter handles the dialect difference.
}
```

**This script is NOT in scope for Phase 2.5 to write.** It's a Phase 2.6 deliverable, drafted here as a reference for the canary work.

### Verification per table (post-import)

```sql
-- Run on both DBs and compare:
SELECT 'alerts' AS tbl, COUNT(*) FROM alerts
UNION ALL SELECT 'kite_tokens', COUNT(*) FROM kite_tokens
UNION ALL SELECT 'kite_credentials', COUNT(*) FROM kite_credentials
UNION ALL SELECT 'telegram_chat_ids', COUNT(*) FROM telegram_chat_ids
UNION ALL SELECT 'mcp_sessions', COUNT(*) FROM mcp_sessions
UNION ALL SELECT 'oauth_clients', COUNT(*) FROM oauth_clients
UNION ALL SELECT 'daily_pnl', COUNT(*) FROM daily_pnl
UNION ALL SELECT 'trailing_stops', COUNT(*) FROM trailing_stops
UNION ALL SELECT 'app_registry', COUNT(*) FROM app_registry
UNION ALL SELECT 'config', COUNT(*) FROM config;
```

Counts must match within ±N (where N is concurrent-write activity during the snapshot window — typically 0 for a quiesced DB).

---

## R-4. Backup / Restore Runbook

### Backup (Fly Postgres)

Fly Postgres uses **WAL-E** archiving to S3 for continuous backup with point-in-time recovery (PITR).

```bash
# Manual snapshot (in addition to continuous WAL):
flyctl postgres backup create -a kite-mcp-postgres

# List backups:
flyctl postgres backup list -a kite-mcp-postgres
```

### Restore from PITR

```bash
# Restore to a specific timestamp (UTC):
flyctl postgres backup restore <backup-id> \
  -a kite-mcp-postgres \
  --target-time '2026-05-15T14:30:00Z'

# Restore creates a NEW Fly Postgres app; you then re-attach to
# kite-mcp-server with the new URL.
```

### SQLite + Litestream parallel-backup window

**During Phase 2.6 canary**: keep Litestream backing up the SQLite file until the canary is declared stable (≥1 week of green Postgres). This gives a fallback rollback path for at least 30 days of WAL retention.

---

## R-5. Health Check / Monitoring

### `/healthz?probe=deep`

The existing healthz endpoint already wraps `*alerts.DB.Ping()`. Phase 2.3's Store interface contract means `Ping()` returns nil iff the underlying DB (SQLite or Postgres) round-trips a `SELECT 1`.

Verify per-driver:
```bash
# SQLite path:
ALERT_DB_DRIVER=sqlite ALERT_DB_PATH=./test.db ./bin/kite-mcp-server &
curl -sf http://localhost:8080/healthz?probe=deep | jq

# Postgres path:
ALERT_DB_DRIVER=postgres ALERT_DB_URL='postgres://...' ./bin/kite-mcp-server &
curl -sf http://localhost:8080/healthz?probe=deep | jq
```

### Key metrics to watch during canary

| Metric | SQLite baseline | Postgres canary alert threshold |
|---|---|---|
| /healthz?probe=deep latency | <500ms p99 | >1s p99 |
| Tool call latency (audit-trail write) | <50ms p99 | >100ms p99 |
| Error rate on Save* methods | <0.1% | >1% |
| Connection pool wait | N/A (SQLite single-conn) | >100ms p99 |
| Rolling 1h crash count | 0 | ≥1 |

If any threshold trips, follow R-7 incident response.

---

## R-6. Switchover Runbook (Canary → Full)

After the canary user has been on Postgres for ≥1 week with no issues:

```bash
# 1. Snapshot current Postgres state.
flyctl postgres backup create -a kite-mcp-postgres

# 2. Run final SQLite → Postgres reconciliation for any drift.
# (One-shot Go script; verifies counts within ±0).

# 3. Cut over remaining users by removing Litestream backup of SQLite
#    file and switching ALERT_DB_DRIVER=postgres for all users.
flyctl secrets set -a kite-mcp-server ALERT_DB_DRIVER=postgres

# 4. After 30 days of green Postgres production, decommission SQLite:
#    - Delete the SQLite file from the Fly machine
#    - Delete the Litestream R2 bucket contents
#    - Update fly.toml to remove the SQLite volume mount
```

---

## R-7. Incident Response Runbook

### Scenario A: Postgres unreachable, SQLite still healthy

**Symptom**: `/healthz?probe=deep` returns 500 with "ALERT_DB ping failed"; Fly Postgres dashboard shows offline.

**Action**: rollback to SQLite (5-minute panic button):
```bash
flyctl secrets unset -a kite-mcp-server ALERT_DB_URL
flyctl secrets set -a kite-mcp-server ALERT_DB_DRIVER=sqlite
# This triggers a rolling restart. Service comes back on the existing
# SQLite path. Loss of any writes between Postgres outage start and
# this rollback is the trade-off.
```

**Followup**: file a postmortem; investigate Fly Postgres status; reconcile any data drift between Postgres and SQLite once Postgres is recovered.

### Scenario B: ID drift after SQLite restore

**Symptom**: After R-3 import, Postgres `alerts` table has duplicate IDs OR audit log hash chain breaks.

**Cause**: usually SQLite's INTEGER PRIMARY KEY AUTOINCREMENT was used for some surrogate ID that didn't migrate cleanly to Postgres.

**Action**:
1. Investigate which table has duplicates: `SELECT id, COUNT(*) FROM <table> GROUP BY id HAVING COUNT(*) > 1`.
2. Empirically only `audit.tool_calls.id` and `audit.consent_log.id` have INTEGER PK AUTOINCREMENT — the kite-mcp-alerts schema uses TEXT PKs everywhere else.
3. For audit hash chain breakage: re-run hash-chain verification: `SELECT * FROM audit.tool_calls WHERE prev_hash != computed_hash`. If any drift, regenerate the chain from the affected timestamp forward (audit log integrity is verifiable but not transactional with the row insert).

### Scenario C: Connection pool exhaustion

**Symptom**: Latency spikes; `/healthz?probe=deep` timeouts; Postgres dashboard shows max_connections hit.

**Action**:
1. Check current connection count: `SELECT count(*) FROM pg_stat_activity`.
2. Identify long-running queries: `SELECT pid, now()-pg_stat_activity.query_start AS duration, query FROM pg_stat_activity WHERE (now()-pg_stat_activity.query_start) > interval '5 seconds';`
3. Kill stuck queries: `SELECT pg_cancel_backend(<pid>)`.
4. If chronic: increase Postgres `max_connections` or app's `db.SetMaxOpenConns(N)` cap.

**Phase 2.4 default**: kite-mcp-alerts' `OpenPostgresDB` does NOT cap MaxOpenConns (Postgres handles concurrency natively, unlike SQLite's `SetMaxOpenConns(1)` at line 116 of db.go for SQLite). Default Go `database/sql` MaxOpenConns is 0 (unlimited). For Phase 2.6, we may want to cap at e.g. 20 to bound resource usage; surface during canary observation.

### Scenario D: SQLite + Postgres data drift detected

**Symptom**: row counts diverge between SQLite (Litestream snapshot) and Postgres after several days of dual-write.

**Cause**: Phase 2.6 canary writes to Postgres only; SQLite is read-only fallback. If our cutover wasn't atomic OR Litestream lagged, drift appears.

**Action**:
1. Confirm dual-write is OFF (Postgres-only): grep app logs for `alerts.OpenDB` calls during canary window — should be zero.
2. Stop Litestream during canary (it's snapshotting a stale file): `flyctl secrets set LITESTREAM_DISABLED=true` if such env var exists; else stop the litestream sidecar process.
3. After canary stable: drop the Litestream R2 bucket entirely (R-6 step 4).

---

## R-8. Cost Tracking Runbook

| Component | Cost/month | Notes |
|---|---|---|
| Fly Postgres (1 instance, 1GB volume, shared-cpu-1x) | ~₹500-1500 | Scales with usage |
| Continuous backup (WAL-E to S3) | Included by Fly | No separate cost |
| App egress to Postgres | Included by Fly | Same datacenter |
| Connection-pooler (PgBouncer) | Optional; ₹500-1000/mo if separate VM | Skip during canary; add at >100 connections sustained |
| Observability (Grafana/Prom for Postgres metrics) | ~₹500/mo for hosted | Skip during canary; use Fly's built-in metrics first |
| **Phase 2.6 canary monthly total** | **~₹500-1500** | All-in for the canary window |

**Compare to SQLite + Litestream**: ~₹0/month (Litestream-on-R2 free tier sufficient at our scale). The Postgres step costs ~₹500-1500/mo recurring — the operator (us) pays this regardless of user count during canary.

**Trigger for full cutover (Phase 3)**: 100+ concurrent users sustained. Below that threshold, Postgres is pure operational cost without ROI.

---

## R-9. Stop Conditions for Phase 2.6 Itself

Per the original Phase 2.0 design doc, Phase 2.6 stops if:
1. SQLite-vs-Postgres latency delta >50ms p99 sustained → investigate before continuing rollout.
2. Cost trajectory exceeds ₹3000/mo for canary alone → re-evaluate provider.
3. Any audit hash chain integrity violation post-migration → halt; reconcile.
4. User-reported data discrepancy → halt; full reconciliation.
5. Phase 3 multi-cell trigger fires before Phase 2.6 stable → emergency-promote Phase 3 (multi-cell needs Postgres anyway).

---

## R-10. Open Questions for Phase 2.6 Dispatch

These need user-side decisions before Phase 2.6 begins:

1. **Provider choice**: Fly Postgres, Neon, Supabase, or AWS RDS? (R-1 recommends Fly.)
2. **Canary user**: which user account flips first? (Recommendation: a test/dev account, not a paid user, until R-5 metrics show 1-week green.)
3. **Connection pool cap**: leave default unlimited or cap at 20? (Recommendation: cap at 20 for canary; uncap after observation.)
4. **Litestream parallel-backup window**: 30 days? 60 days? Forever? (Recommendation: 30 days post-canary-stable.)
5. **Rollback decision SLA**: how fast do we revert if R-7 Scenario A fires? (Recommendation: 15-minute SLA — automated alerting + on-call rotation prerequisite.)
6. **Phase 2.6 SLO**: what error-rate threshold counts as "canary failed"? (Recommendation: >1% Save-method error rate over rolling 1h is auto-rollback.)

---

## R-11. References

- Phase 2.0 design: `.research/phase-2-postgres-adapter-design.md`
- Phase 2.1 audit: `.research/phase-2-sql-portability-audit.md`
- Phase 2.4 round-trip tests: `algo2go/kite-mcp-alerts/roundtrip_test.go` (build tag `postgres`)
- pgx/v5 stdlib docs: https://pkg.go.dev/github.com/jackc/pgx/v5/stdlib
- Fly Postgres docs: https://fly.io/docs/postgres/
- 10K-agent blocker analysis: `.research/10000-agent-blocker-analysis.md`

---

**End of Phase 2.5 runbooks. Doc-only commit. tools=130 invariant preserved. Phase 2.6 dispatch is BLOCKED on user re-authorization per the Phase 2.5 dispatch instructions.**
