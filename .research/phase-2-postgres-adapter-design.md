# Phase 2 — Postgres Adapter Design

**Date**: 2026-05-09 IST
**HEAD**: `c6eea80` (kc/sectors Path A.26 — Path A inauguration COMPLETE; 27 algo2go modules external)
**Production**: v252 LIVE; tools=130; 64th consecutive deploy
**Pick justification**: see `.research/phase-2-pick.md`
**Trigger threshold**: 1000+ concurrent users (per `.research/10000-agent-blocker-analysis.md` L2.4)
**Authority**: this doc is normative for the Phase 2 work; the implementation will live across two repos (this + `algo2go/kite-mcp-alerts`). Updates require commit + push.

---

## TL;DR

The persistence layer at HEAD `c6eea80` consists of one consolidated SQLite database (`alerts.DB` in external `algo2go/kite-mcp-alerts`) holding **5 logical tables**: price-alerts, audit, sessions, tokens, credentials. Per-tenant scoping is by email column. The `*alerts.DB` type wraps `*sql.DB` from `modernc.org/sqlite` (cgo-free).

**Phase 2 design**: introduce a `Store` port interface in this repo's `app/providers/store_port.go`, with two implementations:
1. **SQLite adapter** (existing, lives in external `algo2go/kite-mcp-alerts`)
2. **Postgres adapter** (new, lives in external `algo2go/kite-mcp-alerts` alongside SQLite)

Selection at runtime via `ALERT_DB_DRIVER` env var (default `sqlite`, opt-in `postgres`). Both implementations satisfy the same `Store` port; the Fx provider `ProvideAlertDB` becomes a driver-switching factory.

**Key constraint**: SQL portability. Current `algo2go/kite-mcp-alerts` SQL likely uses SQLite-specific syntax (`INSERT OR REPLACE`, `?` placeholders, `INTEGER PRIMARY KEY AUTOINCREMENT`). Phase 2.1 audits and rewrites SQL to be portable across both dialects — OR uses dialect-specific `BuildInsert(dialect)` helpers.

**Smallest first step (THIS COMMIT)**: define the `Store` port interface as a doc + stub in `app/providers/store_port.go` (compile-clean, no behavior change, no driver added yet).

**Calendar to ready**: ~2-4 weeks of focused engineering. Implementation lives mostly in `algo2go/kite-mcp-alerts` external repo; this repo's changes are ~5-10% of total LOC (config + injection + tests).

---

## Empirical Baseline

### Current persistence state at HEAD `c6eea80`

| Component | Type | Driver | Location |
|---|---|---|---|
| `alerts.DB` (struct) | concrete | `database/sql` over `modernc.org/sqlite` | `algo2go/kite-mcp-alerts` external repo |
| Schema | 5 logical tables | SQLite-flavored DDL | `algo2go/kite-mcp-alerts` |
| Per-tenant scoping | column-based | by `email TEXT` | within each table |
| Encryption at rest | AES-256-GCM via HKDF | per-row | `OAUTH_JWT_SECRET` derives KEK |
| Backup | Litestream → Cloudflare R2 | streaming WAL | bucket `kite-mcp-backup` |
| Lifecycle | Fx-managed | `OnStop` calls `db.Close()` | `app/wire.go` composition |

### The seam — `app/providers/alertdb.go`

Empirical chokepoint at lines 54-69 (verified at HEAD `c6eea80`):

```go
func ProvideAlertDB(cfg AlertDBConfig, logger *slog.Logger) (*alerts.DB, error) {
    if cfg.Path == "" {
        return nil, nil
    }
    db, err := alerts.OpenDB(cfg.Path)
    if err != nil { /* log + downgrade */ }
    return db, nil
}
```

**This is the only call site that constructs the DB.** Every consumer downstream (`AlertSvc`, `AuditStore`, `BillingStore`, `CredentialStore`, `SessionRegistry`, `KiteTokenStore`) receives `*alerts.DB` via Fx injection. Swapping the constructor here propagates everywhere.

### Consumers of `*alerts.DB` (count: 15 files in `app/providers`)

```
app/providers/alert_svc.go
app/providers/audit.go            app/providers/audit_init.go
app/providers/audit_init_test.go  app/providers/audit_middleware_test.go
app/providers/billing.go          app/providers/billing_test.go
app/providers/family_test.go      app/providers/manager.go
app/providers/providers_test.go   app/providers/riskguard.go
app/providers/riskguard_test.go   app/providers/scheduler.go
app/providers/scheduler_test.go   app/providers/telegram.go
app/providers/telegram_test.go
```

Plus 6 files in `app/` (root) using `*alerts.DB`: `adapters.go`, `adapters_test.go`, `adapters_local_bus.go`, `server_edge_test.go`, `wire.go`, `interfaces.go`-aliased usages.

**Implication**: introducing a port-level abstraction `Store` MUST preserve `*alerts.DB` as the concrete return type to avoid touching 21+ files. The port lives ABOVE `*alerts.DB`, not below.

---

## Design

### Layer model

```
┌─────────────────────────────────────────────────────────────┐
│ app/wire.go (composition root)                               │
│  ↓ requests via Fx                                           │
├─────────────────────────────────────────────────────────────┤
│ app/providers/alertdb.go::ProvideAlertDB (factory)           │
│  ↓ selects driver from ALERT_DB_DRIVER env                   │
│  ├─ sqlite (default) → alerts.OpenDB(path)                   │
│  └─ postgres (opt-in) → alerts.OpenPostgresDB(url)           │
├─────────────────────────────────────────────────────────────┤
│ external: github.com/algo2go/kite-mcp-alerts                 │
│  ├─ alerts.DB (concrete struct, wraps *sql.DB)               │
│  ├─ alerts.OpenDB(path string) (*DB, error)         [SQLite] │
│  ├─ alerts.OpenPostgresDB(url string) (*DB, error)  [NEW]    │
│  └─ alerts.Store (interface — see below)            [NEW]    │
├─────────────────────────────────────────────────────────────┤
│ database/sql (Go stdlib)                                      │
├─────────────────────────────────────────────────────────────┤
│ drivers:                                                      │
│  ├─ modernc.org/sqlite (cgo-free)                            │
│  └─ github.com/jackc/pgx/v5/stdlib (Postgres)                │
└─────────────────────────────────────────────────────────────┘
```

### `Store` port interface (in this repo, this commit)

The port lives in `app/providers/store_port.go` and is INTENTIONALLY a documentation-only stub at this commit. It is NOT yet implemented by `*alerts.DB` — that's the external-repo work in Phase 2.2.

**Why a stub now**: it locks in the contract for the external repo's implementation, surfaces SQL-portability constraints early, and gives Phase 3 (multi-cell) a stable boundary to plan against.

The interface (sketched below — full Go in `store_port.go`):

```
type Store interface {
    AlertReader   // GetAlertsByEmail, AlertCount, ...
    AlertWriter   // CreateAlert, UpdateAlert, DeleteAlert, ...
    AuditReader   // QueryAuditLog, GetCallByID, ...
    AuditWriter   // RecordToolCall, ...
    SessionStore  // SaveSession, LoadSession, DeleteSession, ...
    TokenStore    // SaveToken, LoadToken, RevokeToken, ...
    CredentialStore // SaveCredentials, LoadCredentials, DeleteCredentials, ...
    HealthCheck() error
    Close() error
}
```

**Note**: each sub-interface (AlertReader, AuditWriter, etc.) is already implemented as a narrow type alias in `kc/interfaces.go` (e.g., `kc.AlertStoreInterface` aliases `alerts.AlertStoreInterface`). The `Store` port is the **union**, exposed for the rare consumer that needs it all (the composition root). Most consumers depend on a sub-interface only — Interface Segregation already in practice.

### Driver-switching factory

`ProvideAlertDB` becomes:

```
func ProvideAlertDB(cfg AlertDBConfig, logger *slog.Logger) (*alerts.DB, error) {
    switch cfg.Driver {
    case "", "sqlite":
        return alerts.OpenDB(cfg.Path)
    case "postgres":
        return alerts.OpenPostgresDB(cfg.URL)
    default:
        return nil, fmt.Errorf("unknown driver: %q", cfg.Driver)
    }
}
```

`AlertDBConfig` extends:

```
type AlertDBConfig struct {
    Driver string  // "sqlite" (default) or "postgres"
    Path   string  // SQLite-only: filesystem path
    URL    string  // Postgres-only: postgres://user:pass@host/db
}
```

Env binding (in production wiring at `app/config.go` or equivalent):

```
ALERT_DB_DRIVER  # "sqlite" or "postgres"; default "sqlite"
ALERT_DB_PATH    # SQLite-only
ALERT_DB_URL     # Postgres-only
```

### SQL portability strategy

Two paths considered:

**Path A: portable SQL (preferred)**
- Rewrite SQLite-specific syntax in `algo2go/kite-mcp-alerts`:
  - `INSERT OR REPLACE` → `INSERT ... ON CONFLICT (...) DO UPDATE`
  - `?` placeholders → `?` for SQLite, `$1, $2, ...` for Postgres (handled via dialect-aware query builder OR raw-SQL-per-dialect)
  - `INTEGER PRIMARY KEY AUTOINCREMENT` → `BIGSERIAL PRIMARY KEY` (Postgres) / `INTEGER PRIMARY KEY AUTOINCREMENT` (SQLite)
  - `BLOB` → `BYTEA` (Postgres) / `BLOB` (SQLite)
  - `DATETIME` → `TIMESTAMP` (Postgres) / `DATETIME` (SQLite)
- Use `sq` (squirrel) or hand-coded dialect dispatcher
- Pro: single SQL surface; easier to keep both drivers in sync
- Con: refactor surface in external repo

**Path B: dialect-specific SQL files**
- Maintain `schema_sqlite.sql` + `schema_postgres.sql` separately
- `OpenDB` / `OpenPostgresDB` each load their own
- Pro: each dialect uses native idioms (better performance)
- Con: drift risk; double-maintenance

**Recommendation**: Path A for tables. Path B for migrations only (each dialect's migration framework handles versioning natively).

### Migration tooling

- **SQLite**: keep current ad-hoc CREATE TABLE IF NOT EXISTS pattern (works, low risk)
- **Postgres**: use `golang-migrate/migrate` (mature, supports up/down, integrates with `database/sql`) — runs at `OpenPostgresDB` init time

### Driver dependency

Add to external `algo2go/kite-mcp-alerts` go.mod:
```
github.com/jackc/pgx/v5 v5.x.x  // includes /stdlib
```

This repo (root): no new deps. The existing `replace github.com/algo2go/kite-mcp-alerts => ...` is the only touch point if/when we want to test against the external repo's branch locally.

### Encryption at rest — unchanged

The AES-256-GCM-via-HKDF wrapper sits in application code (the row encryptor, NOT the driver). Postgres TDE (transparent data encryption) is offered by managed-Postgres providers but adds complexity; keep app-layer encryption identical across both drivers for portability.

### Litestream → Postgres equivalent

- **SQLite**: Litestream → R2 (current; works, $0/mo)
- **Postgres**: managed-Postgres providers ship native PITR + replication; Litestream is sqlite-specific, no equivalent needed for Postgres
- **Backup strategy** changes per driver — document in Phase 2.5 "Operational runbooks"

---

## Cost ceiling at scale

### SQLite (current — zero-user to ~1000 users)

| Component | Cost |
|---|---|
| Local SQLite file | ₹0 |
| Litestream → R2 backup | ₹0/mo (free tier) |
| Litestream binary | ₹0 |
| **Total** | **₹0/mo** |

### Postgres (Phase 2 ready, Phase 3 trigger fires)

| Component | Cost |
|---|---|
| Neon (managed Postgres, generous free tier; 0.5 GB free) | ₹0-2K/mo at <500 users |
| Supabase (Postgres + extras; 500 MB free) | ₹0-2K/mo at <500 users |
| AWS RDS db.t4g.micro (Postgres) | ~₹2-5K/mo |
| Hetzner Cloud + self-hosted Postgres | ~₹600-1K/mo (CPX21) |
| Per-cell shard at 10 cells (Phase 3) | ~₹15-30K/mo total |

**Crossover**: SQLite + Litestream is cheaper at <500 concurrent users. Postgres ROI inflects when:
1. SQLite single-writer becomes bottleneck (>100K writes/hour) OR
2. Multi-cell read replication required (Phase 3 trigger) OR
3. Cross-cell aggregate queries needed (currently zero)

**Phase 2 doesn't migrate.** It builds the optionality. Migration triggers in Phase 3.

---

## Hard dependencies

1. **`algo2go/kite-mcp-alerts` external repo** must be modified to add `OpenPostgresDB` + dual-dialect schema. This is the bulk of Phase 2 implementation work.
2. **No `replace` directive added** in this repo's go.mod during design phase. `replace` is only for local testing during implementation; production stays on tagged version.
3. **`pgx/v5` driver** added to `algo2go/kite-mcp-alerts` go.mod; pulls in via Go module graph when this repo updates the dep.
4. **CI integration**: Postgres test container in `algo2go/kite-mcp-alerts` CI matrix; in-tree CI here remains SQLite-only (faster, no Docker dep).
5. **Migration test in CI**: round-trip `SQLite dump → Postgres load → compare row counts` in `algo2go/kite-mcp-alerts`.

---

## Phased work breakdown

| Phase | Scope | Repo | Budget |
|---|---|---|---|
| 2.0 | Pick + design doc + port stub | this | ~3-4h (THIS DISPATCH) |
| 2.1 | SQL portability audit in external repo (catalog SQLite-isms) | external | ~1-2 days |
| 2.2 | Add `OpenPostgresDB` constructor + Postgres schema | external | ~3-5 days |
| 2.3 | Driver-switching factory in `ProvideAlertDB` | this | ~1-2 days |
| 2.4 | Round-trip migration test (SQLite → Postgres) | external | ~2-3 days |
| 2.5 | Operational runbooks (Postgres backup, restore, switchover) | this `.research/` | ~1 day |
| 2.6 | Production rollout — opt-in Postgres for canary user | both | ~1-2 days |

**Total**: ~14-21 engineer-days. Calendar: ~3-4 weeks at 1-agent pace; ~1-2 weeks at 3-agent pace.

---

## ROI rationale

- **Today**: zero direct ROI (SQLite handles current load).
- **At Phase 3 trigger** (100+ concurrent users sustained): port interface unlocks per-cell shard architecture. Without Phase 2's port, Phase 3 is blocked on partition strategy.
- **At Phase 4 trigger** (regulatory: NSE empanelment ~50 paid subs): Phase 3 cells need per-region data residency; Postgres replication is the canonical solution.
- **Risk avoidance**: SQLite single-writer hits a wall at sustained ~100-1000 writes/sec. Audit log + ticker spool can spike there during market hours.

**The port interface is the cheap insurance.** Even if we never migrate to Postgres, having the port stabilizes the boundary for any future store substitution (e.g., DynamoDB-on-AWS, FoundationDB, etc.).

---

## Smallest first concrete step (THIS COMMIT)

**File**: `app/providers/store_port.go` — port interface stub, compile-clean, no behavior change.

**Surface**: ~150-200 LOC of Go documentation comments + interface declarations. Imports `algo2go/kite-mcp-alerts` to reference existing sub-interfaces. Each method commented with: SQL semantics, dialect portability constraint, encryption invariants, per-tenant scoping rule.

**Test**: `app/providers/store_port_test.go` verifies `*alerts.DB` satisfies `Store` (i.e., the existing concrete already meets the contract — proves zero-behavior-change). One assertion only:
```
var _ Store = (*alerts.DB)(nil)
```

**Tools=130 invariant**: PRESERVED (no `mcp.NewTool(...)` added).

**WSL2**: `go build ./...` + `go test ./app/providers/...` MUST pass green before push.

---

## Recommended next dispatch

After this commit lands, the next research-or-execution dispatch should be:

**Phase 2.1 — SQL portability audit in `algo2go/kite-mcp-alerts`** (deferred to a sub-agent who clones that external repo).

Brief skeleton:
```
Domain: persistence portability audit — algo2go/kite-mcp-alerts
Repo: github.com/algo2go/kite-mcp-alerts (separate clone)
Budget: 1-2 days
Output: .research/phase-2-sql-portability-audit.md (in THIS repo)
  - All SQLite-specific syntax with proposed Postgres equivalents
  - Migration plan for INSERT OR REPLACE → ON CONFLICT
  - Placeholder strategy ($N for Postgres vs ? for SQLite)
  - Dialect-dispatch helper API sketch
Hard rules: no edits to algo2go repo yet — audit only.
```

Subsequent dispatches (sequential):
- **Phase 2.2** — implement `OpenPostgresDB` in external repo (3-5 days)
- **Phase 2.3** — driver-switching `ProvideAlertDB` in this repo (1-2 days)
- **Phase 2.4** — round-trip migration test (2-3 days)
- **Phase 2.5-2.6** — runbooks + canary rollout (2-3 days)

**Stop conditions for dispatch chain**:
1. SQL portability audit reveals >20% of SQL surface needs rewrite → escalate to user with cost impact
2. `pgx` driver adds >5MB to binary → reconsider (current binary ~30MB; +16% is borderline)
3. Postgres test container in CI doubles CI run time → reconsider (kills budget gain from Phase 1.4 audit)
4. Phase 3 trigger fires before Phase 2.4 ships → emergency-promote Phase 2

---

## Out of scope for Phase 2

- Per-cell shard router (that's Phase 3.2)
- Cross-cell aggregate queries (that's Phase 3.4)
- Postgres-specific features (LISTEN/NOTIFY, JSONB, full-text search) — keep SQL portable until at-scale need surfaces
- Migration FROM SQLite TO Postgres for existing users (Phase 2.4 round-trip test is the upgrade path; production migration is Phase 2.6)
- DynamoDB / FoundationDB / other-store evaluation (port interface enables future eval; not Phase 2 work)

---

**End of design. Doc-only commit. tools=130 invariant verified at HEAD `c6eea80` (64th deploy streak).**
