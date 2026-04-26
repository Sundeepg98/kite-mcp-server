# ADR 0002: SQLDB Port — Postgres Readiness

**Status**: Accepted (2026-04-26)
**Author**: kite-mcp-server architecture
**Decision drivers**: dim-11 (ISO 25010 Portability) auditor expectations; path-to-100 deep-dive Class 3 (`2a1f933`).

---

## Context

Auditors evaluating dim-11 (Portability) ask: "Is the system extensible to other DB engines (Postgres, MySQL)?" Today kite-mcp-server runs SQLite via `*alerts.DB` (`kc/alerts/db.go`). Cloudflare R2 + Litestream replication makes the SQLite dependency low-friction at our scale, but the auditor question deserves a structural answer.

## Decision

Define a narrow `kc/alerts.SQLDB` interface (`kc/alerts/db.go:13`) capturing the dialect-portable subset of `*alerts.DB`:

```go
type SQLDB interface {
    ExecDDL(ddl string) error
    ExecInsert(query string, args ...any) error
    ExecResult(query string, args ...any) (sql.Result, error)
    QueryRow(query string, args ...any) *sql.Row
    RawQuery(query string, args ...any) (*sql.Rows, error)
    Close() error
    Ping() error
    SetEncryptionKey(key []byte)
}
```

Compile-time assertion: `kc/alerts/db_test.go:39 — var _ SQLDB = (*DB)(nil)`. Plus runtime contract test `TestSQLDB_DBSatisfiesInterface` proving the interface is real, not Go-rules-accidental.

## Postgres adapter contract

A future Postgres adapter ships as `kc/alerts/postgres.go` (or `kc/alerts/postgresdb.go`) with one new compile-time assertion:

```go
var _ SQLDB = (*PostgresDB)(nil)
```

The build fails immediately if signatures drift.

## What's NOT on SQLDB (and why)

`GetConfig` / `SetConfig` use SQLite-specific syntax:

```sql
INSERT OR REPLACE INTO config (key, value) VALUES (?, ?)
```

Postgres equivalent:

```sql
INSERT INTO config (key, value) VALUES ($1, $2)
ON CONFLICT (key) DO UPDATE SET value = $2
```

These methods stay on `*DB` directly. A `PostgresDB` would have a parallel `GetConfig`/`SetConfig` with Postgres-flavored SQL — same method names, dialect-specific bodies. Callers reach through the concrete type for these (3 callsites in production: `kc/alerts/encryption_salt.go`, `kc/audit/hashpublish_chain.go`, `kc/manager_init.go`). A real Postgres migration would update those 3 callsites to a `ConfigStore` sub-interface or use a runtime dispatch helper.

## DDL portability

Schema files (`kc/alerts/db.go:68-200`) use SQLite-flavored DDL:
- `INTEGER PRIMARY KEY` (SQLite) → `BIGSERIAL PRIMARY KEY` (Postgres)
- `TEXT` (SQLite, type-flexible) → `VARCHAR(N)` or `TEXT` (Postgres, strict)
- `TEXT NOT NULL DEFAULT '{}'` for JSON (SQLite) → `JSONB NOT NULL DEFAULT '{}'::jsonb` (Postgres-native)

A real adapter would maintain a parallel DDL pass. ~150 LOC of DDL translation, mechanical.

## Why no real Postgres adapter today

Per `78c243e` business-case analysis:
- **LOC cost**: ~400-600 LOC for driver swap + DDL translation + transaction-isolation tuning
- **CI cost**: ARM64 Postgres test matrix (~200 LOC of GitHub Actions YAML)
- **Demand signal**: 0 paying customers running off Fly.io / SQLite
- **Score lift**: dim-11 73→80 (+7pt) from interface stub; +15pt only with real adapter
- **Opportunity cost**: same engineering time better spent on user-facing features

Verdict: ship interface readiness (this ADR + `SQLDB` interface in `0a9e78d`); defer real adapter until paying customer demands non-Fly.io deployment.

## Consequences

**Positive**:
- Auditor question answered: "Yes, port exists at `kc/alerts/db.go:13`."
- Future contributor adding Postgres has a single satisfaction target.
- Zero ongoing maintenance cost.

**Neutral**:
- Score lift capped at +7pt without real adapter.

**Negative**:
- Schema DDL bit-rot risk: new tables added to `kc/alerts/db.go`'s DDL block use SQLite-flavored syntax; the parallel Postgres DDL would lag. Mitigation: gate new DDL on a comment line documenting Postgres equivalent (e.g. `-- pg: BIGSERIAL PRIMARY KEY`). Not enforced today.

## References

- `kc/alerts/db.go:13` — `SQLDB` interface definition (introduced commit `0a9e78d`)
- `kc/alerts/db_test.go:39` — compile-time satisfaction assertion
- `kc/alerts/db.go:285-324` — `*DB` methods that satisfy the interface (plus `GetConfig`/`SetConfig` that intentionally don't)
- `etc/litestream.yml` — current SQLite → R2 replication config (alternative high-availability path)
- `.research/path-to-100-per-class-deep-dive.md` Class 3
- `.research/path-to-100-business-case.md` (`78c243e`) §6 — Postgres adapter LOC cost
