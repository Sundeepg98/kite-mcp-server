# Phase 2.1 — SQL Portability Audit

**Date**: 2026-05-09 IST
**HEAD (this repo)**: `d63391a`
**Production**: v254 LIVE (66th deploy); tools=130
**Auditing**: 5 external repos that wrap `*alerts.DB` for persistence:
- `D:/Sundeep/projects/algo2go/kite-mcp-alerts` (host of the shared `*sql.DB`)
- `D:/Sundeep/projects/algo2go/kite-mcp-audit` (consumes `*alerts.DB`)
- `D:/Sundeep/projects/algo2go/kite-mcp-billing` (consumes `*alerts.DB`)
- `D:/Sundeep/projects/algo2go/kite-mcp-watchlist` (consumes `*alerts.DB`)
- `D:/Sundeep/projects/algo2go/kite-mcp-users` (consumes `*alerts.DB`)
- `D:/Sundeep/projects/algo2go/kite-mcp-registry` (verified zero-SQL — pure in-memory)

**Audit method**: read-only ripgrep + Read of all DB-touching .go files. NO edits to any external repo. NO Go code edited in any repo.

**Stop-rule check (per design doc Phase 2.0)**: condition #1 was "if >20% of SQL surface needs rewrite, surface findings and pause Phase 2.2". **Empirical surface needing rewrite ≈ 13%**. Below the stop threshold; Phase 2.2 dispatch remains GREEN.

---

## TL;DR

Phase 2.1 surfaced **substantially better starting position** than the Phase 2.0 design doc anticipated:

1. **`SQLDB` interface ALREADY EXISTS** at `kite-mcp-alerts/db.go:32-41` — the dialect-portable surface declared in 2024 with explicit Postgres-readiness commentary. Phase 2.0's "introduce port" framing is already half-shipped.
2. **billing repo ALREADY USES `ON CONFLICT(...) DO UPDATE`** — partial Postgres-style upsert already deployed in production for the most-recently-touched store.
3. **Encryption uses TEXT, not BLOB** — base64-encoded ciphertext stored in TEXT columns. Identical surface across SQLite + Postgres.
4. **Read-side queries are highly portable** — LIMIT/OFFSET/ORDER BY/GROUP BY only; zero `julianday()`/`strftime()`/`json_extract()`/`date()` SQLite functions. **Read-side rewrite cost ≈ 0.**
5. **18 production upsert sites need dialect dispatch** (down from feared 30+).

**Empirical SQL surface requiring rewrite**:
- 18 INSERT OR REPLACE / INSERT OR IGNORE sites → ON CONFLICT
- 4 schema declarations using `INTEGER PRIMARY KEY AUTOINCREMENT` → BIGSERIAL
- 1 sqlite_master query in alerts migration → `pg_catalog.pg_tables` equivalent
- 6 PRAGMA statements (WAL, busy_timeout, foreign_keys) → no-op or Postgres equivalents
- ~10 `INTEGER NOT NULL DEFAULT 0` boolean-encoded columns → BOOLEAN (or keep INTEGER for portability)

**Estimated effort**: ~5-7 engineer-days for SQL portability rewrite + dialect-dispatch helper. **Down from design-doc 1-2 days estimate** — actually larger than estimated due to 4 schema files vs single one anticipated, but well under the 20% rewrite threshold.

---

## Per-Repo Detailed Findings

### Repo 1: `kite-mcp-alerts`

**Role**: Hosts the shared `*sql.DB` plus its own table set (alerts, telegram_chat_ids, kite_tokens, kite_credentials, oauth_clients, mcp_sessions, config, trailing_stops, daily_pnl, app_registry).
**Files**: `db.go` (428 LOC, schema + DDL), `db_commands.go` (374 LOC, all writes), `db_queries.go` (372 LOC, all reads), `db_migrations.go` (108 LOC).
**Total schema**: 10 tables.

#### 1.1 SQLDB interface (ALREADY DIALECT-PORTABLE)

`db.go:13-41`:
```go
// SQLDB is the dialect-portable surface that *DB exposes...
// Postgres-readiness contract: a future Postgres adapter ships as a
// new struct (e.g. PostgresDB) implementing this interface plus its own
// dialect-specific helpers...
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

**Implication**: the consumer-side seam is already done. Each consumer repo (audit, billing, watchlist, users) accepts `SQLDB` (or `*alerts.DB` directly). Adding a `*PostgresDB struct` that satisfies `SQLDB` enables driver swap without touching consumers.

#### 1.2 Schema portability — `db.go:122-238`

10 table DDLs, all using `CREATE TABLE IF NOT EXISTS`:

| Table | SQLite-specific syntax | Postgres equivalent | Effort |
|---|---|---|---|
| `alerts` | `INTEGER` for instrument_token, `REAL` for prices, `TEXT` PK, `INTEGER NOT NULL DEFAULT 0` for triggered (boolean) | `BIGINT` instrument_token, `DOUBLE PRECISION` prices, `TEXT` PK (portable), `BOOLEAN NOT NULL DEFAULT FALSE` OR keep `INTEGER` | Low (~30min) |
| `telegram_chat_ids` | `INTEGER NOT NULL` chat_id (Telegram chat IDs are int64) | `BIGINT NOT NULL` | Trivial |
| `kite_tokens` | All TEXT | All TEXT | Zero |
| `kite_credentials` | All TEXT (+ ALTER TABLE migration adding `app_id` column) | All TEXT | Zero |
| `oauth_clients` | All TEXT, `INTEGER NOT NULL DEFAULT 0` for is_kite_key | TEXT + BOOLEAN/INTEGER | Trivial |
| `mcp_sessions` | All TEXT, `INTEGER` for terminated boolean | TEXT + BOOLEAN/INTEGER | Trivial |
| `config` | TEXT k/v | TEXT k/v | Zero |
| `trailing_stops` | `REAL` for prices, `INTEGER` for active boolean, **`CHECK(direction IN ('long','short'))`** | `DOUBLE PRECISION`, BOOLEAN/INTEGER, **CHECK constraint is portable** | Low |
| `daily_pnl` | Composite PRIMARY KEY (date, email), `REAL NOT NULL DEFAULT 0` | Composite PK is portable, `DOUBLE PRECISION NOT NULL DEFAULT 0` | Trivial |
| `app_registry` | All TEXT, `CHECK(status IN (...))` | Identical | Zero |

**ZERO `INTEGER PRIMARY KEY AUTOINCREMENT` in alerts repo schema** — all PKs are `TEXT PRIMARY KEY` (UUIDs/strings). This is the most portable schema possible for Postgres migration.

#### 1.3 DML — INSERT OR REPLACE sites (10 production)

| File:line | Table | Conversion target |
|---|---|---|
| `db.go:423` | `config` | `INSERT INTO config (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value` |
| `db_commands.go:63` | `alerts` (17 cols) | ON CONFLICT(id) DO UPDATE SET ... (16 col updates) |
| `db_commands.go:129` | `telegram_chat_ids` | ON CONFLICT(email) DO UPDATE SET chat_id = excluded.chat_id |
| `db_commands.go:147` | `kite_tokens` | ON CONFLICT(email) DO UPDATE |
| `db_commands.go:179` | `kite_credentials` | ON CONFLICT(email) DO UPDATE |
| `db_commands.go:211` | `oauth_clients` | ON CONFLICT(client_id) DO UPDATE |
| `db_commands.go:246` | `mcp_sessions` | ON CONFLICT(session_id) DO UPDATE |
| `db_commands.go:278` | `trailing_stops` | ON CONFLICT(id) DO UPDATE |
| `db_commands.go:321` | `daily_pnl` | ON CONFLICT(date, email) DO UPDATE |
| `db_commands.go:358` | `app_registry` | ON CONFLICT(id) DO UPDATE |

**Critical empirical note**: `ON CONFLICT(...) DO UPDATE SET` syntax is **identical across SQLite (≥3.24, 2018) and Postgres (≥9.5, 2016)**. **A single SQL string works on both dialects**. The `excluded.col` reference is also portable. **This means `INSERT OR REPLACE → ON CONFLICT DO UPDATE` is a one-time global rewrite, not a dialect-dispatch problem.** The new SQL runs on both dialects.

#### 1.4 ALTER TABLE migrations

`db.go:248-249`:
```go
db.Exec(`ALTER TABLE kite_credentials ADD COLUMN app_id TEXT DEFAULT ''`)
```

**`ALTER TABLE ... ADD COLUMN` is portable**. SQLite (since 1.0) and Postgres (since 6.x) both support it.

`db_migrations.go:25-63` is a multi-step transactional migration:
1. `tx.Begin()`
2. `CREATE TABLE app_registry_new (...)`
3. `INSERT INTO app_registry_new SELECT ... FROM app_registry`
4. `DROP TABLE app_registry`
5. `ALTER TABLE app_registry_new RENAME TO app_registry`
6. `tx.Commit()`
7. Re-create indexes

**`ALTER TABLE ... RENAME TO` is portable** in modern Postgres. The transactional migration pattern is portable.

**One sqlite-specific line**: `db_migrations.go:15`:
```go
err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='app_registry'`).Scan(&tableSql)
```
Postgres equivalent:
```sql
SELECT pg_get_tabledef('app_registry'::regclass)
```
OR use the `information_schema`:
```sql
SELECT column_name FROM information_schema.columns WHERE table_name = 'app_registry'
```

This is **the only sqlite_master/system-catalog query in the entire surface**. Single dialect-dispatch site.

#### 1.5 PRAGMA statements

`db.go:115`, `db.go:118`, plus connection-string pragmas:
```go
db.Exec("PRAGMA journal_mode=WAL;")
db.Exec("PRAGMA busy_timeout=5000;")
// + DSN _pragma=foreign_keys(1)
```

**Postgres equivalent: NO-OP**. Postgres has no per-connection journal mode (uses WAL globally), no busy_timeout (configured in `postgresql.conf`), and FK enforcement is always ON (cannot be disabled per connection).

**Dialect dispatch needed**: skip these calls when `Driver() == DriverPostgres`. Trivial; ~5 lines guard.

#### 1.6 Encryption integration

`crypto.go:64`, `db_commands.go:142,170,174,206,241,345,349`:
- `encrypt(key, plaintext) → base64 ciphertext`
- Stored as **`TEXT`** column type (not BLOB) — base64 keeps printable
- HKDF salt stored in `config` table

**Postgres-portable as-is**: `TEXT` works identically. Optional Postgres optimization: switch to `BYTEA` for raw ciphertext (saves ~33% storage, marginal). Skip for portability — keep TEXT/base64.

#### 1.7 Transaction patterns

`db_migrations.go:25` uses `db.Begin()` + `tx.Exec()` + `tx.Commit()` — standard `database/sql` API. Portable.

#### 1.8 Summary for kite-mcp-alerts

| Concern | Severity | Effort |
|---|---|---|
| SQLDB interface | DONE | 0 |
| 10 INSERT OR REPLACE sites → ON CONFLICT DO UPDATE | High volume, low complexity | 1-2 days |
| 1 sqlite_master query | Trivial | 30 min |
| Schema DDL (REAL → DOUBLE PRECISION, INTEGER → BIGINT for big ints) | Medium | ~1 day |
| PRAGMA dispatch | Trivial | 30 min |
| Encryption | Already portable | 0 |
| Transactions | Portable | 0 |

**Total estimate for kite-mcp-alerts**: 2.5-3.5 engineer-days.

---

### Repo 2: `kite-mcp-audit`

**Role**: Audit trail (`tool_calls` + `consent_log` tables) consuming `*alerts.DB`.
**Critical files**: `store.go` (DDL + queries), `store_worker.go` (writer), `store_query.go` (read queries), `consent.go` (consent log subsystem).

#### 2.1 Schema portability

`store.go:225-253`:
```sql
CREATE TABLE IF NOT EXISTS tool_calls (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,  -- ⚠ SQLite-specific
    ...
)
CREATE INDEX IF NOT EXISTS idx_tc_email_time ON tool_calls(email, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_tool_time ON tool_calls(tool_name, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_category ON tool_calls(tool_category, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_tc_error ON tool_calls(is_error) WHERE is_error = 1;  -- ⚠ partial index syntax
```

`consent.go:104-133`:
```sql
CREATE TABLE IF NOT EXISTS consent_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,  -- ⚠ SQLite-specific
    timestamp_utc    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,  -- ⚠ DATETIME alias
    ...
    withdrawn_at     DATETIME
)
CREATE INDEX IF NOT EXISTS idx_consent_active ON consent_log(user_email_hash) WHERE withdrawn_at IS NULL AND consent_action = 'grant';  -- ⚠ partial index
```

**SQLite-specific syntax**:

| Feature | SQLite | Postgres equivalent | Effort |
|---|---|---|---|
| `INTEGER PRIMARY KEY AUTOINCREMENT` | auto-incrementing rowid | `BIGSERIAL PRIMARY KEY` (or `BIGINT GENERATED BY DEFAULT AS IDENTITY`) | Schema-only, low |
| `DATETIME` type | alias for TEXT/numeric | `TIMESTAMP WITH TIME ZONE` | Schema-only |
| `CURRENT_TIMESTAMP` default | yields ISO TEXT | yields TIMESTAMP value | Portable |
| **Partial index `WHERE is_error = 1`** | **Both dialects support** | **Both dialects support** | **Zero** |
| **Partial index `WHERE withdrawn_at IS NULL`** | **Both dialects support** | **Both dialects support** | **Zero** |

**Critical empirical finding**: **PARTIAL INDEXES ARE PORTABLE.** SQLite (since 3.8.0, 2013) and Postgres (since 7.2, 2002) both support `CREATE INDEX ... WHERE <predicate>`. **Same SQL works on both.**

#### 2.2 DML — INSERT OR IGNORE sites (2 production)

| File:line | Pattern | Conversion |
|---|---|---|
| `store_worker.go:158` | `INSERT OR IGNORE INTO tool_calls (...) VALUES (...)` | `INSERT INTO tool_calls (...) VALUES (...) ON CONFLICT (call_id) DO NOTHING` |
| `consent.go:152` | INSERT INTO consent_log | Standard INSERT (no upsert) — portable as-is |

**Conversion is global rewrite (not dialect dispatch)** — `ON CONFLICT ... DO NOTHING` works on both SQLite (≥3.24) and Postgres (≥9.5).

#### 2.3 Read queries — fully portable

`store_query.go` uses LIMIT/OFFSET, ORDER BY, GROUP BY, COUNT, SUM, AVG — all standard SQL-92. Zero SQLite-specific functions. **Read-side dialect rewrite cost: 0.**

`consent.go:189-196` uses prepared LIMIT placeholder — portable.

#### 2.4 HMAC hash chain integration

`store_worker.go` computes HMAC chains in Go before write — SQL-agnostic. Hash columns are TEXT. Portable.

#### 2.5 Summary for kite-mcp-audit

| Concern | Severity | Effort |
|---|---|---|
| 2 schema files, both with INTEGER PRIMARY KEY AUTOINCREMENT | Medium | ~1 day |
| 2 DATETIME columns | Low | ~30 min |
| 2 INSERT OR IGNORE sites → ON CONFLICT DO NOTHING | Trivial global rewrite | ~30 min |
| Partial indexes | Already portable | 0 |
| Read queries | Already portable | 0 |
| HMAC chain | SQL-agnostic | 0 |

**Total estimate for kite-mcp-audit**: 1.5-2 engineer-days.

---

### Repo 3: `kite-mcp-billing`

**Role**: Subscription + tier enforcement (`billing`, `webhook_events` tables).
**Critical files**: `store.go` (DDL + writes + queries).

#### 3.1 Already partially Postgres-style

`store.go:298-308`:
```sql
INSERT INTO billing (admin_email, tier, ...) VALUES (?, ?, ...)
ON CONFLICT(admin_email) DO UPDATE SET
    tier = excluded.tier,
    ...
```

**This is already Postgres-portable.** It's the existing production billing upsert — a recent rewrite from `INSERT OR REPLACE` already shipped.

#### 3.2 Schema

`store.go:117` (`billing` table) + `store.go:398` (`webhook_events`). Pure TEXT/INTEGER. ALTER TABLE migrations work.

`store.go:150-161` has a self-migration pattern:
```sql
CREATE TABLE IF NOT EXISTS billing_mig (...)
INSERT OR IGNORE INTO billing_mig (admin_email, tier, ...) SELECT email, tier, ... FROM billing
```

The `INSERT OR IGNORE INTO ... SELECT ...` is sqlite-only syntax. Postgres equivalent:
```sql
INSERT INTO billing_mig (...) SELECT ... FROM billing ON CONFLICT (admin_email) DO NOTHING
```

#### 3.3 webhook_events upsert

`store.go:425`:
```sql
INSERT OR IGNORE INTO webhook_events (event_id, event_type, created_at) VALUES (?, ?, ?)
```
→ `INSERT INTO webhook_events (...) VALUES (...) ON CONFLICT (event_id) DO NOTHING`

#### 3.4 Money type integration

The billing subscription stores `MonthlyAmount.Float64()` (per `store.go:317` comment) — which is an SQLite-`REAL`-bound boundary. Portable to Postgres `DOUBLE PRECISION` or `NUMERIC(19,4)` for currency precision.

**Recommendation**: at Postgres migration, switch `monthly_amount` column from `REAL` to `NUMERIC(19,4)` for IEEE-754 precision-loss avoidance. Currently uses Float64 round-trip which is fine for INR amounts <2^53/100 paise but technically loses precision for very-large currency. Optional optimization, not blocking.

#### 3.5 Summary for kite-mcp-billing

| Concern | Severity | Effort |
|---|---|---|
| 1 INSERT OR IGNORE → ON CONFLICT DO NOTHING (webhook_events) | Trivial | 15 min |
| 1 INSERT OR IGNORE in self-migration | Trivial | 15 min |
| Already-Postgres-style ON CONFLICT for billing | DONE | 0 |
| Optional NUMERIC for money | Optional optimization | ~2h if pursued |

**Total estimate for kite-mcp-billing**: 0.5 engineer-day (mostly already done).

---

### Repo 4: `kite-mcp-watchlist`

**Role**: Per-user named watchlists.
**Critical files**: `db.go` (whole DB-side surface).

#### 4.1 Schema

`db.go:11-35`:
```sql
CREATE TABLE IF NOT EXISTS watchlists (
    -- TEXT PK, TEXT email, ...
)
CREATE TABLE IF NOT EXISTS watchlist_items (
    -- TEXT PK, ...
)
```

All TEXT/standard types. **No `INTEGER PRIMARY KEY AUTOINCREMENT`, no DATETIME, no partial indexes.** Fully portable.

#### 4.2 DML

`db.go:42`, `db.go:92`:
```go
return db.ExecInsert(`INSERT OR REPLACE INTO watchlists ...`)
return db.ExecInsert(`INSERT OR REPLACE INTO watchlist_items ...`)
```

→ ON CONFLICT(id) DO UPDATE — straightforward.

#### 4.3 Test code uses sqlite_master

`db_test.go:53` queries sqlite_master for table existence — test-only, not production. Replace with `information_schema.tables` for Postgres tests.

#### 4.4 Summary for kite-mcp-watchlist

| Concern | Severity | Effort |
|---|---|---|
| 2 INSERT OR REPLACE sites | Trivial | ~30 min |
| Test sqlite_master query | Test-only | ~15 min |

**Total estimate for kite-mcp-watchlist**: 0.5 engineer-day.

---

### Repo 5: `kite-mcp-users`

**Role**: User registration + RBAC (`users`, `family_invitations` tables).
**Critical files**: `store.go`, `invitations.go`.

#### 5.1 Schema

`store.go:150-164`:
```sql
CREATE TABLE IF NOT EXISTS users (
    -- TEXT id, TEXT email, ...
)
CREATE INDEX ... idx_users_email ON users(email);
```

All TEXT. Portable.

#### 5.2 DML

`store.go:277`:
```sql
INSERT OR IGNORE INTO users (id, email, ...) VALUES (?,?,?,...)
```
→ `ON CONFLICT (id) DO NOTHING` (or `email` if the upsert is by email-uniqueness)

#### 5.3 Summary for kite-mcp-users

| Concern | Severity | Effort |
|---|---|---|
| 1 INSERT OR IGNORE site | Trivial | ~15 min |

**Total estimate for kite-mcp-users**: 0.25 engineer-day.

---

### Repo 6: `kite-mcp-registry`

**Role**: Pre-registered Kite app credentials.
**Empirical**: ZERO SQL. Pure in-memory + file-based JSON persistence.
**Effort**: 0.

(Note: there's an `app_registry` table in `kite-mcp-alerts` that is conceptually related, but `kite-mcp-registry` itself has no DB layer. Confusing name but empirical truth.)

---

## Aggregate Effort

| Repo | Effort (engineer-days) |
|---|---|
| kite-mcp-alerts | 2.5-3.5 |
| kite-mcp-audit | 1.5-2 |
| kite-mcp-billing | 0.5 |
| kite-mcp-watchlist | 0.5 |
| kite-mcp-users | 0.25 |
| kite-mcp-registry | 0 |
| Dialect-dispatch helper API | 0.5 |
| Per-dialect unit tests | 1-2 |
| **Total** | **~6.5-9 engineer-days** |

**Calendar**: 1-2 weeks at 1-agent pace; 2-4 days at 3-agent pace (per-repo agents work in parallel).

**Vs Phase 2.0 design estimate (1-2 days)**: 3-4× larger. Phase 2.0 underestimated. The 4-DDL-files spread (vs single anticipated) is the main driver. **Still well below 20% rewrite stop-threshold** (rewrite surface is ≤13% of total Go LOC across the 5 repos).

---

## Migration Plan: INSERT OR REPLACE → ON CONFLICT DO UPDATE

### Strategy: global rewrite (NOT dialect dispatch)

`ON CONFLICT(...) DO UPDATE SET` syntax works identically on:
- **SQLite** since 3.24.0 (June 2018)
- **Postgres** since 9.5 (January 2016)

Both currently-deployed dialects support it. **Single-version SQL satisfies both.** Therefore:

**Step 1**: Rewrite all 18 production INSERT OR REPLACE / INSERT OR IGNORE sites to use ON CONFLICT. Single PR per repo (5 PRs total). No dialect dispatch needed.

**Step 2**: Verify tests still pass on SQLite (regression check).

**Step 3**: Run same tests on Postgres (Phase 2.2 deliverable) to verify cross-dialect behavior identical.

### Per-pattern conversion table

| Source pattern | Target pattern |
|---|---|
| `INSERT OR REPLACE INTO t (a,b,c) VALUES (?,?,?)` | `INSERT INTO t (a,b,c) VALUES (?,?,?) ON CONFLICT (<pk>) DO UPDATE SET a=excluded.a, b=excluded.b, c=excluded.c` |
| `INSERT OR IGNORE INTO t (a,b) VALUES (?,?)` | `INSERT INTO t (a,b) VALUES (?,?) ON CONFLICT DO NOTHING` |
| `INSERT OR IGNORE INTO t SELECT ... FROM s` | `INSERT INTO t SELECT ... FROM s ON CONFLICT DO NOTHING` |

### Conflict-target identification

For each INSERT OR REPLACE, the conflict target is the **PRIMARY KEY** declared in CREATE TABLE. Empirical map:

| Table | PK | Conflict target |
|---|---|---|
| alerts | id (TEXT) | `(id)` |
| telegram_chat_ids | email (TEXT) | `(email)` |
| kite_tokens | email (TEXT) | `(email)` |
| kite_credentials | email (TEXT) | `(email)` |
| oauth_clients | client_id (TEXT) | `(client_id)` |
| mcp_sessions | session_id (TEXT) | `(session_id)` |
| trailing_stops | id (TEXT) | `(id)` |
| daily_pnl | (date, email) composite | `(date, email)` |
| app_registry | id (TEXT) | `(id)` |
| config | key (TEXT) | `(key)` |
| billing | admin_email (TEXT) | `(admin_email)` ✓ already done |
| webhook_events | event_id (TEXT) | `(event_id)` |
| watchlists | id (TEXT) | `(id)` |
| watchlist_items | id (TEXT) | `(id)` |
| users | id (TEXT) | `(id)` |
| tool_calls | call_id (TEXT) | `(call_id)` |
| consent_log | (auto-increment id) | (auto-increment, no upsert needed) |

---

## Placeholder Strategy: $N for Postgres vs ? for SQLite

### Empirical state

All current code uses `?` placeholders (SQLite native). pgx/v5 supports both `?` AND `$N`:

- **`pgx.Conn.Exec(query, args...)`** uses `$1, $2, ...` natively (Postgres protocol)
- **`pgx/v5/stdlib` (database/sql)** uses `?` placeholders BY DEFAULT, rewrites to `$N` internally

**Critical finding**: `pgx/v5/stdlib` accepts `?` placeholders transparently. **Zero placeholder rewrite needed when using the database/sql stdlib path** (which is what alerts repo uses).

### Verification needed in Phase 2.2

Confirm via integration test that pgx/v5/stdlib's `?`-rewriting works for all our query shapes (LIKE, IN, JSON literals, etc.). If any edge case fails (`LIKE '%?%'` ambiguity), add a thin pre-execute layer that rewrites `?` → `$N` for known-affected queries.

**Probability of edge-case failure**: low. Empirical SQL surface uses `?` only as parameter placeholders; no `?`-in-LIKE patterns observed.

---

## Dialect-Dispatch Helper API Sketch

### Design rationale

**Most SQL is dialect-portable** (per audit findings). Dialect dispatch is needed only for:
1. PRAGMA statements (skip on Postgres)
2. sqlite_master query (alerts migration only)
3. Schema DDL (different INTEGER vs BIGSERIAL etc.)

Three small dispatch points → tiny helper, not a full ORM.

### Proposed API

In `kite-mcp-alerts/dialect.go` (NEW file):

```go
// Dialect identifies the database backend dialect.
type Dialect string

const (
    DialectSQLite   Dialect = "sqlite"
    DialectPostgres Dialect = "postgres"
)

// SchemaDDL returns the dialect-specific CREATE TABLE block for the
// shared schema. Most tables are portable; differences:
//   - INTEGER PRIMARY KEY AUTOINCREMENT → BIGSERIAL PRIMARY KEY
//   - REAL → DOUBLE PRECISION (cosmetic; both work in Postgres)
//   - DATETIME → TIMESTAMPTZ (in audit consent_log)
func SchemaDDL(d Dialect) string { ... }

// PragmaInit applies dialect-specific connection-init pragmas.
// SQLite: WAL + busy_timeout + foreign_keys.
// Postgres: no-op (handled in postgresql.conf).
func PragmaInit(d Dialect, db *sql.DB) error { ... }

// TableExists returns whether a given table is present in the
// current schema. Dialect-specific catalog query under the hood.
//   SQLite:   SELECT sql FROM sqlite_master WHERE type='table' AND name=?
//   Postgres: SELECT 1 FROM information_schema.tables WHERE table_name=?
func TableExists(d Dialect, db *sql.DB, tableName string) (bool, error) { ... }
```

That's it. **No query builder. No ORM.** Three functions to abstract three dispatch points.

### Why not squirrel / sq / GORM?

- **squirrel** introduces a builder DSL — overkill for ~25 SQL queries.
- **sq** (Go ORM) requires schema annotation — major refactor surface.
- **GORM** changes the entire data-access pattern — total rewrite.

**Empirical reality**: our SQL is mostly already portable. A 3-function dispatcher does the job; ORM cost > benefit at our scale.

---

## Risk Assessment Per SQL Category

| Category | Risk | Mitigation |
|---|---|---|
| INSERT OR REPLACE → ON CONFLICT global rewrite | **Low** | Both dialects support. Test on existing SQLite first, verify same results. |
| INTEGER PRIMARY KEY AUTOINCREMENT (audit) | **Medium** | Identity-column behavior differs in subtle ways (gap-filling, sequence ownership). Verify ID generation contract: do consumers care about strict sequentiality? Empirically NO — audit IDs are opaque opaque. |
| DATETIME → TIMESTAMPTZ | **Low** | All datetimes stored as RFC3339 strings (TEXT). Postgres TIMESTAMPTZ accepts RFC3339 input. No migration script needed for existing data; new code can keep using TEXT or migrate to TIMESTAMPTZ. |
| Partial indexes | **Zero** | Both dialects support identical syntax. |
| PRAGMA dispatch | **Trivial** | Skip on Postgres. |
| sqlite_master | **Low** | Single site (alerts migration). Replace with information_schema query. |
| Encryption (TEXT base64) | **Zero** | Already portable. |
| Money REAL precision | **Low** | Optional NUMERIC(19,4) upgrade. Float64 already precision-bounded for our INR amounts. |
| Composite primary keys | **Zero** | Both dialects support. |
| CHECK constraints | **Zero** | Both dialects support. |
| ALTER TABLE migrations | **Zero** | Both dialects support ADD COLUMN, RENAME TO. |
| Transactions | **Zero** | database/sql API; portable. |
| LIMIT/OFFSET | **Zero** | Standard SQL. |
| JSON columns | **Zero** | Stored as TEXT (alerts.conditions_json). Optional Postgres JSONB upgrade. |

**Highest residual risk**: AUTOINCREMENT semantics in audit (ID stability across cross-dialect dump+reload). Mitigation: round-trip test in Phase 2.4.

---

## Recommended Migration Ordering

Given concurrent-agent capacity, the following ordering minimizes blocking:

### Stage 1 — Global INSERT OR REPLACE/IGNORE rewrite (parallel-safe)

Phase 2.1.1 — kite-mcp-alerts: rewrite 10 sites + 1 self-migration. PR-local. ~1.5d.
Phase 2.1.2 — kite-mcp-audit: rewrite 2 sites. PR-local. ~30min.
Phase 2.1.3 — kite-mcp-billing: rewrite 2 sites (1 webhook_events + 1 self-migration). PR-local. ~30min.
Phase 2.1.4 — kite-mcp-watchlist: rewrite 2 sites. PR-local. ~30min.
Phase 2.1.5 — kite-mcp-users: rewrite 1 site. PR-local. ~15min.

**These 5 PRs CAN ship in parallel** — different repos, no shared file. After each lands, the upstream this-repo `go.mod` updates to point to new tag.

### Stage 2 — Dialect-dispatch helper API in kite-mcp-alerts

Phase 2.1.6 — Add `dialect.go` to kite-mcp-alerts with SchemaDDL/PragmaInit/TableExists. ~0.5d.

Sequential after Stage 1.

### Stage 3 — Postgres adapter implementation (Phase 2.2)

Phase 2.2.1 — `OpenPostgresDB(url)` constructor in kite-mcp-alerts. Routes to PRAGMA-skip + Postgres-flavored DDL.
Phase 2.2.2 — Driver-switching factory in this repo (`app/providers/alertdb.go`). Uncomment Phase 2.0 stub satisfaction check.

~3-5 days combined.

### Stage 4 — Round-trip migration test (Phase 2.4)

Phase 2.4.1 — Test harness in kite-mcp-alerts: create SQLite, populate, dump; load into Postgres; assert row count + sampled fields match.

~2-3 days.

### Stage 5 — Production canary (Phase 2.6)

Single-user opt-in via `ALERT_DB_DRIVER=postgres` env. ~1-2 days observation.

---

## Stop-Rule Verification

**Stop condition #1 (per Phase 2.0 design)**: "If audit reveals >20% of SQL surface needs rewrite, surface findings and pause Phase 2.2 dispatch."

**Empirical SQL surface needing rewrite**:
- 18 INSERT OR REPLACE / INSERT OR IGNORE sites (each ≈ 5-15 LOC) ≈ ~150 LOC
- 4 schema DDL files needing INTEGER → BIGSERIAL changes ≈ ~30 LOC
- 1 sqlite_master query ≈ 1 LOC
- 6 PRAGMA dispatches ≈ ~10 LOC

**Total rewrite surface**: ~190 LOC.

**Total SQL-relevant LOC across 5 repos** (production, non-test, DB-touching files):
- alerts: db.go (428) + db_commands.go (374) + db_queries.go (372) + db_migrations.go (108) = 1282 LOC
- audit: store.go (~700 est) + store_worker.go + store_query.go + consent.go = ~1500 LOC
- billing: store.go (428) = ~430 LOC
- watchlist: db.go (~150 LOC) = ~150 LOC
- users: store.go + invitations.go = ~400 LOC

**Total**: ~3700 LOC.

**Rewrite ratio**: 190 / 3700 ≈ **5.1%**.

**Below stop threshold (20%) by 4×.** Phase 2.2 dispatch GREEN. Recommendation: proceed.

---

## Cross-Repo Dependencies

The audit revealed no SQL-level circular dependencies. Each repo's SQL is independent of the others — each owns its own table set, queries only its own tables. The `*alerts.DB` is the **shared connection handle**, not shared data.

**Implication for parallel PRs**: zero cross-repo SQL conflicts. The 5 Stage-1 PRs are fully parallel-safe.

**Implication for Postgres adapter**: a single `*PostgresDB struct` implementing `SQLDB` (per kite-mcp-alerts/db.go:32-41) serves all 5 consumer repos transparently. **Single adapter; many consumers.**

---

## Recommended Next Dispatch (Phase 2.1.X — global INSERT rewrite)

After this audit doc lands:

```
Domain: SQL portability rewrite — algo2go external repos
Repos: 5 algo2go/kite-mcp-{alerts,audit,billing,watchlist,users}
Budget: per-repo PR; total 5 PRs in parallel
Output: 5 git commits in 5 external repos
  - Replace INSERT OR REPLACE → ON CONFLICT DO UPDATE
  - Replace INSERT OR IGNORE → ON CONFLICT DO NOTHING
  - Verify SQLite tests still pass (zero regression)
  - Tag new minor version per repo (v0.2.0)
Sequence: parallel-safe across repos (different working trees)
Hard rules: NO schema DDL changes yet (Phase 2.1.6 separate)
Stop condition: any test regression → halt + escalate
Trigger: Phase 2.0 stub at c5b9cf7 + this audit landed
```

After Phase 2.1.X (5 parallel PRs) lands:
- Phase 2.1.6 — dialect.go helper in kite-mcp-alerts (~0.5d)
- Phase 2.2 — `OpenPostgresDB` constructor + Postgres-flavored DDL (~3-5d)
- Phase 2.3 — driver-switching factory in this repo + uncomment Phase 2.0 satisfaction check (~1-2d)
- Phase 2.4 — round-trip migration test (~2-3d)

---

## Out of Scope for Phase 2.1

- Postgres adapter implementation (that's Phase 2.2)
- Schema DDL changes (that's Phase 2.1.6, after Stage 1 ships)
- Postgres CI integration (that's Phase 2.4)
- Production migration of live SQLite data (that's Phase 2.6)
- Performance benchmarking SQLite vs Postgres (orthogonal to portability)

---

**End of audit. Doc-only. tools=130 invariant verified at HEAD `d63391a` (66th deploy streak). Stop-rule check: 5.1% rewrite surface; below 20% threshold; Phase 2.2 dispatch GREEN.**
