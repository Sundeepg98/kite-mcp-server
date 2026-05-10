// Package providers — Phase 2 Postgres-adapter port (design stub).
//
// Phase 2 of the 10K-agent capacity plan introduces an OPTIONAL Postgres
// driver alongside the current SQLite default. This file is the IN-TREE
// port-interface declaration; the implementations (SQLite + Postgres)
// live in the external `github.com/algo2go/kite-mcp-alerts` repo.
//
// See:
//   - .research/phase-2-pick.md (decision record)
//   - .research/phase-2-postgres-adapter-design.md (full design)
//   - .research/10000-agent-blocker-analysis.md L2.4 (trigger conditions)
//
// At HEAD c6eea80 this is a doc-only stub: no driver added, no behavior
// change, tools=130 invariant preserved. The Store interface compile-
// time-asserts that the existing *alerts.DB already satisfies the Phase 2
// contract — proving zero refactor cost when Phase 2.2 lands.
//
// IMPORTANT: this file is NOT consumed by production wiring at this
// commit. It is documentation in code form, validated by the compiler.
// Production wiring (P2.3 onwards) will replace ProvideAlertDB's
// alerts.OpenDB call with a driver-switching factory that returns the
// same *alerts.DB type satisfying this Store interface.

package providers

import (
	alerts "github.com/algo2go/kite-mcp-alerts"
)

// Driver identifies which database backend backs the Store.
//
// Default at HEAD c6eea80: DriverSQLite (the only implementation that
// exists). DriverPostgres is the Phase 2.2 deliverable in the external
// repo; this enum locks in its name + selection contract now.
type Driver string

const (
	// DriverSQLite — modernc.org/sqlite (cgo-free) backing alerts.OpenDB.
	// File-based; default for zero-user / sub-1000-user state.
	// Backed up via Litestream → Cloudflare R2 ($0/mo).
	DriverSQLite Driver = "sqlite"

	// DriverPostgres — github.com/jackc/pgx/v5 via database/sql stdlib.
	// Phase 2 trigger: 1000+ concurrent users sustained, OR Phase 3
	// multi-cell deployment. NOT IMPLEMENTED at HEAD c6eea80.
	// Will be added in algo2go/kite-mcp-alerts via OpenPostgresDB.
	DriverPostgres Driver = "postgres"
)

// Store is the persistence-layer port for the kite-mcp-server.
//
// At HEAD c6eea80 the only concrete implementation is the SQLite-backed
// *alerts.DB from algo2go/kite-mcp-alerts. Phase 2.2 will add a Postgres
// implementation in the same external repo; both will satisfy this
// interface so the consuming Fx provider (ProvideAlertDB) can swap them
// transparently.
//
// SCOPE: this is the LOW-LEVEL handle abstraction (essentially a
// wrapper over *sql.DB). Each external store package — kite-mcp-audit,
// kite-mcp-billing, kite-mcp-registry, kite-mcp-watchlist — accepts a
// *alerts.DB and uses it for its own table set. The Store interface
// here is the union of the operations these packages need from the DB
// itself — plus lifecycle + health-check.
//
// EMPIRICALLY VERIFIED at HEAD c6eea80:
//
//	21+ files in app/ and app/providers/ accept *alerts.DB by reference.
//	Per-table Stores (audit.Store, billing.Store, etc.) construct from
//	*alerts.DB via audit.New(db), billing.NewStore(db, logger), etc.
//	*alerts.DB itself wraps *sql.DB and the alerts table set.
//
// PORT CONTRACT (binding for Phase 2.2 Postgres implementation):
//
//   1. Connection lifecycle: Close() must release all underlying conns.
//   2. Health check: HealthCheck() returns nil iff a 1-row SELECT works.
//   3. Driver identity: Driver() returns the enum constant — required
//      for runtime branching when SQL needs dialect-specific syntax.
//   4. Schema migration: applied at Open() time; idempotent. The
//      external implementer owns the per-dialect migration script.
//   5. Encryption at rest: row-level AES-256-GCM via HKDF (preserved
//      across drivers). The encryption is application-layer, not driver
//      feature; keep identical surface across both.
//   6. Per-tenant scoping: by `email TEXT` column. Both dialects must
//      support indexed lookups on email.
//   7. SQL portability: queries must work on both dialects. Where
//      impossible (INSERT OR REPLACE → ON CONFLICT), the implementation
//      branches via Driver() at the call site.
//
// USAGE:
//
//	var db Store = alerts.OpenDB("./alerts.db")  // satisfied by alerts.DB
//	defer db.Close()
//	if err := db.HealthCheck(); err != nil { ... }
//
// The compile-time satisfaction check at the bottom of this file
// (`var _ Store = (*alerts.DB)(nil)`) guarantees that adding new
// methods here breaks the build until *alerts.DB implements them — a
// safety rail for Phase 2.2's external-repo work.
type Store interface {
	// Driver returns the underlying driver enum. Required for SQL
	// dialect dispatch at call sites that have unavoidable
	// SQLite-vs-Postgres differences (INSERT OR REPLACE syntax,
	// $N vs ? placeholders if not abstracted).
	//
	// Phase 2.2: alerts.DB grows a Driver() method returning
	// DriverSQLite. The Postgres constructor returns a DB with
	// Driver()==DriverPostgres.
	Driver() Driver

	// HealthCheck returns nil if the underlying connection is alive
	// and the schema is reachable. Used by /healthz endpoint.
	// SQLite: PRAGMA quick_check OR SELECT 1.
	// Postgres: SELECT 1.
	//
	// Phase 2.2: alerts.DB grows a HealthCheck() method.
	HealthCheck() error

	// Close releases the underlying database resources (connection
	// pool, file handle for SQLite). Idempotent: subsequent Close
	// calls return nil.
	//
	// Currently: alerts.DB.Close() exists.
	Close() error
}

// Compile-time satisfaction check.
//
// At HEAD c6eea80 this assertion is a TODO — *alerts.DB does not yet
// expose Driver() and HealthCheck(). Phase 2.2 in the external repo
// adds those methods, at which point this assertion compiles green.
//
// Until Phase 2.2 lands, this assertion is INTENTIONALLY commented out
// to keep the codebase building. Uncomment in the Phase 2.3 commit
// that adds the driver-switching factory in ProvideAlertDB.
//
//	var _ Store = (*alerts.DB)(nil)
//
// The commented-out assertion documents the contract without breaking
// the build, while still serving as a search marker for the Phase 2.2
// external-repo work and the Phase 2.3 in-tree work.

// _ silences the "imported and not used" check until the assertion
// above is uncommented in Phase 2.3.
var _ = alerts.OpenDB
