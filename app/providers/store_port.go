// Package providers — Phase 2 Postgres-adapter port.
//
// Phase 2 of the 10K-agent capacity plan introduces an OPTIONAL Postgres
// driver alongside the current SQLite default. This file is the IN-TREE
// port-interface declaration; the implementations live in the external
// `github.com/algo2go/kite-mcp-alerts` repo (v0.4.0+ ships both SQLite
// and Postgres backends).
//
// See:
//   - .research/phase-2-pick.md (decision record)
//   - .research/phase-2-postgres-adapter-design.md (full design)
//   - .research/phase-2-sql-portability-audit.md (Stage 1 SQL audit)
//   - .research/10000-agent-blocker-analysis.md L2.4 (trigger conditions)
//
// Phase 2.3 (this commit): the compile-time satisfaction check at the
// bottom of this file is now ACTIVE — `*alerts.DB` (from
// kite-mcp-alerts v0.4.0) is verified to satisfy the Store interface.
// ProvideAlertDB in alertdb.go is now a driver-switching factory.

package providers

import (
	alerts "github.com/algo2go/kite-mcp-alerts"
)

// Dialect is a re-export of alerts.Dialect so consumers of this package
// can refer to "the database dialect" without importing alerts directly.
// Identical type — type alias preserves interchangeability at every
// call site.
//
// Phase 2.3 reconciliation: the original Phase 2.0 stub used a local
// `Driver` enum. Phase 2.2 in the external repo shipped `Dialect`
// (semantically identical, just a different name). Phase 2.3 converges
// on the external name to avoid double-vocabulary.
type Dialect = alerts.Dialect

// Re-exported dialect constants. See alerts.DialectSQLite /
// alerts.DialectPostgres for the source of truth.
const (
	DialectSQLite   = alerts.DialectSQLite
	DialectPostgres = alerts.DialectPostgres
)

// Store is the persistence-layer port for the kite-mcp-server.
//
// At Phase 2.3 the implementing concrete type is *alerts.DB from
// kite-mcp-alerts v0.4.0, opened via alerts.OpenDB (SQLite) or
// alerts.OpenPostgresDB (Postgres) by ProvideAlertDB based on the
// AlertDBConfig.Driver field.
//
// SCOPE: this is the LOW-LEVEL handle abstraction (essentially a
// wrapper over *sql.DB). Each external store package — kite-mcp-audit,
// kite-mcp-billing, kite-mcp-registry, kite-mcp-watchlist — accepts a
// *alerts.DB and uses it for its own table set. The Store interface
// here is the minimal contract those packages don't directly use but
// that the orchestrator (ProvideAlertDB + healthz handler) needs.
//
// PORT CONTRACT (binding for the kite-mcp-alerts implementation):
//
//   1. Connection lifecycle: Close() must release all underlying conns.
//   2. Health check: Ping() returns nil iff a 1-row SELECT works.
//      Used by /healthz?probe=deep.
//   3. Dialect identity: Dialect() returns the enum constant for SQL
//      dispatch in dialect.go's TableExists/ColumnExists/PragmaInit
//      helpers. Verified by the *alerts.DB.Dialect() method added in
//      kite-mcp-alerts v0.4.0.
//   4. Schema migration: applied at Open() time; idempotent. The
//      external implementer owns the per-dialect migration script.
//   5. Encryption at rest: row-level AES-256-GCM via HKDF (preserved
//      across drivers). Application-layer, not a driver feature.
//   6. Per-tenant scoping: by `email TEXT` column.
//   7. SQL portability: queries use the dialect-portable ON CONFLICT
//      form (Phase 2.1 Stage 1; v0.2.0+). Dialect-specific paths
//      (PRAGMA dispatch, sqlite_master vs information_schema) route
//      through dialect.go helpers (Phase 2.1.6; v0.3.x).
//
// USAGE:
//
//	var db Store = alerts.OpenDB("./alerts.db")  // satisfied by alerts.DB
//	defer db.Close()
//	if err := db.Ping(); err != nil { ... }
//	switch db.Dialect() {
//	case DialectSQLite: ...
//	case DialectPostgres: ...
//	}
//
// The compile-time satisfaction check at the bottom of this file
// (`var _ Store = (*alerts.DB)(nil)`) is ACTIVE at Phase 2.3 — adding
// new methods here breaks the build until *alerts.DB implements them,
// preventing accidental contract drift.
type Store interface {
	// Dialect returns the underlying database dialect. Required for
	// SQL dispatch at call sites that have unavoidable SQLite-vs-
	// Postgres differences (catalog queries, PRAGMA, etc.).
	Dialect() Dialect

	// Ping returns nil if the underlying connection is alive and the
	// schema is reachable. Used by /healthz?probe=deep.
	// SQLite: SELECT 1 round-trip (modernc.org/sqlite Ping is
	//         insufficient — see alerts.DB.Ping comment).
	// Postgres: SELECT 1 round-trip via pgx.
	Ping() error

	// Close releases the underlying database resources (connection
	// pool, file handle for SQLite). Idempotent: subsequent Close
	// calls return nil.
	Close() error
}

// Compile-time satisfaction check — *alerts.DB (kite-mcp-alerts v0.4.0)
// satisfies the Store interface. Phase 2.3: ACTIVE. Adding methods to
// the Store interface breaks the build until *alerts.DB implements
// them, catching contract drift at compile time.
var _ Store = (*alerts.DB)(nil)
