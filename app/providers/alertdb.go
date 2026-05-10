package providers

import (
	"fmt"
	"log/slog"

	"github.com/algo2go/kite-mcp-alerts"
)

// AlertDBConfig is the narrow input the alertDB provider needs.
//
// The full app.Config has 30+ fields; the provider receives only the
// ones it cares about. Splitting into per-provider config types keeps
// Fx provider signatures readable and prevents the whole-Config
// dependency anti-pattern (every provider depending on every config).
//
// Phase 2.3: extends the original Path-only config with Driver + URL
// fields so production wiring can opt into Postgres via env vars
// without breaking the SQLite default. Pre-Phase-2.3 callers that
// construct the literal {Path: ...} continue to work unchanged
// (empty Driver defaults to SQLite).
type AlertDBConfig struct {
	// Driver selects which database backend to open.
	//
	//   ""         (empty)  — defaults to "sqlite" (back-compat)
	//   "sqlite"            — opens SQLite via alerts.OpenDB(Path)
	//   "postgres"          — opens Postgres via alerts.OpenPostgresDB(URL)
	//
	// Production wiring binds from the ALERT_DB_DRIVER env var.
	Driver string

	// Path is the SQLite file path (ALERT_DB_PATH env var).
	// Used only when Driver is "" or "sqlite".
	// Empty path with SQLite = in-memory mode = (nil, nil) return.
	Path string

	// URL is the Postgres connection string (ALERT_DB_URL env var).
	// Used only when Driver is "postgres". Required when so —
	// empty URL with Driver="postgres" is a configuration error
	// (no in-memory Postgres equivalent).
	//
	// Format: postgres://user:pass@host:port/dbname?sslmode=...
	URL string
}

// ProvideAlertDB opens the database used for alert / audit / session /
// token / credential persistence. Phase 2.3: switches between the
// SQLite OpenDB and the Postgres OpenPostgresDB based on cfg.Driver.
//
// CONTRACT for the SQLite path (Driver=="" or "sqlite"; preserves
// app/wire.go:62-69 legacy behaviour):
//
//	(nil, nil)        — empty Path; in-memory mode, no persistence.
//	                    Production wiring decides whether to elevate
//	                    this to a startup error via the audit-required-
//	                    in-production guard.
//	(*alerts.DB, nil) — open succeeded; caller owns Close() lifecycle
//	                    via fx.Lifecycle hook in the composition site.
//	(nil, nil)        — open FAILED; logged and silently downgraded.
//
// CONTRACT for the Postgres path (Driver=="postgres"):
//
//	(nil, err)        — empty URL is a config error. NO silent-
//	                    downgrade — Postgres has no in-memory mode,
//	                    so an empty URL almost certainly means the
//	                    operator forgot to set ALERT_DB_URL.
//	(*alerts.DB, nil) — open succeeded.
//	(nil, err)        — Postgres open/ping/schema-bootstrap failed.
//	                    Surfaced as an error (NOT silently downgraded
//	                    like SQLite) so misconfigured Postgres
//	                    deployments fail loudly at startup.
//
// Asymmetry rationale: SQLite's silent downgrade is legacy-preserving
// (wire.go:64). Postgres has no equivalent legacy contract — the
// failure modes there (wrong URL, network outage, auth failure) are
// almost always config bugs that deserve early surfacing.
//
// Unknown Driver values: error. Configuration bugs must not silently
// fall through.
//
// Lifecycle responsibility: the caller wires (*alerts.DB).Close()
// into fx.Lifecycle.Append OnStop. This provider does NOT call
// lc.Append itself (per package convention).
func ProvideAlertDB(cfg AlertDBConfig, logger *slog.Logger) (*alerts.DB, error) {
	switch cfg.Driver {
	case "", "sqlite":
		// SQLite path — preserves legacy behaviour byte-for-byte
		// when Driver is empty (the pre-Phase-2.3 contract).
		if cfg.Path == "" {
			return nil, nil
		}
		db, err := alerts.OpenDB(cfg.Path)
		if err != nil {
			// Match legacy wire.go:64: log and downgrade.
			if logger != nil {
				logger.Error("Failed to open alert DB, using in-memory only",
					"path", cfg.Path, "error", err)
			}
			return nil, nil
		}
		return db, nil

	case "postgres":
		if cfg.URL == "" {
			return nil, fmt.Errorf("ProvideAlertDB: postgres driver requires URL (ALERT_DB_URL)")
		}
		db, err := alerts.OpenPostgresDB(cfg.URL)
		if err != nil {
			// Postgres failures surface (no silent downgrade — see
			// contract above). Log for visibility, then return err.
			if logger != nil {
				logger.Error("Failed to open postgres DB", "error", err)
			}
			return nil, fmt.Errorf("ProvideAlertDB postgres: %w", err)
		}
		return db, nil

	default:
		return nil, fmt.Errorf("ProvideAlertDB: unknown driver %q (want sqlite or postgres)", cfg.Driver)
	}
}
