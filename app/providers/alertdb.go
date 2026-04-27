package providers

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// AlertDBConfig is the narrow input the alertDB provider needs.
//
// The full app.Config has 30+ fields; the provider receives only the
// ones it cares about. Splitting into per-provider config types keeps
// Fx provider signatures readable and prevents the whole-Config
// dependency anti-pattern (every provider depending on every config).
//
// Production wiring (P2.3 onwards) constructs AlertDBConfig from the
// running app.Config via a dedicated extractor; tests construct it
// directly with literal values.
type AlertDBConfig struct {
	// Path is the SQLite file path (ALERT_DB_PATH env var).
	// Empty path = in-memory mode = (nil, nil) return.
	Path string
}

// ProvideAlertDB opens the SQLite database used for alert / audit /
// session / token / credential persistence. Returns (nil, nil) for
// the in-memory mode (empty path) — downstream consumers MUST
// nil-check the returned *alerts.DB before using it.
//
// CONTRACT (preserves app/wire.go:62-69 legacy behaviour):
//
//	(nil, nil)        — empty path; in-memory mode, no persistence.
//	                    Production wiring (P2.3) decides whether to
//	                    elevate this to a startup error via the audit-
//	                    required-in-production guard.
//	(*alerts.DB, nil) — open succeeded; caller owns Close() lifecycle
//	                    via fx.Lifecycle hook in the composition site.
//	(nil, nil)        — open FAILED; logged via the supplied logger
//	                    and silently downgraded. This matches the
//	                    legacy "log + fall through with nil alertDB"
//	                    contract from wire.go:64. Production wiring's
//	                    DevMode guard at wire.go:178-220 surfaces the
//	                    nil DB as a startup error in non-Dev mode.
//
// Why no error return on open failure? Because the legacy code path
// already silenced it. Forcing callers to handle a now-Open-failed
// error class would be a behavioural change beyond P2.2's "drop-in
// provider" charter. P2.3+ may revisit if the silent-downgrade
// becomes inconvenient at the composition site.
//
// Lifecycle responsibility: the caller (P2.3 composition) wires
// alertDB.Close() into fx.Lifecycle.Append OnStop. This provider
// does NOT call lc.Append itself (per package convention).
func ProvideAlertDB(cfg AlertDBConfig, logger *slog.Logger) (*alerts.DB, error) {
	if cfg.Path == "" {
		return nil, nil
	}
	db, err := alerts.OpenDB(cfg.Path)
	if err != nil {
		// Match legacy wire.go:64 behaviour: log and downgrade. The
		// non-DevMode startup-error elevation is the composition
		// site's job, not the provider's.
		if logger != nil {
			logger.Error("Failed to open alert DB, using in-memory only", "path", cfg.Path, "error", err)
		}
		return nil, nil
	}
	return db, nil
}
