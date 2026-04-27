package providers

import (
	"errors"
	"fmt"
	"log/slog"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// riskguard.go — Wave D Phase 2 Slice P2.4c. Provides initialization
// of the *riskguard.Guard as an Fx graph node.
//
// LEGACY BEHAVIOUR PRESERVED
//
// The original imperative chain at app/wire.go:297-407 ran:
//   1. SetDB on the pre-constructed guard (when AlertDB available)
//   2. InitTable (production fail-fast; DevMode log+continue)
//   3. LoadLimits (same fail-fast/continue policy)
//   4. SetFreezeQuantityLookup (when instruments manager available)
//   5. SetLTPLookup (always — adapter is nil-safe internally)
//   6. SetBaselineProvider (when audit store available)
//   7. SetAutoFreezeNotifier (closure with kcManager + admin emails)
//   8. DiscoverPlugins (when RISKGUARD_PLUGIN_DIR configured)
//
// Steps 1-3 + 4-6 + 8 move into this provider. Steps 7 (auto-freeze
// closure) STAYS at the composition site because the closure
// captures kcManager (for lazy EventDispatcher resolution),
// AdminEmails, and the TelegramNotifier — all app-package state
// that doesn't belong in the providers package.
//
// CONFIG
//
// RiskGuardConfig captures the narrow inputs that drive the
// production-vs-DevMode error policy. The composition site
// constructs it from app.Config + app.DevMode and supplies via
// fx.Supply.
//
// WRAPPER
//
// Returns *InitializedRiskGuard with two fields:
//   - Guard: the same *riskguard.Guard pointer supplied as input
//     (mutated in-place). Non-nil iff the input was non-nil.
//   - LimitsLoaded: true when InitTable + LoadLimits both succeeded
//     (or DevMode-no-DB path), false when DevMode-init-failed. The
//     composition site assigns this to app.riskLimitsLoaded.
//
// ERROR CONTRACT
//
// Production failures bubble through with the
// "riskguard required in production:" prefix preserved from
// wire.go:317/324/330. DevMode swallows + logs + sets
// LimitsLoaded=false (matches wire.go:319-321/326-328).

// RiskGuardConfig captures the policy + feature-toggle inputs the
// init chain needs. Constructed at composition site from app.Config.
type RiskGuardConfig struct {
	// DevMode gates the production-vs-DevMode fail-fast policy. When
	// true, init failures log + continue with degraded state. When
	// false, init failures bubble through as startup errors.
	DevMode bool

	// PluginDir is the RISKGUARD_PLUGIN_DIR env value. When non-empty,
	// triggers DiscoverPlugins which registers subprocess checks from
	// a plugins.json manifest. Empty disables discovery.
	PluginDir string
}

// InitializedRiskGuard wraps the post-init *riskguard.Guard plus
// the LimitsLoaded boolean signal. Per the wrapper-type convention
// (see audit_init.go), this gives Fx a distinct type for "post-init"
// vs "raw guard input" — preventing graph-conflict errors.
type InitializedRiskGuard struct {
	// Guard is the post-init *riskguard.Guard, same pointer as
	// supplied to the provider. Always non-nil when the wrapper
	// itself is non-nil (provider returns nil-wrapper only on error).
	Guard *riskguard.Guard

	// LimitsLoaded mirrors app.riskLimitsLoaded — true when InitTable
	// + LoadLimits succeeded (or DevMode-no-DB path), false when
	// DevMode swallowed an init failure.
	LimitsLoaded bool
}

// riskguardInitInput is the fx.In struct convention for providers
// with multiple inputs. Marked optional fields are nil-tolerant:
// the provider checks each before wiring.
type riskguardInitInput struct {
	fx.In

	// Guard is the pre-constructed *riskguard.Guard. The composition
	// site constructs it before fx.New (wire.go preRiskGuard pattern)
	// so the kcManager can hold a reference for risk checks during
	// the rest of the bootstrap sequence.
	Guard *riskguard.Guard

	// DB is the optional SQLite handle for limits persistence. Nil
	// in in-memory mode; production-mode-without-DB is a fatal error
	// surfaced by Config.DevMode=false at the InitTable step.
	DB *alerts.DB `optional:"true"`

	// FreezeLookup is the instruments-manager wrapper used to enforce
	// per-instrument freeze quantities. Nil-safe — when unset, the
	// freeze-quantity check no-ops.
	FreezeLookup riskguard.FreezeQuantityLookup `optional:"true"`

	// LTPLookup is the SEBI OTR-band-check oracle. Composition site
	// supplies a riskguardLTPAdapter wrapping kcManager. Nil-safe —
	// the band check passes through when no quote is available.
	LTPLookup riskguard.LTPLookup `optional:"true"`

	// AuditStore drives the anomaly-detection baseline (μ+3σ rolling
	// stats per user). Nil-safe — when unset, anomaly checks fail
	// open per audit_init.go's contract.
	AuditStore *audit.Store `optional:"true"`

	// Config captures the policy inputs (DevMode + PluginDir).
	Config RiskGuardConfig

	// Logger is required for plugin-discovery error logging and
	// init-failure reports.
	Logger *slog.Logger
}

// InitializeRiskGuard runs the riskguard init chain and returns the
// post-init wrapper. See file-level doc comment for the full
// contract; per-step semantics mirror app/wire.go:297-407 modulo
// the auto-freeze closure (which stays at composition).
func InitializeRiskGuard(in riskguardInitInput) (*InitializedRiskGuard, error) {
	if in.Guard == nil {
		return nil, errors.New("riskguard provider: guard input is required")
	}

	guard := in.Guard
	limitsLoaded := true

	// Step 1-3: DB init + LoadLimits with fail-fast / DevMode policy.
	if in.DB != nil {
		guard.SetDB(in.DB)
		if err := guard.InitTable(); err != nil {
			if !in.Config.DevMode {
				return nil, fmt.Errorf("riskguard required in production: init risk_limits table: %w", err)
			}
			if in.Logger != nil {
				in.Logger.Error("Failed to initialize risk_limits table (DevMode: continuing)", "error", err)
			}
			limitsLoaded = false
		}
		if err := guard.LoadLimits(); err != nil {
			if !in.Config.DevMode {
				return nil, fmt.Errorf("riskguard required in production: load limits (refusing to start without user-configured limits): %w", err)
			}
			if in.Logger != nil {
				in.Logger.Error("Failed to load risk limits (DevMode: continuing with defaults)", "error", err)
			}
			limitsLoaded = false
		}
	} else if !in.Config.DevMode {
		return nil, fmt.Errorf("riskguard required in production: no alert DB configured (set ALERT_DB_PATH)")
	}

	// Step 4: FreezeQuantityLookup (nil-safe; check before wiring to
	// avoid storing a typed-nil interface that the guard would
	// dereference on every order check).
	if in.FreezeLookup != nil {
		guard.SetFreezeQuantityLookup(in.FreezeLookup)
	}

	// Step 5: LTPLookup. Always wire when supplied — the adapter is
	// designed to be nil-safe internally (returns found=false when
	// no active session). nil-input still skipped to avoid the
	// typed-nil-interface footgun.
	if in.LTPLookup != nil {
		guard.SetLTPLookup(in.LTPLookup)
	}

	// Step 6: BaselineProvider for anomaly detection. *audit.Store
	// satisfies riskguard.BaselineProvider via its UserOrderStats
	// method. Skip when nil — anomaly check fails open.
	if in.AuditStore != nil {
		guard.SetBaselineProvider(in.AuditStore)
		if in.Logger != nil {
			in.Logger.Info("riskguard anomaly baseline wired", "provider", "audit")
		}
	}

	// Step 8: Plugin discovery. Empty PluginDir = no-op. Errors are
	// logged and continued (one bad plugin must not block the rest).
	if in.Config.PluginDir != "" {
		if err := riskguard.DiscoverPlugins(
			in.Config.PluginDir,
			guard.RegisterSubprocessCheck,
			in.Logger,
		); err != nil {
			if in.Logger != nil {
				in.Logger.Warn("riskguard plugin discovery had errors (continuing)",
					"plugin_dir", in.Config.PluginDir, "error", err)
			}
		}
	}

	return &InitializedRiskGuard{
		Guard:        guard,
		LimitsLoaded: limitsLoaded,
	}, nil
}
