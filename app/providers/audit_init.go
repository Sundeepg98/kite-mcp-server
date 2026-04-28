package providers

import (
	"context"
	"fmt"
	"log/slog"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// audit_init.go runs the audit store's startup-time initialization
// chain: InitTable + EnsureEncryptionSalt + SetEncryptionKey +
// SeedChain + SetLogger + StartWorker + hash-publisher start.
//
// Wave D Phase 2 Slice P2.3b. Replaces the imperative chain at
// app/wire.go:177-221 with a single function that composition sites
// invoke via fx.Invoke.
//
// LIFECYCLE OWNERSHIP
//
// This function does NOT register any lifecycle hooks. The existing
// app/wire.go:825-829 chain already registers
// app.lifecycle.Append("audit_store", ...) for store.Stop, and
// app.hashPublisherCancel is captured into the outer App struct so
// the existing wire.go:151-153 success-defer + main.go signal-handler
// chain keeps working unchanged. The Fx adapter pattern from P2.3a
// remains foundation work for P2.4+ where eventDispatcher subscribers
// and scheduler genuinely need OnStart/OnStop pairs.
//
// ERROR POLICY
//
// Mirrors app/wire.go:181-184 + 191-194 + 219-220:
//
//	Production mode (DevMode=false):
//	  - InitTable failure → return error (caller fails-fast)
//	  - EnsureEncryptionSalt failure → return error
//	  - Subsequent steps run only after Init/Encrypt succeed
//
//	DevMode (DevMode=true):
//	  - All failures → log + return nil (operator can run without
//	    audit during local dev)
//
// The "audit required in production but no DB configured" guard
// (wire.go:219-220) lives at the composition site, not here — this
// function is only called WITH a live store. Composition gates the
// invocation on `if store != nil` after ProvideAuditStore returns.

// AuditConfig captures the narrow inputs the audit init chain needs
// from the surrounding app.Config. Two fields:
//
//	OAuthJWTSecret — when non-empty, drives encryption key derivation
//	                 via alerts.EnsureEncryptionSalt. Empty disables
//	                 encryption (matches wire.go:188 conditional).
//	DevMode        — gates the production-vs-dev error policy described
//	                 in this file's doc comment.
type AuditConfig struct {
	OAuthJWTSecret string
	DevMode        bool
}

// InitializeAuditStore runs the post-construction init chain and
// returns a usable *audit.Store handle, or nil if the chain did NOT
// complete fully (DevMode swallowed an error, or the input store was
// nil). The returned pointer-or-nil signals downstream consumers
// (specifically ProvideAuditMiddleware) whether to wire the audit
// middleware: a nil return means "audit disabled, do not wire."
//
// SIGNATURE CHOICE
//
// Returns (*audit.Store, error) so it can plug into fx.Provide and
// drive the type graph: ProvideAuditMiddleware depends on the
// returned store and only fires when init succeeded. A simpler
// `func() error` invoke would not have given us "wire middleware
// only when init fully succeeded" — we'd need a side-channel flag.
// Re-exposing the same pointer via fx.Provide is the natural way to
// express "this dependency is ready for downstream use."
//
// CONTRACT
//
//	(store, nil) — All chain steps succeeded. The returned pointer
//	               is the same one supplied as input (audit.Store is
//	               mutated in-place). Worker is running; encryption
//	               + chain seeded if OAuthJWTSecret was set.
//	(nil, nil)   — Either:
//	               * input store was nil (in-memory mode), OR
//	               * a chain step failed in DevMode (swallowed +
//	                 logged; downstream consumers see nil store and
//	                 omit the audit middleware).
//	(nil, err)   — Production-mode failure. The error message
//	               preserves wire.go's "audit trail required in
//	               production:" prefix so log/alerting rules
//	               continue to match.
//
// The hash-publisher is intentionally NOT started here — see the
// HASH-PUBLISHER NOTE below for why.
//
// HASH-PUBLISHER NOTE
//
// Starting the hash-publisher requires creating a context.WithCancel
// and storing the cancel function back on the *App struct
// (app.hashPublisherCancel). Doing that from this provider would
// require either (a) passing the App pointer in (defeats the
// decoupling goal), or (b) returning the cancel function and having
// the composition site stash it (works but couples the provider's
// signature to App-internal state).
//
// For P2.3b's beachhead, hash-publisher startup REMAINS at the
// composition site (wire.go) via the separate StartAuditHashPublisher
// provider, which the composition calls AFTER InitializeAuditStore
// returns. Future work can extract it into its own Fx provider when
// the App-side state mutations are factored out.

// auditInitInput is the one-arg-struct convention Fx providers
// adopt when their input list grows past 3 fields. Keeps the call
// site readable: fx.Provide(InitializeAuditStore) without
// fx.Annotate gymnastics. The input field names match the
// fx.Supply'd value types.
type auditInitInput struct {
	fx.In

	Store  *audit.Store
	DB     *alerts.DB
	Config AuditConfig
	Logger *slog.Logger
}

// InitializedAuditStore wraps a *audit.Store that has completed the
// init chain. The wrapper exists ONLY to give Fx a distinct type for
// "post-init store" vs "supplied raw store" — without it, the graph
// would have two providers for *audit.Store (the fx.Supply input and
// the InitializeAuditStore output) and fail with "type already
// provided" errors.
//
// Downstream consumers (e.g. ProvideAuditMiddleware) take an
// *InitializedAuditStore parameter; the wrapper's nil-Store-or-
// populated-Store state signals whether the chain succeeded (matches
// the legacy "audit middleware wired only when InitTable succeeded"
// semantic from app/wire.go:204).
//
// Composition sites unwrap to *audit.Store via the Store field for
// non-Fx consumers (e.g. app.auditStore field on App).
type InitializedAuditStore struct {
	// Store is the post-init *audit.Store, or nil when the init chain
	// did not complete (DevMode-init-failed) or input was nil.
	Store *audit.Store
}

// InitializeAuditStore is structurally an fx.Provide target. See the
// preceding doc comment block for the full contract.
func InitializeAuditStore(in auditInitInput) (*InitializedAuditStore, error) {
	store := in.Store
	db := in.DB
	cfg := in.Config
	logger := in.Logger

	if store == nil {
		// In-memory mode. The composition site has already decided
		// that production-mode-without-DB is an error class; if we
		// reach here with nil store, audit is genuinely disabled.
		return &InitializedAuditStore{Store: nil}, nil
	}

	// Step 1: InitTable. Production fails fast; DevMode logs + skips
	// the rest of the chain (returning nil-Store wrapper so caller
	// drops audit middleware wiring).
	if err := store.InitTable(); err != nil {
		if cfg.DevMode {
			if logger != nil {
				logger.Error("Failed to initialize audit table (DevMode: continuing without audit)", "error", err)
			}
			return &InitializedAuditStore{Store: nil}, nil
		}
		return nil, fmt.Errorf("audit trail required in production: init table: %w", err)
	}

	// Step 2: encryption + chain seeding. Conditional on
	// OAuthJWTSecret being supplied (matches wire.go:188 guard).
	if cfg.OAuthJWTSecret != "" && db != nil {
		encKey, err := alerts.EnsureEncryptionSalt(db, cfg.OAuthJWTSecret)
		if err != nil {
			if cfg.DevMode {
				if logger != nil {
					logger.Error("Failed to derive audit encryption key (DevMode: continuing)", "error", err)
				}
				// DevMode: fall through to step 3 without encryption.
			} else {
				return nil, fmt.Errorf("audit trail required in production: derive encryption key: %w", err)
			}
		} else {
			store.SetEncryptionKey(encKey)
			store.SeedChain()
			if logger != nil {
				logger.Info("Audit trail encryption and hash chaining enabled")
			}
		}
	}

	// Step 3: logger + worker. These are infallible in our codebase
	// (SetLoggerPort is a struct-field write; StartWorkerCtx spawns
	// a goroutine with sync.Once). Lifecycle Stop is registered by
	// the composition site's existing app.lifecycle.Append chain.
	//
	// SOLID 99→100 cleanup: migrated from the deprecated SetLogger
	// (*slog.Logger) and StartWorker() shims to the canonical
	// port-typed + ctx-aware variants. context.Background() is the
	// service-ctx — InitializeAuditStore runs at app startup with
	// no request ctx in scope.
	store.SetLoggerPort(logport.NewSlog(logger))
	store.StartWorkerCtx(context.Background())
	if logger != nil {
		logger.Info("Audit trail enabled")
	}

	return &InitializedAuditStore{Store: store}, nil
}

// StartAuditHashPublisher is the post-init step that the composition
// site calls after InitializeAuditStore returns nil and after the
// caller has wired auditMiddleware into the server options. Returns
// the cancel function the App must stash for graceful shutdown.
//
// Split from InitializeAuditStore per the HASH-PUBLISHER NOTE above:
// returning the cancel func keeps the App-internal state mutation at
// the composition site rather than threading the App pointer through
// the provider.
//
// Returns nil cancelFn when store is nil (no work scheduled).
func StartAuditHashPublisher(
	store *audit.Store,
	cfg AuditConfig,
	logger *slog.Logger,
) context.CancelFunc {
	if store == nil {
		return nil
	}
	hpCfg := audit.LoadHashPublishConfig([]byte(cfg.OAuthJWTSecret))
	hpCtx, hpCancel := context.WithCancel(context.Background())
	audit.StartHashPublisher(hpCtx, store, hpCfg, logger)
	return hpCancel
}
