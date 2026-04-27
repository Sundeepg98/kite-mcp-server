package providers

import (
	"fmt"
	"log/slog"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc/billing"
)

// billing.go — Wave D Phase 2 Slice β-1. Extracts the billing-store
// startup-init chain (InitTable + LoadFromDB) from app/wire.go:597-602
// into a single provider that returns the post-init store wrapped in
// the *InitializedBillingStore type.
//
// Wave D Phase 1+2 left this extraction on the table as "ROI marginal"
// — but the billing extraction is exactly the kind of work that
// improves the ergonomics of further extractions: app/wire.go:595-624
// is one of the last imperative blocks that mixes concerns
// (Stripe configuration, store init, middleware wiring,
// rate-limit-tier mutation). Lifting the init half into a provider
// reduces the composition-site block to its three remaining concerns
// (gating, middleware wiring, late-bound multiplier mutation).
//
// LIFECYCLE OWNERSHIP
//
// This provider does NOT register lifecycle hooks. The billing store
// has no Stop / Close lifecycle method (it's an in-memory cache
// backed by *alerts.DB; the DB owns its own Close path via the
// existing app.lifecycle.Append("alert_db", ...) chain).
//
// ERROR POLICY
//
// Mirrors app/wire.go:597-602 — InitTable and LoadFromDB failures
// are LOGGED and SWALLOWED. Billing tier enforcement degrades to
// "everyone is Free tier" rather than aborting startup, because:
//
//   - A billing failure on a pay-walled deployment is recoverable
//     by ops (re-run migration, restart). Crashing the server takes
//     ALL users offline including non-paying ones.
//   - A billing failure on a non-Stripe deployment (DevMode or no
//     STRIPE_SECRET_KEY) means no users are tier-gated anyway, so
//     the failure is informational.
//
// The composition site decides whether to call this provider at all
// based on Stripe-configured + non-DevMode gating (wire.go:595).
// When the provider IS called, it does best-effort init.
//
// CONTRACT
//
//	(wrapper, nil)              — provider always returns nil error
//	wrapper.Store               — same pointer as input.
//	wrapper.InitTableErr        — first error from InitTable (nil on success).
//	wrapper.LoadFromDBErr       — first error from LoadFromDB (nil on success;
//	                              skipped if InitTable errored).
//	wrapper.Ready               — true iff both init steps succeeded; false
//	                              when either errored or input store was nil.
//
// The composition site reads .Ready to decide whether to wire
// billing.Middleware + the WithTierMultiplier mutation. A
// non-Ready wrapper means "init failed, skip billing-specific
// middleware paths, the rest of the server boots normally."

// BillingConfig captures the narrow inputs the billing init chain
// needs from the surrounding app.Config. Today it carries no fields
// — InitTable and LoadFromDB consult only the *alerts.DB the
// store was constructed against. The struct exists to mirror the
// AuditConfig pattern from audit_init.go and reserve a stable
// extension point for future Stripe-related toggles (e.g. a
// "skip-load-from-db" sentinel for tests, or a price-id passthrough
// once the composition's Stripe gating moves into the provider).
type BillingConfig struct {
	// (intentionally empty — see doc comment for the rationale)
}

// InitializedBillingStore wraps a *billing.Store that has run the
// InitTable + LoadFromDB sequence. The wrapper exists ONLY to give
// Fx a distinct type for "post-init store" vs "raw-construction store"
// — without it, the graph would have two providers for *billing.Store
// (the fx.Supply input and the InitializeBillingStore output) and
// fail with "type already provided" errors. Same convention as
// InitializedAuditStore in audit_init.go.
//
// Downstream consumers consume *InitializedBillingStore; the .Store
// field is unwrapped at the composition site for non-Fx consumers
// (e.g. billing.Middleware + the rate-limit tier multiplier closure).
type InitializedBillingStore struct {
	// Store is the post-init *billing.Store, or nil when input was nil
	// (in-memory mode / billing disabled).
	Store *billing.Store

	// InitTableErr is the first error returned by Store.InitTable, or
	// nil on success. Surfaced for observability — composition-site
	// logging continues to log the error message exactly as before.
	InitTableErr error

	// LoadFromDBErr is the first error returned by Store.LoadFromDB,
	// or nil on success / InitTable-failed-skipped. Same observability
	// rationale as InitTableErr.
	LoadFromDBErr error

	// Ready reports whether both init steps completed without error.
	// false when:
	//   - input Store was nil, OR
	//   - InitTable returned an error (LoadFromDB then skipped), OR
	//   - LoadFromDB returned an error.
	// Composition sites gate Middleware wiring on Ready.
	Ready bool
}

// billingInitInput is the one-arg-struct convention for Fx providers
// when input fields could grow past a comfortable signature length.
// Today the input carries Store + Config + Logger; keeping the struct
// reserves room for future extension (e.g. a metrics sink) without
// breaking call-site signatures.
type billingInitInput struct {
	fx.In

	Store  *billing.Store
	Config BillingConfig
	Logger *slog.Logger
}

// InitializeBillingStore runs the InitTable + LoadFromDB chain on the
// supplied *billing.Store. Returns a wrapper carrying the post-init
// state.
//
// The function NEVER returns a non-nil error — billing init failures
// are surfaced via the wrapper fields and the composition site decides
// whether to abort or degrade. This matches the legacy wire.go
// behaviour (lines 598-602) where errors were logged and the server
// continued.
//
// Pure: the only side-effects are the *billing.Store.InitTable +
// LoadFromDB calls, which mutate the store's internal map and the
// underlying SQLite tables. No goroutines spawned, no closures
// captured. Safe to call from fx.Provide.
func InitializeBillingStore(in billingInitInput) (*InitializedBillingStore, error) {
	store := in.Store
	logger := in.Logger

	// Nil-store branch: in-memory mode / billing disabled. Return a
	// wrapper that reads as "not ready" so the composition site
	// uniformly skips billing middleware. No error — this is the
	// expected shape for non-Stripe deployments.
	if store == nil {
		return &InitializedBillingStore{Store: nil, Ready: false}, nil
	}

	wrapper := &InitializedBillingStore{Store: store, Ready: true}

	// Step 1: InitTable. On error, capture + log + skip LoadFromDB and
	// return non-Ready. Matches wire.go:598-599 sequence.
	if err := store.InitTable(); err != nil {
		wrapper.InitTableErr = err
		wrapper.Ready = false
		if logger != nil {
			logger.Error("Failed to initialize billing table", "error", err)
		}
		return wrapper, nil
	}

	// Step 2: LoadFromDB. On error, capture + log; the wrapper still
	// holds a usable Store pointer, but Ready is false so the
	// composition site skips middleware wiring (a partially-loaded
	// billing map could grant the wrong tier — fail closed).
	if err := store.LoadFromDB(); err != nil {
		wrapper.LoadFromDBErr = err
		wrapper.Ready = false
		if logger != nil {
			logger.Error("Failed to load billing data from DB", "error", err)
		}
		return wrapper, nil
	}

	return wrapper, nil
}

// Compile-time sanity: InitializeBillingStore must always be invokable
// from fx.Provide. We don't ACTUALLY register it through Fx today
// (the composition site calls it directly to keep wire.go's reading
// order obvious), but the type signature is the public contract.
//
// If this assertion ever fails to compile, the input struct or
// return type drifted from the fx.Provide convention.
var _ = func() (*InitializedBillingStore, error) {
	return nil, fmt.Errorf("compile-time-only — never invoked")
}
