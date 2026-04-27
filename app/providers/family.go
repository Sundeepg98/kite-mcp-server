package providers

import (
	"context"
	"log/slog"
	"sync/atomic"
	"time"

	"go.uber.org/fx"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// family.go — Wave D Phase 2 Slice β-2. Extracts the family-invitation
// startup-init chain (InitTable + LoadFromDB), FamilyService
// construction, AND the 6-hour expired-invitation cleanup goroutine
// from app/wire.go:633-668.
//
// THIS IS THE FIRST PRODUCTION USE OF FxLifecycleAdapter (P2.3a's
// 88e6d71). The cleanup-goroutine OnStop hook routes through the
// adapter onto the host's *app.LifecycleManager, proving the bridge
// under real load.
//
// Wave D Phase 1+2 left this on the table as "ROI marginal" — the
// user pushed back: shipping it. The composition site at wire.go:633
// -668 mixes four concerns (init chain, family-service construction,
// kcManager mutation, cleanup goroutine + cancel-funnel registration);
// lifting all four into a provider narrows the composition block to
// one fx.New invocation that returns the post-init wrapper.
//
// LIFECYCLE OWNERSHIP
//
// The cleanup goroutine's OnStop is registered via the supplied
// *FxLifecycleAdapter (P2.3a). The adapter forwards OnStop to the
// host's LifecycleAppender (typically *app.LifecycleManager). When
// the host calls Shutdown(), the registered cancel function fires
// and the goroutine returns from its select.
//
// This replaces the legacy app.invitationCleanupCancel field +
// app.lifecycle.Append("invitation_cleanup", ...) chain at wire.go:
// 651 + 811-814. The field becomes redundant after β-2 lands; the
// composition site assigns nothing to it and the existing graceful-
// shutdown signal path keeps working.
//
// ERROR POLICY
//
// Mirrors app/wire.go:635-639 — InitTable and LoadFromDB failures
// are LOGGED and SWALLOWED. Family-invitation persistence failures
// degrade to "in-memory only" rather than aborting startup, because:
//
//   - A SQLite migration failure is recoverable by ops; aborting
//     startup loses ALL users incl. those with no family setup.
//   - In-memory mode (no DB / DB nil) is already a supported mode;
//     a partial-init falls into the same equivalence class.
//
// CONTRACT
//
//	(wrapper, nil) — provider always returns nil error
//	wrapper.Service       — *kc.FamilyService, or nil when input
//	                        UserStore/BillingStore was nil.
//	wrapper.InitTableErr  — first error from InitTable (nil on success).
//	wrapper.LoadFromDBErr — first error from LoadFromDB (nil on success
//	                        or InitTable-failed-skipped).
//	wrapper.Ready         — true iff init+load+service-construction
//	                        all succeeded; false otherwise.
//
// FamilyDeps.CleanupTickerInterval defaults to 6 hours (production
// value, matches wire.go:653). Tests supply a millisecond-scale
// interval to make the goroutine observable. CleanupFunc defaults
// to InvitationStore.CleanupExpired.

// FamilyDeps carries the inputs the family provider consumes.
// Single-arg-struct convention; the field count is just past
// "comfortable signature length" so the struct provides a stable
// extension point.
type FamilyDeps struct {
	// InvitationStore is the *users.InvitationStore the composition
	// site pre-constructed (matches wire.go:89 preInvStore). nil =
	// in-memory mode / no DB; provider returns a not-Ready wrapper.
	InvitationStore *users.InvitationStore

	// UserStore is the *users.Store passed to NewFamilyService. nil
	// is permitted but yields a nil FamilyService (kc.NewFamilyService
	// validates internally).
	UserStore kc.FamilyUserStore

	// BillingStore is the BillingStoreInterface passed to
	// NewFamilyService. nil yields tier=Free for all admins (per
	// kc.FamilyService.MaxUsers fallback at family_service.go:62-63).
	BillingStore kc.BillingStoreInterface

	// CleanupFunc, when non-nil, REPLACES the default cleanup
	// behaviour (s.CleanupExpired()). Tests use this seam to record
	// invocations or short-circuit. Production passes nil and the
	// provider wires the default closure.
	CleanupFunc func() int

	// CleanupTickerInterval governs how often the cleanup goroutine
	// runs. Zero falls through to the production default (6 hours).
	// Tests supply a millisecond-scale value to make the tick
	// observable.
	CleanupTickerInterval time.Duration

	// Lifecycle is the FxLifecycleAdapter the provider registers its
	// goroutine OnStop hook on. nil disables the goroutine entirely
	// (the wrapper is otherwise still constructed; useful for tests
	// that only need the FamilyService).
	Lifecycle *FxLifecycleAdapter

	// Logger receives init-error log lines + the periodic cleanup
	// summary. nil = silent.
	Logger *slog.Logger
}

// InitializedFamilyService wraps the post-construction *kc.FamilyService
// + init-step error visibility. Per the wrapper-type convention
// (audit_init.go's InitializedAuditStore, billing.go's
// InitializedBillingStore): gives Fx a distinct type for "post-init
// service" vs "raw construction".
type InitializedFamilyService struct {
	// Service is the *kc.FamilyService, or nil if input UserStore /
	// BillingStore was missing.
	Service *kc.FamilyService

	// InitTableErr is the first error from InvitationStore.InitTable,
	// or nil on success.
	InitTableErr error

	// LoadFromDBErr is the first error from InvitationStore.LoadFromDB,
	// or nil on success / InitTable-failed-skipped.
	LoadFromDBErr error

	// Ready reports whether the init chain succeeded AND the service
	// was constructed. false when:
	//   - InvitationStore was nil, OR
	//   - InitTable / LoadFromDB returned an error, OR
	//   - UserStore/BillingStore was nil so Service = nil.
	Ready bool

	// CleanupGoroutineRunning reports whether the cleanup goroutine
	// was spawned. true iff Lifecycle was non-nil AND the init chain
	// reached the goroutine-spawn step. Surfaced for test assertion;
	// no production caller reads it.
	CleanupGoroutineRunning bool
}

// InitializeFamilyService runs the family-store init chain, constructs
// the FamilyService, and (when a Lifecycle adapter is supplied) spawns
// the 6-hour expired-invitation cleanup goroutine with its OnStop hook
// registered via the adapter.
//
// The function NEVER returns a non-nil error — failures surface via
// the wrapper. Matches the legacy wire.go:635-668 best-effort
// behaviour.
//
// PURE-WHERE-POSSIBLE: the only side-effects are:
//   - InvitationStore.InitTable + LoadFromDB (SQLite I/O via
//     the wrapped *alerts.DB; idempotent).
//   - kc.NewFamilyService construction (in-memory struct).
//   - One goroutine spawn iff Lifecycle != nil.
func InitializeFamilyService(in FamilyDeps) (*InitializedFamilyService, error) {
	wrapper := &InitializedFamilyService{}

	// Nil-store branch: in-memory mode / no DB. Return a non-Ready
	// wrapper that matches the wire.go:633 if-alertDB-nil branch.
	if in.InvitationStore == nil {
		return wrapper, nil
	}

	// Step 1: InitTable. On error, log + capture + skip LoadFromDB
	// + return non-Ready. Matches wire.go:635-636.
	if err := in.InvitationStore.InitTable(); err != nil {
		wrapper.InitTableErr = err
		if in.Logger != nil {
			in.Logger.Error("Failed to initialize invitations table", "error", err)
		}
		return wrapper, nil
	}

	// Step 2: LoadFromDB. On error, log + capture + return non-Ready.
	// Service construction is skipped — a partially-loaded invitation
	// map could grant the wrong tier (fail closed).
	if err := in.InvitationStore.LoadFromDB(); err != nil {
		wrapper.LoadFromDBErr = err
		if in.Logger != nil {
			in.Logger.Error("Failed to load invitations from DB", "error", err)
		}
		return wrapper, nil
	}

	// Step 3: construct the FamilyService. Requires non-nil
	// UserStore + BillingStore.
	if in.UserStore == nil || in.BillingStore == nil {
		// Init succeeded but FamilyService cannot be built. Return
		// the wrapper as Ready=false so the composition site skips
		// `kcManager.SetFamilyService` — same outcome as the legacy
		// flow when these stores were nil (wire.go didn't gate the
		// service-construction call separately, but kc.NewFamilyService
		// returned a non-nil pointer with nil internal stores; the
		// service's accessors all nil-check internally).
		return wrapper, nil
	}
	wrapper.Service = kc.NewFamilyService(
		in.UserStore,
		in.BillingStore,
		in.InvitationStore,
	)
	wrapper.Ready = true

	// Step 4: cleanup goroutine. Only spawned when a Lifecycle
	// adapter is supplied — tests that don't need the goroutine pass
	// nil and observe Service-only state.
	if in.Lifecycle != nil {
		spawnFamilyCleanupGoroutine(in, wrapper)
	}

	return wrapper, nil
}

// spawnFamilyCleanupGoroutine encapsulates the goroutine-lifecycle
// dance. Split from InitializeFamilyService so its closure captures
// (cleanupFn, ticker, ctx) are localized and tests can mentally model
// each stage independently.
//
// Defaults applied:
//
//	in.CleanupFunc nil          → s.CleanupExpired() default closure.
//	in.CleanupTickerInterval=0  → 6 hours (production value).
//
// The goroutine is registered with the adapter via fx.Hook{OnStart:
// no-op, OnStop: cancel}. OnStart runs SYNCHRONOUSLY at adapter.Append
// time (per P2.3a's contract), but in our case the goroutine is
// already spawned BEFORE we call adapter.Append so OnStart is a
// formality (the contract is satisfied).
func spawnFamilyCleanupGoroutine(in FamilyDeps, wrapper *InitializedFamilyService) {
	cleanupFn := in.CleanupFunc
	if cleanupFn == nil {
		cleanupFn = func() int { return in.InvitationStore.CleanupExpired() }
	}
	interval := in.CleanupTickerInterval
	if interval <= 0 {
		interval = 6 * time.Hour
	}

	ctx, cancel := context.WithCancel(context.Background())

	// Track goroutine completion so OnStop can wait for it. Without
	// the wait, a fast Stop() could let the goroutine outlive the
	// test or shutdown — breaking goroutine-leak detection.
	doneCh := make(chan struct{})

	go func() {
		defer close(doneCh)
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n := cleanupFn(); n > 0 && in.Logger != nil {
					in.Logger.Info("Cleaned up expired invitations", "count", n)
				}
			}
		}
	}()

	// Track whether the OnStop already fired so re-entrant Shutdown
	// is a no-op (mirrors the existing app.LifecycleManager sync.Once
	// semantics).
	var stopped atomic.Bool

	in.Lifecycle.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			// No-op: goroutine is already running. The Hook contract
			// requires OnStart to be present so the OnStop registration
			// is honoured by FxLifecycleAdapter.Append (which only
			// registers OnStop when the hook's OnStart succeeds).
			return nil
		},
		OnStop: func(_ context.Context) error {
			if stopped.Swap(true) {
				return nil
			}
			cancel()
			// Wait for the goroutine to actually return so callers
			// observing "Stop completed" can rely on no-pending-work.
			// Bounded by a short deadline so a hung goroutine doesn't
			// block the host's shutdown.
			select {
			case <-doneCh:
			case <-time.After(2 * time.Second):
				// Best-effort timeout — goroutine kept running past
				// 2s. Surfaced via log but not via error (matches the
				// existing best-effort shutdown semantics).
				if in.Logger != nil {
					in.Logger.Warn("invitation cleanup goroutine did not exit within 2s")
				}
			}
			return nil
		},
	})
	wrapper.CleanupGoroutineRunning = true
}
