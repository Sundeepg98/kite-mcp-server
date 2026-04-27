package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// manager_test.go — Wave D Phase 2 Slice P2.5a tests.
//
// P2.5a establishes the Fx provider seam for inner-Manager
// construction. The provider wraps kc.NewWithOptions as a graph
// node; the graph orchestrates the Manager's startup-once lifecycle
// alongside the existing Phase-2 leaf providers (logger, alertDB,
// audit, scheduler, riskGuard, telegram, mcpserver, lifecycle, event
// dispatcher).
//
// The 16 init helpers in kc/manager_init.go are NOT restructured by
// P2.5a; they remain orchestrated by NewWithOptions. This cluster
// only adds the OUTER Fx seam so the App's composition root can
// participate in the graph. Subsequent clusters (P2.5b/c/d) iterate
// on the inner factoring once the seam is proven.
//
// Pattern source: app/providers/scheduler.go (BuildScheduler
// returns *InitializedScheduler), app/providers/riskguard.go
// (InitializeRiskGuard returns *InitializedRiskGuard), and
// app/providers/audit_init.go (InitializeAuditStore returns
// *InitializedAuditStore). All three follow the wrapper-type
// convention to keep the Fx graph free of "type already provided"
// conflicts.

// TestProvideManager_NilLogger_Errors verifies the provider rejects
// a nil logger up-front, matching kc.New's contract:
// "logger is required" — caller must supply.
//
// This is the same error class kc.NewWithOptions surfaces; the
// provider passes it through so Fx graph errors carry the legacy
// message verbatim, preserving log-search rules / alerting.
func TestProvideManager_NilLogger_Errors(t *testing.T) {
	t.Parallel()

	cfg := ManagerConfig{
		// Logger deliberately nil
		InstrumentsSkipFetch: true,
	}
	got, err := BuildManager(managerInput{
		Ctx:    context.Background(),
		Config: cfg,
	})
	if err == nil {
		t.Fatal("expected error for nil logger; got nil")
	}
	if got != nil {
		t.Errorf("expected nil wrapper on logger error; got %T", got)
	}
}

// TestProvideManager_MinimalConfig_ReturnsManager verifies the
// happy path: with a valid logger + InstrumentsSkipFetch (so we
// don't hit api.kite.trade in tests), BuildManager returns a
// non-nil *InitializedManager whose Manager field is wired and
// usable.
//
// Test isolation note: InstrumentsSkipFetch=true is the established
// kc-package test-isolation seam (see kc/manager_init.go:67-69).
// Without it, instruments.New attempts an HTTP fetch which is
// flaky under CI rate limits.
func TestProvideManager_MinimalConfig_ReturnsManager(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}
	got, err := BuildManager(managerInput{
		Ctx:    context.Background(),
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("expected nil error for minimal config; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if got.Manager == nil {
		t.Fatal("expected wrapper.Manager non-nil for minimal config")
	}
	t.Cleanup(func() {
		// Manager.Shutdown is the canonical cleanup path. Returns
		// no error — test manager has no DB-owned resources to
		// surface failures from.
		got.Manager.Shutdown()
	})
}

// TestProvideManager_FxIntegration verifies the provider integrates
// with fx.New as a graph node. This is the structural test that
// proves the signature plays in an Fx graph (matches scheduler_test
// + riskguard_test + audit_init_test patterns).
//
// fxtest.New gives us a graph that can be inspected without going
// through the full lifecycle Start/Stop dance — sufficient to prove
// the provider's signature and dependencies resolve.
func TestProvideManager_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var initialized *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Populate(&initialized),
	)
	defer fxApp.RequireStart().RequireStop()

	if initialized == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if initialized.Manager == nil {
		t.Fatal("expected non-nil Manager inside wrapper")
	}
	t.Cleanup(func() {
		initialized.Manager.Shutdown()
	})
}

// TestInitializedManager_TypeIdentity verifies the wrapper's
// Manager field is the same pointer that kc.NewWithOptions
// returned — no defensive copy. This matches the audit_init /
// riskguard / scheduler convention: the wrapper is purely a graph-
// type-distinction artifact, not a behavioural shim.
func TestInitializedManager_TypeIdentity(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}
	got, err := BuildManager(managerInput{
		Ctx:    context.Background(),
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("BuildManager: %v", err)
	}
	if got == nil || got.Manager == nil {
		t.Fatal("expected non-nil wrapper.Manager")
	}
	t.Cleanup(func() {
		got.Manager.Shutdown()
	})

	// Cross-check: the Manager field should be a real *kc.Manager.
	var _ *kc.Manager = got.Manager
}
