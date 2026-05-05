package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// session_svc_test.go — Anchor 6 PR 6.3 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) — pins the contract:
//
//	nil wrapper or wrapper with nil Manager → nil SessionService
//	wrapper with populated Manager          → Manager.SessionSvc()

// TestProvideSessionSvc_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service.
func TestProvideSessionSvc_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideSessionSvc(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvideSessionSvc_NilManager_ReturnsNil verifies that a wrapper
// with a nil Manager field yields a nil service.
func TestProvideSessionSvc_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideSessionSvc(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideSessionSvc_LiveManager_ReturnsService verifies that a
// wrapper with a populated Manager yields a non-nil
// *kc.SessionService — the same pointer Manager.SessionSvc() returns.
// Pointer-identity assertion guards against accidental wrap/copy.
func TestProvideSessionSvc_LiveManager_ReturnsService(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}
	mgrInit, err := BuildManager(managerInput{
		Ctx:    context.Background(),
		Config: cfg,
	})
	if err != nil {
		t.Fatalf("BuildManager: %v", err)
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil wrapper.Manager")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })

	got := ProvideSessionSvc(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil SessionService for populated wrapper")
	}
	if got != mgrInit.Manager.SessionSvc {
		t.Error("expected pointer-identity with Manager.SessionSvc(); got a different pointer (regression: provider wrapped/copied the service)")
	}

	var _ *kc.SessionService = got
}

// TestProvideSessionSvc_FxIntegration verifies the provider integrates
// with fx.New as a graph node.
func TestProvideSessionSvc_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var sessSvc *kc.SessionService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideSessionSvc),
		fx.Populate(&sessSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if sessSvc == nil {
		t.Fatal("expected non-nil *kc.SessionService from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if sessSvc != mgrInit.Manager.SessionSvc {
		t.Error("expected pointer-identity between graph-resolved SessionService and Manager.SessionSvc()")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
