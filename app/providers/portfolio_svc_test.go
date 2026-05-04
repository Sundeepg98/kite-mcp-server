package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// portfolio_svc_test.go — Anchor 6 PR 6.5 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) — pins the contract:
//
//	nil wrapper or wrapper with nil Manager → nil PortfolioService
//	wrapper with populated Manager          → Manager.PortfolioSvc()

// TestProvidePortfolioSvc_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service.
func TestProvidePortfolioSvc_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvidePortfolioSvc(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvidePortfolioSvc_NilManager_ReturnsNil verifies that a
// wrapper with a nil Manager field yields a nil service.
func TestProvidePortfolioSvc_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvidePortfolioSvc(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvidePortfolioSvc_LiveManager_ReturnsService verifies that a
// wrapper with a populated Manager yields a non-nil
// *kc.PortfolioService — the same pointer Manager.PortfolioSvc()
// returns. Pointer-identity assertion guards against accidental
// wrap/copy regression.
func TestProvidePortfolioSvc_LiveManager_ReturnsService(t *testing.T) {
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

	got := ProvidePortfolioSvc(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil PortfolioService for populated wrapper")
	}
	if got != mgrInit.Manager.PortfolioSvc() {
		t.Error("expected pointer-identity with Manager.PortfolioSvc(); got a different pointer (regression: provider wrapped/copied the service)")
	}

	var _ *kc.PortfolioService = got
}

// TestProvidePortfolioSvc_FxIntegration verifies the provider
// integrates with fx.New as a graph node.
func TestProvidePortfolioSvc_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var pfSvc *kc.PortfolioService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvidePortfolioSvc),
		fx.Populate(&pfSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if pfSvc == nil {
		t.Fatal("expected non-nil *kc.PortfolioService from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if pfSvc != mgrInit.Manager.PortfolioSvc() {
		t.Error("expected pointer-identity between graph-resolved PortfolioService and Manager.PortfolioSvc()")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
