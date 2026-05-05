package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// order_svc_test.go — Anchor 6 PR 6.7 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) — pins the contract:
//
//	nil wrapper or wrapper with nil Manager → nil OrderService
//	wrapper with populated Manager          → Manager.OrderSvc()

// TestProvideOrderSvc_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service.
func TestProvideOrderSvc_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideOrderSvc(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvideOrderSvc_NilManager_ReturnsNil verifies that a wrapper
// with a nil Manager field yields a nil service.
func TestProvideOrderSvc_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideOrderSvc(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideOrderSvc_LiveManager_ReturnsService verifies that a
// wrapper with a populated Manager yields a non-nil *kc.OrderService
// — the same pointer Manager.OrderSvc() returns. Pointer-identity
// assertion guards against accidental wrap/copy regression.
func TestProvideOrderSvc_LiveManager_ReturnsService(t *testing.T) {
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

	got := ProvideOrderSvc(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil OrderService for populated wrapper")
	}
	if got != mgrInit.Manager.OrderSvc {
		t.Error("expected pointer-identity with Manager.OrderSvc(); got a different pointer (regression: provider wrapped/copied the service)")
	}

	var _ *kc.OrderService = got
}

// TestProvideOrderSvc_FxIntegration verifies the provider integrates
// with fx.New as a graph node.
func TestProvideOrderSvc_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var orderSvc *kc.OrderService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideOrderSvc),
		fx.Populate(&orderSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if orderSvc == nil {
		t.Fatal("expected non-nil *kc.OrderService from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if orderSvc != mgrInit.Manager.OrderSvc {
		t.Error("expected pointer-identity between graph-resolved OrderService and Manager.OrderSvc()")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
