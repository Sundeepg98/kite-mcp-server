package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// alert_svc_test.go — Anchor 6 PR 6.9 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) — pins the contract:
//
//	nil wrapper or wrapper with nil Manager → nil AlertService
//	wrapper with populated Manager          → Manager.AlertSvc()

// TestProvideAlertSvc_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service.
func TestProvideAlertSvc_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideAlertSvc(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvideAlertSvc_NilManager_ReturnsNil verifies that a wrapper
// with a nil Manager field yields a nil service.
func TestProvideAlertSvc_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideAlertSvc(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideAlertSvc_LiveManager_ReturnsService verifies that a
// wrapper with a populated Manager yields a non-nil *kc.AlertService
// — the same pointer Manager.AlertSvc() returns. Pointer-identity
// assertion guards against accidental wrap/copy regression.
func TestProvideAlertSvc_LiveManager_ReturnsService(t *testing.T) {
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

	got := ProvideAlertSvc(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil AlertService for populated wrapper")
	}
	if got != mgrInit.Manager.AlertSvc() {
		t.Error("expected pointer-identity with Manager.AlertSvc(); got a different pointer (regression: provider wrapped/copied the service)")
	}

	var _ *kc.AlertService = got
}

// TestProvideAlertSvc_FxIntegration verifies the provider integrates
// with fx.New as a graph node.
func TestProvideAlertSvc_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var alertSvc *kc.AlertService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideAlertSvc),
		fx.Populate(&alertSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if alertSvc == nil {
		t.Fatal("expected non-nil *kc.AlertService from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if alertSvc != mgrInit.Manager.AlertSvc() {
		t.Error("expected pointer-identity between graph-resolved AlertService and Manager.AlertSvc()")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
