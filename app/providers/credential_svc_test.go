package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// credential_svc_test.go — Anchor 6 PR 6.1 tests.
//
// PR 6.1 is the risk-floor add-provider for the kc-root god-struct
// decomposition (per .research/tier-5-and-anchor-6-pre-stage.md).
// These tests pin the contract:
//
//	nil wrapper or wrapper with nil Manager → nil CredentialService
//	wrapper with populated Manager          → Manager.CredentialSvc()
//
// The provider is purely additive — Manager.CredentialSvc() (kc/manager_
// accessors.go:23) stays unchanged. Future PR 6.2 will delete the
// Manager method after a 24-hour deploy observation gate confirms this
// PR's Fx wiring is healthy in prod.

// TestProvideCredentialSvc_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service. The nil-wrapper
// case shouldn't occur in normal Fx graph wiring (BuildManager
// returns a non-nil wrapper or an error), but the provider defends
// against it for direct-test callers.
func TestProvideCredentialSvc_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideCredentialSvc(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvideCredentialSvc_NilManager_ReturnsNil verifies that a
// wrapper with a nil Manager field yields a nil service. The
// BuildManager contract (app/providers/manager.go:166-171) returns a
// non-nil wrapper only on success, but this test pins the defensive
// behavior in case a downstream caller constructs an
// InitializedManager{} struct literal directly.
func TestProvideCredentialSvc_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideCredentialSvc(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideCredentialSvc_LiveManager_ReturnsService verifies that a
// wrapper with a populated Manager yields a non-nil
// *kc.CredentialService — the same pointer Manager.CredentialSvc()
// returns. Pointer-identity assertion guards against an accidental
// "wrap in a new struct" or "make a copy" regression.
func TestProvideCredentialSvc_LiveManager_ReturnsService(t *testing.T) {
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

	got := ProvideCredentialSvc(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil CredentialService for populated wrapper")
	}
	if got != mgrInit.Manager.CredentialSvc() {
		t.Error("expected pointer-identity with Manager.CredentialSvc(); got a different pointer (regression: provider wrapped/copied the service)")
	}

	// Cross-check: the value should be a real *kc.CredentialService.
	var _ *kc.CredentialService = got
}

// TestProvideCredentialSvc_FxIntegration verifies the provider
// integrates with fx.New as a graph node. This is the structural test
// that proves the signature plays in an Fx graph (matches the
// audit_middleware_test / scheduler_test patterns).
func TestProvideCredentialSvc_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var credSvc *kc.CredentialService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideCredentialSvc),
		fx.Populate(&credSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if credSvc == nil {
		t.Fatal("expected non-nil *kc.CredentialService from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	if credSvc != mgrInit.Manager.CredentialSvc() {
		t.Error("expected pointer-identity between graph-resolved CredentialService and Manager.CredentialSvc()")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
