package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	"github.com/zerodha/kite-mcp-server/kc"
)

// family_service_test.go — Anchor 6 PR 6.11 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) with one nuance: family
// billing is optional, so Manager.FamilyService() can legitimately
// return nil after successful Manager construction. The
// LiveManager / FxIntegration tests assert pointer-identity with
// whatever Manager.FamilyService() returns (nil or non-nil) rather
// than requiring non-nil.

// TestProvideFamilyService_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil service.
func TestProvideFamilyService_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideFamilyService(nil)
	if got != nil {
		t.Errorf("expected nil service for nil wrapper; got %T", got)
	}
}

// TestProvideFamilyService_NilManager_ReturnsNil verifies that a
// wrapper with a nil Manager field yields a nil service.
func TestProvideFamilyService_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideFamilyService(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil service for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideFamilyService_LiveManager_PointerIdentity verifies that
// the provider returns the SAME pointer Manager.FamilyService()
// returns — whether that pointer is nil (default for newly-built
// Manager: family billing is opt-in via SetFamilyService) or non-nil
// (when SetFamilyService was called). Pointer-identity is the load-
// bearing assertion: it guards against accidental wrap/copy
// regression in either direction.
//
// Default-construction Manager has FamilyService() == nil. The test
// asserts the provider passes through that nil unchanged — same
// contract as Manager.FamilyService().
func TestProvideFamilyService_LiveManager_PointerIdentity(t *testing.T) {
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

	got := ProvideFamilyService(mgrInit)
	want := mgrInit.Manager.FamilyService()
	if got != want {
		t.Errorf("expected pointer-identity with Manager.FamilyService(); got %p want %p", got, want)
	}

	// Type assertion in case got is non-nil — cross-check the type.
	var _ *kc.FamilyService = got
}

// TestProvideFamilyService_FxIntegration verifies the provider
// integrates with fx.New as a graph node. Like the LiveManager test,
// the assertion is pointer-identity with Manager.FamilyService(),
// not non-nil.
func TestProvideFamilyService_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var famSvc *kc.FamilyService
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideFamilyService),
		fx.Populate(&famSvc, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}
	want := mgrInit.Manager.FamilyService()
	if famSvc != want {
		t.Errorf("expected pointer-identity between graph-resolved FamilyService and Manager.FamilyService(); got %p want %p", famSvc, want)
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
