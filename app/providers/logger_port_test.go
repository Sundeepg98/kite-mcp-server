package providers

import (
	"context"
	"testing"

	"go.uber.org/fx"
	"go.uber.org/fx/fxtest"

	logport "github.com/algo2go/kite-mcp-logger"
)

// logger_port_test.go — Anchor 6 PR 6.13 tests.
//
// Mirrors credential_svc_test.go (PR 6.1) with one structural
// deviation: pointer-identity is NOT asserted because
// Manager.LoggerPort() constructs a fresh wrapper on each call (see
// kc/manager_accessors.go:59-64). Instead the LiveManager / Fx
// integration tests assert functional equivalence — both wrappers
// expose the same underlying *slog.Logger via logport.AsSlog().

// TestProvideLoggerPort_NilWrapper_ReturnsNil verifies that a nil
// *InitializedManager input yields a nil logger.
func TestProvideLoggerPort_NilWrapper_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideLoggerPort(nil)
	if got != nil {
		t.Errorf("expected nil logger for nil wrapper; got %T", got)
	}
}

// TestProvideLoggerPort_NilManager_ReturnsNil verifies that a wrapper
// with a nil Manager field yields a nil logger.
func TestProvideLoggerPort_NilManager_ReturnsNil(t *testing.T) {
	t.Parallel()

	got := ProvideLoggerPort(&InitializedManager{Manager: nil})
	if got != nil {
		t.Errorf("expected nil logger for nil-Manager wrapper; got %T", got)
	}
}

// TestProvideLoggerPort_LiveManager_FunctionalEquivalence verifies
// that the provider returns a non-nil logport.Logger that wraps the
// SAME underlying *slog.Logger as Manager.LoggerPort()'s wrapper.
//
// Pointer-identity-on-the-wrapper would FAIL here because
// Manager.LoggerPort() constructs a fresh *slogAdapter on each call
// (kc/manager_accessors.go:60-64). The structural-deviation note in
// logger_port.go documents why this is correct behavior, not a bug.
//
// We assert functional equivalence via logport.AsSlog() which
// extracts the underlying *slog.Logger from any *slogAdapter
// wrapper. Both wrappers must extract to the same *slog.Logger
// pointer — that's the load-bearing equivalence claim.
func TestProvideLoggerPort_LiveManager_FunctionalEquivalence(t *testing.T) {
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

	got := ProvideLoggerPort(mgrInit)
	if got == nil {
		t.Fatal("expected non-nil Logger for populated wrapper")
	}

	// Functional equivalence: both wrappers must expose the same
	// underlying *slog.Logger. AsSlog returns nil for non-slogAdapter
	// implementations (e.g. NewNoop), so a non-nil match here also
	// proves the wrapper is the slogAdapter variant.
	gotSlog := logport.AsSlog(got)
	wantSlog := mgrInit.Manager.Logger
	if gotSlog == nil || wantSlog == nil {
		t.Fatalf("expected both wrappers to be slogAdapter variants; got %T and %T", got, mgrInit.Manager.Logger)
	}
	if gotSlog != wantSlog {
		t.Error("expected provider's wrapper and Manager.LoggerPort()'s wrapper to share the same underlying *slog.Logger; got different pointers (regression: provider wrapped a different logger)")
	}
}

// TestProvideLoggerPort_FxIntegration verifies the provider integrates
// with fx.New as a graph node. Same functional-equivalence contract
// as the LiveManager test — pointer-identity-on-the-wrapper does not
// hold because Manager.LoggerPort() constructs fresh wrappers on each
// call.
func TestProvideLoggerPort_FxIntegration(t *testing.T) {
	t.Parallel()

	logger := testLogger()
	cfg := ManagerConfig{
		Logger:               logger,
		InstrumentsSkipFetch: true,
		DevMode:              true,
	}

	var loggerPort logport.Logger
	var mgrInit *InitializedManager
	fxApp := fxtest.New(t,
		fx.Supply(cfg),
		fx.Supply(fx.Annotate(context.Background(), fx.As(new(context.Context)))),
		fx.Provide(BuildManager),
		fx.Provide(ProvideLoggerPort),
		fx.Populate(&loggerPort, &mgrInit),
	)
	defer fxApp.RequireStart().RequireStop()

	if loggerPort == nil {
		t.Fatal("expected non-nil logport.Logger from fx graph")
	}
	if mgrInit == nil || mgrInit.Manager == nil {
		t.Fatal("expected non-nil InitializedManager from fx graph")
	}

	gotSlog := logport.AsSlog(loggerPort)
	wantSlog := mgrInit.Manager.Logger
	if gotSlog == nil || wantSlog == nil {
		t.Fatalf("expected both wrappers to be slogAdapter variants; got %T and %T", loggerPort, mgrInit.Manager.Logger)
	}
	if gotSlog != wantSlog {
		t.Error("expected graph-resolved Logger and Manager.LoggerPort() to share the same underlying *slog.Logger")
	}
	t.Cleanup(func() { mgrInit.Manager.Shutdown() })
}
