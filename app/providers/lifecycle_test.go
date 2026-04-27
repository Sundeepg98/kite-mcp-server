package providers

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"go.uber.org/fx"
)

// TestNewLifecycleAdapter_OnStartRuns verifies that hooks registered
// via the adapter run their OnStart functions when fx.New starts the
// app. This is the foundation for P2.3b: providers that need to
// initialize at startup (audit InitTable, hash-publisher Start) will
// use OnStart.
func TestNewLifecycleAdapter_OnStartRuns(t *testing.T) {
	t.Parallel()

	var startCalled atomic.Int32

	app := fx.New(
		fx.NopLogger,
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{
				OnStart: func(_ context.Context) error {
					startCalled.Add(1)
					return nil
				},
			})
		}),
	)
	if err := app.Err(); err != nil {
		t.Fatalf("fx.New error: %v", err)
	}

	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("app.Start error: %v", err)
	}
	if got := startCalled.Load(); got != 1 {
		t.Errorf("OnStart called %d times, want 1", got)
	}
	if err := app.Stop(context.Background()); err != nil {
		t.Fatalf("app.Stop error: %v", err)
	}
}

// TestNewLifecycleAdapter_OnStopRuns_ReverseOrder verifies that
// OnStop hooks run in REVERSE order of registration. This matches
// our existing app.LifecycleManager append-order-then-shutdown
// behaviour where the LAST registered stop runs FIRST (services
// teardown is the inverse of bring-up). Critically: this matches
// Fx's native semantics so the adapter doesn't have to re-order.
//
// (Implementation note: app.LifecycleManager actually runs stops in
// APPEND ORDER, not reverse. Fx runs OnStop in REVERSE order. This
// test pins the Fx behaviour we'll observe; the lifecycle adapter
// in P2.3b's audit-chain wiring must reconcile the two. For P2.3a,
// we just document Fx's own behaviour.)
func TestNewLifecycleAdapter_OnStopRuns_ReverseOrder(t *testing.T) {
	t.Parallel()

	var order []string

	app := fx.New(
		fx.NopLogger,
		fx.Invoke(func(lc fx.Lifecycle) {
			lc.Append(fx.Hook{
				OnStop: func(_ context.Context) error {
					order = append(order, "first-registered")
					return nil
				},
			})
			lc.Append(fx.Hook{
				OnStop: func(_ context.Context) error {
					order = append(order, "second-registered")
					return nil
				},
			})
		}),
	)
	if err := app.Err(); err != nil {
		t.Fatalf("fx.New error: %v", err)
	}
	if err := app.Start(context.Background()); err != nil {
		t.Fatalf("app.Start error: %v", err)
	}
	if err := app.Stop(context.Background()); err != nil {
		t.Fatalf("app.Stop error: %v", err)
	}

	if len(order) != 2 {
		t.Fatalf("expected 2 OnStop calls, got %d", len(order))
	}
	if order[0] != "second-registered" {
		t.Errorf("expected reverse order; got %v", order)
	}
}

// TestBridgeFxToAppLifecycle_OnStopFlowsToManager verifies the
// adapter's core promise: a hook registered via the Fx Lifecycle
// also gets registered with our app.LifecycleManager so the existing
// shutdown-coordination machinery (graceful HTTP drain, error-path
// defer, sync.Once idempotency) keeps working.
//
// This is the load-bearing test for P2.3a: P2.3b will rely on this
// bridge so audit-store Stop() runs whether shutdown is initiated
// by Fx (e.g., test) or by SIGINT (production graceful path).
func TestBridgeFxToAppLifecycle_OnStopFlowsToManager(t *testing.T) {
	t.Parallel()

	// Track that OnStop ran via the existing manager path, not via
	// fx.App.Stop. We do this by having the adapter NOT call OnStop
	// itself — instead it registers OnStop with the manager, and
	// manager.Shutdown() is what actually fires it.
	var managerStopRan atomic.Bool

	// Construct an adapter wired to a manager. The adapter's
	// fx.Lifecycle method receives Hook.OnStop and forwards it to
	// manager.Append("hook-N", OnStop).
	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("test-bridge", mgr)

	adapter.Append(fx.Hook{
		OnStop: func(_ context.Context) error {
			managerStopRan.Store(true)
			return nil
		},
	})

	// Adapter should have registered the OnStop with the manager.
	// Triggering manager.Shutdown should fire the OnStop callback
	// via the manager's existing chain (NOT via fx.App.Stop).
	mgr.Shutdown()

	if !managerStopRan.Load() {
		t.Error("OnStop did not run via manager.Shutdown()")
	}
}

// TestBridgeFxToAppLifecycle_OnStartFiresImmediately verifies that
// the adapter runs OnStart synchronously at Append-time (matching
// the legacy "construct + initialize inline" pattern in wire.go)
// rather than deferring to a separate fx.App.Start invocation.
//
// Why? Because our App is NOT going to be a full fx.App that calls
// Start/Stop. Instead, P2.3b's beachhead uses Fx purely as a graph
// resolver: dependencies wire up, providers are invoked, OnStart
// runs as part of the graph-resolution step. The legacy code expects
// "by the time NewWithOptions returns, audit InitTable has been
// called" — preserving that contract is non-negotiable.
//
// The adapter therefore runs OnStart inline at Append() time. If
// OnStart returns an error, Append captures it and a subsequent
// adapter.Err() call surfaces it for the composition site to
// fail-fast on.
func TestBridgeFxToAppLifecycle_OnStartFiresImmediately(t *testing.T) {
	t.Parallel()

	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("test-onstart", mgr)

	var startCalled atomic.Bool
	adapter.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			startCalled.Store(true)
			return nil
		},
	})

	if !startCalled.Load() {
		t.Error("OnStart did not fire synchronously at Append time")
	}
	if err := adapter.Err(); err != nil {
		t.Errorf("unexpected adapter error: %v", err)
	}
}

// TestBridgeFxToAppLifecycle_OnStartError_Captured verifies that an
// OnStart error is captured by the adapter and surfaced via Err().
// Composition sites use this to fail-fast: after building the Fx
// graph, check adapter.Err() and abort if a startup hook errored.
func TestBridgeFxToAppLifecycle_OnStartError_Captured(t *testing.T) {
	t.Parallel()

	mgr := newTestLifecycleManager(t)
	adapter := NewFxLifecycleAdapter("test-onstart-err", mgr)

	wantErr := errors.New("startup boom")
	adapter.Append(fx.Hook{
		OnStart: func(_ context.Context) error {
			return wantErr
		},
	})

	gotErr := adapter.Err()
	if gotErr == nil {
		t.Fatal("expected captured error, got nil")
	}
	if !errors.Is(gotErr, wantErr) {
		t.Errorf("expected wrapped wantErr, got %v", gotErr)
	}
}

// newTestLifecycleManager mirrors app.NewLifecycleManager(testLogger())
// but lives in this package's test file to avoid an import cycle
// with the app package. The adapter's manager parameter is typed as
// LifecycleAppender (a narrow interface) so tests can supply this
// shim and production wiring (P2.3b) supplies *app.LifecycleManager.
func newTestLifecycleManager(t *testing.T) *fakeLifecycleManager {
	t.Helper()
	return &fakeLifecycleManager{}
}

// fakeLifecycleManager implements LifecycleAppender for tests.
// It records appended hooks and runs them on Shutdown in append
// order (matching the production *app.LifecycleManager contract).
type fakeLifecycleManager struct {
	stops []func() error
}

func (m *fakeLifecycleManager) Append(_ string, fn func() error) {
	if fn == nil {
		return
	}
	m.stops = append(m.stops, fn)
}

func (m *fakeLifecycleManager) Shutdown() {
	for _, fn := range m.stops {
		_ = fn()
	}
}
