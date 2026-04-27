package providers

import (
	"context"
	"fmt"
	"sync"

	"go.uber.org/fx"
)

// lifecycle.go bridges Fx's fx.Lifecycle interface to the App's
// existing *app.LifecycleManager. Wave D Phase 2 Slice P2.3a.
//
// PROBLEM
//
// Fx's lifecycle model is symmetric: Hook{OnStart, OnStop} pairs
// register at graph-construction time, OnStart runs at fx.App.Start,
// OnStop runs at fx.App.Stop in REVERSE registration order.
//
// Our existing app.LifecycleManager is asymmetric: services
// construct + initialize inline (legacy wire.go pattern), then
// register a stop function via Append(name, fn). Shutdown runs
// stops in APPEND order (forward).
//
// The two patterns conflict in three ways:
//   1. Symmetric vs. asymmetric: Fx wants both OnStart + OnStop;
//      LifecycleManager only handles OnStop.
//   2. Reverse vs. forward order: shutdowns run in opposite directions.
//   3. Lifecycle ownership: under fx.App, Start/Stop is the public
//      API; under our App, main.go's signal handler triggers
//      LifecycleManager.Shutdown() directly.
//
// SOLUTION
//
// FxLifecycleAdapter is a hybrid that:
//   - Implements fx.Lifecycle so providers can call lc.Append(Hook{...})
//     idiomatically.
//   - On Hook receipt, runs OnStart SYNCHRONOUSLY at Append time
//     (preserving legacy "constructor returns means initialized"
//     contract). Errors are captured via Err().
//   - On Hook receipt, registers Hook.OnStop with the wrapped
//     LifecycleAppender (typically *app.LifecycleManager) using a
//     synthesized name like "fx-test-bridge-2" that's stable for log
//     correlation. Order semantics defer to the LifecycleAppender's
//     existing contract (forward order in our case).
//   - Does NOT participate in fx.App.Start/Stop. We never call those.
//     The adapter is used ONLY as a graph-resolution-time bridge.
//
// CONSEQUENCE
//
// Phase 2 uses Fx as a "wire-only" tool: we construct a graph, let
// providers run, register lifecycle hooks via the adapter, then drop
// the fx.App handle. Shutdown coordination stays with the existing
// LifecycleManager. This keeps the existing graceful-shutdown signal
// path unchanged — main.go and lifecycle_test.go don't have to learn
// fx.App semantics.
//
// COST
//
// We give up Fx's reverse-order shutdown (would need refactoring
// LifecycleManager). For audit-chain wiring (P2.3b), the order
// difference doesn't matter: each subsystem registers its own stop
// independent of others. If we later need cross-domain reverse-order
// shutdown semantics, this adapter can be extended (e.g., a
// reorderingLifecycleAppender that buffers and reverses).

// LifecycleAppender is the narrow contract the FxLifecycleAdapter
// requires from its host. *app.LifecycleManager satisfies this; tests
// supply a fake.
type LifecycleAppender interface {
	Append(name string, fn func() error)
}

// FxLifecycleAdapter satisfies fx.Lifecycle while delegating to a
// LifecycleAppender for OnStop coordination.
type FxLifecycleAdapter struct {
	prefix string
	mgr    LifecycleAppender

	mu      sync.Mutex
	counter int
	startEr error // first OnStart error, sticky
}

// Compile-time check: adapter satisfies fx.Lifecycle.
var _ fx.Lifecycle = (*FxLifecycleAdapter)(nil)

// NewFxLifecycleAdapter constructs a bridge for the given manager.
// The prefix is prepended to synthesized hook names ("audit", "kc")
// so log entries can be correlated to the originating provider set.
//
// mgr is typically the App's *LifecycleManager; tests supply a fake.
// Passing a nil mgr is permitted — the adapter swallows OnStop hooks
// silently. (This makes fx-graph tests that don't need real shutdown
// trivial to write; they construct an adapter with nil mgr and only
// observe OnStart side-effects.)
func NewFxLifecycleAdapter(prefix string, mgr LifecycleAppender) *FxLifecycleAdapter {
	return &FxLifecycleAdapter{prefix: prefix, mgr: mgr}
}

// Append implements fx.Lifecycle. Per the doc-comment design:
//
//   - OnStart runs synchronously RIGHT NOW. If it returns an error,
//     the error is captured (sticky — only the first error is kept)
//     and OnStop is NOT registered (the resource never initialized
//     so there's nothing to tear down).
//   - OnStop is registered with the wrapped LifecycleAppender via a
//     synthesized name "{prefix}-{counter}".
//
// Concurrent calls to Append are serialized via the adapter's mutex.
func (a *FxLifecycleAdapter) Append(h fx.Hook) {
	a.mu.Lock()
	defer a.mu.Unlock()

	// If a prior OnStart already errored, refuse to wire further
	// hooks — the graph is in a half-initialized state and forward
	// progress is unsafe. This mirrors fx.App's own short-circuit
	// where a startup error propagates.
	if a.startEr != nil {
		return
	}

	a.counter++
	name := fmt.Sprintf("%s-%d", a.prefix, a.counter)

	if h.OnStart != nil {
		if err := h.OnStart(context.Background()); err != nil {
			a.startEr = fmt.Errorf("fx hook %q OnStart: %w", name, err)
			return
		}
	}

	if h.OnStop != nil && a.mgr != nil {
		// Wrap OnStop in a func() error closure so the manager's
		// signature is satisfied. ctx.Background() is used because
		// the existing LifecycleManager has no ctx propagation.
		// Future shutdown-deadline support can flow ctx in here.
		fn := h.OnStop
		a.mgr.Append(name, func() error {
			return fn(context.Background())
		})
	}
}

// Err returns the first OnStart error captured, or nil.
//
// Composition sites call this AFTER fx.New(...) to detect failed
// providers. Once Err() returns non-nil, the graph is partially
// constructed and the application MUST NOT proceed — the calling
// code should log + return the error and let the lifecycle's
// already-registered OnStops run via the host's normal shutdown
// path (deferred LifecycleManager.Shutdown).
func (a *FxLifecycleAdapter) Err() error {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.startEr
}
