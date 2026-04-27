// Package providers contains the Fx provider declarations that
// compose the App's dependency graph.
//
// Wave D Phase 2 Slice P2.2 introduces this package with three leaf
// providers (Logger, AlertDB, AuditStore). Subsequent slices add
// per-domain providers and wire them via fx.New in P2.3.
//
// CONVENTION
//
// Each provider is a function with the signature:
//
//	ProvideX(deps...) (X, error)   // when construction can fail
//	ProvideX(deps...) X            // when construction is infallible
//
// Providers SHOULD NOT call fx.Lifecycle.Append themselves; lifecycle
// hooks are registered by the composition site (P2.3+) so providers
// stay pure functions that are testable in isolation. The lifecycle
// adapter at app/providers/lifecycle.go (P2.3) bridges fx.Lifecycle
// to our existing app.lifecycle.Append pattern.
//
// Provider files map 1:1 to the bounded contexts they serve:
//
//	logger.go       — *slog.Logger (externally supplied)
//	alertdb.go      — *alerts.DB (SQLite handle, possibly nil)
//	audit.go        — *audit.Store (in-memory wrapper, possibly nil)
//	... (P2.4 adds eventdispatcher, riskguard, telegram, scheduler,
//	 middleware, mcpserver)
//
// See .research/wave-d-phase-2-wire-fx-plan.md §6 for the full slice
// plan and Wire-vs-Fx rationale.
package providers

import "log/slog"

// ProvideLogger exposes the externally-supplied *slog.Logger to the
// Fx graph as a typed dependency. The logger is constructed by main.go
// (or a test fixture) and threaded through the App's NewApp constructor
// today; under Phase 2's fx.New composition (P2.3+), it becomes the
// fx.Supply'd seed for the whole graph.
//
// The provider is a plain passthrough — it does NOT validate or wrap
// the logger. Callers that pass nil get nil back; downstream code
// already nil-tolerates the logger via the logport.NewNoop fallback
// (see app.App.Logger).
//
// Why a function provider instead of fx.Supply directly?
//
// Uniformity. Every other dependency in this package surfaces via a
// Provide* function (some with side-effects, some pure). Treating the
// logger the same way makes the provider graph readable as a single
// list of Provide* declarations rather than a mixed Supply+Provide
// composition. The cost is one extra indirection per startup, which
// is negligible.
func ProvideLogger(logger *slog.Logger) *slog.Logger {
	return logger
}
