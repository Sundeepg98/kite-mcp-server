package alerts

import (
	"testing"

	"go.uber.org/goleak"
)

// leak_sentinel_test.go — forward-looking goroutine-leak sentinel for
// the alerts package. Today NewStore + NewEvaluator do not spawn any
// background goroutines; the Store is purely in-memory with optional
// write-through DB persistence, and the Evaluator is a pure function
// over the Store (no ticker, no watcher loop).
//
// This sentinel guards against future refactors that add a background
// goroutine (e.g. a periodic evaluator tick, a change-feed watcher,
// an SSE broadcaster fan-out) without a matching Stop/Shutdown hook.
// goleak's stack-trace output pinpoints the exact function that
// leaked, making the regression immediately fixable.
//
// Pattern note: earlier packages (scheduler, audit, ticker) used a
// delta-NumGoroutine pattern with no external dep. This batch uses
// go.uber.org/goleak explicitly per the orchestrator brief — the
// richer failure output is worth the single indirect dep that goleak
// adds.

// TestGoroutineLeakSentinel_Alerts verifies that building an alerts
// Store (the canonical construction path) does not leak goroutines.
// Passing the fresh goleak baseline means: whatever finalizer /
// background workers the runtime has at this point, our construction
// added zero.
func TestGoroutineLeakSentinel_Alerts(t *testing.T) {
	defer goleak.VerifyNone(t,
		// SQLite (modernc.org/sqlite) spawns connection-pool goroutines
		// per *alerts.DB; in-memory DBs that remain open for t.Cleanup
		// duration legitimately keep those alive.
		goleak.IgnoreTopFunction("database/sql.(*DB).connectionOpener"),
		goleak.IgnoreTopFunction("database/sql.(*DB).connectionResetter"),
	)

	// Build 10 stores with varying callbacks. None should spawn a
	// background goroutine today.
	for i := 0; i < 10; i++ {
		_ = NewStore(nil) // nil callback — no notification path
		_ = NewStore(func(a *Alert, price float64) {
			// User-supplied callback; the Store must not invoke it
			// from a background goroutine on construction.
			_ = a
			_ = price
		})
	}
}
