package ticker

import (
	"log/slog"
	"os"
	"runtime"
	"testing"
	"time"
)

// leak_sentinel_test.go — guards against goroutine leaks from Service's
// New/Shutdown lifecycle. Today New() does not spawn goroutines (each
// Start(email) starts a per-user WebSocket goroutine via the external
// kiteticker library, which requires a live broker connection and is
// not exercised here). Shutdown cancels every user's context.
//
// This sentinel is a forward-looking guard: if a refactor ever adds a
// background goroutine to the Service itself (e.g. a health-check
// goroutine, a global reconnect supervisor, a cross-user tick fanout),
// the delta-of-NumGoroutine assertion will catch a missing cleanup
// path before it ships.
//
// Pattern mirrors app/leak_sentinel_test.go (no external goleak dep).

func leakTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestGoroutineLeakSentinel_Service verifies that 20 New()+Shutdown()
// cycles do not accumulate goroutines beyond test-runtime noise. If a
// future refactor adds a per-Service background goroutine without a
// matching Shutdown hook, delta will grow by one per cycle.
func TestGoroutineLeakSentinel_Service(t *testing.T) {
	// Warmup: one construct/shutdown pair to settle lazy package init.
	warm := New(Config{Logger: leakTestLogger()})
	warm.Shutdown()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	baseline := runtime.NumGoroutine()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		svc := New(Config{Logger: leakTestLogger()})
		// Touch a read method so the sentinel exercises a real API
		// surface, not just the ctor. IsRunning takes the reader lock
		// and is safe to call on an empty Service.
		_ = svc.IsRunning("nobody@example.com")
		svc.Shutdown()
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	delta := after - baseline
	// Tolerance 3 for GC helpers / test runtime noise. If a future
	// refactor adds a leaky background goroutine to the Service
	// constructor, delta will climb to ~20.
	const tolerance = 3
	if delta > tolerance {
		t.Errorf("ticker Service goroutine leak: baseline=%d after=%d delta=%d exceeds tolerance=%d",
			baseline, after, delta, tolerance)
	}
}

// TestServiceShutdownIdempotent locks in that Shutdown can be called
// multiple times without panic. Today Shutdown just clears a map
// under mu; a refactor that added channel close() calls without a
// sync.Once guard would break this contract silently.
func TestServiceShutdownIdempotent(t *testing.T) {
	svc := New(Config{Logger: leakTestLogger()})
	// Triple Shutdown — must not panic.
	svc.Shutdown()
	svc.Shutdown()
	svc.Shutdown()
}
