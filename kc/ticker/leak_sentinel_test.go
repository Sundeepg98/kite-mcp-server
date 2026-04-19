package ticker

import (
	"log/slog"
	"os"
	"testing"

	"go.uber.org/goleak"
)

// leak_sentinel_test.go — goroutine-leak sentinel for the ticker
// package. Forward-looking: Service.New today does not spawn its own
// goroutines (per-user WebSocket goroutines via kiteticker require a
// live broker connection and aren't exercised in unit tests).
//
// Uses go.uber.org/goleak VerifyNone at test end for precise stack
// traces on any leak; replaces the earlier runtime.NumGoroutine-delta
// pattern which required per-cycle warmup sleeps.

func leakTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestGoroutineLeakSentinel_Service verifies that New+Shutdown cycles
// leave no goroutines behind. If a future refactor adds a
// per-Service background goroutine without a matching Shutdown hook,
// goleak.VerifyNone catches it with the exact leaking function.
func TestGoroutineLeakSentinel_Service(t *testing.T) {
	defer goleak.VerifyNone(t,
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
		// Other ticker tests in the same package call Service.Start,
		// which spawns `go func() { t.ServeWithContext(ctx) }()`. The
		// goroutine exits when ctx is cancelled, but under parallel
		// package execution it may outlive the test that spawned it
		// and still be visible to this sentinel's VerifyNone. Ignoring
		// the specific ServeWithContext frame means a real leak in
		// New/Shutdown (this sentinel's contract) still fires.
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).ServeWithContext"),
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).start"),
		goleak.IgnoreAnyFunction("github.com/gorilla/websocket.(*Conn).NextReader"),
		goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
	)
	const cycles = 10
	for i := 0; i < cycles; i++ {
		svc := New(Config{Logger: leakTestLogger()})
		// Touch a read method so the sentinel exercises a real API
		// surface, not just the ctor. IsRunning takes the reader lock
		// and is safe to call on an empty Service.
		_ = svc.IsRunning("nobody@example.com")
		svc.Shutdown()
	}
}

// TestServiceShutdownIdempotent locks in that Shutdown can be called
// multiple times without panic.
func TestServiceShutdownIdempotent(t *testing.T) {
	svc := New(Config{Logger: leakTestLogger()})
	// Triple Shutdown — must not panic.
	svc.Shutdown()
	svc.Shutdown()
	svc.Shutdown()
}
