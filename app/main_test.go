package app

import (
	"os"
	"testing"

	"github.com/zerodha/kite-mcp-server/mcp"
	"go.uber.org/goleak"
)

// main_test.go — package-level goroutine-leak guard for the app package.
//
// TestMain runs all tests, shuts down shared package-level singletons
// (mcp.ltpCache), then runs goleak.Find(). Every test's t.Cleanup
// handlers have run at that point; any goroutine still alive is a real
// leak — not parallel-test interference.
//
// Apr-2026 Round 4 fixes that unblocked this migration:
//   - SessionRegistry.StopCleanupRoutine now blocks on a WaitGroup.
//   - ToolCache.Close() + mcp.ShutdownLtpCache helper.
//   - app.rateLimiters.Stop() waits on cleanupDone.
//   - startRateLimitReloadLoop returns doneCh; stopRateLimitReload joins.
//   - startStdIOServer uses context.WithCancel tied to shutdownCh.
//   - newTestApp pre-wires app.shutdownCh and closes on Cleanup.
//   - Every app/*_test.go site that constructs rateLimiters / audit.Store
//     / instruments.Manager directly now registers t.Cleanup with the
//     appropriate Stop / Shutdown method.
//
// Ignore list covers only 3rd-party SDK goroutines that have no
// user-facing Close hook. Nothing from kite-mcp-server itself.
func TestMain(m *testing.M) {
	code := m.Run()
	// Shut down mcp package singletons before goleak inspects so the
	// ltpCache cleanup ticker doesn't show as a leak.
	mcp.ShutdownLtpCache()
	if code != 0 {
		os.Exit(code)
	}
	if err := goleak.Find(
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
		// net/http HTTP/2 and HTTP/1.1 keep-alive pools — Stripe SDK
		// and test probe clients both hit these. Idle-timeout bounded,
		// not leak-bounded.
		goleak.IgnoreAnyFunction("net/http.(*http2ClientConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).readLoop"),
		goleak.IgnoreAnyFunction("net/http.(*persistConn).writeLoop"),
		// gokiteconnect WebSocket ticker goroutines — same rationale as
		// kc/ticker/leak_sentinel_test.go.
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).ServeWithContext"),
		goleak.IgnoreAnyFunction("github.com/zerodha/gokiteconnect/v4/ticker.(*Ticker).start"),
		goleak.IgnoreAnyFunction("github.com/gorilla/websocket.(*Conn).NextReader"),
	); err != nil {
		println("goleak: errors on successful test run:")
		println(err.Error())
		os.Exit(1)
	}
}
