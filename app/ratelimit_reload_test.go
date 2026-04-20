package app

import (
	"io"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/mcp"
)

func TestParseRateLimitEnv_Valid(t *testing.T) {
	t.Parallel()

	got, err := parseRateLimitEnv("place_order=5, modify_order=10,cancel_order=25")
	require.NoError(t, err)
	assert.Equal(t, map[string]int{
		"place_order":  5,
		"modify_order": 10,
		"cancel_order": 25,
	}, got)
}

func TestParseRateLimitEnv_Empty(t *testing.T) {
	t.Parallel()

	got, err := parseRateLimitEnv("")
	require.NoError(t, err)
	assert.Nil(t, got, "empty env returns nil map so callers can detect 'unset'")

	got, err = parseRateLimitEnv("   ")
	require.NoError(t, err)
	assert.Nil(t, got)
}

func TestParseRateLimitEnv_Malformed(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		in      string
		errSubs string
	}{
		{"missing equals", "place_order:5", "missing '='"},
		{"empty tool", "=10", "empty tool name"},
		{"non-int limit", "place_order=five", "non-integer"},
		{"negative limit", "place_order=-1", "negative"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parseRateLimitEnv(tc.in)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.errSubs)
		})
	}
}

// TestStartRateLimitReloadLoop_SIGHUPUpdatesLimits proves the SIGHUP
// handler swaps the limiter's caps in response to a real signal. Uses
// a self-directed syscall.Kill to simulate an operator's `kill -HUP`.
//
// Skipped on Windows because syscall.SIGHUP is not supported — the
// signal.Notify call is a platform no-op there (documented in
// ratelimit_reload.go design note).
func TestStartRateLimitReloadLoop_SIGHUPUpdatesLimits(t *testing.T) {
	if _, ok := any(syscall.SIGHUP).(syscall.Signal); !ok {
		t.Skip("SIGHUP not available on this platform")
	}
	// Also skip when running on Windows specifically — signal.Notify for
	// SIGHUP is a no-op and the test cannot meaningfully assert.
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("SIGHUP reload not supported on Windows")
	}

	rl := mcp.NewToolRateLimiter(map[string]int{"place_order": 100})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stopCh := make(chan struct{})
	defer close(stopCh)

	t.Setenv("KITE_RATELIMIT", "place_order=3,modify_order=7")

	sigCh := startRateLimitReloadLoop(rl, logger, stopCh)
	// Send the signal directly into the channel — equivalent to kill -HUP
	// from the operator's perspective and keeps the test independent of
	// the OS signal-delivery timing window.
	sigCh <- syscall.SIGHUP

	// Poll for the swap to land (goroutine runs asynchronously).
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rl.SetLimits(rl.CurrentLimits()) // no-op that doubles as mutex sync
		if cl := rl.CurrentLimits(); cl["place_order"] == 3 && cl["modify_order"] == 7 {
			return // swap landed, test passes
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("SIGHUP reload did not update limits within timeout; got %+v", rl.CurrentLimits())
}

// TestStartRateLimitReloadLoop_StopChanExits proves closing stopCh causes
// the background goroutine to exit cleanly. Regression for Apr-2026 leak
// audit where wire.go fired the loop with a nil stopCh — the goroutine
// then lived for the process lifetime and leaked into every test using
// goleak-style sentinels.
//
// Uses a test-scoped stack-frame count (not NumGoroutine delta) so the
// signal survives concurrent parallel tests that may also spin up their
// own reload loops via RunServer. Records baseline before start so only
// THIS loop's arrival and departure are asserted.
func TestStartRateLimitReloadLoop_StopChanExits(t *testing.T) {
	rl := mcp.NewToolRateLimiter(map[string]int{"place_order": 100})
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stopCh := make(chan struct{})

	baseline := countLoopGoroutines()
	_ = startRateLimitReloadLoop(rl, logger, stopCh)
	require.Eventually(t, func() bool {
		return countLoopGoroutines() > baseline
	}, 2*time.Second, 5*time.Millisecond, "loop goroutine should be visible after start")

	close(stopCh)

	require.Eventually(t, func() bool {
		return countLoopGoroutines() <= baseline
	}, 2*time.Second, 5*time.Millisecond, "loop goroutine should exit after stopCh close")
}

// countLoopGoroutines returns the number of goroutines whose current
// stack contains the signature of startRateLimitReloadLoop's closure.
// Parallel-safe relative-count variant — absolute value can fluctuate
// because other parallel tests create their own reload loops via
// RunServer.
func countLoopGoroutines() int {
	buf := make([]byte, 1<<16)
	n := runtime.Stack(buf, true)
	stacks := string(buf[:n])
	// The goroutine runs an anonymous closure inside
	// startRateLimitReloadLoop — its frame always contains the
	// function name.
	return strings.Count(stacks, "app.startRateLimitReloadLoop.func1")
}

// TestApp_StopRateLimitReload_Idempotent verifies the App helper that
// closes rateLimitReloadStop is safe to call multiple times. Both the
// graceful-shutdown path and cleanupInitializeServices call it, so a
// full integration test path ends up double-calling.
func TestApp_StopRateLimitReload_Idempotent(t *testing.T) {
	t.Parallel()

	app := &App{rateLimitReloadStop: make(chan struct{})}
	// Four calls — any of these panicking ("close of closed channel")
	// would fail the test and flag the regression.
	app.stopRateLimitReload()
	app.stopRateLimitReload()
	app.stopRateLimitReload()
	app.stopRateLimitReload()

	// Channel must actually be closed.
	select {
	case _, ok := <-app.rateLimitReloadStop:
		assert.False(t, ok, "rateLimitReloadStop should be closed after stopRateLimitReload")
	default:
		t.Fatal("rateLimitReloadStop should be closed; read blocked")
	}
}

// TestApp_StopRateLimitReload_NilChannel verifies the helper is a safe
// no-op when rateLimitReloadStop was never initialized (e.g., tests that
// construct an App directly without calling wire.go).
func TestApp_StopRateLimitReload_NilChannel(t *testing.T) {
	t.Parallel()

	app := &App{}
	// Must not panic.
	app.stopRateLimitReload()
}
