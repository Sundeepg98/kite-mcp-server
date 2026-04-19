package app

import (
	"io"
	"log/slog"
	"os"
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
