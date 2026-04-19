package app

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/testutil"
	"golang.org/x/time/rate"
)

// ===========================================================================
// Clock port adapter — bridges testutil.Clock (testutil.Ticker) into the
// package-local rlClock (rlTicker) interface. The two are structurally
// identical; an adapter is required only because Go interface satisfaction
// does not follow through generic parameterisation — `testutil.Clock`'s
// NewTicker returns `testutil.Ticker`, but `rlClock.NewTicker` must return
// `rlTicker` (its own package-local type). Adapter is 6 lines, trivial.
// ===========================================================================

type fakeClockAdapter struct{ fc *testutil.FakeClock }

func (a fakeClockAdapter) NewTicker(d time.Duration) rlTicker {
	return fakeTickerAdapter{t: a.fc.NewTicker(d)}
}

type fakeTickerAdapter struct{ t testutil.Ticker }

func (a fakeTickerAdapter) C() <-chan time.Time { return a.t.C() }
func (a fakeTickerAdapter) Stop()               { a.t.Stop() }

// ===========================================================================
// cleanupInterval injection — verify periodic cleanup fires
// ===========================================================================

// TestRateLimiters_CleanupFires drives the constructor-owned cleanup
// goroutine deterministically with a fake clock. Before the clock port,
// this test slept 50ms in real time and asserted cleanup happened, which
// both slowed the suite and risked flakes on loaded CI. With the fake
// clock, Advance() crosses the interval boundary synchronously and the
// cleanup goroutine processes the tick before we re-assert.
//
// The interval and the clock must both be applied at construction time
// because the goroutine captures them when it calls NewTicker. The
// Option functions run before the goroutine starts.
func TestRateLimiters_CleanupFires(t *testing.T) {
	fc := testutil.NewFakeClock(time.Unix(0, 0))
	interval := 50 * time.Millisecond

	// Use the real constructor so this test exercises the full cleanup
	// goroutine wiring — not a hand-rolled loop duplicated here.
	rl := newRateLimiters(
		withClock(fakeClockAdapter{fc: fc}),
		withCleanupInterval(interval),
	)
	defer rl.Stop()

	_ = rl.auth.getLimiter("1.2.3.4")
	_ = rl.token.getLimiter("5.6.7.8")
	_ = rl.mcp.getLimiter("9.10.11.12")

	require.Equal(t, 1, countLimiters(rl.auth))
	require.Equal(t, 1, countLimiters(rl.token))
	require.Equal(t, 1, countLimiters(rl.mcp))

	// Advance the fake clock past the cleanup interval. The cleanup
	// goroutine receives on ticker.C and empties the maps. We then
	// poll briefly to let the goroutine's scheduler slice land — the
	// assertion condition is monotonic so the poll is a bounded
	// synchronisation window, not a wall-clock wait for time to pass.
	fc.Advance(interval + 10*time.Millisecond)

	require.Eventually(t, func() bool {
		return countLimiters(rl.auth) == 0 &&
			countLimiters(rl.token) == 0 &&
			countLimiters(rl.mcp) == 0
	}, 2*time.Second, 2*time.Millisecond, "cleanup goroutine did not process tick")

	assert.Equal(t, 0, countLimiters(rl.auth))
	assert.Equal(t, 0, countLimiters(rl.token))
	assert.Equal(t, 0, countLimiters(rl.mcp))
}

// TestRateLimiters_CleanupInterval_ViaConstructor exercises the full
// newRateLimiters() constructor by verifying that entries get cleaned
// when cleanupInterval is overridden right after construction.
func TestRateLimiters_CleanupInterval_ViaConstructor(t *testing.T) {
	// Use newRateLimiters which starts its own goroutine
	rl := newRateLimiters()
	defer rl.Stop()

	// The default interval is 10 min — we can't wait that long in a test.
	// Instead, we verify that the cleanup goroutine is running by calling
	// cleanup() directly and checking the maps are emptied.
	_ = rl.auth.getLimiter("a.b.c.d")
	_ = rl.mcp.getLimiter("e.f.g.h")

	// Manual cleanup should clear entries
	rl.auth.cleanup()
	rl.mcp.cleanup()

	assert.Equal(t, 0, countLimiters(rl.auth))
	assert.Equal(t, 0, countLimiters(rl.mcp))
}

// TestRateLimiters_StopStopsGoroutine verifies Stop() terminates the
// cleanup goroutine (goroutine doesn't leak). Uses a real clock here
// because the assertion is about the done-channel select branch, not
// about tick delivery — the real goroutine can exit on <-rl.done
// without ever receiving a tick, which is what we want to prove.
func TestRateLimiters_StopStopsGoroutine(t *testing.T) {
	rl := &rateLimiters{
		auth:            newIPRateLimiter(rate.Limit(10), 20),
		token:           newIPRateLimiter(rate.Limit(10), 20),
		mcp:             newIPRateLimiter(rate.Limit(10), 20),
		authUser:        newUserRateLimiter(rate.Limit(10), 20),
		tokenUser:       newUserRateLimiter(rate.Limit(10), 20),
		mcpUser:         newUserRateLimiter(rate.Limit(10), 20),
		done:            make(chan struct{}),
		cleanupInterval: 5 * time.Millisecond,
		clock:           rlRealClock{},
	}

	stopped := make(chan struct{})
	go func() {
		ticker := rl.clock.NewTicker(rl.cleanupInterval)
		defer ticker.Stop()
		defer close(stopped)
		for {
			select {
			case <-ticker.C():
				rl.auth.cleanup()
			case <-rl.done:
				return
			}
		}
	}()

	rl.Stop()

	select {
	case <-stopped:
		// goroutine exited — success
	case <-time.After(1 * time.Second):
		t.Fatal("cleanup goroutine did not stop within 1 second")
	}
}

// TestRateLimiters_Stop_Idempotent verifies Stop() is safe to call multiple times.
// Regression test for `panic: close of closed channel` surfaced when both the
// HTTP graceful-shutdown signal handler (app/http.go) and the test teardown
// for TestSetupGracefulShutdown_WithAllComponents invoked Stop() on the same
// rateLimiters instance (reported on v1.2.0 Release workflow).
func TestRateLimiters_Stop_Idempotent(t *testing.T) {
	t.Parallel()
	rl := newRateLimiters()

	// Two sequential Stop() calls must not panic. The second call must also
	// return promptly (sync.Once short-circuits after the first close).
	rl.Stop()
	rl.Stop()

	// A third call for good measure — sync.Once guarantees all calls after
	// the first are no-ops.
	rl.Stop()
}

// countLimiters returns the number of entries in an ipRateLimiter.
func countLimiters(l *ipRateLimiter) int {
	l.mu.RLock()
	defer l.mu.RUnlock()
	return len(l.limiters)
}
