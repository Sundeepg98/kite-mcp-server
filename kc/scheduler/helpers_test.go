package scheduler

import (
	"sync/atomic"
	"testing"
	"time"
)

// helpers_test.go — shared test helpers for the scheduler package.
//
// Rationale: scheduler tick() spawns task fns in goroutines for panic
// isolation (scheduler.go line 187). Tests historically used
// time.Sleep(20ms) + atomic-load to wait for the goroutine to run.
// Those fixed sleeps slowed the suite and introduced race-on-busy-CI
// flakes — this file replaces the pattern with deterministic polling
// for positive assertions and a short fixed wait for negative ones.

// pollCount blocks until counter.Load() == want, or fails the test at
// the supplied budget. Used in place of:
//
//	time.Sleep(20 * time.Millisecond)
//	if counter.Load() != want { t.Fatal(...) }
//
// Typical wall-clock: 0-5ms (the goroutine usually lands within one
// scheduler quantum). Budget default: 500ms covers slow CI runners.
func pollCount(t *testing.T, counter *atomic.Int32, want int32, msg string) {
	t.Helper()
	pollCountWithin(t, counter, want, 500*time.Millisecond, msg)
}

// pollCountWithin is the configurable variant; most callers should use
// pollCount.
func pollCountWithin(t *testing.T, counter *atomic.Int32, want int32, budget time.Duration, msg string) {
	t.Helper()
	deadline := time.Now().Add(budget)
	for {
		if counter.Load() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s: counter=%d, want=%d after %v", msg, counter.Load(), want, budget)
		}
		time.Sleep(time.Millisecond)
	}
}

// ensureNoIncrement asserts that within the supplied window, counter
// does NOT exceed want. Used for "task should NOT run" assertions
// (weekend / holiday / wrong-time ticks). A short window is enough
// because the tick itself is synchronous and any goroutine it would
// have spawned runs immediately or not at all — 20ms is a generous
// safety margin for scheduler busy time.
//
// If an assertion needs a tighter bound, use a specific shorter window.
func ensureNoIncrement(t *testing.T, counter *atomic.Int32, want int32, msg string) {
	t.Helper()
	ensureNoIncrementWithin(t, counter, want, 20*time.Millisecond, msg)
}

// ensureNoIncrementWithin is the configurable variant.
func ensureNoIncrementWithin(t *testing.T, counter *atomic.Int32, want int32, window time.Duration, msg string) {
	t.Helper()
	// Brief wait + final check. This is the inherently-racy "prove a
	// negative" case; we accept the small time cost in exchange for
	// test clarity.
	time.Sleep(window)
	if got := counter.Load(); got != want {
		t.Fatalf("%s: counter=%d, want=%d", msg, got, want)
	}
}
