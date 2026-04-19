package scheduler

import (
	"testing"
	"time"

	"go.uber.org/goleak"
)

// leak_sentinel_test.go — goroutine-leak sentinel for the scheduler
// package. Uses go.uber.org/goleak VerifyNone at test end to get
// precise stack traces on any leak; replaces the earlier
// runtime.NumGoroutine-delta pattern which only produced a count and
// required per-cycle warmup sleeps for stable baseline.
//
// Scheduler.Start spawns one loop() goroutine; Stop closes s.done
// which the loop selects on and exits. A refactor that drops the
// close would leak one goroutine per cycle — goleak.VerifyNone
// catches this immediately with the exact function that leaked.

// TestGoroutineLeakSentinel_Scheduler verifies that 10 Start+Stop
// cycles leave no goroutines behind. Runs considerably fewer cycles
// than the prior NumGoroutine implementation because goleak is a
// strict equality check, not a tolerance range — any survivor
// triggers failure.
func TestGoroutineLeakSentinel_Scheduler(t *testing.T) {
	defer goleak.VerifyNone(t,
		// testing framework helpers left by t.Parallel and package
		// init live forever — filter them out.
		goleak.IgnoreTopFunction("testing.(*T).Parallel"),
	)
	const cycles = 10
	for i := 0; i < cycles; i++ {
		s := New(testLogger())
		s.SetTickInterval(5 * time.Millisecond)
		s.Start()
		s.Stop() // Stop blocks until the loop goroutine exits
	}
}

// TestSchedulerStopIdempotent locks in the double-Stop safety that
// scheduler.Stop() implements via the select-on-done pattern.
func TestSchedulerStopIdempotent(t *testing.T) {
	s := New(testLogger())
	s.SetTickInterval(5 * time.Millisecond)
	s.Start()
	// Triple Stop — must not panic.
	s.Stop()
	s.Stop()
	s.Stop()
}
