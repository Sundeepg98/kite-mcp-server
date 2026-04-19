package scheduler

import (
	"runtime"
	"testing"
	"time"
)

// leak_sentinel_test.go — guards against goroutine leaks from the
// Scheduler's Start/Stop lifecycle. The scheduler spawns one loop()
// goroutine per Start() call; Stop() closes done which the loop
// selects on and exits. If a refactor ever forgets to close(done) or
// leaves a blocking receive, this sentinel catches the regression.
//
// Pattern mirrors app/leak_sentinel_test.go (no external goleak dep):
// measure NumGoroutine before and after a cycle of Start+Stop calls;
// allow a small tolerance for test-runtime noise (GC helpers, etc.).

// TestGoroutineLeakSentinel_Scheduler verifies that 20 Start()+Stop()
// cycles do not accumulate goroutines. A missing close(done) would
// leak one goroutine per cycle, so delta would be ~20.
func TestGoroutineLeakSentinel_Scheduler(t *testing.T) {
	// Warmup: one cycle to settle lazy runtime workers (time package
	// initializers, etc.) before measuring the baseline.
	warm := New(testLogger())
	warm.SetTickInterval(10 * time.Millisecond)
	warm.Start()
	time.Sleep(20 * time.Millisecond)
	warm.Stop()
	runtime.GC()
	time.Sleep(50 * time.Millisecond)

	baseline := runtime.NumGoroutine()

	const cycles = 20
	for i := 0; i < cycles; i++ {
		s := New(testLogger())
		// Short tick interval so the loop is actually running on the
		// `case <-ticker.C:` path at least once during the cycle.
		s.SetTickInterval(5 * time.Millisecond)
		s.Start()
		// Give the loop a moment to enter its select.
		time.Sleep(10 * time.Millisecond)
		s.Stop()
	}
	runtime.GC()
	time.Sleep(100 * time.Millisecond)
	after := runtime.NumGoroutine()

	delta := after - baseline
	// Tolerance 3 allows for GC helpers and Go runtime noise. Without
	// the Stop path working, delta would be ~20.
	const tolerance = 3
	if delta > tolerance {
		t.Errorf("scheduler goroutine leak: baseline=%d after=%d delta=%d exceeds tolerance=%d",
			baseline, after, delta, tolerance)
	}
}

// TestSchedulerStopIdempotent locks in the double-Stop safety that
// scheduler.Stop() implements via the select-on-done pattern. A refactor
// that removed the `case <-s.done:` branch would panic on the second
// close(done); this test fails loudly instead.
func TestSchedulerStopIdempotent(t *testing.T) {
	s := New(testLogger())
	s.SetTickInterval(5 * time.Millisecond)
	s.Start()
	time.Sleep(10 * time.Millisecond)

	// Triple Stop — must not panic.
	s.Stop()
	s.Stop()
	s.Stop()
}
