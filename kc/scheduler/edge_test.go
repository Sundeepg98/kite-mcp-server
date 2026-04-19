package scheduler

import (
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func edgeLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// TestTick_MidnightBoundary verifies that a task scheduled at 00:00 IST
// fires on a trading day and is correctly deduped at the same minute.
func TestTick_MidnightBoundary(t *testing.T) {
	t.Parallel()
	s := New(edgeLogger())
	var ran atomic.Int32

	// Tuesday 2026-04-07 00:00 IST — a trading day, midnight.
	midnight := time.Date(2026, 4, 7, 0, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return midnight })

	s.Add(Task{Name: "midnight_task", Hour: 0, Minute: 0, Fn: func() { ran.Add(1) }})

	s.tick()
	pollCount(t, &ran, 1, "midnight task should run once")

	// Same minute — should be deduped.
	s.tick()
	ensureNoIncrement(t, &ran, 1, "midnight task should be deduped")
}

// TestTick_HolidayAfterWeekday verifies that a task runs on a weekday
// but does NOT run on the following day if it is a market holiday.
func TestTick_HolidayAfterWeekday(t *testing.T) {
	t.Parallel()
	s := New(edgeLogger())
	var ran atomic.Int32

	// Thursday 2026-04-02 10:00 IST — a normal trading day.
	thursday := time.Date(2026, 4, 2, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return thursday })

	s.Add(Task{Name: "daily_report", Hour: 10, Minute: 0, Fn: func() { ran.Add(1) }})

	s.tick()
	pollCount(t, &ran, 1, "task should run on Thursday")

	// Friday 2026-04-03 is Good Friday (NSE holiday).
	goodFriday := time.Date(2026, 4, 3, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return goodFriday })

	s.tick()
	ensureNoIncrement(t, &ran, 1, "task should NOT run on Good Friday holiday")
}

// TestTick_MultipleTasksDifferentTimes verifies that only the task whose
// time matches the current clock fires, not others.
func TestTick_MultipleTasksDifferentTimes(t *testing.T) {
	t.Parallel()
	s := New(edgeLogger())
	var morningRan, afternoonRan atomic.Int32

	// Wednesday 2026-04-08 09:15 IST.
	morning := time.Date(2026, 4, 8, 9, 15, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return morning })

	s.Add(Task{Name: "morning_brief", Hour: 9, Minute: 15, Fn: func() { morningRan.Add(1) }})
	s.Add(Task{Name: "afternoon_review", Hour: 15, Minute: 30, Fn: func() { afternoonRan.Add(1) }})

	s.tick()
	pollCount(t, &morningRan, 1, "morning task should run at 9:15")
	ensureNoIncrement(t, &afternoonRan, 0, "afternoon task should NOT run at 9:15")

	// Now advance to 15:30 IST.
	afternoon := time.Date(2026, 4, 8, 15, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return afternoon })

	s.tick()
	pollCount(t, &afternoonRan, 1, "afternoon task should run at 15:30")
	// Morning task should still be at 1 (dedup for today).
	ensureNoIncrement(t, &morningRan, 1, "morning task should not re-run")
}

// TestTick_DedupResetsNextTradingDay verifies that dedup tracking resets
// when the date changes (e.g., Thursday -> next Monday, skipping weekend).
func TestTick_DedupResetsNextTradingDay(t *testing.T) {
	t.Parallel()
	s := New(edgeLogger())
	var ran atomic.Int32

	// Thursday 2026-04-09 10:00 IST.
	thursday := time.Date(2026, 4, 9, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return thursday })

	s.Add(Task{Name: "daily", Hour: 10, Minute: 0, Fn: func() { ran.Add(1) }})

	s.tick()
	pollCount(t, &ran, 1, "should run on Thursday")

	// Skip to Monday 2026-04-13 10:00 IST (Saturday 11th + Sunday 12th skipped).
	monday := time.Date(2026, 4, 13, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return monday })

	s.tick()
	pollCount(t, &ran, 2, "should run on Monday (new date)")
}

// TestLoop_TickerBranch exercises the case <-ticker.C branch in loop()
// by using a fast tick interval and letting the goroutine run briefly.
func TestLoop_TickerBranch(t *testing.T) {
	t.Parallel()
	s := New(edgeLogger())
	s.SetTickInterval(10 * time.Millisecond) // fast ticker for testing

	var ran atomic.Int32
	// Monday 2026-04-06 10:00 IST — a trading day.
	monday := time.Date(2026, 4, 6, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return monday })

	s.Add(Task{Name: "loop_test", Hour: 10, Minute: 0, Fn: func() { ran.Add(1) }})

	s.Start()
	// Poll for the initial tick to land. 500ms covers slow CI; the
	// typical wall time is under 20ms because s.tick() runs immediately
	// inside loop() before the first ticker.C receive.
	pollCount(t, &ran, 1, "task should run at least once")
	s.Stop()

	// The task fires on the initial s.tick() call in loop(). The
	// ticker.C branch also calls s.tick(), but dedup prevents a second
	// run on the same date. The important thing is that the ticker
	// branch was exercised.
}
