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
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("midnight task should run once, ran %d", ran.Load())
	}

	// Same minute — should be deduped.
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("midnight task should be deduped, ran %d", ran.Load())
	}
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
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("task should run on Thursday, ran %d", ran.Load())
	}

	// Friday 2026-04-03 is Good Friday (NSE holiday).
	goodFriday := time.Date(2026, 4, 3, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return goodFriday })

	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("task should NOT run on Good Friday holiday, ran %d", ran.Load())
	}
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
	time.Sleep(20 * time.Millisecond)

	if morningRan.Load() != 1 {
		t.Fatalf("morning task should run at 9:15, ran %d", morningRan.Load())
	}
	if afternoonRan.Load() != 0 {
		t.Fatalf("afternoon task should NOT run at 9:15, ran %d", afternoonRan.Load())
	}

	// Now advance to 15:30 IST.
	afternoon := time.Date(2026, 4, 8, 15, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return afternoon })

	s.tick()
	time.Sleep(20 * time.Millisecond)

	if afternoonRan.Load() != 1 {
		t.Fatalf("afternoon task should run at 15:30, ran %d", afternoonRan.Load())
	}
	// Morning task should still be at 1 (dedup for today).
	if morningRan.Load() != 1 {
		t.Fatalf("morning task should not re-run, ran %d", morningRan.Load())
	}
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
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("should run on Thursday, ran %d", ran.Load())
	}

	// Skip to Monday 2026-04-13 10:00 IST (Saturday 11th + Sunday 12th skipped).
	monday := time.Date(2026, 4, 13, 10, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return monday })

	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 2 {
		t.Fatalf("should run on Monday (new date), ran %d", ran.Load())
	}
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
	// Wait long enough for the initial tick + at least one ticker.C tick.
	time.Sleep(80 * time.Millisecond)
	s.Stop()

	// The task fires on the initial s.tick() call in loop().
	// The ticker.C branch also calls s.tick(), but dedup prevents a second run
	// on the same date. The important thing is that the ticker branch was exercised.
	if ran.Load() < 1 {
		t.Fatalf("task should run at least once, ran %d", ran.Load())
	}
}
