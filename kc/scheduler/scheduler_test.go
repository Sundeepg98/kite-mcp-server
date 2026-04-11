package scheduler

import (
	"log/slog"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

func TestNew(t *testing.T) {
	s := New(testLogger())
	if s == nil {
		t.Fatal("New returned nil")
	}
	if s.lastRun == nil {
		t.Fatal("lastRun map not initialized")
	}
}

func TestAddTask(t *testing.T) {
	s := New(testLogger())
	s.Add(Task{Name: "test", Hour: 9, Minute: 0, Fn: func() {}})
	if len(s.tasks) != 1 {
		t.Fatalf("expected 1 task, got %d", len(s.tasks))
	}
	if s.tasks[0].Name != "test" {
		t.Fatalf("expected task name 'test', got %q", s.tasks[0].Name)
	}
}

func TestStartStop(t *testing.T) {
	s := New(testLogger())
	s.Add(Task{Name: "noop", Hour: 99, Minute: 99, Fn: func() {}})
	s.Start()
	// Give the goroutine time to start.
	time.Sleep(50 * time.Millisecond)
	s.Stop()
	// Double stop should not panic.
	s.Stop()
}

func TestTickSkipsWeekend(t *testing.T) {
	s := New(testLogger())
	var called atomic.Int32
	s.Add(Task{Name: "weekend_test", Hour: 10, Minute: 0, Fn: func() { called.Add(1) }})

	// Inject Saturday 10:00 AM IST.
	sat := time.Date(2026, 4, 4, 10, 0, 0, 0, kolkataLoc) // Saturday
	s.SetClock(func() time.Time { return sat })
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if called.Load() != 0 {
		t.Fatal("task should NOT run on Saturday")
	}

	// Inject Sunday 10:00 AM IST.
	sun := time.Date(2026, 4, 5, 10, 0, 0, 0, kolkataLoc) // Sunday
	s.SetClock(func() time.Time { return sun })
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if called.Load() != 0 {
		t.Fatal("task should NOT run on Sunday")
	}

	// Verify the helper recognises weekends.
	if !IsWeekend(sat) {
		t.Error("Saturday should be weekend")
	}
	if !IsWeekend(sun) {
		t.Error("Sunday should be weekend")
	}
	mon := time.Date(2026, 4, 6, 10, 0, 0, 0, kolkataLoc) // Monday
	if IsWeekend(mon) {
		t.Error("Monday should not be weekend")
	}
}

func TestDeduplication(t *testing.T) {
	s := New(testLogger())
	var called atomic.Int32

	// Wednesday 2026-04-08 10:30 IST — a known trading day.
	wed := time.Date(2026, 4, 8, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wed })

	s.Add(Task{
		Name:   "dedup",
		Hour:   10,
		Minute: 30,
		Fn:     func() { called.Add(1) },
	})

	// First tick should fire the task.
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if called.Load() != 1 {
		t.Fatalf("expected 1 call, got %d", called.Load())
	}

	// Second tick at the same minute should be deduplicated.
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if called.Load() != 1 {
		t.Fatalf("expected still 1 call after dedup, got %d", called.Load())
	}
}

func TestTaskPanicRecovery(t *testing.T) {
	s := New(testLogger())

	// Wednesday 2026-04-08 10:30 IST — a known trading day.
	wed := time.Date(2026, 4, 8, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wed })

	s.Add(Task{
		Name:   "panicker",
		Hour:   10,
		Minute: 30,
		Fn:     func() { panic("boom") },
	})

	// tick should not panic (recovery is in the goroutine).
	s.tick()
	time.Sleep(50 * time.Millisecond) // let goroutine finish
}

func TestIsMarketHoliday(t *testing.T) {
	// Republic Day 2026 is a known holiday.
	republicDay := time.Date(2026, 1, 26, 10, 0, 0, 0, kolkataLoc)
	if !IsMarketHoliday(republicDay) {
		t.Error("2026-01-26 (Republic Day) should be a market holiday")
	}

	// Diwali-Balipratipada 2026
	diwali := time.Date(2026, 11, 10, 10, 0, 0, 0, kolkataLoc)
	if !IsMarketHoliday(diwali) {
		t.Error("2026-11-10 (Diwali-Balipratipada) should be a market holiday")
	}

	// A normal trading day (2026-01-27 is a Tuesday, no holiday).
	normalDay := time.Date(2026, 1, 27, 10, 0, 0, 0, kolkataLoc)
	if IsMarketHoliday(normalDay) {
		t.Error("2026-01-27 should not be a market holiday")
	}
}

func TestIsTradingDay(t *testing.T) {
	// Saturday is not a trading day
	sat := time.Date(2026, 4, 4, 10, 0, 0, 0, kolkataLoc)
	if IsTradingDay(sat) {
		t.Error("Saturday should not be a trading day")
	}

	// Holiday is not a trading day (Good Friday, 2026-04-03 is a Friday)
	holiday := time.Date(2026, 4, 3, 10, 0, 0, 0, kolkataLoc)
	if IsTradingDay(holiday) {
		t.Error("2026-04-03 (Good Friday) should not be a trading day")
	}

	// Normal weekday that's not a holiday
	normal := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc) // Tuesday
	if !IsTradingDay(normal) {
		t.Error("2026-04-07 (Tuesday, no holiday) should be a trading day")
	}
}

func TestTickSkipsHoliday(t *testing.T) {
	// We verify the exported helper functions which tick() depends on.
	// tick() calls IsMarketHoliday internally and returns early on holidays.
	republicDay := time.Date(2026, 1, 26, 9, 0, 0, 0, kolkataLoc)
	if !IsMarketHoliday(republicDay) {
		t.Error("Republic Day should be a market holiday")
	}
	if IsTradingDay(republicDay) {
		t.Error("Republic Day should not be a trading day")
	}
}

func TestTodayIST(t *testing.T) {
	today := TodayIST()
	if len(today) != 10 { // "2006-01-02"
		t.Fatalf("unexpected date format: %q", today)
	}
}

func TestNowIST(t *testing.T) {
	now := NowIST()
	if now.Location().String() != "Asia/Kolkata" {
		t.Fatalf("expected Asia/Kolkata, got %s", now.Location())
	}
}

// --- MarketStatus ---

func TestMarketStatus_Open(t *testing.T) {
	t.Parallel()
	// Wednesday 2026-04-08, 10:00 AM IST
	tm := time.Date(2026, 4, 8, 4, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "open" {
		t.Errorf("expected open, got %s", got)
	}
}

func TestMarketStatus_PreOpen(t *testing.T) {
	t.Parallel()
	// Wednesday 2026-04-08, 9:05 AM IST
	tm := time.Date(2026, 4, 8, 3, 35, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "pre_open" {
		t.Errorf("expected pre_open, got %s", got)
	}
}

func TestMarketStatus_ClosingSession(t *testing.T) {
	t.Parallel()
	// Wednesday 2026-04-08, 3:35 PM IST
	tm := time.Date(2026, 4, 8, 10, 5, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closing_session" {
		t.Errorf("expected closing_session, got %s", got)
	}
}

func TestMarketStatus_Closed(t *testing.T) {
	t.Parallel()
	// Wednesday 2026-04-08, 5:00 PM IST
	tm := time.Date(2026, 4, 8, 11, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed" {
		t.Errorf("expected closed, got %s", got)
	}
}

func TestMarketStatus_ClosedEarlyMorning(t *testing.T) {
	t.Parallel()
	// Wednesday 2026-04-08, 7:00 AM IST
	tm := time.Date(2026, 4, 8, 1, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed" {
		t.Errorf("expected closed, got %s", got)
	}
}

func TestMarketStatus_Weekend(t *testing.T) {
	t.Parallel()
	// Saturday 2026-04-11
	tm := time.Date(2026, 4, 11, 4, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed_weekend" {
		t.Errorf("expected closed_weekend, got %s", got)
	}
}

func TestMarketStatus_Sunday(t *testing.T) {
	t.Parallel()
	// Sunday 2026-04-12
	tm := time.Date(2026, 4, 12, 4, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed_weekend" {
		t.Errorf("expected closed_weekend, got %s", got)
	}
}

func TestMarketStatus_Holiday(t *testing.T) {
	t.Parallel()
	// 2026-01-26 Republic Day (Monday)
	tm := time.Date(2026, 1, 26, 4, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed_holiday" {
		t.Errorf("expected closed_holiday, got %s", got)
	}
}

func TestMarketStatus_PreOpenBoundary(t *testing.T) {
	t.Parallel()
	// Exactly 9:00 AM IST (540 minutes)
	tm := time.Date(2026, 4, 8, 3, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "pre_open" {
		t.Errorf("expected pre_open, got %s", got)
	}
}

func TestMarketStatus_OpenBoundary(t *testing.T) {
	t.Parallel()
	// Exactly 9:15 AM IST (555 minutes)
	tm := time.Date(2026, 4, 8, 3, 45, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "open" {
		t.Errorf("expected open, got %s", got)
	}
}

func TestMarketStatus_ClosingBoundary(t *testing.T) {
	t.Parallel()
	// Exactly 3:30 PM IST (930 minutes)
	tm := time.Date(2026, 4, 8, 10, 0, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closing_session" {
		t.Errorf("expected closing_session, got %s", got)
	}
}

func TestMarketStatus_ClosedAfterClosing(t *testing.T) {
	t.Parallel()
	// 4:00 PM IST (960 minutes)
	tm := time.Date(2026, 4, 8, 10, 30, 0, 0, time.UTC)
	if got := MarketStatus(tm); got != "closed" {
		t.Errorf("expected closed, got %s", got)
	}
}

func TestIsWeekend_UTC(t *testing.T) {
	t.Parallel()
	// UTC Friday evening = IST Saturday morning
	satUTC := time.Date(2026, 4, 10, 20, 0, 0, 0, time.UTC)
	if !IsWeekend(satUTC) {
		t.Error("expected IST Saturday to be weekend")
	}
}

func TestAllNSEHolidays(t *testing.T) {
	t.Parallel()
	holidays := []string{
		"2026-01-26", "2026-03-03", "2026-03-26", "2026-03-31",
		"2026-04-03", "2026-04-14", "2026-05-01", "2026-05-28",
		"2026-06-26", "2026-09-14", "2026-10-02", "2026-10-20",
		"2026-11-10", "2026-11-24", "2026-12-25",
	}
	for _, ds := range holidays {
		tm, _ := time.Parse("2006-01-02", ds)
		ist := tm.In(kolkataLoc)
		if !IsMarketHoliday(ist) {
			t.Errorf("expected %s to be a holiday", ds)
		}
	}
}

// --- Deterministic tick() tests using injected clock ---

func TestTick_Weekday_TaskRuns(t *testing.T) {
	s := New(testLogger())
	var ran atomic.Int32

	// Wednesday 2026-04-08 10:30 IST — a known trading day.
	wednesday := time.Date(2026, 4, 8, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wednesday })

	s.Add(Task{Name: "weekday_test", Hour: 10, Minute: 30, Fn: func() { ran.Add(1) }})
	s.tick()
	time.Sleep(20 * time.Millisecond)

	if ran.Load() != 1 {
		t.Fatalf("task should run on weekday at matching time; ran %d times", ran.Load())
	}
}

func TestTick_Weekend_NoExecution(t *testing.T) {
	s := New(testLogger())
	var ran atomic.Int32

	// Saturday 2026-04-11 10:30 IST.
	saturday := time.Date(2026, 4, 11, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return saturday })

	s.Add(Task{Name: "weekend_noop", Hour: 10, Minute: 30, Fn: func() { ran.Add(1) }})
	s.tick()
	time.Sleep(20 * time.Millisecond)

	if ran.Load() != 0 {
		t.Fatal("task should NOT run on weekend")
	}
}

func TestTick_Holiday_NoExecution(t *testing.T) {
	s := New(testLogger())
	var ran atomic.Int32

	// Republic Day 2026-01-26 (Monday) 10:30 IST — NSE holiday.
	holiday := time.Date(2026, 1, 26, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return holiday })

	s.Add(Task{Name: "holiday_noop", Hour: 10, Minute: 30, Fn: func() { ran.Add(1) }})
	s.tick()
	time.Sleep(20 * time.Millisecond)

	if ran.Load() != 0 {
		t.Fatal("task should NOT run on market holiday")
	}
}

func TestTick_WrongTime_NoExecution(t *testing.T) {
	s := New(testLogger())
	var ran atomic.Int32

	// Wednesday 2026-04-08 08:00 IST — trading day but task is at 10:30.
	early := time.Date(2026, 4, 8, 8, 0, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return early })

	s.Add(Task{Name: "wrong_time", Hour: 10, Minute: 30, Fn: func() { ran.Add(1) }})
	s.tick()
	time.Sleep(20 * time.Millisecond)

	if ran.Load() != 0 {
		t.Fatal("task should NOT run when current time does not match task time")
	}
}

func TestTick_MultipleTasksSameTime(t *testing.T) {
	s := New(testLogger())
	var countA, countB atomic.Int32

	wednesday := time.Date(2026, 4, 8, 9, 15, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wednesday })

	s.Add(Task{Name: "task_a", Hour: 9, Minute: 15, Fn: func() { countA.Add(1) }})
	s.Add(Task{Name: "task_b", Hour: 9, Minute: 15, Fn: func() { countB.Add(1) }})
	s.tick()
	time.Sleep(20 * time.Millisecond)

	if countA.Load() != 1 {
		t.Fatalf("task_a should run once, ran %d", countA.Load())
	}
	if countB.Load() != 1 {
		t.Fatalf("task_b should run once, ran %d", countB.Load())
	}
}

func TestTick_Dedup_AcrossTicks(t *testing.T) {
	s := New(testLogger())
	var ran atomic.Int32

	wednesday := time.Date(2026, 4, 8, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return wednesday })

	s.Add(Task{Name: "dedup_clock", Hour: 10, Minute: 30, Fn: func() { ran.Add(1) }})

	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("first tick: expected 1, got %d", ran.Load())
	}

	// Same time, second tick — should be deduped.
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 1 {
		t.Fatalf("second tick: expected still 1, got %d", ran.Load())
	}

	// Advance to next day (Thursday) — should run again.
	thursday := time.Date(2026, 4, 9, 10, 30, 0, 0, kolkataLoc)
	s.SetClock(func() time.Time { return thursday })
	s.tick()
	time.Sleep(20 * time.Millisecond)
	if ran.Load() != 2 {
		t.Fatalf("next day tick: expected 2, got %d", ran.Load())
	}
}
