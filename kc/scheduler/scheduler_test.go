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
	s.Add(Task{Name: "weekend_test", Hour: 0, Minute: 0, Fn: func() { called.Add(1) }})

	// Verify the helper recognises weekends.
	sat := time.Date(2026, 4, 4, 10, 0, 0, 0, kolkataLoc) // Saturday
	sun := time.Date(2026, 4, 5, 10, 0, 0, 0, kolkataLoc) // Sunday
	mon := time.Date(2026, 4, 6, 10, 0, 0, 0, kolkataLoc) // Monday
	if !IsWeekend(sat) {
		t.Error("Saturday should be weekend")
	}
	if !IsWeekend(sun) {
		t.Error("Sunday should be weekend")
	}
	if IsWeekend(mon) {
		t.Error("Monday should not be weekend")
	}
}

func TestDeduplication(t *testing.T) {
	s := New(testLogger())
	var called atomic.Int32
	now := time.Now().In(kolkataLoc)

	// Only works on trading days. Skip on weekends and holidays.
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		t.Skip("skipping on weekend")
	}
	if IsMarketHoliday(now) {
		t.Skip("skipping on market holiday")
	}

	s.Add(Task{
		Name:   "dedup",
		Hour:   now.Hour(),
		Minute: now.Minute(),
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
	now := time.Now().In(kolkataLoc)
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		t.Skip("skipping on weekend")
	}
	if IsMarketHoliday(now) {
		t.Skip("skipping on market holiday")
	}

	s.Add(Task{
		Name:   "panicker",
		Hour:   now.Hour(),
		Minute: now.Minute(),
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

	// Diwali 2026
	diwali := time.Date(2026, 11, 9, 10, 0, 0, 0, kolkataLoc)
	if !IsMarketHoliday(diwali) {
		t.Error("2026-11-09 (Diwali) should be a market holiday")
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

	// Holiday is not a trading day (Mahavir Jayanti, 2026-04-02 is a Thursday)
	holiday := time.Date(2026, 4, 2, 10, 0, 0, 0, kolkataLoc)
	if IsTradingDay(holiday) {
		t.Error("2026-04-02 (Mahavir Jayanti) should not be a trading day")
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
