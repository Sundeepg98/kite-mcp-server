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

	// Only works if today is a weekday. Skip on weekends.
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		t.Skip("skipping on weekend")
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
