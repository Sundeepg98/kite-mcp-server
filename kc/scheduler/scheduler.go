// Package scheduler provides a simple IST-aware task scheduler that runs
// named tasks at specific times on trading days (Monday–Friday).
package scheduler

import (
	"log/slog"
	"sync"
	"time"
)

// kolkataLoc is the cached Asia/Kolkata timezone.
var kolkataLoc = func() *time.Location {
	loc, err := time.LoadLocation("Asia/Kolkata")
	if err != nil {
		panic("failed to load Asia/Kolkata timezone: " + err.Error())
	}
	return loc
}()

// Task describes a named function that should run once per trading day at a
// specific IST time.
type Task struct {
	Name   string // unique identifier for dedup tracking
	Hour   int    // IST hour (0-23)
	Minute int    // IST minute (0-59)
	Fn     func() // the work to perform
}

// Scheduler checks every minute whether any registered task should fire.
// Tasks only run on weekdays (Mon-Fri) and at most once per calendar day.
type Scheduler struct {
	mu      sync.Mutex
	tasks   []Task
	lastRun map[string]string // task name -> "2006-01-02" of last execution
	done    chan struct{}
	logger  *slog.Logger
}

// New creates a new Scheduler.
func New(logger *slog.Logger) *Scheduler {
	return &Scheduler{
		lastRun: make(map[string]string),
		done:    make(chan struct{}),
		logger:  logger,
	}
}

// Add registers a task. Must be called before Start.
func (s *Scheduler) Add(task Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, task)
}

// Start launches a background goroutine that ticks every minute.
func (s *Scheduler) Start() {
	go s.loop()
}

// Stop signals the scheduler goroutine to exit.
func (s *Scheduler) Stop() {
	select {
	case <-s.done:
		// already closed
	default:
		close(s.done)
	}
}

// loop is the main ticker loop, running every 60 seconds.
func (s *Scheduler) loop() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	// Check immediately on start so we don't wait up to 60s for the first tick.
	s.tick()

	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.tick()
		}
	}
}

// nseHolidays2026 lists NSE trading holidays for 2026.
var nseHolidays2026 = map[string]bool{
	"2026-01-26": true, // Republic Day
	"2026-02-26": true, // Maha Shivaratri
	"2026-03-10": true, // Holi
	"2026-03-30": true, // Id-Ul-Fitr
	"2026-04-01": true, // Annual Bank Closing / Ram Navami
	"2026-04-02": true, // Mahavir Jayanti
	"2026-04-06": true, // Dr. Ambedkar Jayanti (observed)
	"2026-04-14": true, // Good Friday
	"2026-05-01": true, // May Day
	"2026-06-06": true, // Id-Ul-Adha (Bakri Id)
	"2026-07-06": true, // Muharram
	"2026-08-15": true, // Independence Day
	"2026-08-16": true, // Parsi New Year
	"2026-09-04": true, // Milad-un-Nabi
	"2026-10-02": true, // Mahatma Gandhi Jayanti
	"2026-10-20": true, // Dussehra
	"2026-11-09": true, // Diwali (Laxmi Pujan)
	"2026-11-10": true, // Diwali Balipratipada
	"2026-11-19": true, // Guru Nanak Jayanti
	"2026-12-25": true, // Christmas
}

// IsMarketHoliday returns true if the given time falls on an NSE trading holiday.
func IsMarketHoliday(t time.Time) bool {
	dateStr := t.In(kolkataLoc).Format("2006-01-02")
	return nseHolidays2026[dateStr]
}

// IsTradingDay returns true if the given time is a weekday and not a market holiday.
func IsTradingDay(t time.Time) bool {
	return !IsWeekend(t) && !IsMarketHoliday(t)
}

// tick evaluates all tasks against the current IST time.
func (s *Scheduler) tick() {
	now := time.Now().In(kolkataLoc)

	// Skip weekends and market holidays.
	if now.Weekday() == time.Saturday || now.Weekday() == time.Sunday {
		return
	}
	if IsMarketHoliday(now) {
		return
	}

	today := now.Format("2006-01-02")

	s.mu.Lock()
	defer s.mu.Unlock()

	for _, t := range s.tasks {
		if now.Hour() == t.Hour && now.Minute() == t.Minute {
			if s.lastRun[t.Name] == today {
				continue // already ran today
			}
			s.lastRun[t.Name] = today
			s.logger.Info("Scheduler: running task", "task", t.Name, "time", now.Format(time.RFC3339))

			// Run in a separate goroutine so one slow task doesn't block others.
			fn := t.Fn
			name := t.Name
			go func() {
				defer func() {
					if r := recover(); r != nil {
						s.logger.Error("Scheduler: task panicked", "task", name, "panic", r)
					}
				}()
				fn()
			}()
		}
	}
}

// IsWeekend returns true if the given time falls on Saturday or Sunday in IST.
func IsWeekend(t time.Time) bool {
	ist := t.In(kolkataLoc)
	return ist.Weekday() == time.Saturday || ist.Weekday() == time.Sunday
}

// TodayIST returns today's date string in IST (format "2006-01-02").
func TodayIST() string {
	return time.Now().In(kolkataLoc).Format("2006-01-02")
}

// NowIST returns the current time in IST.
func NowIST() time.Time {
	return time.Now().In(kolkataLoc)
}
