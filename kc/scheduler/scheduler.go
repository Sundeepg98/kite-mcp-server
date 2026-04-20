// Package scheduler provides a simple IST-aware task scheduler that runs
// named tasks at specific times on trading days (Monday–Friday).
package scheduler

import (
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/isttz"
)

// kolkataLoc is an alias for the shared IST timezone (kc/isttz leaf package).
var kolkataLoc = isttz.Location

// Task describes a named function that should run once per trading day at a
// specific IST time.
type Task struct {
	Name   string // unique identifier for dedup tracking
	Hour   int    // IST hour (0-23)
	Minute int    // IST minute (0-59)
	Fn     func() // the work to perform
}

// Clock returns the current time. Defaults to time.Now.
// Override in tests via SetClock to control time.
type Clock func() time.Time

// Scheduler checks every minute whether any registered task should fire.
// Tasks only run on weekdays (Mon-Fri) and at most once per calendar day.
type Scheduler struct {
	mu           sync.Mutex
	tasks        []Task
	// providers are plugin-registered sources of additional tasks. Their
	// Tasks() method is invoked exactly once by Start, before the tick
	// goroutine launches. See provider.go for the full contract and
	// rationale for one-shot (not per-tick) collection.
	providers    []TaskProvider
	lastRun      map[string]string // task name -> "2006-01-02" of last execution
	done         chan struct{}
	// loopDone is closed by the loop goroutine when it exits. Stop() waits
	// on it so callers observe the goroutine has actually terminated —
	// without this goleak-style sentinels race the exit.
	loopDone     chan struct{}
	logger       *slog.Logger
	clock        Clock
	tickInterval time.Duration // default 60s, override in tests
}

// New creates a new Scheduler.
func New(logger *slog.Logger) *Scheduler {
	return &Scheduler{
		lastRun:      make(map[string]string),
		done:         make(chan struct{}),
		loopDone:     make(chan struct{}),
		logger:       logger,
		clock:        time.Now,
		tickInterval: 60 * time.Second,
	}
}

// SetClock overrides the time source (for testing).
// Safe to call concurrently with a running scheduler; tick() reads the
// clock under s.mu.
func (s *Scheduler) SetClock(c Clock) {
	s.mu.Lock()
	s.clock = c
	s.mu.Unlock()
}

// SetTickInterval overrides the loop tick interval (for testing).
// Must be called before Start — the loop caches the interval at launch
// and won't observe later changes.
func (s *Scheduler) SetTickInterval(d time.Duration) {
	s.mu.Lock()
	s.tickInterval = d
	s.mu.Unlock()
}

// Add registers a task. Must be called before Start.
func (s *Scheduler) Add(task Task) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tasks = append(s.tasks, task)
}

// Start launches a background goroutine that ticks every minute.
//
// Before the goroutine launches, every registered TaskProvider is
// consulted via Tasks() and its returned tasks are appended to the
// scheduler's task list. This is the single collection point for
// plugin-contributed schedules — Tasks() is NOT called again until
// the scheduler is stopped and a new one is constructed.
func (s *Scheduler) Start() {
	s.collectProviderTasks()
	go s.loop()
}

// Stop signals the scheduler goroutine to exit and waits for it to finish.
// Safe to call multiple times (select guards the channel close, loopDone
// reads are idempotent on a closed channel). Safe to call without Start:
// loopDone is initialised in New and only closed by loop — the bounded
// wait below protects against "Stop before Start" by returning once a
// small window passes with no signal.
func (s *Scheduler) Stop() {
	alreadyStopped := false
	select {
	case <-s.done:
		alreadyStopped = true
	default:
		close(s.done)
	}
	if alreadyStopped {
		// Second call: loop already exited during the first Stop.
		return
	}
	// Wait for the loop goroutine to actually exit. Without this wait,
	// goleak sentinels race the scheduler exit and report a spurious
	// leak even though the Stop signal was delivered. Timeout covers
	// the "Stop before Start" case — loop never runs, loopDone never
	// closes; after the timeout we accept the mildly-degenerate state
	// (nothing actually leaked because nothing ran).
	if s.loopDone != nil {
		select {
		case <-s.loopDone:
		case <-time.After(2 * time.Second):
		}
	}
}

// loop is the main ticker loop, running at tickInterval (default 60s).
func (s *Scheduler) loop() {
	defer close(s.loopDone)
	s.mu.Lock()
	interval := s.tickInterval
	s.mu.Unlock()
	ticker := time.NewTicker(interval)
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

// nseHolidays lists NSE trading holidays.
// Add 2027 holidays when NSE announces them.
var nseHolidays = map[string]bool{
	"2026-01-26": true, // Republic Day
	"2026-03-03": true, // Holi
	"2026-03-26": true, // Ram Navami
	"2026-03-31": true, // Mahavir Jayanti
	"2026-04-03": true, // Good Friday
	"2026-04-14": true, // Dr. Ambedkar Jayanti
	"2026-05-01": true, // Maharashtra Day
	"2026-05-28": true, // Bakri Eid
	"2026-06-26": true, // Muharram
	"2026-09-14": true, // Ganesh Chaturthi
	"2026-10-02": true, // Mahatma Gandhi Jayanti
	"2026-10-20": true, // Dussehra
	"2026-11-10": true, // Diwali-Balipratipada
	"2026-11-24": true, // Guru Nanak Jayanti
	"2026-12-25": true, // Christmas
}

// IsMarketHoliday returns true if the given time falls on an NSE trading holiday.
func IsMarketHoliday(t time.Time) bool {
	dateStr := t.In(kolkataLoc).Format("2006-01-02")
	return nseHolidays[dateStr]
}

// IsTradingDay returns true if the given time is a weekday and not a market holiday.
func IsTradingDay(t time.Time) bool {
	return !IsWeekend(t) && !IsMarketHoliday(t)
}

// tick evaluates all tasks against the current IST time.
func (s *Scheduler) tick() {
	s.mu.Lock()
	clock := s.clock
	s.mu.Unlock()
	now := clock().In(kolkataLoc)

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

// MarketStatus returns the current market status based on IST time.
// Possible values: "pre_open", "open", "closing_session", "closed", "closed_weekend", "closed_holiday".
func MarketStatus(t time.Time) string {
	ist := t.In(kolkataLoc)
	if IsWeekend(ist) {
		return "closed_weekend"
	}
	if IsMarketHoliday(ist) {
		return "closed_holiday"
	}
	h, m := ist.Hour(), ist.Minute()
	mins := h*60 + m
	switch {
	case mins >= 540 && mins < 555:
		return "pre_open"
	case mins >= 555 && mins < 930:
		return "open"
	case mins >= 930 && mins < 960:
		return "closing_session"
	default:
		return "closed"
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
