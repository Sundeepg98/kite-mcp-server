// Package testutil hosts in-memory test fakes for the production ports
// defined in github.com/algo2go/kite-mcp-clockport. Production code does
// NOT import testutil; only _test.go files do.
//
// FakeClock + fakeTicker provide a deterministic implementation of
// clockport.Clock + clockport.Ticker that advances only when Advance()
// is called. This lets rate-limit / scheduler-style goroutines be
// driven forward without wall-clock waits.
//
// The matching production port + RealClock implementation live at
// github.com/algo2go/kite-mcp-clockport (Path A.27, 28th algo2go
// module). The split is documented at
// .research/testutil-clock-port-split-design.md (commit fa6c70a) and
// .research/path-a-27-clockport-pick.md (this commit).
//
// What this fake does NOT help with:
//   - Sleeps that wait for external I/O (TCP bind, HTTP server readiness,
//     SQLite worker drain). A fake clock cannot make the OS bind faster;
//     those sleeps stay and belong to integration-test scope.
package testutil

import (
	"sync"
	"time"

	"github.com/algo2go/kite-mcp-clockport"
)

// ---------------------------------------------------------------------
// Fake implementation — deterministic, advances only via Advance.
// Implements clockport.Clock (structural typing — no explicit declaration
// needed; the var-_-clockport.Clock assertion in clock_test.go enforces it).
// ---------------------------------------------------------------------

// FakeClock is a test clock whose time only moves when Advance is called.
// All Tickers registered via NewTicker observe the advances atomically.
//
// FakeClock is safe for concurrent use. Ticker channels are buffered (1)
// so an Advance that crosses multiple tick boundaries delivers one tick
// per boundary without blocking; if the caller has not drained the
// channel, subsequent ticks across the same boundary coalesce (matching
// the stdlib time.Ticker semantics).
type FakeClock struct {
	mu      sync.Mutex
	now     time.Time
	tickers []*fakeTicker
}

// NewFakeClock returns a FakeClock initialised to the given time. Pass
// time.Now() if the absolute value is irrelevant.
func NewFakeClock(start time.Time) *FakeClock {
	return &FakeClock{now: start}
}

// Now returns the current fake time.
func (f *FakeClock) Now() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

// NewTicker registers a ticker that fires when Advance crosses the given
// interval. Stop removes it from the registry.
func (f *FakeClock) NewTicker(d time.Duration) clockport.Ticker {
	if d <= 0 {
		// Match stdlib semantics: time.NewTicker panics on d<=0. We
		// return a ticker with a closed channel instead of panicking so
		// the caller can still call Stop cleanly — tests exercising the
		// d<=0 error path should hit production validation separately.
		ch := make(chan time.Time)
		close(ch)
		t := &fakeTicker{ch: ch, closed: true}
		return t
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	t := &fakeTicker{
		ch:       make(chan time.Time, 1),
		interval: d,
		next:     f.now.Add(d),
		parent:   f,
	}
	f.tickers = append(f.tickers, t)
	return t
}

// Advance moves the fake clock forward by d, delivering ticks for every
// registered ticker whose `next` boundary the advance crosses. Returns
// the count of ticks delivered across all tickers.
func (f *FakeClock) Advance(d time.Duration) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
	delivered := 0
	for _, t := range f.tickers {
		if t.closed {
			continue
		}
		// Deliver every tick that fits in the window [oldNow, newNow].
		for !t.next.After(f.now) {
			select {
			case t.ch <- t.next:
				delivered++
			default:
				// Channel buffer full: drop in line with stdlib
				// time.Ticker coalescing semantics.
			}
			t.next = t.next.Add(t.interval)
		}
	}
	return delivered
}

// Set moves the fake clock to the given time, delivering ticks for any
// boundary the jump crosses. Useful when tests want absolute control.
func (f *FakeClock) Set(to time.Time) int {
	f.mu.Lock()
	d := to.Sub(f.now)
	f.mu.Unlock()
	if d <= 0 {
		return 0
	}
	return f.Advance(d)
}

type fakeTicker struct {
	ch       chan time.Time
	interval time.Duration
	next     time.Time
	parent   *FakeClock
	closed   bool
	once     sync.Once
}

func (t *fakeTicker) C() <-chan time.Time { return t.ch }
func (t *fakeTicker) Stop() {
	t.once.Do(func() {
		if t.parent != nil {
			t.parent.mu.Lock()
			defer t.parent.mu.Unlock()
		}
		t.closed = true
		// Do NOT close(t.ch) here: a concurrent Advance may still
		// attempt a non-blocking send on it. Leaving the channel open
		// is safe because receivers select on it and Advance filters
		// closed tickers before sending.
	})
}
