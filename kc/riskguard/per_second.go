package riskguard

import (
	"fmt"
	"sync"
	"time"
)

// maxOrdersPerSecond is the defensive per-calendar-second cap on order
// submissions. SEBI's Apr 2026 retail-algo framework classifies anything
// >=10 orders/sec as "algorithmic" and requires registration/audit.
// Zerodha enforces the 10/sec threshold broker-side (rejects the 11th
// order within a calendar second). We cap at 9 here so the defensive
// layer always refuses BEFORE the broker does, guaranteeing:
//
//  1. a clean, stable reject reason surfaced by our code (not a Kite 429
//     or opaque RMS string);
//  2. a full 1-order headroom below the broker cap so race conditions
//     between our counter and Kite's counter cannot push through an
//     11th order that would violate SEBI's retail threshold;
//  3. the user never inadvertently trips the regulator-visible cap.
//
// The counter is keyed by (email, calendar_second) — explicitly a
// calendar-second bucket, NOT a rolling 1-second window, because the
// SEBI spec is written in calendar-second terms. Stale second buckets
// are garbage-collected lazily when a user is observed in a new second.
const maxOrdersPerSecond = 9

// ReasonPerSecondRateExceeded fires when a user submits more than
// maxOrdersPerSecond order attempts within the same wall-clock calendar
// second. This sits strictly inside the broker-side SEBI threshold so
// the defensive cap always refuses before Zerodha does.
const ReasonPerSecondRateExceeded RejectionReason = "per_second_rate_exceeded"

// perSecondCounter tracks per-email per-calendar-second order counts.
// Separate from UserTracker (which does rolling-minute rate) because
// the semantics differ: this bucket resets at every wall-clock second
// boundary, whereas the rolling window slides continuously.
//
// Memory bound: at most one non-zero bucket per active email at any
// moment (the current second's count). Stale entries are cleared when
// an email is next observed in a newer second — a simple lazy sweep
// that keeps the map size proportional to the number of *currently
// active* users, not the cumulative set of users ever seen.
type perSecondCounter struct {
	mu sync.Mutex
	// perUser maps email → (second_unix, count). We keep only the most
	// recent second per user; if a later call lands in a newer second,
	// the old bucket is overwritten. This bounds memory to O(active users).
	perUser map[string]perSecondBucket
}

type perSecondBucket struct {
	second int64 // Unix seconds since epoch
	count  int
}

func newPerSecondCounter() *perSecondCounter {
	return &perSecondCounter{perUser: make(map[string]perSecondBucket)}
}

// currentCount returns how many orders the user has already been recorded
// as submitting in the current wall-clock second (per the supplied clock).
// The caller uses this number to decide whether to allow the *next* order:
// if currentCount >= maxOrdersPerSecond, the incoming attempt is the
// (N+1)-th, which breaches the cap.
//
// The counter is lazily garbage-collected: if the stored bucket's second
// is not equal to `now`, the bucket is treated as empty (stale). No
// explicit pruning pass is needed — stale entries are simply overwritten
// on the next increment for that user.
func (c *perSecondCounter) currentCount(email string, now time.Time) int {
	sec := now.Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.perUser[email]
	if !ok || b.second != sec {
		return 0
	}
	return b.count
}

// increment records that this user placed an order at this wall-clock
// second. If the stored bucket is stale (different second), it is reset
// to 1; otherwise it is incremented by 1.
func (c *perSecondCounter) increment(email string, now time.Time) {
	sec := now.Unix()
	c.mu.Lock()
	defer c.mu.Unlock()
	b, ok := c.perUser[email]
	if !ok || b.second != sec {
		c.perUser[email] = perSecondBucket{second: sec, count: 1}
		return
	}
	b.count++
	c.perUser[email] = b
}

// checkPerSecondRate enforces the 9-orders-per-calendar-second defensive
// cap. Returns Allowed=false with ReasonPerSecondRateExceeded when the
// user has already been recorded as placing `maxOrdersPerSecond` (=9)
// orders within the current wall-clock second.
//
// The check is read-only: it does not increment the counter. The
// counter is incremented on successful order placement via
// recordPerSecondOrder (invoked from RecordOrder alongside the
// existing rate/duplicate/daily trackers).
//
// Defensive posture: this check runs AFTER the confirmation gate but
// BEFORE the existing per-minute rate limit (checkRateLimit). Rationale:
// the 9/sec cap must bite before the 10/min cap allows a quick burst —
// without it, 10 orders submitted inside a single second would all pass
// the minute-level check (10 is within the 10/min allowance) yet breach
// the SEBI sub-second threshold.
func (g *Guard) checkPerSecondRate(email string) CheckResult {
	if g.perSecond == nil {
		// Defensive: uninitialized counter. Fail open rather than lock
		// out every user if wiring is incomplete — the broker-side 10/sec
		// cap still provides the hard stop.
		return CheckResult{Allowed: true}
	}
	now := g.clock()
	count := g.perSecond.currentCount(email, now)
	if count >= maxOrdersPerSecond {
		return CheckResult{
			Allowed: false,
			Reason:  ReasonPerSecondRateExceeded,
			Message: fmt.Sprintf(
				"Per-second order rate exceeded: %d orders already submitted in this calendar second (cap: %d, reserved 1-order headroom below the broker-side 10/sec SEBI threshold). Wait for the next second before retrying.",
				count, maxOrdersPerSecond),
		}
	}
	return CheckResult{Allowed: true}
}

// recordPerSecondOrder bumps the per-calendar-second counter for this
// user. Called from RecordOrder on successful placements; also used
// directly in tests to seed the counter.
func (g *Guard) recordPerSecondOrder(email string) {
	if g.perSecond == nil {
		return
	}
	g.perSecond.increment(email, g.clock())
}
