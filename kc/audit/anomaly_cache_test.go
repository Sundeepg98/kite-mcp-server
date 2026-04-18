package audit

import (
	"encoding/json"
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStatsCache_GetMiss verifies an empty cache returns ok=false.
func TestStatsCache_GetMiss(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	_, _, _, ok := c.Get("missing@user.com", 30)
	assert.False(t, ok, "empty cache must report miss")
}

// TestStatsCache_SetThenGet verifies a Set value is retrievable within TTL.
func TestStatsCache_SetThenGet(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	c.Set("user@example.com", 30, 1000, 200, 10)

	m, s, n, ok := c.Get("user@example.com", 30)
	assert.True(t, ok, "fresh entry must be reported as hit")
	assert.Equal(t, 1000.0, m)
	assert.Equal(t, 200.0, s)
	assert.Equal(t, 10.0, n)
}

// TestStatsCache_TTLExpiry verifies entries past TTL are evicted on Get.
// Uses a very short TTL (1ms) and explicit sleep to exercise the expiry path.
func TestStatsCache_TTLExpiry(t *testing.T) {
	t.Parallel()
	c := newStatsCache(5 * time.Millisecond)

	c.Set("ttl@user.com", 30, 500, 100, 7)

	// Immediately — should hit.
	_, _, _, ok := c.Get("ttl@user.com", 30)
	assert.True(t, ok, "entry within TTL must hit")

	// After TTL — should miss.
	time.Sleep(15 * time.Millisecond)
	_, _, _, ok = c.Get("ttl@user.com", 30)
	assert.False(t, ok, "entry past TTL must miss")
}

// TestStatsCache_Invalidate verifies Invalidate wipes the given email's
// entries but leaves other emails alone.
func TestStatsCache_Invalidate(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	c.Set("alice@x.com", 30, 1000, 100, 5)
	c.Set("alice@x.com", 7, 900, 80, 4)
	c.Set("bob@x.com", 30, 2000, 300, 8)

	c.Invalidate("alice@x.com")

	_, _, _, ok := c.Get("alice@x.com", 30)
	assert.False(t, ok, "invalidated email must miss on 30d key")

	_, _, _, ok = c.Get("alice@x.com", 7)
	assert.False(t, ok, "invalidated email must miss on all day windows")

	_, _, _, ok = c.Get("bob@x.com", 30)
	assert.True(t, ok, "other emails must not be affected by invalidate")
}

// TestStatsCache_DifferentDaysAreSeparate verifies (email, days) is the
// cache key — same email with different windows must store separate entries.
func TestStatsCache_DifferentDaysAreSeparate(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	c.Set("user@x.com", 30, 1000, 100, 5)
	c.Set("user@x.com", 7, 500, 50, 3)

	m30, _, _, ok := c.Get("user@x.com", 30)
	assert.True(t, ok)
	assert.Equal(t, 1000.0, m30)

	m7, _, _, ok := c.Get("user@x.com", 7)
	assert.True(t, ok)
	assert.Equal(t, 500.0, m7)
}

// TestStatsCache_HitRate verifies cacheHitRate tracks hits/misses correctly.
func TestStatsCache_HitRate(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	// Initial state: no queries, rate is 0.
	assert.Equal(t, 0.0, c.cacheHitRate())

	// 1 miss.
	_, _, _, _ = c.Get("x@y.com", 30)
	assert.InDelta(t, 0.0, c.cacheHitRate(), 0.001)

	// Populate, then 2 hits → 2/3 = 0.666…
	c.Set("x@y.com", 30, 1, 1, 1)
	_, _, _, _ = c.Get("x@y.com", 30)
	_, _, _, _ = c.Get("x@y.com", 30)
	assert.InDelta(t, 2.0/3.0, c.cacheHitRate(), 0.001)
}

// TestStatsCache_ConcurrentAccess exercises race detection under parallel
// reads, writes, and invalidates. Run with `go test -race` to verify.
func TestStatsCache_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	c := newStatsCache(15 * time.Minute)

	const workers = 16
	const iters = 500

	var wg sync.WaitGroup
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			for i := 0; i < iters; i++ {
				email := "user@x.com"
				switch i % 4 {
				case 0:
					c.Set(email, 30, float64(id*i), float64(i), float64(id))
				case 1:
					_, _, _, _ = c.Get(email, 30)
				case 2:
					c.Invalidate(email)
				case 3:
					_ = c.cacheHitRate()
				}
			}
		}(w)
	}
	wg.Wait()
	// If we got here without the race detector firing, the test passes.
	// Sanity: hit-rate is a valid number in [0, 1].
	r := c.cacheHitRate()
	assert.GreaterOrEqual(t, r, 0.0)
	assert.LessOrEqual(t, r, 1.0)
}

// TestStatsCache_NilSafety verifies a nil *statsCache receiver treats all
// operations as no-ops — the UserOrderStats caller can skip cache logic when
// the cache hasn't been initialised.
func TestStatsCache_NilSafety(t *testing.T) {
	t.Parallel()
	var c *statsCache

	// Get on nil must report miss without panicking.
	_, _, _, ok := c.Get("x@y.com", 30)
	assert.False(t, ok)

	// Set and Invalidate on nil must be no-ops (no panic).
	c.Set("x@y.com", 30, 1, 1, 1)
	c.Invalidate("x@y.com")
	assert.Equal(t, 0.0, c.cacheHitRate())
}

// insertOrderRowDirect bypasses s.Record() (and therefore the automatic
// cache invalidation) by writing to tool_calls via db.ExecInsert. Used in
// cache tests to prove that fresh DB rows are NOT visible when the cache
// serves a hit.
func insertOrderRowDirect(t *testing.T, s *Store, email, tool string, qty, price float64, startedAt time.Time) {
	t.Helper()
	params := map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"quantity":         qty,
		"price":            price,
		"order_type":       "LIMIT",
	}
	paramJSON, err := json.Marshal(params)
	require.NoError(t, err)

	err = s.db.ExecInsert(
		`INSERT OR IGNORE INTO tool_calls (call_id, email, session_id, tool_name, tool_category, input_params, started_at, completed_at, duration_ms) VALUES (?,?,?,?,?,?,?,?,?)`,
		fmt.Sprintf("direct-%d-%d", startedAt.UnixNano(), int64(qty*price)),
		email,
		"sess-direct",
		tool,
		"order",
		string(paramJSON),
		startedAt.Format(time.RFC3339Nano),
		startedAt.Add(50*time.Millisecond).Format(time.RFC3339Nano),
		int64(50),
	)
	require.NoError(t, err)
}

// TestUserOrderStats_CacheHitsAfterFirstQuery verifies the second UserOrderStats
// call within TTL is served from cache and does not re-scan the DB.
// Approach: seed baseline via Record(), call once to populate cache, then
// insert new rows DIRECTLY via db.ExecInsert (bypassing Record's invalidation
// hook). The second UserOrderStats call must still return the cached values,
// proving that the cache is the source of truth within TTL.
func TestUserOrderStats_CacheHitsAfterFirstQuery(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "cached@user.com"
	now := time.Now().UTC()

	// Seed 5 orders at Rs 1000 each.
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}

	// First call — populates cache.
	mean1, _, count1 := s.UserOrderStats(email, 30)
	assert.Equal(t, 5.0, count1)
	assert.InDelta(t, 1000.0, mean1, 0.1)

	// Insert new orders DIRECTLY into the DB (bypasses Record invalidation).
	// If the cache is active, the next call must NOT see these rows.
	for i := 0; i < 5; i++ {
		insertOrderRowDirect(t, s, email, "place_order", 1, 100000, now.Add(-time.Duration(i+10)*time.Hour))
	}

	mean2, _, count2 := s.UserOrderStats(email, 30)
	assert.Equal(t, count1, count2, "cached call must return the same count as the seeding call")
	assert.InDelta(t, mean1, mean2, 0.1, "cached call must return the same mean — DB changes must not leak through")
}

// TestUserOrderStats_CacheMissAfterInvalidate verifies that InvalidateStats
// forces the next UserOrderStats call to re-query the DB.
func TestUserOrderStats_CacheMissAfterInvalidate(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "invalidate@user.com"
	now := time.Now().UTC()

	// Seed 5 orders at Rs 1000 each.
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}

	// Populate cache.
	mean1, _, _ := s.UserOrderStats(email, 30)
	assert.InDelta(t, 1000.0, mean1, 0.1)

	// Add 5 more orders at Rs 5000 each, then invalidate.
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 5000, now.Add(-time.Duration(i+10)*time.Hour))
	}
	s.InvalidateStatsCache(email)

	// Next call should see all 10 orders; mean = (5*1000 + 5*5000)/10 = 3000.
	mean2, _, count2 := s.UserOrderStats(email, 30)
	assert.Equal(t, 10.0, count2)
	assert.InDelta(t, 3000.0, mean2, 0.1)
}

// TestUserOrderStats_RecordOrderInvalidates verifies that recording a new
// order tool call via Record() automatically invalidates the user's cache so
// the next stats query sees the new row.
func TestUserOrderStats_RecordOrderInvalidates(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "auto@user.com"
	now := time.Now().UTC()

	// Seed baseline.
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}
	mean1, _, _ := s.UserOrderStats(email, 30)
	assert.InDelta(t, 1000.0, mean1, 0.1)

	// Record a new place_order via the normal Record() path. This must
	// invalidate the cache so the next UserOrderStats call sees it.
	recordOrderEntry(t, s, email, "place_order", 1, 11000, now.Add(-30*time.Minute))

	// New mean should reflect 6 orders: (5*1000 + 11000)/6 = 2666.66…
	mean2, _, count2 := s.UserOrderStats(email, 30)
	assert.Equal(t, 6.0, count2, "post-record query should see the new order")
	assert.InDelta(t, 2666.67, mean2, 1.0)
}

// TestUserOrderStats_NonOrderRecordDoesNotInvalidate ensures a get_ltp or
// other non-order tool call does NOT invalidate the anomaly stats cache —
// only place_order/modify_order matter for baselines.
func TestUserOrderStats_NonOrderRecordDoesNotInvalidate(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "noninvalidate@user.com"
	now := time.Now().UTC()

	// Seed baseline.
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}
	mean1, _, _ := s.UserOrderStats(email, 30)

	// Record a non-order tool call. Count each direct cache check.
	nonOrder := &ToolCall{
		CallID:      "non-order-1",
		Email:       email,
		SessionID:   "sess-x",
		ToolName:    "get_ltp",
		InputParams: `{"symbol":"INFY"}`,
		StartedAt:   now,
		CompletedAt: now.Add(10 * time.Millisecond),
	}
	_ = s.Record(nonOrder)

	// The cache entry for the steady-baseline email should still be present.
	// We verify indirectly by checking that a second UserOrderStats call
	// returns exactly the same (mean, count) as before. Cache-backed, count
	// does not pick up the get_ltp row (it's not an order tool anyway).
	mean2, _, _ := s.UserOrderStats(email, 30)
	assert.InDelta(t, mean1, mean2, 0.01, "non-order Record must not perturb cached baseline")
}

// TestUserOrderStats_HitCounterIncrementsUnderLoad exercises the cache under
// repeat queries and asserts the hit-rate climbs, serving as a smoke test
// that the cache is actually wired in UserOrderStats.
func TestUserOrderStats_HitCounterIncrementsUnderLoad(t *testing.T) {
	t.Parallel()
	s := openTestStore(t)

	email := "load@user.com"
	now := time.Now().UTC()
	for i := 0; i < 5; i++ {
		recordOrderEntry(t, s, email, "place_order", 1, 1000, now.Add(-time.Duration(i)*time.Hour))
	}

	// Prime cache.
	_, _, _ = s.UserOrderStats(email, 30)
	baseline := atomic.LoadUint64(&s.statsCache.hits)

	// 10 more calls, all should hit.
	for i := 0; i < 10; i++ {
		_, _, _ = s.UserOrderStats(email, 30)
	}
	after := atomic.LoadUint64(&s.statsCache.hits)
	assert.Equal(t, baseline+10, after, "10 follow-up UserOrderStats calls should all hit")
}
