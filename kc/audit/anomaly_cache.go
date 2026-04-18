package audit

import (
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultMaxStatsCacheEntries is the default size cap for statsCache.
//
// Under normal operation the key space is bounded by (active users) *
// (distinct days windows). Active users today are in the hundreds and only
// `days=30` is queried, so we expect real-world len() to sit well below
// this. The cap is defence in depth: a brute-force login loop or a bug in
// email parsing could otherwise grow the cache without bound and OOM the
// process. 10_000 entries is cheap (~1 MB of map+entries on a 64-bit
// runtime) and several orders of magnitude above the expected steady state.
const DefaultMaxStatsCacheEntries = 10_000

// statsCache is a small in-memory TTL cache for UserOrderStats results.
//
// Rationale: UserOrderStats is called on every place_order to evaluate
// the anomaly baseline. The underlying SQL query scans the user's 30-day
// history of order rows, parses JSON, computes mean/stdev. That is not
// free when a user fires orders rapidly.
//
// The baseline itself drifts slowly: one new order changes a 50-sample
// mean by at most 2% in most cases. A 15-minute TTL is more than enough
// to eliminate the repeat-scan burn without materially degrading the
// signal quality. When a new order IS recorded, the Record() hook calls
// Invalidate() for the affected email, so the very next anomaly check
// reflects the new row.
//
// Eviction strategy: TTL + bounded size with random single-entry eviction
// on insert overflow. Entries are lazily evicted on Get() when they are
// stale. When Set() would push len beyond maxEntries, we drop one
// arbitrary entry (Go's map iteration order is randomised, so this is a
// cheap random eviction). We chose random over LRU because the hit-rate
// penalty on overflow is acceptable — overflow only occurs under a DoS /
// bug condition anyway, and proper LRU (container/list) would add
// per-entry bookkeeping for no gain in the common path.
type statsCache struct {
	mu         sync.RWMutex
	entries    map[string]cachedEntry
	ttl        time.Duration
	maxEntries int

	// hits and misses are touched under the lock for correctness with the
	// map state but are also atomically readable so cacheHitRate() can be
	// safely called from monitoring goroutines. Using atomics avoids lock
	// contention on the hot read path for metrics scraping.
	hits   uint64
	misses uint64
}

// cachedEntry is one row in the cache: a snapshot of UserOrderStats output
// plus the wall-clock time it was computed, used for TTL eviction.
type cachedEntry struct {
	mean     float64
	stdev    float64
	count    float64
	storedAt time.Time
}

// newStatsCache constructs an empty TTL cache with the default size cap
// (DefaultMaxStatsCacheEntries). Use newStatsCacheWithSize to override.
func newStatsCache(ttl time.Duration) *statsCache {
	return newStatsCacheWithSize(ttl, DefaultMaxStatsCacheEntries)
}

// newStatsCacheWithSize constructs an empty TTL cache with an explicit
// entry cap. A non-positive maxEntries is rejected and falls back to the
// default — an unbounded or unusable cache is never safer than a bounded
// one, and silently correcting keeps callers simple.
func newStatsCacheWithSize(ttl time.Duration, maxEntries int) *statsCache {
	if maxEntries <= 0 {
		maxEntries = DefaultMaxStatsCacheEntries
	}
	return &statsCache{
		entries:    make(map[string]cachedEntry),
		ttl:        ttl,
		maxEntries: maxEntries,
	}
}

// cacheKey combines email and days into the map key.
func cacheKey(email string, days int) string {
	return fmt.Sprintf("%s:%d", email, days)
}

// Get returns the cached (mean, stdev, count) for the given (email, days)
// if the entry exists and is within TTL. Misses and expired entries return
// ok=false. A nil receiver is treated as a perpetual miss — lets callers
// skip initialisation guards.
func (c *statsCache) Get(email string, days int) (mean, stdev, count float64, ok bool) {
	if c == nil {
		return 0, 0, 0, false
	}
	key := cacheKey(email, days)

	c.mu.RLock()
	e, found := c.entries[key]
	ttl := c.ttl
	c.mu.RUnlock()

	if !found {
		atomic.AddUint64(&c.misses, 1)
		return 0, 0, 0, false
	}
	if time.Since(e.storedAt) > ttl {
		// Lazy eviction: drop the stale entry so repeat misses don't hold
		// memory indefinitely for dormant users.
		c.mu.Lock()
		if cur, stillThere := c.entries[key]; stillThere && cur.storedAt.Equal(e.storedAt) {
			delete(c.entries, key)
		}
		c.mu.Unlock()

		atomic.AddUint64(&c.misses, 1)
		return 0, 0, 0, false
	}

	atomic.AddUint64(&c.hits, 1)
	return e.mean, e.stdev, e.count, true
}

// Set stores a (mean, stdev, count) snapshot in the cache with the current
// time as storedAt. A nil receiver is a no-op.
//
// If inserting would push len(entries) past maxEntries (and the key isn't
// already present, i.e. this is a genuinely new entry), one arbitrary
// existing entry is evicted first. Go's map iteration order is
// pseudo-random per-run, which gives us cheap random eviction without
// per-entry bookkeeping.
func (c *statsCache) Set(email string, days int, mean, stdev, count float64) {
	if c == nil {
		return
	}
	key := cacheKey(email, days)
	c.mu.Lock()
	// Bound the map size. We only need to evict when this is a net-new key
	// AND we're already at the cap — replacing an existing entry leaves
	// len unchanged.
	if _, present := c.entries[key]; !present && len(c.entries) >= c.maxEntries {
		for k := range c.entries {
			delete(c.entries, k)
			break
		}
	}
	c.entries[key] = cachedEntry{
		mean:     mean,
		stdev:    stdev,
		count:    count,
		storedAt: time.Now(),
	}
	c.mu.Unlock()
}

// Invalidate drops every cached entry for the given email, regardless of
// the days window. Called whenever a new order row lands in the audit log
// so the next anomaly check sees the fresh data. A nil receiver is a no-op.
func (c *statsCache) Invalidate(email string) {
	if c == nil {
		return
	}
	prefix := email + ":"
	c.mu.Lock()
	for k := range c.entries {
		if strings.HasPrefix(k, prefix) {
			delete(c.entries, k)
		}
	}
	c.mu.Unlock()
}

// cacheHitRate returns the fraction of Get() calls that resulted in a hit
// over the lifetime of the cache. Returns 0 when no queries have been made
// (or on a nil receiver). Safe to call concurrently with cache operations.
func (c *statsCache) cacheHitRate() float64 {
	if c == nil {
		return 0
	}
	h := atomic.LoadUint64(&c.hits)
	m := atomic.LoadUint64(&c.misses)
	total := h + m
	if total == 0 {
		return 0
	}
	return float64(h) / float64(total)
}
