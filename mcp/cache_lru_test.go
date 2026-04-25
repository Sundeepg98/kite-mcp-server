package mcp

// cache_lru_test.go — TDD-first tests for the bounded-LRU behaviour added
// in PR-E. Each test exercises one observable invariant of the cap+evict
// mechanism. See cache.go for the production code.

import (
	"strconv"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestToolCache_RespectsMaxEntries — when MaxEntries=N and we Set N+1
// keys, the cache evicts the LEAST RECENTLY USED key, keeping size at N.
func TestToolCache_RespectsMaxEntries(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(time.Hour, 3)
	defer c.Close()

	c.Set("a", 1)
	c.Set("b", 2)
	c.Set("c", 3)
	require.Equal(t, 3, c.Size())

	// Touch "a" so "b" becomes least-recently-used.
	_, ok := c.Get("a")
	require.True(t, ok)

	// Insert "d" — must evict "b" (LRU), not "a" (recently touched).
	c.Set("d", 4)
	assert.Equal(t, 3, c.Size())

	_, hasA := c.Get("a")
	_, hasB := c.Get("b")
	_, hasC := c.Get("c")
	_, hasD := c.Get("d")
	assert.True(t, hasA, "a was just touched — must survive")
	assert.False(t, hasB, "b is least-recently-used — must be evicted")
	assert.True(t, hasC)
	assert.True(t, hasD)
}

// TestToolCache_UpdateExisting — Set on a known key updates value AND
// promotes recency without changing the size.
func TestToolCache_UpdateExisting(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(time.Hour, 2)
	defer c.Close()

	c.Set("a", 1)
	c.Set("b", 2)

	// Update "a" — size stays 2, value becomes 99, "a" is now most recent.
	c.Set("a", 99)
	assert.Equal(t, 2, c.Size())
	v, ok := c.Get("a")
	require.True(t, ok)
	assert.Equal(t, 99, v)

	// Adding "c" must evict "b" (now LRU after "a"'s promotion), not "a".
	c.Set("c", 3)
	_, hasA := c.Get("a")
	_, hasB := c.Get("b")
	assert.True(t, hasA)
	assert.False(t, hasB, "b became LRU after a's update — must be evicted")
}

// TestToolCache_ZeroMaxIsUnbounded — passing maxEntries=0 (or negative)
// preserves the original unbounded behaviour. Lets the package-level
// singleton stay backward-compatible if a future caller wants infinite
// cache (and accepts the memory exposure).
func TestToolCache_ZeroMaxIsUnbounded(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(time.Hour, 0)
	defer c.Close()
	for i := 0; i < 1000; i++ {
		c.Set(strconv.Itoa(i), i)
	}
	assert.Equal(t, 1000, c.Size(), "maxEntries=0 must NOT evict")
}

// TestToolCache_TTLStillApplies — bounded cache still honors per-entry
// TTL: an expired entry returns (nil, false) from Get even if it's
// inside the size cap.
func TestToolCache_TTLStillApplies(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(10*time.Millisecond, 100)
	defer c.Close()

	c.Set("k", "v")
	// Immediately readable.
	v, ok := c.Get("k")
	require.True(t, ok)
	assert.Equal(t, "v", v)

	// After TTL expiry, Get reports miss.
	time.Sleep(20 * time.Millisecond)
	_, ok = c.Get("k")
	assert.False(t, ok, "expired entry must miss even when within size cap")
}

// TestToolCache_EvictionPreservesNewest — repeated Set on a single key
// followed by N more inserts must NOT evict the hot key.
func TestToolCache_EvictionPreservesNewest(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(time.Hour, 5)
	defer c.Close()

	c.Set("hot", "value")
	for i := 0; i < 10; i++ {
		// Every Set on "hot" promotes it to MRU.
		c.Set("hot", "value")
		c.Set("filler-"+strconv.Itoa(i), i)
	}
	_, ok := c.Get("hot")
	assert.True(t, ok, "repeatedly-set key must survive eviction churn")
}

// TestToolCache_GetMissNoEviction — Get on a missing key must NOT
// touch the LRU order or evict anything.
func TestToolCache_GetMissNoEviction(t *testing.T) {
	t.Parallel()
	c := NewBoundedToolCache(time.Hour, 2)
	defer c.Close()
	c.Set("a", 1)
	c.Set("b", 2)

	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
	assert.Equal(t, 2, c.Size(), "Get-miss must not change size")

	// Original order preserved: adding "c" evicts "a" (LRU after b's insert).
	c.Set("c", 3)
	_, hasA := c.Get("a")
	_, hasB := c.Get("b")
	assert.False(t, hasA)
	assert.True(t, hasB)
}

// TestNewToolCache_BackwardCompat — the legacy NewToolCache constructor
// still exists and produces an unbounded cache (regression guard for
// the package-level ltpCache wiring).
func TestNewToolCache_BackwardCompat(t *testing.T) {
	t.Parallel()
	c := NewToolCache(time.Hour)
	defer c.Close()

	for i := 0; i < 500; i++ {
		c.Set(strconv.Itoa(i), i)
	}
	assert.Equal(t, 500, c.Size(), "NewToolCache must remain unbounded for back-compat")
}
