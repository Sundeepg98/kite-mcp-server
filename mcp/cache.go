package mcp

import (
	"container/list"
	"sync"
	"time"
)

// ToolCache provides a simple TTL cache for read-heavy tool responses.
// Keyed by tool name + email + serialized args hash.
//
// Background goroutine lifecycle: NewToolCache spawns a cleanup goroutine
// that runs until Close() is called. Production uses a package-level
// singleton (ltpCache) that lives for the process lifetime; tests can
// construct their own caches and call Close() to release the goroutine.
//
// Bounded LRU (PR-E): when maxEntries > 0, Set evicts the least-
// recently-used entry once size hits the cap. Touching a key via Get
// or re-Set promotes it to most-recently-used. Pass maxEntries=0 to
// the constructor for the legacy unbounded behaviour (NewToolCache
// retains that path for back-compat). Eviction order is maintained by
// container/list — O(1) per operation, no per-Set allocation churn.
type ToolCache struct {
	mu          sync.RWMutex
	entries     map[string]*list.Element // points at lruList nodes
	lruList     *list.List               // front = MRU, back = LRU
	ttl         time.Duration
	maxEntries  int // 0 = unbounded
	stopCh      chan struct{}
	stopOnce    sync.Once
	doneCh      chan struct{}
}

// cacheEntry is the *list.Element value type. It carries the key so
// eviction (which only has the back-of-list element) can find and delete
// the corresponding map entry without a reverse lookup.
type cacheEntry struct {
	key       string
	data      any
	expiresAt time.Time
}

// NewToolCache creates an UNBOUNDED cache with the given TTL. Existing
// callers (the package-level ltpCache singleton) keep working unchanged.
// Prefer NewBoundedToolCache for new caches that risk unbounded growth.
func NewToolCache(ttl time.Duration) *ToolCache {
	return NewBoundedToolCache(ttl, 0)
}

// NewBoundedToolCache creates a TTL cache that also evicts via LRU once
// size reaches maxEntries. Pass maxEntries=0 (or negative) to opt out
// of the size cap — equivalent to NewToolCache.
//
// Choosing maxEntries: 1000 is the production default for ltpCache —
// each LTP entry is ~200B, so 1000 = ~200KB of cache footprint. A
// hostile or runaway caller can no longer drive the cache to OOM.
func NewBoundedToolCache(ttl time.Duration, maxEntries int) *ToolCache {
	if maxEntries < 0 {
		maxEntries = 0
	}
	c := &ToolCache{
		entries:    make(map[string]*list.Element),
		lruList:    list.New(),
		ttl:        ttl,
		maxEntries: maxEntries,
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}
	go func() {
		defer close(c.doneCh)
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-c.stopCh:
				return
			case <-ticker.C:
				c.cleanup()
			}
		}
	}()
	return c
}

// Close stops the background cleanup goroutine and waits for it to exit.
// Safe to call multiple times — stopOnce guards the stopCh close, and
// the doneCh read is idempotent (reads from a closed channel always
// succeed). Callers that need a bounded wait should use CloseWithTimeout.
func (c *ToolCache) Close() {
	c.stopOnce.Do(func() {
		close(c.stopCh)
	})
	<-c.doneCh
}

// Get retrieves a cached value. Returns nil if not found or expired.
// On hit, promotes the entry to MRU (front of the LRU list) so a
// subsequent eviction targets a colder key.
//
// We take the write-lock here rather than the read-lock because
// MoveToFront mutates the list. The previous version's RLock was a
// micro-optimisation that doesn't survive bounded-LRU semantics —
// reads are still fast (single map lookup + list-pointer rewire).
func (c *ToolCache) Get(key string) (any, bool) {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return nil, false
	}
	entry := elem.Value.(*cacheEntry)
	if now.After(entry.expiresAt) {
		// Expired — clean up eagerly so size stays accurate.
		c.lruList.Remove(elem)
		delete(c.entries, key)
		return nil, false
	}
	c.lruList.MoveToFront(elem)
	return entry.data, true
}

// Set stores a value with the configured TTL. If the key already
// exists, the value is updated and the entry promoted to MRU.
// Otherwise a new entry is inserted at the front of the LRU list,
// and if maxEntries > 0 and size exceeds the cap, the back-most
// (LRU) entry is evicted to make room.
func (c *ToolCache) Set(key string, data any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	expiresAt := time.Now().Add(c.ttl)
	if elem, ok := c.entries[key]; ok {
		entry := elem.Value.(*cacheEntry)
		entry.data = data
		entry.expiresAt = expiresAt
		c.lruList.MoveToFront(elem)
		return
	}
	entry := &cacheEntry{key: key, data: data, expiresAt: expiresAt}
	elem := c.lruList.PushFront(entry)
	c.entries[key] = elem
	if c.maxEntries > 0 && c.lruList.Len() > c.maxEntries {
		// Evict the LRU entry. Back of list is oldest.
		oldest := c.lruList.Back()
		if oldest != nil {
			oldEntry := oldest.Value.(*cacheEntry)
			c.lruList.Remove(oldest)
			delete(c.entries, oldEntry.key)
		}
	}
}

// cleanup removes expired entries. Walks the entire list under the
// write-lock; runs every 5 minutes from the goroutine spawned in the
// constructor. The work is O(n) but n is capped by maxEntries so the
// pause stays bounded.
func (c *ToolCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	// Iterate via the list so we can safely remove while walking.
	for elem := c.lruList.Front(); elem != nil; {
		next := elem.Next()
		entry := elem.Value.(*cacheEntry)
		if now.After(entry.expiresAt) {
			c.lruList.Remove(elem)
			delete(c.entries, entry.key)
		}
		elem = next
	}
}

// Size returns the number of cached entries.
func (c *ToolCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// Clear removes all entries.
func (c *ToolCache) Clear() {
	c.mu.Lock()
	c.entries = make(map[string]*list.Element)
	c.lruList = list.New()
	c.mu.Unlock()
}

// CacheKey builds a cache key from tool name, email, and a distinguishing suffix.
func CacheKey(toolName, email, suffix string) string {
	return toolName + ":" + email + ":" + suffix
}

// expireForTest forces a known key's expiry timestamp. Test-only seam
// for cleanup-path coverage that needs an entry the cleanup loop will
// see as expired RIGHT NOW without a sleep. Returns true when the key
// existed and was rewritten; false when no such key.
//
// Lowercased package-private name + _ForTest suffix so production code
// won't reach for it; if it ever moves to a public API a build tag is
// the next defence. Located on the cache itself so the test doesn't
// have to peer through reflection.
func (c *ToolCache) expireForTest(key string, expiresAt time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	elem, ok := c.entries[key]
	if !ok {
		return false
	}
	elem.Value.(*cacheEntry).expiresAt = expiresAt
	return true
}
