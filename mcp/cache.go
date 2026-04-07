package mcp

import (
	"sync"
	"time"
)

// ToolCache provides a simple TTL cache for read-heavy tool responses.
// Keyed by tool name + email + serialized args hash.
type ToolCache struct {
	mu      sync.RWMutex
	entries map[string]*cacheEntry
	ttl     time.Duration
}

type cacheEntry struct {
	data      interface{}
	expiresAt time.Time
}

// NewToolCache creates a cache with the given TTL.
func NewToolCache(ttl time.Duration) *ToolCache {
	c := &ToolCache{
		entries: make(map[string]*cacheEntry),
		ttl:     ttl,
	}
	// Background cleanup every 5 minutes
	go func() {
		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()
		for range ticker.C {
			c.cleanup()
		}
	}()
	return c
}

// Get retrieves a cached value. Returns nil if not found or expired.
func (c *ToolCache) Get(key string) (interface{}, bool) {
	c.mu.RLock()
	entry, ok := c.entries[key]
	c.mu.RUnlock()
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.data, true
}

// Set stores a value with the configured TTL.
func (c *ToolCache) Set(key string, data interface{}) {
	c.mu.Lock()
	c.entries[key] = &cacheEntry{
		data:      data,
		expiresAt: time.Now().Add(c.ttl),
	}
	c.mu.Unlock()
}

// cleanup removes expired entries.
func (c *ToolCache) cleanup() {
	now := time.Now()
	c.mu.Lock()
	for key, entry := range c.entries {
		if now.After(entry.expiresAt) {
			delete(c.entries, key)
		}
	}
	c.mu.Unlock()
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
	c.entries = make(map[string]*cacheEntry)
	c.mu.Unlock()
}

// CacheKey builds a cache key from tool name, email, and a distinguishing suffix.
func CacheKey(toolName, email, suffix string) string {
	return toolName + ":" + email + ":" + suffix
}
