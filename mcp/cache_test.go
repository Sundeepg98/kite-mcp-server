package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToolCache_SetGet(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	c.Set("key1", "value1")

	val, ok := c.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestToolCache_Expiry(t *testing.T) {
	t.Parallel()
	c := NewToolCache(50 * time.Millisecond)
	c.Set("key1", "value1")

	time.Sleep(100 * time.Millisecond)

	_, ok := c.Get("key1")
	assert.False(t, ok, "should be expired")
}

func TestToolCache_Miss(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
}

func TestToolCache_Clear(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	c.Set("k1", "v1")
	c.Set("k2", "v2")
	assert.Equal(t, 2, c.Size())
	c.Clear()
	assert.Equal(t, 0, c.Size())
}

func TestCacheKey(t *testing.T) {
	t.Parallel()
	key := CacheKey("get_ltp", "user@example.com", "NSE:INFY")
	assert.Equal(t, "get_ltp:user@example.com:NSE:INFY", key)
}
