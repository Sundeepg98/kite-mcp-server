package mcp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestToolCache_SetGet(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	t.Cleanup(c.Close)
	c.Set("key1", "value1")

	val, ok := c.Get("key1")
	assert.True(t, ok)
	assert.Equal(t, "value1", val)
}

func TestToolCache_Expiry(t *testing.T) {
	t.Parallel()
	c := NewToolCache(50 * time.Millisecond)
	t.Cleanup(c.Close)
	c.Set("key1", "value1")

	time.Sleep(100 * time.Millisecond)

	_, ok := c.Get("key1")
	assert.False(t, ok, "should be expired")
}

func TestToolCache_Miss(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	t.Cleanup(c.Close)
	_, ok := c.Get("nonexistent")
	assert.False(t, ok)
}

func TestToolCache_Clear(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	t.Cleanup(c.Close)
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

// TestToolCache_Close_StopsGoroutine proves Close bounds the caller's
// wait — the cleanup goroutine must exit before Close returns. Without
// a WaitGroup-style join, goleak sentinels race the goroutine's exit.
func TestToolCache_Close_StopsGoroutine(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	t.Cleanup(c.Close)

	done := make(chan struct{})
	go func() {
		c.Close()
		close(done)
	}()
	select {
	case <-done:
		// success — Close observed doneCh signal from the goroutine
	case <-time.After(3 * time.Second):
		t.Fatal("ToolCache.Close did not return within 3s — goroutine Join likely blocked")
	}
}

// TestToolCache_Close_Idempotent verifies multiple Close calls don't
// panic (stopOnce guards close of stopCh; doneCh is closed exactly once
// by the goroutine, which Close reads from — reads on closed chan are
// always successful).
func TestToolCache_Close_Idempotent(t *testing.T) {
	t.Parallel()
	c := NewToolCache(1 * time.Second)
	t.Cleanup(c.Close)
	c.Close()
	c.Close() // second call must not panic on close-of-closed-channel
	c.Close() // third call exercises stopOnce-guard fast path
}
