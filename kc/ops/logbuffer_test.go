package ops

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLogBufferAddAndRecent(t *testing.T) {
	lb := NewLogBuffer(5)

	// Empty buffer
	assert.Nil(t, lb.Recent(10))

	// Add entries
	for i := 0; i < 3; i++ {
		lb.Add(LogEntry{Time: time.Now(), Level: "INFO", Message: "msg"})
	}
	entries := lb.Recent(10)
	assert.Len(t, entries, 3)
}

func TestLogBufferRingOverflow(t *testing.T) {
	lb := NewLogBuffer(3)

	// Add 5 entries to a buffer of capacity 3
	for i := 0; i < 5; i++ {
		lb.Add(LogEntry{Message: string(rune('a' + i))})
	}

	// Should only keep the last 3
	entries := lb.Recent(10)
	require.Len(t, entries, 3)
	assert.Equal(t, "c", entries[0].Message)
	assert.Equal(t, "d", entries[1].Message)
	assert.Equal(t, "e", entries[2].Message)
}

func TestLogBufferRecentOrder(t *testing.T) {
	lb := NewLogBuffer(10)
	lb.Add(LogEntry{Message: "first"})
	lb.Add(LogEntry{Message: "second"})
	lb.Add(LogEntry{Message: "third"})

	entries := lb.Recent(2)
	require.Len(t, entries, 2)
	// Chronological: second, third (most recent 2)
	assert.Equal(t, "second", entries[0].Message)
	assert.Equal(t, "third", entries[1].Message)
}

func TestLogBufferListener(t *testing.T) {
	lb := NewLogBuffer(10)

	ch := lb.AddListener("test")
	defer lb.RemoveListener("test")

	lb.Add(LogEntry{Message: "hello"})

	select {
	case entry := <-ch:
		assert.Equal(t, "hello", entry.Message)
	case <-time.After(time.Second):
		t.Fatal("listener did not receive entry")
	}
}

func TestLogBufferRemoveListenerCloses(t *testing.T) {
	lb := NewLogBuffer(10)

	ch := lb.AddListener("test")
	lb.RemoveListener("test")

	// Channel should be closed
	_, ok := <-ch
	assert.False(t, ok, "channel should be closed after RemoveListener")
}

func TestLogBufferMultipleListeners(t *testing.T) {
	lb := NewLogBuffer(10)

	ch1 := lb.AddListener("l1")
	ch2 := lb.AddListener("l2")
	defer lb.RemoveListener("l1")
	defer lb.RemoveListener("l2")

	lb.Add(LogEntry{Message: "broadcast"})

	select {
	case e := <-ch1:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("listener 1 did not receive")
	}

	select {
	case e := <-ch2:
		assert.Equal(t, "broadcast", e.Message)
	case <-time.After(time.Second):
		t.Fatal("listener 2 did not receive")
	}
}

func TestLogBufferSlowListener(t *testing.T) {
	lb := NewLogBuffer(10)

	// Create listener with small buffer (default is 100, but we test drop behavior)
	ch := lb.AddListener("slow")
	defer lb.RemoveListener("slow")

	// Fill the channel buffer (100 entries)
	for i := 0; i < 100; i++ {
		lb.Add(LogEntry{Message: "fill"})
	}

	// 101st entry should be dropped (non-blocking send)
	lb.Add(LogEntry{Message: "dropped"})

	// Drain and verify we got 100 entries
	count := 0
	for {
		select {
		case <-ch:
			count++
		default:
			goto done
		}
	}
done:
	assert.Equal(t, 100, count)
}
