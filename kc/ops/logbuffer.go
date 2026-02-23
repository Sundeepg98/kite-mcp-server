package ops

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"
)

// LogEntry represents a single structured log record.
type LogEntry struct {
	Time    time.Time `json:"time"`
	Level   string    `json:"level"`
	Message string    `json:"msg"`
	Attrs   string    `json:"attrs,omitempty"`
}

// LogBuffer is a fixed-capacity ring buffer with pub/sub fan-out for log entries.
type LogBuffer struct {
	mu      sync.RWMutex
	entries []LogEntry
	head    int
	size    int
	bufCap  int

	listenerMu sync.RWMutex
	listeners  map[string]chan LogEntry
}

// NewLogBuffer allocates a ring buffer with the given capacity.
func NewLogBuffer(capacity int) *LogBuffer {
	return &LogBuffer{
		entries:   make([]LogEntry, capacity),
		bufCap:    capacity,
		listeners: make(map[string]chan LogEntry),
	}
}

// Add writes an entry to the ring buffer and fans out to all listeners.
func (lb *LogBuffer) Add(entry LogEntry) {
	lb.mu.Lock()
	lb.entries[lb.head] = entry
	lb.head = (lb.head + 1) % lb.bufCap
	if lb.size < lb.bufCap {
		lb.size++
	}
	lb.mu.Unlock()

	lb.listenerMu.RLock()
	for _, ch := range lb.listeners {
		select {
		case ch <- entry:
		default:
		}
	}
	lb.listenerMu.RUnlock()
}

// Recent returns the last n entries in chronological order.
func (lb *LogBuffer) Recent(n int) []LogEntry {
	lb.mu.RLock()
	defer lb.mu.RUnlock()

	if n > lb.size {
		n = lb.size
	}
	if n == 0 {
		return nil
	}

	result := make([]LogEntry, n)
	start := (lb.head - n + lb.bufCap) % lb.bufCap
	for i := 0; i < n; i++ {
		result[i] = lb.entries[(start+i)%lb.bufCap]
	}
	return result
}

// AddListener registers a buffered channel for streaming new entries.
func (lb *LogBuffer) AddListener(id string) chan LogEntry {
	ch := make(chan LogEntry, 100)
	lb.listenerMu.Lock()
	lb.listeners[id] = ch
	lb.listenerMu.Unlock()
	return ch
}

// RemoveListener unregisters a listener by id and closes its channel.
func (lb *LogBuffer) RemoveListener(id string) {
	lb.listenerMu.Lock()
	ch, exists := lb.listeners[id]
	delete(lb.listeners, id)
	lb.listenerMu.Unlock()
	if exists {
		close(ch)
	}
}

// TeeHandler wraps an slog.Handler and copies every record to a LogBuffer.
type TeeHandler struct {
	inner slog.Handler
	buf   *LogBuffer
}

var _ slog.Handler = (*TeeHandler)(nil)

// NewTeeHandler creates a handler that tees records to both inner and buf.
func NewTeeHandler(inner slog.Handler, buf *LogBuffer) *TeeHandler {
	return &TeeHandler{inner: inner, buf: buf}
}

// Enabled delegates to the inner handler.
func (h *TeeHandler) Enabled(ctx context.Context, level slog.Level) bool {
	return h.inner.Enabled(ctx, level)
}

// Handle extracts attrs from the record, adds a LogEntry to the buffer, and delegates to inner.
func (h *TeeHandler) Handle(ctx context.Context, r slog.Record) error {
	var buf strings.Builder
	r.Attrs(func(a slog.Attr) bool {
		fmt.Fprintf(&buf, "%s=%v ", a.Key, a.Value.Any())
		return true
	})

	entry := LogEntry{
		Time:    r.Time,
		Level:   r.Level.String(),
		Message: r.Message,
		Attrs:   strings.TrimSpace(buf.String()),
	}
	h.buf.Add(entry)

	return h.inner.Handle(ctx, r)
}

// WithAttrs returns a new TeeHandler whose inner handler has the given attrs.
func (h *TeeHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	return &TeeHandler{inner: h.inner.WithAttrs(attrs), buf: h.buf}
}

// WithGroup returns a new TeeHandler whose inner handler uses the given group.
func (h *TeeHandler) WithGroup(name string) slog.Handler {
	return &TeeHandler{inner: h.inner.WithGroup(name), buf: h.buf}
}
