package logger

import (
	"context"
	"sync"
)

// CaptureRecord is a single observed log call. CaptureLogger appends
// one of these per Debug/Info/Warn/Error invocation. Args is the raw
// variadic slice the caller passed (for Error, the err is implicitly
// appended after "error" — exactly mirroring slogAdapter.Error so a
// CaptureLogger test exercises the same code path).
type CaptureRecord struct {
	Level string
	Msg   string
	Args  []any
}

// CaptureLogger is a Logger that records every call into an in-memory
// slice. Useful in tests that want to assert "we logged X" without
// piping through slog handlers / io.Discard / regex matches.
//
// Records is protected by a sync.Mutex so the same logger can be used
// from a goroutine spawned inside the system-under-test. With returns
// a child that shares the SAME mutex + records slice — you can attach
// the parent CaptureLogger and read from it after the system writes
// through any number of child loggers. Each child carries its own
// "with" prefix that gets prepended to every record's Args.
type CaptureLogger struct {
	mu      *sync.Mutex
	records *[]CaptureRecord
	prefix  []any
}

// NewCapture returns an empty CaptureLogger.
func NewCapture() *CaptureLogger {
	mu := &sync.Mutex{}
	rs := make([]CaptureRecord, 0, 8)
	return &CaptureLogger{mu: mu, records: &rs}
}

// Records returns a snapshot copy of all observed records. Safe to
// call concurrently with logger writes; the returned slice is
// independent of the live buffer.
func (c *CaptureLogger) Records() []CaptureRecord {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]CaptureRecord, len(*c.records))
	copy(out, *c.records)
	return out
}

func (c *CaptureLogger) append(level, msg string, args []any) {
	all := make([]any, 0, len(c.prefix)+len(args))
	all = append(all, c.prefix...)
	all = append(all, args...)
	c.mu.Lock()
	*c.records = append(*c.records, CaptureRecord{Level: level, Msg: msg, Args: all})
	c.mu.Unlock()
}

func (c *CaptureLogger) Debug(_ context.Context, msg string, args ...any) {
	c.append("debug", msg, args)
}

func (c *CaptureLogger) Info(_ context.Context, msg string, args ...any) {
	c.append("info", msg, args)
}

func (c *CaptureLogger) Warn(_ context.Context, msg string, args ...any) {
	c.append("warn", msg, args)
}

func (c *CaptureLogger) Error(_ context.Context, msg string, err error, args ...any) {
	if err != nil {
		args = append(args, errorKey, err)
	}
	c.append("error", msg, args)
}

// With produces a child CaptureLogger that prefixes every record's
// Args with the supplied pairs. Records are recorded into the same
// underlying slice — there's only one buffer per Capture root.
func (c *CaptureLogger) With(args ...any) Logger {
	combined := make([]any, 0, len(c.prefix)+len(args))
	combined = append(combined, c.prefix...)
	combined = append(combined, args...)
	return &CaptureLogger{mu: c.mu, records: c.records, prefix: combined}
}
