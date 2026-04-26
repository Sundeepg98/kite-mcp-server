package logger

import "context"

// noopLogger discards every record. It is the canonical fixture for
// tests that don't care about log output — drop it into a constructor
// that requires a Logger and the test stays parallel-safe (no slog
// SetDefault races, no captured-os.Stderr races).
type noopLogger struct{}

// NewNoop returns a Logger that discards every record.
//
// Cheaper than NewSlog(slog.New(slog.NewTextHandler(io.Discard, nil)))
// because it short-circuits before any allocation — the slog path
// still allocates the slog.Record, formats the time, walks the args
// slice, etc., even when the handler is io.Discard. For a hot test
// loop the difference is real.
func NewNoop() Logger { return noopLogger{} }

func (noopLogger) Debug(_ context.Context, _ string, _ ...any)        {}
func (noopLogger) Info(_ context.Context, _ string, _ ...any)         {}
func (noopLogger) Warn(_ context.Context, _ string, _ ...any)         {}
func (noopLogger) Error(_ context.Context, _ string, _ error, _ ...any) {}

// With on a noop logger trivially returns the same noop — there is
// no state to carry forward.
func (n noopLogger) With(_ ...any) Logger { return n }
