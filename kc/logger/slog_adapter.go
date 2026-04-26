package logger

import (
	"context"
	"log/slog"
)

// slogAdapter is the production Logger implementation: a thin wrapper
// over *slog.Logger that preserves slog's full feature set (handlers,
// levels, structured attributes, request-scoped With chains).
//
// The adapter intentionally delegates to slog.Logger.LogAttrs / Log
// rather than the convenience wrappers (Info, Warn, …) so the
// `runtime.Caller` skip frame remains correct when slog records the
// call site (HandlerOptions.AddSource = true). Without this, every log
// line points at slog_adapter.go instead of the real call site, which
// makes the slog ouput effectively useless for triage.
//
// The errorKey constant is the canonical attribute name for the err
// argument of Error. We keep it in lockstep with the rest of the
// codebase, where every existing call site already uses "error" for
// the wrapped error value (e.g. logger.Error("foo failed", "error", err)).
type slogAdapter struct {
	l *slog.Logger
}

const errorKey = "error"

// NewSlog wraps an *slog.Logger as a Logger port. A nil input is
// replaced by slog.Default() so callers don't have to nil-check before
// constructing — the canonical "no logger configured" path still works
// (output goes to slog's default handler).
func NewSlog(l *slog.Logger) Logger {
	if l == nil {
		l = slog.Default()
	}
	return &slogAdapter{l: l}
}

// log forwards to slog with the correct context and level. We use
// slog.Logger.Log so the variadic args are interpreted exactly as a
// caller would expect from a direct slog.Info etc. call.
func (a *slogAdapter) log(ctx context.Context, level slog.Level, msg string, args ...any) {
	if !a.l.Enabled(ctx, level) {
		return
	}
	a.l.Log(ctx, level, msg, args...)
}

func (a *slogAdapter) Debug(ctx context.Context, msg string, args ...any) {
	a.log(ctx, slog.LevelDebug, msg, args...)
}

func (a *slogAdapter) Info(ctx context.Context, msg string, args ...any) {
	a.log(ctx, slog.LevelInfo, msg, args...)
}

func (a *slogAdapter) Warn(ctx context.Context, msg string, args ...any) {
	a.log(ctx, slog.LevelWarn, msg, args...)
}

// Error attaches err under the canonical "error" key, then forwards.
// When err is nil we still emit an Error-level record but skip the key
// — never lie about an error existing. Callers should reach for Warn
// instead when there's no concrete error object.
func (a *slogAdapter) Error(ctx context.Context, msg string, err error, args ...any) {
	if err != nil {
		args = append(args, errorKey, err)
	}
	a.log(ctx, slog.LevelError, msg, args...)
}

// With chains via slog.Logger.With and re-wraps. The returned Logger
// shares no mutable state with the receiver — slog.Logger.With clones
// the underlying handler, so concurrent writes from the parent and
// child are safe.
func (a *slogAdapter) With(args ...any) Logger {
	return &slogAdapter{l: a.l.With(args...)}
}

// Slog exposes the underlying *slog.Logger for the rare case a caller
// must hand a slog.Logger to a third-party API. New code should depend
// on Logger; this is an escape hatch for incremental migration.
func (a *slogAdapter) Slog() *slog.Logger {
	return a.l
}

// AsSlog returns the *slog.Logger from a Logger when the underlying
// implementation is a slogAdapter, otherwise nil. Used by the few
// remaining call sites that have to bridge to a slog-typed parameter
// during incremental migration. Returning nil rather than panicking
// keeps mock-Logger tests from blowing up if they hit a not-yet-
// migrated branch.
func AsSlog(l Logger) *slog.Logger {
	if a, ok := l.(*slogAdapter); ok {
		return a.l
	}
	return nil
}
