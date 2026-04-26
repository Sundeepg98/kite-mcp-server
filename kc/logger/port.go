// Package logger defines a minimal Logger port (hexagonal-style) and a
// few thin adapters around it. The goal is to:
//
//  1. Decouple call sites from the concrete *slog.Logger so tests can
//     swap in a no-op (or a capturing) implementation per test without
//     touching package-level globals — directly enabling agent-side
//     test isolation (one test run, one logger instance, no lingering
//     handler state) and unblocking parallel test execution for any
//     suite that previously serialized on slog.SetDefault.
//  2. Leave the door open to future structured-logging back-ends
//     (zap, zerolog, OpenTelemetry log SDK) without rewriting every
//     call site — only the adapter changes.
//
// Method signatures intentionally mirror slog.Logger's variadic
// `(msg string, args ...any)` shape so the migration is a search-and-
// replace at consumer sites: drop the `*slog.Logger` field type for
// `logger.Logger`, leave the call sites alone. Error is the one
// exception — it lifts `err error` into the signature because the
// existing call-site convention is `logger.Error(msg, "error", err)`,
// which is repetitive and easy to forget; the explicit error parameter
// makes the contract obvious and lets adapters attach the error with a
// canonical key.
//
// This package has zero non-stdlib dependencies, so importing it from
// any kc/* sub-package is acyclic by construction.
package logger

import "context"

// Logger is the minimal structured-logging contract used across the
// codebase. Implementations are required to be safe for concurrent
// use; the canonical adapter (slogAdapter) is, since *slog.Logger is.
//
// `args ...any` follows the slog convention: alternating
// (key string, value any) pairs, or a slog.Attr value, or a slog.Group.
// Adapters MAY normalise these but MUST NOT silently drop them — a
// dropped key is a dropped audit signal.
type Logger interface {
	// Debug logs at debug level. Typically gated by LOG_LEVEL=debug.
	Debug(ctx context.Context, msg string, args ...any)

	// Info logs at info level. The default operational level.
	Info(ctx context.Context, msg string, args ...any)

	// Warn logs at warn level. Used for recoverable anomalies.
	Warn(ctx context.Context, msg string, args ...any)

	// Error logs at error level. err is conventionally attached under
	// the "error" key; pass nil if no error object exists (rare —
	// prefer Warn in that case).
	Error(ctx context.Context, msg string, err error, args ...any)

	// With returns a new Logger that prepends args to every record.
	// Mirrors slog.Logger.With — useful for request-scoped or
	// component-scoped enrichment ("request_id", id; "component",
	// "billing"; etc.).
	With(args ...any) Logger
}
