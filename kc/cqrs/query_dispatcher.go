package cqrs

import (
	"context"
	"log/slog"
	"sync"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// QueryAuditHook is called after every query use case execution for observability.
// It receives the query type name, the user email, the execution duration in
// milliseconds, and any error returned by the query handler.
type QueryAuditHook func(queryType string, email string, durationMs int64, err error)

// QueryDispatcher provides observability for the read side of CQRS.
// It accepts audit hooks that are invoked after each query execution,
// enabling logging, metrics collection, and alerting on slow or failed reads.
//
// Thread-safe: hooks can be added concurrently with Dispatch calls.
//
// Wave D Phase 3 Package 7c-1 (Logger sweep): logger field carries the
// kc/logger.Logger port. Constructor keeps *slog.Logger for backward-
// compat with existing callers (app/wire.go, tests) and wraps via
// logport.NewSlog at the boundary.
type QueryDispatcher struct {
	mu     sync.RWMutex
	hooks  []QueryAuditHook
	logger logport.Logger
}

// NewQueryDispatcher creates a QueryDispatcher with the given logger.
// If logger is nil, error logging is skipped (hooks still fire).
//
// Public signature preserves the *slog.Logger parameter for backward-
// compat; the value is wrapped via logport.NewSlog so the internal
// log path uses the typed port.
func NewQueryDispatcher(logger *slog.Logger) *QueryDispatcher {
	if logger == nil {
		return &QueryDispatcher{}
	}
	return &QueryDispatcher{logger: logport.NewSlog(logger)}
}

// AddHook registers an audit hook that will be called on every Dispatch.
// Hooks are called in the order they were registered.
func (d *QueryDispatcher) AddHook(hook QueryAuditHook) {
	d.mu.Lock()
	defer d.mu.Unlock()
	d.hooks = append(d.hooks, hook)
}

// Dispatch notifies all registered hooks of a completed query execution
// and logs errors via the configured logger.
func (d *QueryDispatcher) Dispatch(queryType string, email string, durationMs int64, err error) {
	d.mu.RLock()
	hooks := make([]QueryAuditHook, len(d.hooks))
	copy(hooks, d.hooks)
	d.mu.RUnlock()

	for _, hook := range hooks {
		hook(queryType, email, durationMs, err)
	}

	if d.logger != nil {
		// QueryDispatcher.Dispatch has no ctx parameter (signature stable
		// for ~20 callers). Use context.Background() at the log boundary
		// per the helper-function convention used elsewhere
		// (kc/usecases/account_usecases.appendRevokedEvent precedent).
		if err != nil {
			d.logger.Error(context.Background(), "Query failed", err,
				"type", queryType,
				"email", email,
				"duration_ms", durationMs,
			)
		} else {
			d.logger.Debug(context.Background(), "Query executed",
				"type", queryType,
				"email", email,
				"duration_ms", durationMs,
			)
		}
	}
}
