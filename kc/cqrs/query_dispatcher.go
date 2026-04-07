package cqrs

import (
	"log/slog"
	"sync"
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
type QueryDispatcher struct {
	mu     sync.RWMutex
	hooks  []QueryAuditHook
	logger *slog.Logger
}

// NewQueryDispatcher creates a QueryDispatcher with the given logger.
// If logger is nil, error logging is skipped (hooks still fire).
func NewQueryDispatcher(logger *slog.Logger) *QueryDispatcher {
	return &QueryDispatcher{logger: logger}
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
		if err != nil {
			d.logger.Error("Query failed",
				"type", queryType,
				"email", email,
				"duration_ms", durationMs,
				"error", err,
			)
		} else {
			d.logger.Debug("Query executed",
				"type", queryType,
				"email", email,
				"duration_ms", durationMs,
			)
		}
	}
}
