package app

import (
	"log/slog"
	"sync"
)

// LifecycleManager owns the ordered teardown of background workers wired
// during initializeServices. It exists for two reasons:
//
//  1. Single source of truth — before this type, the same teardown sequence
//     was hand-maintained in four places (wire.go's success-defer, app.go's
//     RunServer error-path defer, http.go's setupGracefulShutdown, and
//     helpers_test.go's cleanupInitializeServices). They had drifted
//     (wire.go was missing outboxPump, telegramBot, oauthHandler, rateLimiters,
//     and metrics shutdowns) — a class of bug that goroutine-leak audits
//     surface as "background worker still running after test exit".
//
//  2. Wire/fx amenability — a forthcoming DI container migration (Investment A
//     in .research/agent-concurrency-decoupling-plan.md) needs lifecycle
//     OUTSIDE the constructor graph. Wire generates straight-line
//     construction with no cleanup-on-failure; fx has lifecycle hooks but
//     adds runtime DI tax. Either way, by the time the DI container
//     replaces parts of initializeServices, the lifecycle order will
//     already live in one place — this struct — and not need to be
//     re-encoded from scratch.
//
// Contract:
//   - Append registers a stop func. The order of Append calls determines
//     the order of Shutdown invocation: FIRST appended runs FIRST on
//     teardown. Callers append in the order workers are started, which
//     mirrors the production setupGracefulShutdown sequence.
//   - Shutdown invokes every registered stop in append order, recovering
//     from panics so a buggy stop function cannot block the rest. Idempotent
//     via sync.Once — safe to call from both the success-defer in
//     initializeServices AND the graceful-shutdown handler in http.go.
//   - Each registered stop function MUST be idempotent itself (typically
//     sync.Once-guarded or nil-checked) — Shutdown does not double-guard
//     individual stops.
//
// Non-goals:
//   - Concurrent Shutdown: not designed for parallel teardown. Each stop
//     runs synchronously to preserve ordering semantics (e.g., HTTP server
//     drains before audit store stops, otherwise in-flight requests
//     enqueue audit entries after the writer has stopped).
//   - Error aggregation: stop funcs return error but Shutdown logs and
//     continues. A stop failure does not abort the rest of the chain.
type LifecycleManager struct {
	mu     sync.Mutex
	stops  []namedStop
	once   sync.Once
	logger *slog.Logger
}

type namedStop struct {
	name string
	fn   func() error
}

// NewLifecycleManager constructs an empty manager. Logger is used only to
// surface stop-func failures during Shutdown — pass app.logger.
func NewLifecycleManager(logger *slog.Logger) *LifecycleManager {
	return &LifecycleManager{logger: logger}
}

// Append registers a named stop function. Order matters: first appended
// runs first on Shutdown. Pass a name purely for log-surface readability
// when a stop fails or panics.
//
// fn may return error or nil; nil-returning stops are valid for one-shot
// channels (Cancel(), close(ch)). The name is logged on panic recovery
// so an operator can pinpoint a buggy stop without a stack search.
//
// Safe to call concurrently with other Appends but NOT with Shutdown
// (Shutdown takes a read snapshot under the mutex; appending during
// shutdown produces undefined ordering).
func (lm *LifecycleManager) Append(name string, fn func() error) {
	if fn == nil {
		return
	}
	lm.mu.Lock()
	defer lm.mu.Unlock()
	lm.stops = append(lm.stops, namedStop{name: name, fn: fn})
}

// Shutdown invokes every registered stop in append order. Idempotent via
// sync.Once — calling from both the error-path defer AND the
// graceful-shutdown signal handler is safe; the second call is a no-op.
//
// Panics in individual stop funcs are recovered and logged; the chain
// continues. An error returned by a stop func is logged but does not
// abort the chain — every later stop still runs. This is the right
// posture for graceful-shutdown: a partial failure (e.g., DB busy
// during audit-store stop) should still let the HTTP server drain and
// the OS reclaim the rest of the process.
func (lm *LifecycleManager) Shutdown() {
	lm.once.Do(func() {
		lm.mu.Lock()
		stops := append([]namedStop(nil), lm.stops...)
		lm.mu.Unlock()
		for _, s := range stops {
			lm.runOne(s)
		}
	})
}

func (lm *LifecycleManager) runOne(s namedStop) {
	defer func() {
		if r := recover(); r != nil && lm.logger != nil {
			lm.logger.Error("lifecycle stop panicked", "name", s.name, "panic", r)
		}
	}()
	if err := s.fn(); err != nil && lm.logger != nil {
		lm.logger.Error("lifecycle stop failed", "name", s.name, "error", err)
	}
}
