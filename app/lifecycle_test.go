package app

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestLifecycleManager_AppendOrderRespected proves the FIFO-on-append
// contract: workers registered in start order are torn down in the same
// order. This mirrors the production graceful-shutdown sequence (scheduler
// before audit before kcManager). A LIFO would silently invert it.
func TestLifecycleManager_AppendOrderRespected(t *testing.T) {
	t.Parallel()
	var seq []string
	lm := NewLifecycleManager(testLogger())
	lm.Append("first", func() error { seq = append(seq, "first"); return nil })
	lm.Append("second", func() error { seq = append(seq, "second"); return nil })
	lm.Append("third", func() error { seq = append(seq, "third"); return nil })
	lm.Shutdown()
	assert.Equal(t, []string{"first", "second", "third"}, seq)
}

// TestLifecycleManager_ShutdownIsIdempotent proves the sync.Once guard.
// Production calls Shutdown from both the initializeServices success-defer
// AND the graceful-shutdown signal handler — the second call must no-op
// rather than re-running every stop (which would crash on already-closed
// channels, double-Shutdown calls into kcManager, etc.).
func TestLifecycleManager_ShutdownIsIdempotent(t *testing.T) {
	t.Parallel()
	var calls int32
	lm := NewLifecycleManager(testLogger())
	lm.Append("one", func() error { atomic.AddInt32(&calls, 1); return nil })
	lm.Shutdown()
	lm.Shutdown()
	lm.Shutdown()
	assert.Equal(t, int32(1), atomic.LoadInt32(&calls))
}

// TestLifecycleManager_PanicInOneStopDoesNotAbortChain proves the recover
// posture: a buggy stop func that panics MUST NOT prevent later stops from
// running. Otherwise a single misbehaving worker holds the whole graceful
// shutdown hostage and tests that exercise leak sentinels timeout.
func TestLifecycleManager_PanicInOneStopDoesNotAbortChain(t *testing.T) {
	t.Parallel()
	var ranAfterPanic bool
	lm := NewLifecycleManager(testLogger())
	lm.Append("panicker", func() error { panic("boom") })
	lm.Append("after", func() error { ranAfterPanic = true; return nil })
	lm.Shutdown()
	assert.True(t, ranAfterPanic, "stop after panicker must still run")
}

// TestLifecycleManager_ErrorInStopLogsButContinues proves error-tolerance:
// a stop returning an error is logged but the chain continues. Same
// rationale as panic recovery — partial-failure shouldn't block teardown.
func TestLifecycleManager_ErrorInStopLogsButContinues(t *testing.T) {
	t.Parallel()
	var ranAfterError bool
	lm := NewLifecycleManager(testLogger())
	lm.Append("errored", func() error { return errors.New("db busy") })
	lm.Append("after", func() error { ranAfterError = true; return nil })
	lm.Shutdown()
	assert.True(t, ranAfterError)
}

// TestLifecycleManager_NilStopIgnored proves Append's nil-guard. Callers
// that conditionally allocate a worker (`if alertDB != nil { ... }`) can
// pass the cancel func unconditionally; nil cleanly no-ops.
func TestLifecycleManager_NilStopIgnored(t *testing.T) {
	t.Parallel()
	lm := NewLifecycleManager(testLogger())
	lm.Append("nil-stop", nil)
	lm.Shutdown() // must not panic
}

