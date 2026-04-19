package mcp

import (
	"sync"
	"testing"
)

// testDefaultRegistryMu serializes access to DefaultRegistry from
// parallel tests. Tests that mutate DefaultRegistry (register a
// widget, fire a hook, record health) and want to run under
// t.Parallel() MUST acquire this mutex at the top of the test via
// LockDefaultRegistryForTest — otherwise two parallel tests
// will race on the same map.
//
// This is a transitional mechanism. The strategic path is:
//
//   - New tests construct a fresh *Registry via NewRegistry() and
//     call methods on it — zero shared state, no locking needed,
//     true parallelism.
//   - Existing tests that call the free functions (RegisterWidget,
//     OnToolExecution, etc.) hit DefaultRegistry and must serialise
//     through this mutex.
//
// The mutex is CONDITIONALLY compiled (this file has _test in its
// build semantics? — actually no, we keep it in a regular file
// because LockDefaultRegistryForTest is imported by tests in other
// packages too if needed. The var name is lowercase so it's
// package-private; the function is exported so tests in the same
// package can call it without a test-only build tag.
var testDefaultRegistryMu sync.Mutex

// LockDefaultRegistryForTest acquires the DefaultRegistry-serialising
// mutex and registers a t.Cleanup to release it + reset
// DefaultRegistry state. Tests that use this helper are safe to run
// under t.Parallel() AND safe to call any of the ClearX / Register*
// free functions without racing.
//
// Usage:
//
//     func TestFoo(t *testing.T) {
//         t.Parallel()
//         LockDefaultRegistryForTest(t)
//         RegisterWidget(...)
//         // ...
//     }
//
// The cleanup runs DefaultRegistry.Reset() so the NEXT parallel
// test (which will also grab the same mutex) starts with a clean
// registry.
func LockDefaultRegistryForTest(t *testing.T) {
	t.Helper()
	testDefaultRegistryMu.Lock()
	t.Cleanup(func() {
		DefaultRegistry.Reset()
		testDefaultRegistryMu.Unlock()
	})
}
