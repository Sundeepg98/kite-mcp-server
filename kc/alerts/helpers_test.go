package alerts

// helpers_test.go — shared test infrastructure for the kc/alerts package.
// Consolidates helpers that were previously scattered across alert test files
// and aligns the package on testutil.DiscardLogger as the shared no-op logger.

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/testutil"
)

// testLogger returns a discard logger shared across the alerts test suite. It
// delegates to testutil.DiscardLogger so every package converges on the same
// no-op logger fixture.
func testLogger() *slog.Logger {
	return testutil.DiscardLogger()
}

// newTestStore creates a Store with no notify callback (suitable for most
// tests). It lives here so every alerts_*_test.go file can call it without
// re-declaring the factory.
func newTestStore() *Store {
	return NewStore(nil)
}
