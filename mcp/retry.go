package mcp

import (
	"github.com/zerodha/kite-mcp-server/mcp/common"
)

// Anchor 1 PR 1.8: RetryBrokerCall + isTransientError moved to
// mcp/common/retry.go so mcp/alerts (and other sub-packages) can call
// it without circular import. mcp/retry.go retains thin wrappers for
// backward-compatibility with the pre-PR test fixtures
// (mcp/tools_pure_retry_test.go) and the in-package callers
// (mcp/ext_apps.go).

// RetryBrokerCall retries a broker operation up to maxRetries times with exponential backoff.
// Only retries on transient errors (network, timeout). Does NOT retry on auth or validation errors.
func RetryBrokerCall[T any](fn func() (T, error), maxRetries int) (T, error) {
	return common.RetryBrokerCall(fn, maxRetries)
}

// isTransientError preserves the legacy lowercase wrapper for in-package
// tests; new code should call common.IsTransientError directly.
func isTransientError(err error) bool {
	return common.IsTransientError(err)
}
