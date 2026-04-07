package mcp

import (
	"strings"
	"time"
)

// RetryBrokerCall retries a broker operation up to maxRetries times with exponential backoff.
// Only retries on transient errors (network, timeout). Does NOT retry on auth or validation errors.
func RetryBrokerCall[T any](fn func() (T, error), maxRetries int) (T, error) {
	var lastErr error
	var zero T
	for i := 0; i <= maxRetries; i++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		if !isTransientError(err) {
			return zero, err
		}
		lastErr = err
		if i < maxRetries {
			time.Sleep(time.Duration(100*(1<<i)) * time.Millisecond) // 100ms, 200ms, 400ms
		}
	}
	return zero, lastErr
}

func isTransientError(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "timeout") ||
		strings.Contains(msg, "connection") ||
		strings.Contains(msg, "temporary") ||
		strings.Contains(msg, "unavailable") ||
		strings.Contains(msg, "eof")
}
