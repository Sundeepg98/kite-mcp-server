package zerodha

import (
	"strings"
	"time"
)

// retryOnTransient retries fn up to maxRetries times with exponential backoff.
// Only retries on transient network errors (timeout, connection, eof).
func retryOnTransient[T any](fn func() (T, error), maxRetries int) (T, error) {
	var lastErr error
	var zero T
	for i := 0; i <= maxRetries; i++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		msg := strings.ToLower(err.Error())
		if !strings.Contains(msg, "timeout") && !strings.Contains(msg, "connection") && !strings.Contains(msg, "eof") {
			return zero, err
		}
		lastErr = err
		if i < maxRetries {
			time.Sleep(time.Duration(100*(1<<i)) * time.Millisecond)
		}
	}
	return zero, lastErr
}
