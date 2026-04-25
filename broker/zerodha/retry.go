package zerodha

import (
	"strings"
	"time"
)

// retryOnTransient retries fn up to maxRetries times with exponential
// backoff. Only retries on transient errors:
//
//   - Network: "timeout", "connection", "eof"
//   - HTTP 5xx-equivalent: "502", "503", "504"
//   - HTTP throttle: "429"
//
// Other errors (4xx authentication, 4xx bad request, business-rule
// rejections) propagate immediately — retrying would just compound
// the wrong-input pressure or burn rate-limit headroom.
//
// Backoff schedule: 100ms, 200ms, 400ms, 800ms — exponential with no
// jitter. Production typically uses maxRetries=2, so worst-case wall
// time is 100+200=300ms before final attempt completes.
func retryOnTransient[T any](fn func() (T, error), maxRetries int) (T, error) {
	var lastErr error
	var zero T
	for i := 0; i <= maxRetries; i++ {
		result, err := fn()
		if err == nil {
			return result, nil
		}
		if !isTransientError(err.Error()) {
			return zero, err
		}
		lastErr = err
		if i < maxRetries {
			time.Sleep(time.Duration(100*(1<<i)) * time.Millisecond)
		}
	}
	return zero, lastErr
}

// isTransientError classifies an error message as worth retrying.
// Substring matching (lowercased) — the upstream Kite SDK doesn't
// expose typed errors, so we match the human-readable strings the
// SDK propagates from net/http and its own status-code formatting.
//
// Centralised here so PR-E's HTTP additions live next to the
// pre-existing network keywords, and a future addition (say "503
// upstream") only needs one edit.
func isTransientError(msg string) bool {
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "timeout"),
		strings.Contains(low, "connection"),
		strings.Contains(low, "eof"),
		// HTTP 5xx-equivalent transients (Kite + Cloudflare proxy).
		strings.Contains(low, "502"),
		strings.Contains(low, "503"),
		strings.Contains(low, "504"),
		// HTTP throttle — backoff is the literal correct response.
		strings.Contains(low, "429"):
		return true
	}
	return false
}
