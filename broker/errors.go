package broker

import (
	"fmt"
	"time"
)

// RateLimitError indicates the upstream broker has throttled the request
// with HTTP 429 (or an equivalent typed error). Callers can detect it via:
//
//	var rle *broker.RateLimitError
//	if errors.As(err, &rle) { /* react: backoff, freeze risk-guard, alert */ }
//
// This error type is broker-agnostic — every broker adapter is expected to
// classify and wrap 429-equivalent throttling responses into this type so
// downstream consumers (riskguard auto-freeze, retry middleware, telegram
// notifier) need not know which broker produced the throttle.
//
// Backward compatibility: RateLimitError wraps the original error via
// Unwrap(), so callers using untyped `if err != nil` paths continue to
// work — the underlying error is still surfaced via errors.Is.
type RateLimitError struct {
	// RetryAfter is the parsed Retry-After header value if the broker
	// surfaced one; otherwise zero. Callers should treat zero as
	// "unknown — fall back to the caller's default backoff".
	RetryAfter time.Duration

	// Endpoint is the logical broker operation that was throttled
	// (e.g. "place_order", "get_quotes"). Free-form, used for logs
	// and metrics labels.
	Endpoint string

	// Inner is the original error from the broker SDK. Preserved so
	// callers can still inspect details (status text, error type, etc).
	Inner error
}

// Error formats the rate-limit error for human consumption (logs/audit).
func (e *RateLimitError) Error() string {
	if e.RetryAfter > 0 {
		return fmt.Sprintf("broker rate limit on %s (retry after %s): %v", e.Endpoint, e.RetryAfter, e.Inner)
	}
	return fmt.Sprintf("broker rate limit on %s: %v", e.Endpoint, e.Inner)
}

// Unwrap returns the underlying broker error so errors.Is and errors.As
// can drill through to the SDK-level cause.
func (e *RateLimitError) Unwrap() error { return e.Inner }
