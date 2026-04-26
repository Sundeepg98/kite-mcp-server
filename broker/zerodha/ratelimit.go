package zerodha

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// wrapKiteError classifies an error returned by the Kite SDK and, if it
// represents a 429 throttle, wraps it as a *broker.RateLimitError so
// downstream callers can react via errors.As.
//
// Detection strategy (in priority order):
//
//  1. Typed: errors.As against kiteconnect.Error and check Code == 429.
//     This is the canonical path — the SDK populates Code from the HTTP
//     response status (see http.go readEnvelope).
//
//  2. Substring fallback: lowercased "429" appears in err.Error(). Covers
//     legacy paths where the SDK wraps in plain fmt.Errorf, plus tests
//     that synthesise rate-limit errors as bare strings (see retry_test.go).
//
// Non-429 errors are returned unchanged; callers that just check
// `if err != nil` continue to work without modification. nil returns nil.
//
// Endpoint should be the logical broker operation (e.g. "place_order")
// for log/metrics labelling; it has no effect on classification.
func wrapKiteError(err error, endpoint string) error {
	if err == nil {
		return nil
	}
	if !is429(err) {
		return err
	}
	return &broker.RateLimitError{
		RetryAfter: parseRetryAfter(err),
		Endpoint:   endpoint,
		Inner:      err,
	}
}

// is429 returns true if err represents an HTTP 429 throttle response from
// the Kite API. Checks the typed kiteconnect.Error first, then a defensive
// substring match for legacy / wrapped-error paths.
func is429(err error) bool {
	var kerr kiteconnect.Error
	if errors.As(err, &kerr) {
		if kerr.Code == http.StatusTooManyRequests {
			return true
		}
		// Some Kite errors land with Code unset but the message still
		// reflects the throttle — fall through to substring check.
	}
	return strings.Contains(strings.ToLower(err.Error()), "429")
}

// parseRetryAfter scans err.Error() for a Retry-After hint embedded in
// the SDK message. The Kite SDK does not surface response headers in
// the error type, so this is a best-effort heuristic — when no value
// is found we return 0 and let the caller apply its default backoff.
//
// Recognised forms (lowercased): "retry-after: 30" or "retry after 30"
// (numeric seconds). HTTP-date Retry-After values are not supported —
// 99% of Kite responses are integer-seconds.
func parseRetryAfter(err error) time.Duration {
	low := strings.ToLower(err.Error())
	for _, marker := range []string{"retry-after:", "retry-after ", "retry after:", "retry after "} {
		idx := strings.Index(low, marker)
		if idx < 0 {
			continue
		}
		tail := strings.TrimSpace(low[idx+len(marker):])
		// Read the leading integer.
		end := 0
		for end < len(tail) && tail[end] >= '0' && tail[end] <= '9' {
			end++
		}
		if end == 0 {
			continue
		}
		secs, perr := strconv.Atoi(tail[:end])
		if perr != nil || secs <= 0 {
			continue
		}
		return time.Duration(secs) * time.Second
	}
	return 0
}
