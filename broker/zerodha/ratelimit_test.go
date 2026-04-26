package zerodha

import (
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// TestWrapKiteError_Classification is the table-driven happy-path:
// confirms wrapKiteError correctly classifies (or refuses to classify)
// the inputs callers will throw at it.
//
// Backward-compat invariant: every output, when unwrapped via
// errors.Is(err, original), must still match the original — so callers
// using untyped `if err != nil` keep working unchanged.
func TestWrapKiteError_Classification(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name           string
		input          error
		wantRateLimit  bool
		wantRetryAfter time.Duration
	}{
		{
			name:           "nil_passthrough",
			input:          nil,
			wantRateLimit:  false,
			wantRetryAfter: 0,
		},
		{
			name:           "kite_429_typed_no_header",
			input:          kiteconnect.Error{Code: http.StatusTooManyRequests, ErrorType: kiteconnect.NetworkError, Message: "Too many requests"},
			wantRateLimit:  true,
			wantRetryAfter: 0,
		},
		{
			name:           "kite_429_typed_with_retry_after",
			input:          kiteconnect.Error{Code: http.StatusTooManyRequests, ErrorType: kiteconnect.NetworkError, Message: "Too many requests; retry-after: 7"},
			wantRateLimit:  true,
			wantRetryAfter: 7 * time.Second,
		},
		{
			name:           "untyped_429_substring",
			input:          fmt.Errorf("kite api: 429 too many requests"),
			wantRateLimit:  true,
			wantRetryAfter: 0,
		},
		{
			name:           "kite_500_not_429",
			input:          kiteconnect.Error{Code: http.StatusInternalServerError, ErrorType: kiteconnect.GeneralError, Message: "Server error"},
			wantRateLimit:  false,
			wantRetryAfter: 0,
		},
		{
			name:           "kite_400_not_429",
			input:          kiteconnect.Error{Code: http.StatusBadRequest, ErrorType: kiteconnect.InputError, Message: "Bad request"},
			wantRateLimit:  false,
			wantRetryAfter: 0,
		},
		{
			name:           "untyped_other_error",
			input:          fmt.Errorf("some other error"),
			wantRateLimit:  false,
			wantRetryAfter: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := wrapKiteError(tt.input, "place_order")

			// nil-in must be nil-out.
			if tt.input == nil {
				if got != nil {
					t.Fatalf("nil input must produce nil output, got %v", got)
				}
				return
			}

			// Backward-compat: errors.Is(got, original) must always hold.
			if !errors.Is(got, tt.input) {
				t.Errorf("errors.Is(got, input) must be true; got=%v input=%v", got, tt.input)
			}

			// Typed classification.
			var rle *broker.RateLimitError
			isRL := errors.As(got, &rle)
			if isRL != tt.wantRateLimit {
				t.Errorf("RateLimitError classification = %v, want %v (err=%v)", isRL, tt.wantRateLimit, got)
			}

			if isRL {
				if rle.Endpoint != "place_order" {
					t.Errorf("Endpoint = %q, want place_order", rle.Endpoint)
				}
				if rle.RetryAfter != tt.wantRetryAfter {
					t.Errorf("RetryAfter = %v, want %v", rle.RetryAfter, tt.wantRetryAfter)
				}
				if rle.Unwrap() == nil {
					t.Errorf("Unwrap() returned nil; want underlying error")
				}
			}
		})
	}
}

// TestRateLimitError_ErrorMessage confirms the formatted message is
// human-readable for log/audit consumption.
func TestRateLimitError_ErrorMessage(t *testing.T) {
	t.Parallel()
	inner := errors.New("HTTP 429 Too Many Requests")
	rle := &broker.RateLimitError{
		Endpoint:   "place_order",
		RetryAfter: 5 * time.Second,
		Inner:      inner,
	}
	msg := rle.Error()
	if msg == "" {
		t.Fatal("Error() returned empty string")
	}
	// Must mention endpoint and retry-after for operator triage.
	for _, want := range []string{"place_order", "rate limit", "5s"} {
		if !contains(msg, want) {
			t.Errorf("Error() = %q; missing substring %q", msg, want)
		}
	}
}

// TestRateLimitError_NoRetryAfter ensures the message stays clean when
// Retry-After is absent (the common case — Kite often omits the header).
func TestRateLimitError_NoRetryAfter(t *testing.T) {
	t.Parallel()
	rle := &broker.RateLimitError{
		Endpoint: "get_quotes",
		Inner:    errors.New("429"),
	}
	msg := rle.Error()
	if !contains(msg, "get_quotes") || !contains(msg, "rate limit") {
		t.Errorf("Error() = %q; want endpoint + rate-limit phrase", msg)
	}
}

// TestClientMock_PlaceOrder_429ReturnsTypedRateLimitError verifies the
// end-to-end propagation: SDK returns 429 → broker.Client returns
// *broker.RateLimitError that satisfies errors.As + errors.Is.
//
// This is the load-bearing assertion for callers (riskguard auto-freeze,
// retry middleware, telegram notifier) that need to react to 429
// distinctly from generic 5xx / business errors.
//
// Note on retry behaviour: the existing isTransientError() (retry.go)
// matches err.Error() substrings. The Kite SDK's typed Error.Error()
// returns only Message (not Code), so a synthesised typed 429 with
// message "Too many requests" does NOT trigger retry; the wrap happens
// on the first call. The "429"-substring case (covered by retry_test.go
// TestRetryOnTransient_429Retry) does retry. Both paths land in
// wrapKiteError, which is what this test guards.
func TestClientMock_PlaceOrder_429ReturnsTypedRateLimitError(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	sdkErr := kiteconnect.Error{
		Code:      http.StatusTooManyRequests,
		ErrorType: kiteconnect.NetworkError,
		Message:   "Too many requests",
	}
	mock.PlaceOrderFunc = func(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
		return kiteconnect.OrderResponse{}, sdkErr
	}
	c := NewFromSDK(mock)

	_, err := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "MARKET", Quantity: 1,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	// Caller using errors.As gets the typed error.
	var rle *broker.RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *broker.RateLimitError, got %T: %v", err, err)
	}
	if rle.Endpoint != "place_order" {
		t.Errorf("Endpoint = %q, want place_order", rle.Endpoint)
	}

	// Backward-compat invariant: untyped callers (`if err != nil`) keep
	// working — the original SDK error remains reachable via errors.Is.
	if !errors.Is(err, sdkErr) {
		t.Errorf("errors.Is(err, sdkErr) must hold for backward compat; got=%v", err)
	}
}

// TestClientMock_PlaceOrder_429SubstringReturnsTypedAndRetries verifies
// the legacy / wrapped-error path: when the SDK surfaces 429 as a plain
// fmt.Errorf-wrapped string, retryOnTransient retries through (matching
// the existing retry_test.go contract) and the final exhausted error
// surfaces as *broker.RateLimitError.
func TestClientMock_PlaceOrder_429SubstringReturnsTypedAndRetries(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	sdkErr := errors.New("kite api: 429 too many requests")
	mock.PlaceOrderFunc = func(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
		return kiteconnect.OrderResponse{}, sdkErr
	}
	c := NewFromSDK(mock)

	_, err := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "MARKET", Quantity: 1,
	})
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var rle *broker.RateLimitError
	if !errors.As(err, &rle) {
		t.Fatalf("expected *broker.RateLimitError, got %T: %v", err, err)
	}
	if !errors.Is(err, sdkErr) {
		t.Errorf("errors.Is(err, sdkErr) must hold for backward compat; got=%v", err)
	}
	// "429" is a transient match in retry.go: 1 initial + 2 retries = 3 calls.
	if got := mock.CallCount("PlaceOrder"); got != 3 {
		t.Errorf("expected 3 SDK calls (retry exhaustion on substring 429), got %d", got)
	}
}

// contains is a tiny helper to keep the ratelimit test self-contained
// without pulling in strings into the test imports.
func contains(haystack, needle string) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
