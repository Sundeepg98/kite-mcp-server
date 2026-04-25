package zerodha

import (
	"fmt"
	"testing"
)

func TestRetryOnTransient_Success(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := retryOnTransient(func() (string, error) {
		calls++
		return "ok", nil
	}, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "ok" {
		t.Errorf("result = %q, want %q", result, "ok")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1", calls)
	}
}

func TestRetryOnTransient_NonTransientError(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("invalid API key")
	}, 3)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (should not retry non-transient)", calls)
	}
}

func TestRetryOnTransient_TimeoutRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := retryOnTransient(func() (string, error) {
		calls++
		if calls < 3 {
			return "", fmt.Errorf("context deadline exceeded (timeout)")
		}
		return "recovered", nil
	}, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != "recovered" {
		t.Errorf("result = %q, want %q", result, "recovered")
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryOnTransient_ConnectionRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := retryOnTransient(func() (int, error) {
		calls++
		if calls == 1 {
			return 0, fmt.Errorf("connection refused")
		}
		return 42, nil
	}, 2)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result != 42 {
		t.Errorf("result = %d, want 42", result)
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestRetryOnTransient_EOFRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("unexpected EOF")
	}, 2)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	// 1 initial + 2 retries = 3 calls
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryOnTransient_ZeroRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("timeout")
	}, 0)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (0 retries = 1 attempt)", calls)
	}
}

// PR-E Item 2: HTTP-level transient classifications.
//
// Pre-PR-E the matcher only retried on lowercased "timeout" / "connection"
// / "eof". Kite's API + the retail-trade gateway returns transient
// failures as HTTP 503 (Service Unavailable) and 429 (Too Many Requests)
// — both legitimate retry targets that the original heuristic missed.

func TestRetryOnTransient_503Retry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := retryOnTransient(func() (string, error) {
		calls++
		if calls < 2 {
			return "", fmt.Errorf("kite api: server returned 503 service unavailable")
		}
		return "recovered", nil
	}, 3)
	if err != nil {
		t.Fatalf("503 must retry — unexpected error: %v", err)
	}
	if result != "recovered" {
		t.Errorf("result = %q, want %q", result, "recovered")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestRetryOnTransient_429Retry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := retryOnTransient(func() (int, error) {
		calls++
		if calls < 3 {
			return 0, fmt.Errorf("kite api: 429 too many requests")
		}
		return 7, nil
	}, 3)
	if err != nil {
		t.Fatalf("429 must retry — unexpected error: %v", err)
	}
	if result != 7 {
		t.Errorf("result = %d, want 7", result)
	}
	if calls != 3 {
		t.Errorf("calls = %d, want 3", calls)
	}
}

func TestRetryOnTransient_502Retry(t *testing.T) {
	t.Parallel()
	// 502 Bad Gateway from a load balancer is also transient — usually
	// a deployment rollout or backend restart.
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("502 bad gateway")
	}, 1)
	if err == nil {
		t.Fatal("expected error after exhausting retries")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2 (1 initial + 1 retry)", calls)
	}
}

func TestRetryOnTransient_504Retry(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := retryOnTransient(func() (int, error) {
		calls++
		return 0, fmt.Errorf("Gateway Timeout (504)")
	}, 1)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 2 {
		t.Errorf("calls = %d, want 2", calls)
	}
}

func TestRetryOnTransient_400DoesNotRetry(t *testing.T) {
	t.Parallel()
	// Non-transient HTTP errors — caller bug or auth failure — must NOT
	// retry (would just compound the wrong-input pressure).
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("400 bad request: invalid order_type")
	}, 3)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (4xx is non-transient)", calls)
	}
}

func TestRetryOnTransient_401DoesNotRetry(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := retryOnTransient(func() (string, error) {
		calls++
		return "", fmt.Errorf("401 unauthorized")
	}, 3)
	if err == nil {
		t.Fatal("expected error")
	}
	if calls != 1 {
		t.Errorf("calls = %d, want 1 (4xx is non-transient)", calls)
	}
}
