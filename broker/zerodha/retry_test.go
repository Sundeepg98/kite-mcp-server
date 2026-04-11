package zerodha

import (
	"fmt"
	"testing"
)

func TestRetryOnTransient_Success(t *testing.T) {
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
