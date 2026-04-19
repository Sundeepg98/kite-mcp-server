package mcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

// Pure function tests: backtest, indicators, options pricing, sector mapping, portfolio analysis, prompts.

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------


func TestIsTransientError(t *testing.T) {
	t.Parallel()
	assert.True(t, isTransientError(errors.New("connection refused")))
	assert.True(t, isTransientError(errors.New("request timeout")))
	assert.True(t, isTransientError(errors.New("service temporarily unavailable")))
	assert.True(t, isTransientError(errors.New("unexpected EOF")))
	assert.True(t, isTransientError(errors.New("Connection reset by peer")))
	assert.False(t, isTransientError(errors.New("invalid API key")))
	assert.False(t, isTransientError(errors.New("permission denied")))
	assert.False(t, isTransientError(errors.New("bad request")))
}


func TestRetryBrokerCall_SuccessFirstTry(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "ok", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "ok", result)
	assert.Equal(t, 1, calls)
}


func TestRetryBrokerCall_NonTransientFails(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("invalid API key")
	}, 3)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "should not retry non-transient errors")
}


func TestRetryBrokerCall_TransientRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	result, err := RetryBrokerCall(func() (string, error) {
		calls++
		if calls < 3 {
			return "", errors.New("connection timeout")
		}
		return "recovered", nil
	}, 3)
	assert.NoError(t, err)
	assert.Equal(t, "recovered", result)
	assert.Equal(t, 3, calls)
}


func TestRetryBrokerCall_ExhaustsRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (int, error) {
		calls++
		return 0, errors.New("connection timeout every time")
	}, 2)
	assert.Error(t, err)
	assert.Equal(t, 3, calls, "should try 1 + 2 retries = 3 calls")
	assert.Contains(t, err.Error(), "connection timeout")
}


func TestRetryBrokerCall_ZeroRetries(t *testing.T) {
	t.Parallel()
	calls := 0
	_, err := RetryBrokerCall(func() (string, error) {
		calls++
		return "", errors.New("connection refused")
	}, 0)
	assert.Error(t, err)
	assert.Equal(t, 1, calls, "zero retries means just one attempt")
}
