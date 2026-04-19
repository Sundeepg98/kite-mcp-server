package cqrs

import (
	"bytes"
	"errors"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryDispatcher_DispatchCallsHooks(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	var called bool
	var gotType, gotEmail string
	var gotDuration int64
	var gotErr error

	d.AddHook(func(queryType string, email string, durationMs int64, err error) {
		called = true
		gotType = queryType
		gotEmail = email
		gotDuration = durationMs
		gotErr = err
	})

	d.Dispatch("GetPortfolio", "user@example.com", 42, nil)

	assert.True(t, called)
	assert.Equal(t, "GetPortfolio", gotType)
	assert.Equal(t, "user@example.com", gotEmail)
	assert.Equal(t, int64(42), gotDuration)
	assert.NoError(t, gotErr)
}

func TestQueryDispatcher_MultipleHooks(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	var callOrder []int
	for i := 0; i < 3; i++ {
		idx := i
		d.AddHook(func(_ string, _ string, _ int64, _ error) {
			callOrder = append(callOrder, idx)
		})
	}

	d.Dispatch("GetOrders", "user@example.com", 10, nil)

	assert.Equal(t, []int{0, 1, 2}, callOrder, "hooks should fire in registration order")
}

func TestQueryDispatcher_ErrorPassedToHooks(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	testErr := errors.New("broker timeout")
	var hookErr error

	d.AddHook(func(_ string, _ string, _ int64, err error) {
		hookErr = err
	})

	d.Dispatch("GetPositions", "user@example.com", 5000, testErr)

	assert.Equal(t, testErr, hookErr)
}

func TestQueryDispatcher_LogsErrorsOnly(t *testing.T) {
	t.Parallel()
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	d := NewQueryDispatcher(logger)

	// Successful query: should log at debug level.
	d.Dispatch("GetHoldings", "user@example.com", 15, nil)
	debugOutput := buf.String()
	assert.Contains(t, debugOutput, "GetHoldings")

	// Failed query: should log at error level.
	buf.Reset()
	d.Dispatch("GetMargins", "user@example.com", 200, errors.New("connection refused"))
	errorOutput := buf.String()
	assert.Contains(t, errorOutput, "Query failed")
	assert.Contains(t, errorOutput, "GetMargins")
	assert.Contains(t, errorOutput, "connection refused")
}

func TestQueryDispatcher_NilLoggerSafe(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	// Should not panic with nil logger, even on error.
	require.NotPanics(t, func() {
		d.Dispatch("GetOrders", "user@example.com", 10, errors.New("test"))
	})
}

func TestQueryDispatcher_NoHooksNoPanic(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	require.NotPanics(t, func() {
		d.Dispatch("GetAlerts", "user@example.com", 5, nil)
	})
}

func TestQueryDispatcher_ConcurrentDispatch(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	var mu sync.Mutex
	callCount := 0

	d.AddHook(func(_ string, _ string, _ int64, _ error) {
		mu.Lock()
		callCount++
		mu.Unlock()
	})

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			d.Dispatch("GetPortfolio", "user@example.com", 10, nil)
		})
	}
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, 50, callCount)
}

func TestQueryDispatcher_ConcurrentAddAndDispatch(t *testing.T) {
	t.Parallel()
	d := NewQueryDispatcher(nil)

	var wg sync.WaitGroup

	// Concurrently add hooks and dispatch.
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			d.AddHook(func(_ string, _ string, _ int64, _ error) {})
		}()
		go func() {
			defer wg.Done()
			d.Dispatch("GetOrders", "user@example.com", 5, nil)
		}()
	}

	require.NotPanics(t, func() { wg.Wait() })
}
