package mcp

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// CircuitState represents the state of the circuit breaker.
type CircuitState int

const (
	// CircuitClosed means requests pass through normally.
	CircuitClosed CircuitState = iota
	// CircuitOpen means requests are rejected immediately.
	CircuitOpen
	// CircuitHalfOpen means a single probe request is allowed through.
	CircuitHalfOpen
)

// CircuitBreaker implements the circuit breaker pattern for broker API calls.
// After FailureThreshold consecutive failures, the circuit opens for
// OpenDuration. After that, a single probe request is allowed (half-open).
// If the probe succeeds, the circuit closes; if it fails, it re-opens.
type CircuitBreaker struct {
	mu               sync.Mutex
	state            CircuitState
	failures         int
	lastFailure      time.Time
	FailureThreshold int
	OpenDuration     time.Duration
	// brokerTools lists tool name prefixes that are wrapped by the circuit breaker.
	brokerTools []string
}

// NewCircuitBreaker creates a circuit breaker with the given thresholds.
func NewCircuitBreaker(failureThreshold int, openDuration time.Duration) *CircuitBreaker {
	return &CircuitBreaker{
		state:            CircuitClosed,
		FailureThreshold: failureThreshold,
		OpenDuration:     openDuration,
		brokerTools: []string{
			"place_order", "modify_order", "cancel_order",
			"get_holdings", "get_positions", "get_orders",
			"get_ltp", "get_ohlc", "get_quotes",
			"get_margins", "get_profile",
			"place_gtt_order", "modify_gtt_order", "delete_gtt_order",
		},
	}
}

// State returns the current circuit state.
func (cb *CircuitBreaker) State() CircuitState {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	if cb.state == CircuitOpen && time.Since(cb.lastFailure) >= cb.OpenDuration {
		return CircuitHalfOpen
	}
	return cb.state
}

// isBrokerTool checks if the given tool name is a broker API tool.
func (cb *CircuitBreaker) isBrokerTool(name string) bool {
	for _, prefix := range cb.brokerTools {
		if name == prefix {
			return true
		}
	}
	return false
}

// recordSuccess resets the failure counter and closes the circuit.
func (cb *CircuitBreaker) recordSuccess() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures = 0
	cb.state = CircuitClosed
}

// recordFailure increments the failure counter and may open the circuit.
func (cb *CircuitBreaker) recordFailure() {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	cb.failures++
	cb.lastFailure = time.Now()
	if cb.failures >= cb.FailureThreshold {
		cb.state = CircuitOpen
	}
}

// isBrokerError checks if an error result looks like a broker API failure
// (as opposed to a validation error from our own code).
func isBrokerError(result *gomcp.CallToolResult, err error) bool {
	if err != nil {
		msg := err.Error()
		return strings.Contains(msg, "kite") || strings.Contains(msg, "broker") ||
			strings.Contains(msg, "timeout") || strings.Contains(msg, "connection")
	}
	return false
}

// Middleware returns a ToolHandlerMiddleware that wraps broker tools with
// circuit breaker protection.
func (cb *CircuitBreaker) Middleware() server.ToolHandlerMiddleware {
	return func(next server.ToolHandlerFunc) server.ToolHandlerFunc {
		return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
			if !cb.isBrokerTool(request.Params.Name) {
				return next(ctx, request)
			}

			state := cb.State()
			if state == CircuitOpen {
				return gomcp.NewToolResultError(fmt.Sprintf(
					"Broker API circuit breaker is open (too many consecutive failures). "+
						"Requests will resume in %s. Please try again shortly.",
					cb.OpenDuration.Round(time.Second),
				)), nil
			}

			result, err := next(ctx, request)

			if isBrokerError(result, err) {
				cb.recordFailure()
			} else {
				cb.recordSuccess()
			}

			return result, err
		}
	}
}
