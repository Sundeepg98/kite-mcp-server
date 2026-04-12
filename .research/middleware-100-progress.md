# Middleware 95->100%: Circuit Breaker + Correlation ID — DONE

## New Files

### `mcp/correlation_middleware.go`
- Generates UUID per tool call, injects into context via `correlationKey`
- `CorrelationIDFromContext(ctx)` retrieves the ID downstream
- First middleware in chain so all subsequent middleware/handlers have the ID

### `mcp/circuitbreaker_middleware.go`
- Circuit breaker pattern for broker API tools (place_order, get_holdings, etc.)
- 3 states: Closed (normal), Open (rejecting), HalfOpen (probe)
- After 5 consecutive broker failures, circuit opens for 30 seconds
- Success resets failure counter
- Non-broker tools pass through unaffected
- `isBrokerError()` heuristic: checks for "kite", "broker", "timeout", "connection" in error

### Tests
- `mcp/correlation_middleware_test.go` — 3 tests (inject, uniqueness, no-ID)
- `mcp/circuitbreaker_middleware_test.go` — 7 tests (passthrough, closed, open, recovery, reset, broker tool check, error detection)

### Wiring (`app/wire.go`)
- Correlation middleware: first in chain (line 181)
- Circuit breaker: after hooks, before riskguard (threshold=5, duration=30s)

## Verification
- `go vet ./...` — clean
- `go build ./...` — clean
- All 10 new tests pass
