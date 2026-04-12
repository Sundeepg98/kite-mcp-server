# DDD Specification + Glossary Progress

## Status: COMPLETE

## Files Created

### 1. `kc/domain/spec.go` — Specification Pattern
- **Generic `Spec[T]` interface** with `IsSatisfiedBy(T) bool` + `Reason() string`
- **Composite specs**: `And[T]`, `Or[T]`, `Not[T]` for composable rules
- **QuantitySpec** — validates int quantity within [Min, Max] bounds
- **PriceSpec** — validates float64 price is positive and within ceiling
- **OrderSpec** — composes qty + price specs, validates tradingsymbol, transaction type, skips price check for MARKET/SL-M orders
- **OrderCandidate** — transient value object for composite order validation

### 2. `kc/domain/glossary.go` — Ubiquitous Language
- **AdminActor vs AdminRole** — runtime identity (who did it) vs authorization check (is admin)
- **MCPSessionID vs KiteToken vs OAuthToken** — three distinct session concepts documented with type aliases
- **OrderFreezeReason vs GlobalFreezeReason** — per-user vs server-wide freeze semantics
- **Constants**: TransactionBuy/Sell, OrderType (MARKET/LIMIT/SL/SL-M), Product (CNC/MIS/NRML), Exchange (NSE/BSE/NFO/BFO/MCX/CDS)

### 3. `kc/domain/spec_test.go` — Tests
- 30 test functions covering all spec types
- QuantitySpec: within bounds, at bounds, below min, above max, zero, negative, no max, default min
- PriceSpec: valid, zero, negative, above max, no max, at max
- OrderSpec: valid buy limit, market skips price, SL-M skips price, missing tradingsymbol, invalid txn type, qty fails, price fails
- AndSpec: both satisfied, left fails, right fails
- OrSpec: left satisfied, right satisfied, neither satisfied
- NotSpec: inner satisfied (negation fails), inner not satisfied (negation passes)
- Glossary compile-time type alias checks + constant value checks

### 4. Aggregate Event Raising — Already Correct
- `OrderAggregate.Place()` calls `o.Apply(event)` then `o.raise(event)` — events raised BY the aggregate
- Same pattern for `Modify()`, `Cancel()`, `Fill()` in `kc/eventsourcing/order_aggregate.go`
- Same pattern for PositionAggregate and AlertAggregate
- `PlaceOrderUseCase` dispatches to EventDispatcher (pub/sub for subscribers) — this is a different concern (notification) vs aggregate event raising (state machine)

## Verification
- `go vet ./kc/domain/` — PASS
- `go build ./kc/domain/` — PASS
- Test execution blocked by Windows Smart App Control (system policy, not code issue)
