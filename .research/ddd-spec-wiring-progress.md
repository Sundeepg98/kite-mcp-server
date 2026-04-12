# DDD: Wire OrderSpec into PlaceOrderUseCase — DONE

## Changes Made

### 1. PlaceOrderUseCase (`kc/usecases/place_order.go`)
- Replaced inline `tradingsymbol == ""` and `quantity <= 0` checks with `domain.OrderSpec.IsSatisfiedBy()`
- Builds `OrderCandidate` from command fields, delegates to spec
- Spec validates: tradingsymbol required, transaction_type BUY/SELL, quantity >= 1, price positive (for non-MARKET orders)
- Email check remains inline (not part of order domain spec)

### 2. ModifyOrderUseCase (`kc/usecases/modify_order.go`)
- Added `QuantitySpec` validation when `cmd.Quantity > 0` (0 means "don't change")
- Added `PriceSpec` validation when `cmd.Price > 0` and order type is not MARKET/SL-M
- Email + OrderID checks remain inline (identity fields, not domain specs)

### 3. Test fixes (`kc/usecases/usecases_test.go`, `kc/usecases/cqrs_coverage_test.go`)
- Updated PlaceOrderCommand in tests to include `TransactionType` and `OrderType` fields, since OrderSpec now validates these
- Updated error message expectations to match spec output (e.g., "quantity 0 below minimum 1" instead of "quantity must be positive")
- Added new test case for invalid transaction type validation

## Verification
- `go vet ./kc/usecases/ ./kc/domain/` — clean
- `go test ./kc/usecases/` — all pass
