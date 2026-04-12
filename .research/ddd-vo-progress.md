# DDD 90->95%: Wire VOs into Use Case Parameters — DONE

## Changed Commands (kc/cqrs/commands.go)

### PlaceOrderCommand
- `Exchange string` + `Tradingsymbol string` → `Instrument domain.InstrumentKey`
- `Quantity int` → `Qty domain.Quantity` (with JSON marshal/unmarshal support)
- `Price float64` → `Price domain.Money`

### ModifyOrderCommand
- `Price float64` → `Price domain.Money`
- `Quantity int` stays int (0 = "don't modify", incompatible with Quantity VO)

### PlaceGTTCommand
- `Exchange string` + `Tradingsymbol string` → `Instrument domain.InstrumentKey`
- `LastPrice float64` → `LastPrice domain.Money`
- `LimitPrice float64` → `LimitPrice domain.Money`
- `UpperLimitPrice float64` → `UpperLimitPrice domain.Money`
- `LowerLimitPrice float64` → `LowerLimitPrice domain.Money`
- Quantities stay float64 (GTT API accepts fractional)

### ModifyGTTCommand
- Same VO changes as PlaceGTTCommand

## Use Case Updates

### kc/usecases/place_order.go
- Extracts raw values from VOs at top of Execute(): `qty := cmd.Qty.Int()`, `price := cmd.Price.Amount`, etc.
- Passes raw values to riskguard, broker params, and logging
- Passes VOs directly to domain events (OrderPlacedEvent already used VOs)

### kc/usecases/modify_order.go
- Extracts `price := cmd.Price.Amount` for riskguard, broker, and validation

### kc/usecases/gtt_usecases.go
- PlaceGTT: uses `cmd.Instrument.Exchange`, `cmd.LastPrice.Amount`, etc.
- ModifyGTT: same pattern

## MCP Tool Handler Updates (mcp/post_tools.go)
- Added `domain` import
- PlaceOrder: constructs `domain.NewQuantity()`, `domain.NewInstrumentKey()`, `domain.NewINR()`
- ModifyOrder: wraps price with `domain.NewINR()`
- PlaceGTT/ModifyGTT: constructs `domain.NewInstrumentKey()`, `domain.NewINR()` for price fields

## Domain VO Enhancement (kc/domain/quantity.go)
- Added `MarshalJSON()` / `UnmarshalJSON()` to Quantity for JSON round-trip support
- Quantity serializes as plain JSON number (e.g., `10`)

## Test Updates
- `kc/cqrs/cqrs_test.go`: Updated serialization + handler interface tests
- `kc/usecases/usecases_test.go`: Added `testPlaceCmd()` helper, updated all PlaceOrder/ModifyOrder/PlaceGTT/ModifyGTT test constructors
- `kc/usecases/cqrs_coverage_test.go`: Updated PlaceOrder + PlaceGTT test constructors

## Design Decisions
- **ModifyOrderCommand.Quantity stays int**: 0 means "don't change" — Quantity VO requires v>0
- **GTT quantities stay float64**: Kite API accepts fractional GTT quantities
- **TriggerValue fields stay float64**: These are price-like but represent trigger conditions, not monetary amounts
- **Zero-value VOs work for "unset"**: `domain.Money{}` has Amount=0, `domain.Quantity{}` has Int()=0

## Verification
- `go vet ./...` — clean
- `go build ./...` — clean
- All tests pass except 3 pre-existing ext_apps test failures (unrelated to changes)
