# Task #21: broker.Client ISP split

## Before
`broker/broker.go` — `Client` interface with **31 direct methods** covering
profile, portfolio, orders, market data, GTT, position conversion, mutual
funds, and margin calculation. Use cases took the full `Client` even when
they only needed two or three methods — classic ISP violation.

## After
`broker.Client` is now a composite interface embedding **9 focused
sub-interfaces**. It has **0 direct methods**; every operation comes from a
sub-interface. Existing implementations (Zerodha, mock) satisfy `Client`
unchanged because sum-of-methods is still 31.

| Interface          | Methods | Purpose                                            |
|--------------------|---------|----------------------------------------------------|
| `BrokerIdentity`   | 1       | `BrokerName()`                                     |
| `ProfileReader`    | 2       | `GetProfile`, `GetMargins`                         |
| `PortfolioReader`  | 3       | `GetHoldings`, `GetPositions`, `GetTrades`         |
| `OrderManager`     | 6       | Get/Place/Modify/Cancel orders + history + trades  |
| `MarketDataReader` | 4       | `GetLTP`, `GetOHLC`, `GetQuotes`, `GetHistoricalData` |
| `GTTManager`       | 4       | Get/Place/Modify/Delete GTT                        |
| `PositionConverter`| 1       | `ConvertPosition`                                  |
| `MutualFundClient` | 7       | All MF order + SIP + holdings                      |
| `MarginCalculator` | 3       | Order margins, basket margins, charges             |
| **Client (composite)** | **0 direct / 31 via embedding** | Full broker contract |

Sum: 1+2+3+6+4+4+1+7+3 = **31**, unchanged.

`OrderManager` (6) and `MutualFundClient` (7) are slightly above the ≤5
soft target, but stay as single interfaces because every method is cohesive
with the group’s responsibility. Splitting further would just create
`MFOrderReader`/`MFOrderWriter`/`MFSIPManager` trios that callers always
use together. `MarketDataReader` is kept as one since all four are snapshot
reads most callers want together.

## Compatibility
- `broker.Client` still carries every method (via embedding), so all
  existing callers and implementations compile unchanged.
- Use cases and handlers are free to narrow their parameter type to the
  specific sub-interface they need (e.g. `broker.MarketDataReader` for an
  LTP enricher, `broker.OrderManager` for the order-placement use case).
  That narrowing is intentionally **not** rolled out in this task — it
  would touch ~30 files and inflate the diff. The interfaces now exist;
  tightening callers is a follow-up.

## Verification
- `go build ./broker/...` — clean
- `go vet ./broker/...` — clean
- `go test ./broker/...` —
  - `broker` (no tests, OK)
  - `broker/mock` — OK (mock still satisfies `Client`)
  - `broker/zerodha` — OK (Zerodha impl still satisfies `Client`)
- `go build ./...` — surfaces pre-existing kc build errors from #19/#22
  in-progress work (`Manager` missing `GetAPIKeyForEmail`, `PnLService`).
  Verified these errors exist without the `broker.go` change by stashing
  and re-running. **Unrelated to this task.**

## Files touched
- `broker/broker.go` — replaced monolithic `Client` with sub-interfaces +
  composite.
