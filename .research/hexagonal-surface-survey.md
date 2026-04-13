# Hexagonal full-abstraction — Phase 1 SDK surface survey

Task #29 (STEP 20 / PHASE 1). Purpose: enumerate every production call
into `*kiteconnect.Client` inside `broker/zerodha/`, classify it, and
drive the `KiteSDK` interface definition.

Scope: **production code only** (`broker/zerodha/*.go` excluding
`*_test.go`). Test files already import `kiteconnect` for fixture types
and stay untouched in Phase 1.

## 1. Type references (left as-is — NOT part of KiteSDK)

These are `kiteconnect.X` struct/const references used for request/
response parameter types. They live in `convert.go` + a few in
`client.go`. They are type names, not method calls, so they do not
belong on the interface.

| Reference | File | Count | Kind |
|---|---|---|---|
| `kiteconnect.UserProfile` | convert.go:13 | 1 | struct |
| `kiteconnect.AllMargins` | convert.go:26 | 1 | struct |
| `kiteconnect.Margins` | convert.go:33 | 1 | struct |
| `kiteconnect.Holdings` | convert.go:50 | 1 | struct |
| `kiteconnect.Positions` | convert.go:70 | 1 | struct |
| `kiteconnect.Position` | convert.go:77 | 1 | struct |
| `kiteconnect.Orders` | convert.go:95, client.go:107 | 2 | struct |
| `kiteconnect.Trades` | convert.go:121, client.go:220 | 2 | struct |
| `kiteconnect.OrderParams` | convert.go:140, 146 | 2 | struct |
| `kiteconnect.VarietyRegular` | convert.go:143, client.go:153 | 2 | const |
| `kiteconnect.QuoteLTP` | convert.go:164 | 1 | struct |
| `kiteconnect.QuoteOHLC` | convert.go:176 | 1 | struct |
| `kiteconnect.Quote` | convert.go:192 | 1 | struct |
| `kiteconnect.HistoricalData` | convert.go:238 | 1 | struct |
| `kiteconnect.GTTs` | convert.go:255 | 1 | struct |
| `kiteconnect.GTT` | convert.go:263 | 1 | struct |
| `kiteconnect.MFOrders` | convert.go:295 | 1 | struct |
| `kiteconnect.MFSIPs` | convert.go:319 | 1 | struct |
| `kiteconnect.MFHoldings` | convert.go:340 | 1 | struct |
| `kiteconnect.GTTParams` | convert.go:358, 359 | 2 | struct |
| `kiteconnect.GTTSingleLegTrigger` | convert.go:369 | 1 | struct |
| `kiteconnect.TriggerParams` | convert.go:370, 378, 383 | 3 | struct |
| `kiteconnect.GTTOneCancelsOtherTrigger` | convert.go:377 | 1 | struct |
| `kiteconnect.AlertParams` | convert.go:398, 399 | 2 | struct |
| `kiteconnect.AlertType` | convert.go:401 | 1 | type |
| `kiteconnect.AlertOperator` | convert.go:405 | 1 | type |
| `kiteconnect.Basket` | convert.go:413 | 1 | struct |
| `kiteconnect.Alert` | convert.go:421, 442 | 2 | struct |
| `kiteconnect.AlertHistory` | convert.go:450 | 1 | struct |
| `kiteconnect.ConvertPositionParams` | client.go:273 | 1 | struct |
| `kiteconnect.MFOrderParams` | client.go:321 | 1 | struct |
| `kiteconnect.MFSIPParams` | client.go:345 | 1 | struct |
| `kiteconnect.OrderMarginParam` | client.go:374, 376, 396, 398 | 4 | struct |
| `kiteconnect.OrderChargesParam` | client.go:419, 421 | 2 | struct |
| `kiteconnect.GetMarginParams` | client.go:388 | 1 | struct |
| `kiteconnect.GetBasketParams` | client.go:410 | 1 | struct |
| `kiteconnect.GetChargesParams` | client.go:433 | 1 | struct |

## 2. Constructor calls (`kiteconnect.New`) — 5 sites, all in factory.go

| Site | Purpose |
|---|---|
| factory.go:29 | `Factory.Create(apiKey)` — unauthenticated client |
| factory.go:35 | `Factory.CreateWithToken(apiKey, accessToken)` |
| factory.go:50 | `Auth.GetLoginURL(apiKey)` — throwaway client |
| factory.go:56 | `Auth.ExchangeToken(apiKey, apiSecret, requestToken)` |
| factory.go:72 | `Auth.InvalidateToken(apiKey, accessToken)` |

Phase 2 will hide `kiteconnect.New` behind a constructor function
`KiteSDKBuilder func(apiKey string) KiteSDK` injected into the Factory
so tests can supply a fake builder without touching network code.

## 3. Production method calls on `*kiteconnect.Client` — the KiteSDK surface

Every single method below has at least one real production call site.
Nothing speculative was added.

### Connect / auth lifecycle (4 methods)

| Method | Production call sites |
|---|---|
| `SetAccessToken(accessToken string)` | factory.go:36, 73 |
| `GetLoginURL() string` | factory.go:51 |
| `GenerateSession(requestToken, apiSecret string) (UserSession, error)` | factory.go:57 |
| `InvalidateAccessToken() (bool, error)` | factory.go:74 |

### User / portfolio (5 methods)

| Method | Production call sites |
|---|---|
| `GetUserProfile() (UserProfile, error)` | client.go:43 |
| `GetUserMargins() (AllMargins, error)` | client.go:55 |
| `GetHoldings() (Holdings, error)` | client.go:67 |
| `GetPositions() (Positions, error)` | client.go:79 |
| `ConvertPosition(params ConvertPositionParams) (bool, error)` | client.go:273 |

### Orders (7 methods)

| Method | Production call sites |
|---|---|
| `GetOrders() (Orders, error)` | client.go:91 |
| `GetOrderHistory(orderID string) ([]Order, error)` | client.go:103 |
| `GetTrades() (Trades, error)` | client.go:115 |
| `GetOrderTrades(orderID string) ([]Trade, error)` | client.go:216 |
| `PlaceOrder(variety string, orderParams OrderParams) (OrderResponse, error)` | client.go:128 |
| `ModifyOrder(variety, orderID string, orderParams OrderParams) (OrderResponse, error)` | client.go:141 |
| `CancelOrder(variety, orderID string, parentOrderID *string) (OrderResponse, error)` | client.go:156 |

### Market data (4 methods)

| Method | Production call sites |
|---|---|
| `GetLTP(instruments ...string) (QuoteLTP, error)` | client.go:168 |
| `GetOHLC(instruments ...string) (QuoteOHLC, error)` | client.go:180 |
| `GetQuote(instruments ...string) (Quote, error)` | client.go:204 |
| `GetHistoricalData(token int, interval string, from, to time.Time, continuous, OI bool) ([]HistoricalData, error)` | client.go:192 |

### GTT (4 methods)

| Method | Production call sites |
|---|---|
| `GetGTTs() (GTTs, error)` | client.go:228 |
| `PlaceGTT(o GTTParams) (GTTResponse, error)` | client.go:242 |
| `ModifyGTT(triggerID int, o GTTParams) (GTTResponse, error)` | client.go:255 |
| `DeleteGTT(triggerID int) (GTTResponse, error)` | client.go:264 |

### Mutual funds (7 methods)

| Method | Production call sites |
|---|---|
| `GetMFOrders() (MFOrders, error)` | client.go:289 |
| `GetMFSIPs() (MFSIPs, error)` | client.go:300 |
| `GetMFHoldings() (MFHoldings, error)` | client.go:311 |
| `PlaceMFOrder(orderParams MFOrderParams) (MFOrderResponse, error)` | client.go:321 |
| `CancelMFOrder(orderID string) (MFOrderResponse, error)` | client.go:336 |
| `PlaceMFSIP(sipParams MFSIPParams) (MFSIPResponse, error)` | client.go:345 |
| `CancelMFSIP(sipID string) (MFSIPResponse, error)` | client.go:362 |

### Margin calculation (3 methods)

| Method | Production call sites |
|---|---|
| `GetOrderMargins(marparam GetMarginParams) ([]OrderMargins, error)` | client.go:388 |
| `GetBasketMargins(baskparam GetBasketParams) (BasketMargins, error)` | client.go:410 |
| `GetOrderCharges(chargeParam GetChargesParams) ([]OrderCharges, error)` | client.go:433 |

### Native server-side alerts (5 methods)

| Method | Production call sites |
|---|---|
| `CreateAlert(params AlertParams) (Alert, error)` | client.go:448 |
| `GetAlerts(filters map[string]string) ([]Alert, error)` | client.go:458 |
| `ModifyAlert(uuid string, params AlertParams) (Alert, error)` | client.go:469 |
| `DeleteAlerts(uuids ...string) error` | client.go:478 |
| `GetAlertHistory(uuid string) ([]AlertHistory, error)` | client.go:484 |

## 4. Summary

| Category | Method count |
|---|---|
| Connect / auth | 4 |
| User / portfolio | 5 |
| Orders | 7 |
| Market data | 4 |
| GTT | 4 |
| Mutual funds | 7 |
| Margin calculation | 3 |
| Native alerts | 5 |
| **TOTAL KiteSDK methods** | **39** |

Constructor calls (`kiteconnect.New`): **5** (all in factory.go, all
hidden behind a builder function in Phase 2).

## 5. Intentional exclusions

The following gokiteconnect methods are **not** on the interface because
no production site calls them:

- `GetLoginURLWithparams` — factory.go only uses `GetLoginURL()`
- `RenewAccessToken`, `InvalidateRefreshToken` — we don't use refresh tokens
- `GetFullUserProfile`, `GetUserSegmentMargins` — unused
- `GetHoldingsSummary`, `GetHoldingsCompact`, `GetAuctionInstruments` — unused
- `InitiateHoldingsAuth` — unused (not our flow)
- `ExitOrder` — broker.Client routes exits through CancelOrder/PlaceOrder
- `GetInstruments`, `GetInstrumentsByExchange`, `GetMFInstruments` — the
  instruments manager fetches `api.kite.trade/instruments.json` directly
  via HTTP rather than through the SDK Client; it doesn't go through
  this broker adapter
- `GetMFOrderInfo`, `GetMFOrdersByDate`, `GetMFSIPInfo`, `ModifyMFSIP`,
  `GetMFHoldingInfo`, `GetMFAllottedISINs` — unused
- `GetAlert` (single) — unused; we only list via `GetAlerts(filters)`
- `GetGTT(triggerID)` (single) — unused; we only list via `GetGTTs()`
- `SetHTTPClient`, `SetDebug`, `SetBaseURI`, `SetTimeout`, `SetAppName`
  — configuration hooks; not called in production

Adding any of these later is a one-line change, but Phase 1 holds the
line at "exact production footprint, nothing more".

## 6. Phase 1 deliverables

1. `broker/zerodha/sdk_interface.go` — KiteSDK interface (39 methods)
   with compile-time assertion that `*kiteconnect.Client` satisfies it.
2. `broker/zerodha/sdk_adapter.go` — `kiteSDKAdapter` pass-through
   struct with explicit delegation for all 39 methods and a
   `var _ KiteSDK = (*kiteSDKAdapter)(nil)` assertion.
3. This survey document.

No existing file in `broker/zerodha/` was modified. `client.go` still
holds `*kiteconnect.Client` directly; `factory.go` still calls
`kiteconnect.New`. Phase 2 takes care of factory rewiring.
