# KiteClientFactory Refactoring Summary

## Date: 2026-04-11

## Goal
Replace direct `kiteconnect.New()` calls in production code with a `KiteClientFactory` interface, enabling mock injection in tests by pointing clients at httptest servers.

## New Files

### `kc/kite_client.go`
- `KiteClientFactory` interface with two methods:
  - `NewClient(apiKey string) *kiteconnect.Client`
  - `NewClientWithToken(apiKey, accessToken string) *kiteconnect.Client`
- `defaultKiteClientFactory` struct: production implementation that delegates to `kiteconnect.New()`.

## Modified Files

### `kc/manager.go`
1. **Manager struct**: Added `kiteClientFactory KiteClientFactory` field.
2. **New()**: Initializes `kiteClientFactory: &defaultKiteClientFactory{}` in the Manager constructor.
3. **KiteClientFactory() accessor**: Returns the factory for callers.
4. **SetKiteClientFactory() setter**: Allows tests to inject a mock factory.
5. **Trailing stop modifier** (line ~257): Replaced `kiteconnect.New(apiKey)` + `SetAccessToken()` with `m.kiteClientFactory.NewClientWithToken(apiKey, accessToken)`.

### `kc/ops/dashboard.go` (6 replacements)
All 6 `kiteconnect.New()` calls replaced with `d.manager.KiteClientFactory().NewClientWithToken(...)`:
- `handleAPIMarketIndices` handler (market indices OHLC fetch)
- `handleAPIPortfolio` handler (holdings + positions fetch)
- `handleAPIOrders` enrichment (order history + LTP)
- `handleAPIAlerts` enrichment (alert LTP lookup)
- `handleAPISectorExposure` (holdings for sector analysis)
- `handleAPITaxAnalysis` (holdings for tax analysis)

### `kc/ops/dashboard_templates.go` (5 replacements)
All 5 `kiteconnect.New()` calls replaced with `d.manager.KiteClientFactory().NewClientWithToken(...)`:
- Portfolio page template (holdings + positions)
- Market indices bar (OHLC for NIFTY/BANK/SENSEX) - 2 identical blocks
- Orders page template (order enrichment)
- Alerts page template (LTP for active alerts)
- Mobile portfolio template (holdings + positions + OHLC)

## Not Changed (out of scope per instructions)

| File | Reason |
|------|--------|
| `kc/manager.go:NewKiteConnect()` | Package-level helper called from `session_service.go` - would require cascading changes |
| `kc/alerts/briefing.go` (4 calls) | Already has `BrokerDataProvider` interface for testability |
| `kc/telegram/bot.go` (1 call) | Uses `KiteManager` interface; outside `mcp/` and `kc/ops/` scope |
| `broker/zerodha/factory.go` (5 calls) | Broker layer, outside scope |
| `app/app.go` (2 calls) | App layer, outside scope |
| All `*_test.go` files | Explicitly excluded |

## Verification
- `go vet ./...` -- clean (no warnings)
- `go build ./...` -- clean (no errors)

## Total
- **1 file created**: `kc/kite_client.go`
- **3 files modified**: `kc/manager.go`, `kc/ops/dashboard.go`, `kc/ops/dashboard_templates.go`
- **12 `kiteconnect.New()` calls replaced** in production code within scope
