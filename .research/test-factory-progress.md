# Test Factory Progress

## Completed

### 1. `mcp/tools_factory_test.go` — broker.Factory injection tests (22 tests)
- Mock `broker.Factory` that creates Zerodha clients backed by httptest server
- Tests cover: get_profile, get_margins, get_holdings, get_positions, get_orders, get_trades,
  get_ltp, get_ohlc, get_quotes, get_order_history, get_order_trades, get_gtts,
  get_mf_orders, get_mf_sips, get_mf_holdings, get_order_margins, get_basket_margins,
  get_order_charges, portfolio_summary, sector_exposure, tax_harvest_analysis, pre_trade_check
- Unit tests for mockBrokerFactory itself (Create, CreateWithToken)
- All 22 tests PASS

### 2. `kc/ops/factory_test.go` — KiteClientFactory injection tests (11 tests)
- Mock `KiteClientFactory` that returns `*kiteconnect.Client` instances backed by httptest
- Dashboard API success paths: market-indices, portfolio, sector-exposure, tax-analysis, status
- Negative tests: no-creds, no-token, no-auth
- Unit tests for testKiteClientFactory (NewClient, NewClientWithToken)
- All 11 tests PASS

### 3. `kc/session_service.go` — Added SetBrokerFactory setter
- New method `SetBrokerFactory(f broker.Factory)` for test injection
- Follows same pattern as existing `SetAuditStore`, `SetSessionManager`

## Key finding
- gokiteconnect SDK routes `GetOHLC`, `GetLTP`, `GetQuotes` ALL through `/quote` (URIGetQuote)
- The `/quote/ohlc` and `/quote/ltp` paths defined in SDK constants are NOT used by client methods
- Mock servers must handle `/quote` for all quote-related calls

## Total: 33 new tests, all passing
