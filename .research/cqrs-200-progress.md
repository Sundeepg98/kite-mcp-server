# CQRS-200 Progress

## Status: COMPLETE

## Tools routed through use cases

### Ticker tools (5) -- mcp/ticker_tools.go
- [x] start_ticker -> StartTickerUseCase
- [x] stop_ticker -> StopTickerUseCase
- [x] ticker_status -> TickerStatusUseCase
- [x] subscribe_instruments -> SubscribeInstrumentsUseCase
- [x] unsubscribe_instruments -> UnsubscribeInstrumentsUseCase

### Paper trading tools (3) -- mcp/paper_tools.go
- [x] paper_trading_toggle -> PaperTradingToggleUseCase
- [x] paper_trading_status -> PaperTradingStatusUseCase
- [x] paper_trading_reset -> PaperTradingResetUseCase

### Native alert tools (5) -- mcp/native_alert_tools.go
- [x] place_native_alert -> PlaceNativeAlertUseCase (via nativeAlertAdapter)
- [x] list_native_alerts -> ListNativeAlertsUseCase (via nativeAlertAdapter)
- [x] modify_native_alert -> ModifyNativeAlertUseCase (via nativeAlertAdapter)
- [x] delete_native_alert -> DeleteNativeAlertUseCase (via nativeAlertAdapter)
- [x] get_native_alert_history -> GetNativeAlertHistoryUseCase (via nativeAlertAdapter)

### PnL tools (1) -- mcp/pnl_tools.go
- [x] get_pnl_journal -> GetPnLJournalUseCase

### Account tools (2) -- mcp/account_tools.go
- [x] delete_my_account -> DeleteMyAccountUseCase
- [x] update_my_credentials -> UpdateMyCredentialsUseCase

### Context/observability (2) -- mcp/context_tool.go, mcp/observability_tool.go
- [x] trading_context -> TradingContextUseCase
- [x] server_metrics -> ServerMetricsUseCase

### Pre-trade (1) -- mcp/pretrade_tool.go
- [x] pre_trade_check -> PreTradeCheckUseCase

### Setup tools (2) -- mcp/setup_tools.go
- [x] login -> LoginUseCase.Validate()
- [x] open_dashboard -> OpenDashboardUseCase.Validate()

## Files created (no conflicts with cqrs-100)
- kc/cqrs/commands_ext.go (placeholder — LoginCommand in commands.go via cqrs-100)
- kc/cqrs/queries_ext.go (OpenDashboardQuery, TradingContextQuery, ServerMetricsQuery, PreTradeCheckQuery)
- kc/usecases/context_usecases.go (TradingContextUseCase)
- kc/usecases/observability_usecases.go (ServerMetricsUseCase)
- kc/usecases/pretrade_usecases.go (PreTradeCheckUseCase)
- kc/usecases/setup_usecases.go (LoginUseCase, OpenDashboardUseCase)

## Files modified (NOT touching cqrs-100's commands.go/queries.go)
- kc/usecases/account_usecases.go (added UpdateMyCredentialsUseCase)
- mcp/native_alert_tools.go (added nativeAlertAdapter, routed through use cases)
- mcp/account_tools.go (routed through use cases)
- mcp/context_tool.go (routed through TradingContextUseCase)
- mcp/observability_tool.go (routed through ServerMetricsUseCase)
- mcp/pretrade_tool.go (routed through PreTradeCheckUseCase)
- mcp/setup_tools.go (routed through LoginUseCase/OpenDashboardUseCase)

## Build status
- `go build ./...` passes clean
