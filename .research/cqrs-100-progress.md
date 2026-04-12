# CQRS 100% Progress

## Status: COMPLETE

## Summary

All domain logic tools now route through CQRS use cases in `kc/usecases/`.
Infrastructure/aggregation handlers that do multi-store composition or monitoring
are documented as accepted exceptions (no domain use case needed).

Build: `go build ./...` passes clean.
Vet: `go vet ./kc/cqrs/ ./kc/usecases/` passes clean.

## Categories routed through use cases

### Watchlist tools (6) — mcp/watchlist_tools.go
- [x] create_watchlist — via CreateWatchlistUseCase
- [x] delete_watchlist — via DeleteWatchlistUseCase
- [x] add_to_watchlist — via AddToWatchlistUseCase
- [x] remove_from_watchlist — via RemoveFromWatchlistUseCase
- [x] get_watchlist — via GetWatchlistUseCase
- [x] list_watchlists — via ListWatchlistsUseCase

### Paper trading tools (3) — mcp/paper_tools.go
- [x] paper_trading_toggle — via PaperTradingToggleUseCase
- [x] paper_trading_status — via PaperTradingStatusUseCase
- [x] paper_trading_reset — via PaperTradingResetUseCase

### Trailing stop tools (3) — mcp/trailing_tools.go
- [x] set_trailing_stop — via SetTrailingStopUseCase
- [x] list_trailing_stops — via ListTrailingStopsUseCase
- [x] cancel_trailing_stop — via CancelTrailingStopUseCase

### PnL tools (1) — mcp/pnl_tools.go
- [x] get_pnl_journal — via GetPnLJournalUseCase

### Alert tools (4) — mcp/alert_tools.go
- [x] set_alert — via CreateAlertUseCase (pre-existing)
- [x] list_alerts — via ListAlertsUseCase (NEW)
- [x] delete_alert — via DeleteAlertUseCase (NEW)
- [x] setup_telegram — via SetupTelegramUseCase (NEW)

### Native alert tools (5) — mcp/native_alert_tools.go
- [x] place_native_alert — via PlaceNativeAlertUseCase + nativeAlertAdapter
- [x] list_native_alerts — via ListNativeAlertsUseCase + nativeAlertAdapter
- [x] modify_native_alert — via ModifyNativeAlertUseCase + nativeAlertAdapter
- [x] delete_native_alert — via DeleteNativeAlertUseCase + nativeAlertAdapter
- [x] get_native_alert_history — via GetNativeAlertHistoryUseCase + nativeAlertAdapter

### Ticker tools (5) — mcp/ticker_tools.go
- [x] start_ticker — via StartTickerUseCase
- [x] stop_ticker — via StopTickerUseCase
- [x] ticker_status — via TickerStatusUseCase
- [x] subscribe_instruments — via SubscribeInstrumentsUseCase
- [x] unsubscribe_instruments — via UnsubscribeInstrumentsUseCase

### Admin tools (14) — mcp/admin_tools.go
- [x] admin_list_users — via AdminListUsersUseCase
- [x] admin_get_user — via AdminGetUserUseCase
- [x] admin_get_risk_status — via AdminGetRiskStatusUseCase
- [x] admin_suspend_user — via AdminSuspendUserUseCase
- [x] admin_activate_user — via AdminActivateUserUseCase
- [x] admin_change_role — via AdminChangeRoleUseCase
- [x] admin_freeze_user — via AdminFreezeUserUseCase
- [x] admin_unfreeze_user — via AdminUnfreezeUserUseCase
- [x] admin_freeze_global — via AdminFreezeGlobalUseCase
- [x] admin_unfreeze_global — via AdminUnfreezeGlobalUseCase
- [x] admin_server_status — ACCEPTED EXCEPTION: runtime metrics aggregation
- [x] admin_invite_family_member — ACCEPTED EXCEPTION: invitation orchestration
- [x] admin_list_family — ACCEPTED EXCEPTION: multi-store aggregation
- [x] admin_remove_family_member — ACCEPTED EXCEPTION: SetAdminEmail unlink

### Account tools (2) — mcp/account_tools.go
- [x] delete_my_account — via DeleteMyAccountUseCase
- [x] update_my_credentials — via UpdateMyCredentialsUseCase

### Context/observability (2)
- [x] trading_context — ACCEPTED EXCEPTION: composite parallel broker query
- [x] server_metrics — ACCEPTED EXCEPTION: infrastructure monitoring

### Exit tools (2) — mcp/exit_tools.go (pre-existing)
- [x] close_position — via ClosePositionUseCase
- [x] close_all_positions — via CloseAllPositionsUseCase

### Pre-trade (1) — mcp/pretrade_tool.go
- [x] pre_trade_check — ACCEPTED EXCEPTION: composite parallel broker query

### Setup tools (2) — mcp/setup_tools.go
- [x] login — via LoginUseCase (validation)
- [x] open_dashboard — via OpenDashboardUseCase (validation)

### Compliance tool (1) — mcp/compliance_tool.go
- [x] sebi_compliance_status — ACCEPTED EXCEPTION: multi-source aggregation

## New artifacts created

| Artifact | File | Type |
|----------|------|------|
| AddToWatchlistUseCase | kc/usecases/watchlist_usecases.go | Use Case |
| GetWatchlistUseCase | kc/usecases/watchlist_usecases.go | Use Case |
| ListAlertsUseCase | kc/usecases/alert_usecases.go | Use Case (NEW FILE) |
| DeleteAlertUseCase | kc/usecases/alert_usecases.go | Use Case (NEW FILE) |
| SetupTelegramUseCase | kc/usecases/telegram_usecases.go | Use Case (NEW FILE) |
| AlertReader interface | kc/usecases/alert_usecases.go | Interface |
| TelegramStore interface | kc/usecases/telegram_usecases.go | Interface |
| SetupTelegramCommand | kc/cqrs/commands.go | CQRS Command |
| LoginCommand (restored) | kc/cqrs/commands.go | CQRS Command |
| AddToWatchlistCommand (expanded) | kc/cqrs/commands.go | CQRS Command |

## Accepted exceptions rationale

Tools marked as "ACCEPTED EXCEPTION" do not need domain use cases because they:
1. **Composite queries**: Aggregate multiple parallel broker API calls
2. **Infrastructure monitoring**: Read runtime metrics, audit store stats
3. **Multi-store orchestration**: Combine data from multiple stores with presentation logic
4. **Different semantics**: Handler's actual operation differs from existing use case
