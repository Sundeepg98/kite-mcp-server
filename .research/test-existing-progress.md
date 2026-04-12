# Test Existing Injection Points — Progress

## Status: COMPLETE

## Files Created

### 1. kc/alerts/briefing_factory_test.go (16 tests)
Tests using `SetBrokerProvider` injection point:
- `TestBuildMorningBriefing_RealisticPortfolio` — 5-stock portfolio, indices, margin
- `TestBuildMorningBriefing_WithTriggeredAlerts_RealisticData` — alerts + portfolio
- `TestBuildDailySummary_RealisticPortfolio` — gainers/losers, positions
- `TestBuildDailySummary_BrokerErrors_Graceful` — both holdings/positions errors
- `TestSendMorningBriefings_RealisticMultiUser` — end-to-end, 2 users
- `TestSendDailySummaries_RealisticSingleUser` — end-to-end send
- `TestSendMISWarnings_RealisticPositions` — MIS positions through provider
- `TestFormatMISWarning_RealisticPositions` — long+short, PnL formatting
- `TestBuildMorningBriefing_NegativePortfolio` — all holdings in red
- `TestBuildMorningBriefing_LTPError_GracefulDegradation` — LTP error, rest works
- `TestBuildDailySummary_OnlyHoldingsError` — partial failure
- `TestFilterMISPositions_RealisticMix` — CNC/MIS/NRML/closed filtering
- `TestBrokerProvider_DefaultFallback` — nil returns defaultBrokerProvider
- `TestBrokerProvider_OverrideUsed` — SetBrokerProvider replaces default
- `TestBuildDailySummary_EmptyPortfolio` — new user, no trades
- `TestBuildMorningBriefing_AllBrokerErrors` — all API calls fail

### 2. kc/telegram/trading_factory_test.go (8 tests)
Tests using `kiteBaseURI` injection point:
- `TestHandleBuy_MarketOrder_ConfirmAndExecute` — full /buy flow through fakeKiteAPI
- `TestHandleSell_LimitOrder_ConfirmAndExecute` — /sell with LIMIT price
- `TestHandleQuick_BuyMarket_ConfirmAndExecute` — /quick BUY MARKET
- `TestHandleQuick_SellLimit_ConfirmAndExecute` — /quick SELL LIMIT
- `TestExecuteConfirmedOrder_KiteAPIError` — fakeKiteAPI returns error
- `TestExecuteConfirmedOrder_OrderExpired` — no pending order
- `TestNewKiteClient_KiteBaseURI_Applied` — verifies kiteBaseURI set on client
- `TestNewKiteClient_BaseURINotSet` — production mode (no override)

### 3. app/auth_factory_test.go (14 tests)
Tests using `kiteBaseURI` injection point on kiteExchangerAdapter:
- `TestExchangeRequestToken_WithUserStore_Success` — user provisioning path
- `TestExchangeWithCredentials_WithUserStore_Success` — per-user creds + user store
- `TestExchangeWithCredentials_RegistryNewKey` — auto-register new key in registry
- `TestExchangeWithCredentials_RegistryOldKeyReplaced` — old key marked replaced
- `TestExchangeRequestToken_RegistryLastUsedAt` — last_used_at update
- `TestExchangeRequestToken_NoRegistryStore_Factory` — minimal setup
- `TestExchangeWithCredentials_NoRegistryStore_Factory` — no registry
- `TestExchangeRequestToken_FallbackToUserID_Factory` — empty email fallback
- `TestExchangeRequestToken_KiteAPIError_Factory` — error path
- `TestGetCredentials_PerUser_Factory` — per-user credentials returned
- `TestGetCredentials_FallbackToGlobal_Factory` — global fallback
- `TestGetCredentials_NoCredentials_Factory` — neither available
- `TestGetSecretByAPIKey_Factory` — secret lookup by API key

## Verification
- go vet: PASS on all 3 packages (pre-existing issue in app/telegram_test.go is unrelated)
- go test: All 38 new tests PASS
