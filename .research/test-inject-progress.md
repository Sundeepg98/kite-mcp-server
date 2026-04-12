# Test-Inject Progress

## Status: COMPLETE

## Files Created/Modified

### New test files
1. **app/telegram_test.go** — BotAPI mock tests
   - `TestRegisterTelegramWebhook_Success` — full success path with mock Telegram server
   - `TestRegisterTelegramWebhook_NilNotifier_Inject` — nil notifier early exit

2. **app/shutdown_test.go** — shutdownCh injection tests
   - `TestSetupGracefulShutdown_ViaShutdownCh` — close channel triggers graceful shutdown, server stops
   - `TestSetupGracefulShutdown_ViaShutdownCh_NilComponents` — nil optional components don't panic

3. **app/ratelimit_cleanup_test.go** — cleanupInterval ticker tests
   - `TestRateLimiters_CleanupFires` — 10ms interval, verify cleanup fires and empties limiter maps
   - `TestRateLimiters_CleanupInterval_ViaConstructor` — exercise newRateLimiters() constructor
   - `TestRateLimiters_StopStopsGoroutine` — verify Stop() terminates goroutine

4. **mcp/token_refresh_test.go** — IsTokenExpiredFn override tests
   - `TestWithTokenRefresh_AlwaysExpired_ProfileOK` — expired + profile OK = no error, token kept
   - `TestWithTokenRefresh_AlwaysExpired_ProfileFails` — expired + profile fails = error, token deleted
   - `TestWithTokenRefresh_NeverExpired` — not expired = nil, GetProfile not called
   - `TestWithTokenRefresh_EmptyEmail` — empty email early return
   - `TestWithTokenRefresh_NoTokenInStore` — no stored token early return
   - `TestWithTokenRefresh_DefaultFn` — nil IsTokenExpiredFn uses kc.IsKiteTokenExpired

### Supporting files
5. **kc/alerts/testing_helpers.go** — exported `OverrideNewBotFunc()` for cross-package test use

## Test Results
- All 13 new tests pass
- go vet clean on kc/alerts and mcp packages
