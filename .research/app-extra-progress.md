# app/ Coverage Push — Extra Tests (push100_extra_test.go)

## Summary
- **Before**: 82.5% (from existing tests)
- **After**: 83.4% (+0.9pp, 9 new tests)
- **Ceiling**: ~83-84% (remaining lines are integration/lifecycle/unreachable)

## New Tests (9 total in `app/push100_extra_test.go`)

| Test | Target | Lines Hit |
|------|--------|-----------|
| `TestSetupMux_AdminAuth_DoubleSlashPrefix_Push100Extra` | Admin auth "//" prefix redirect | 1079-1081 |
| `TestSetupMux_PricingPage_PremiumTier_Push100Extra` | Pricing page premium tier | 1242-1243 |
| `TestExchangeWithCredentials_KeyExistsDiffUser_Push100Extra` | Key exists, different user reassignment | 1825-1828 |
| `TestExchangeWithCredentials_RegisterError_Push100Extra` | Registry Register ID conflict | 1818-1821 |
| `TestGetLimiter_ConcurrentDoubleCheck_Push100Extra` | Concurrent race on getLimiter | ratelimit.go:38-40 |
| `TestSetupMux_OpsHandler_NoUserStoreNoOAuth_Push100Extra` | AdminSecretPath fallback (no user store, no OAuth) | 1096-1098 |
| `TestExchangeWithCredentials_SuspendedUser_Push100Extra` | provisionUser suspended user error | 1775-1777 |
| `TestExchangeWithCredentials_OffboardedUser_Push100Extra` | provisionUser offboarded user error | 1770-1772 |
| `TestExchangeRequestToken_SuspendedUser_Push100Extra` | provisionUser suspended user on ExchangeRequestToken | 1738-1740 |

## Function Coverage Changes

| Function | Before | After | Delta |
|----------|--------|-------|-------|
| `setupMux` | 91.7% | 92.2% | +0.5pp |
| `ExchangeWithCredentials` | 83.3% | 96.7% | +13.4pp |
| `ExchangeRequestToken` | 93.8% | 100% | +6.2pp |
| `getLimiter` | 91.7% | 100% | +8.3pp |
| Total | 82.5% | 83.4% | +0.9pp |

## Remaining Uncovered (at ceiling)

All remaining uncovered functions are integration/lifecycle code documented in `ceil_test.go`:
- `RunServer` (69%): Full server lifecycle + OAuth wiring
- `initializeServices` (75%): Deep service wiring (env-dependent)
- `initScheduler` (63.2%): Telegram briefing goroutines
- `GetLTP` (53.3%): Active Kite session iteration
- `setupGracefulShutdown` (28.6%): OS signal handler goroutine
- `registerTelegramWebhook` (11.5%): Live Telegram API calls
- `initStatusPageTemplate` (78.6%): Unreachable embed.FS parse errors
- `newRateLimiters` (72.7%): Background ticker goroutine body
- `makeEventPersister` (75%): json.Marshal on domain structs (never fails)
- `serveStatusPage` (96.7%): WriteTo network error (unreachable in tests)
