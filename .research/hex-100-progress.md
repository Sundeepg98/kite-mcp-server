# Hex 100% — Wire KiteClientFactory + broker.Authenticator

## Status: COMPLETE (final pass by split-100)

## Changes Made

### 1. kc/telegram/bot.go (done by prior agent)
- Added local `KiteClientFactory` interface (mirrors `kc.KiteClientFactory`, avoids circular import)
- Added `kiteClientFactory KiteClientFactory` field to `BotHandler` struct
- Updated `NewBotHandler` signature to accept `factory KiteClientFactory` (nil-safe)
- Updated `newKiteClient` method to use factory when non-nil, fallback to direct `kiteconnect.New()` when nil

### 2. kc/telegram/commands_test.go (done by prior agent)
- Updated `NewBotHandler` call to pass `nil` factory

### 3. broker/broker.go
- Added `Email` field to `broker.AuthResult`

### 4. broker/zerodha/factory.go
- Populated `Email` from `sess.Email` in `ExchangeToken`

### 5. app/adapters.go (kiteExchangerAdapter)
- Replaced `kiteBaseURI` + `kiteClientFactory` fields with `authenticator broker.Authenticator`
- Removed `newKiteClient` helper method
- Rewrote `ExchangeRequestToken` to use `authenticator.ExchangeToken()`
- Rewrote `ExchangeWithCredentials` to use `authenticator.ExchangeToken()`

### 6. app/wire.go (production wiring)
- Wired `zerodha.NewAuth()` as the authenticator
- Removed unused `kiteconnect` import

### 7. Test updates
- `auth_factory_test.go`: Created `mockAuthenticator`, replaced all mock HTTP servers
- `server_test.go`: Updated 5 tests to use `newMockAuth`/`newMockAuthError`
- `push100_extra_test.go`: Updated 5 tests to use `newMockAuth`/`newMockAuthError`
- `app_coverage_test.go`: Added `authenticator` field to 4 tests calling Exchange methods

### 8. kc/alerts/briefing_test.go — NO CHANGES NEEDED
- Tests create `&defaultBrokerProvider{}` with nil factory
- Existing nil-fallback in `defaultBrokerProvider.newClient()` handles this correctly

## Verification
- `go vet ./...` — CLEAN
- `go build ./...` — CLEAN
- Tests blocked by Windows SAC policy (not a code issue)
