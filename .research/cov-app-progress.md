# app/ Coverage Progress

## Starting: 80.4% (77.8% if counting the hanging test)
## Current: 83.4%

## New test file: `app/app_push100_test.go`

Added ~40 tests targeting uncovered lines in:
- `initializeServices` (Stripe billing, audit encryption, domain events, family invitations, riskguard)
- `setupMux` (admin password bcrypt, admin secret path fallback, Google SSO, accept-invite paths, Stripe webhook, pricing page)
- `serveLegalPages` (template execute error)
- `serveStatusPage` (landing template error, OAuth redirect, text fallback, 404)
- `makeEventPersister` (all event types, DB closed errors)
- `ExchangeWithCredentials` (registry key replacement, key assignment)
- `KiteTokenChecker` (all paths: empty email, valid token, expired+creds, suspended, offboarded)
- Various small functions and adapters

## Test fixes applied (session 2)
- Fixed 4 tests that called `initializeServices()` hitting real Kite API (429 rate limit)
- `TestSetupMux_StripeWebhookBillingStore_Push100`: now uses `p100Manager(t)` + manual billing store
- `TestInitializeServices_TemplateInitSuccess_Push100`: now tests `initStatusPageTemplate()` directly
- `TestInitializeServices_DomainEvents_Push100`: now uses `p100Manager(t)` + manual event wiring
- `TestInitializeServices_FamilyInvitation_Push100`: now uses `p100Manager(t)` + manual invitation store
- All 35 Push100 tests pass (10.8s total)

## Build fixes applied
- `mcp/paper_tools.go`: removed unused `fmt` import
- `mcp/ticker_tools.go`: added missing `ticker` import
- `mcp/pretrade_tool.go`: removed unused `instrumentKey` variable
- `kc/usecases/observability_usecases.go`: fixed `audit.GlobalStats` -> `audit.Stats`

## Unreachable lines (documented)

### setupGracefulShutdown (28.6%) — lines 901-936
The inner goroutine body waits on `signal.NotifyContext` for OS signals (SIGINT/SIGTERM). Cannot be triggered in unit tests without sending real signals, which is unreliable on Windows. The setup path (wiring the goroutine) IS tested.

### registerTelegramWebhook (11.5%) — lines 1331-1379
Requires a real Telegram Bot API client (`tgbotapi.BotAPI`) to:
1. Create webhook config (`tgbotapi.NewWebhook`)
2. Register with Telegram API (`notifier.Bot().Request(wh)`)
3. Set bot commands (`notifier.Bot().Request(commands)`)
The early returns (nil notifier, no JWT secret) ARE tested. The actual webhook registration requires integration with Telegram.

### initScheduler Telegram paths (63.2%) — lines 733-757
Requires `kcManager.TelegramNotifier()` to return non-nil, which needs `TELEGRAM_BOT_TOKEN` env var and a real Telegram bot. The non-Telegram paths (audit cleanup, PnL snapshot) are covered.

### paperLTPAdapter.GetLTP success path (53.3%) — lines 853-861
Requires an active Kite session with a real `Client` that can call `GetLTP()`. The error paths (no sessions, nil client) are covered.

### initStatusPageTemplate parse errors (78.6%) — lines 1530-1544
Templates are embedded via `embed.FS`. They always parse successfully. The parse error branches are defensive code that can only fail if the embedded FS is corrupted at build time.

### ExchangeRequestToken/WithCredentials provisionUser error (93.8%/83.3%) — lines 1738-1740, 1770-1777
These call `client.GenerateSession()` which connects to the real Kite API. The provisionUser function itself IS tested directly. The error paths (suspended/offboarded users) in provisionUser are covered.

### RunServer OAuth wiring (66.7%) — lines 379-401
The KiteTokenChecker closure IS tested separately. But the RunServer function's own wiring code (creating the closure and setting it on the handler) runs through `initializeServices` + OAuth setup which requires a running server. The individual paths are all verified.

### newRateLimiters cleanup tick (72.7%)
The cleanup goroutine fires every 10 minutes. Would need to either mock the ticker or wait 10+ minutes. The cleanup function itself IS tested directly.

### setupMux admin secret path fallback (line 1096-1098)
`userStore` is always non-nil when created via `kc.New()`, so `userStore != nil` at line 1094 is always true. The `else if` at 1096 is unreachable with a properly-initialized manager.

### initializeServices error paths for DB operations
Lines 460-462, 468-470, 478-480, 488-490, 506-511, 564-566, 588-590, 621-633, 645-664: These are defensive error handling for SQLite operations on `:memory:` databases that never fail. They protect against corrupt or missing DB files in production.

### serveStatusPage WriteTo error (line 1650-1652)
`buf.WriteTo(w)` on `httptest.ResponseRecorder` never fails. Would need a custom writer that errors.

### favicon ReadFile error (line 1288-1291)
The favicon is read from embedded `templates.FS`. It always succeeds unless the binary is corrupted.

### UI hooks AfterInitialize (lines 688-692)
Only called by the MCP framework during client initialization handshake. Not accessible via HTTP tests.
