package app

// ceil_test.go — coverage ceiling documentation for app.
// Current: 82.2%. Ceiling: ~82%.
//
// The app package is the top-level application wiring: server startup,
// service initialization, HTTP mux setup, graceful shutdown, Telegram
// webhook registration, and rate limiting. Many uncovered lines involve
// runtime operations that require external services or OS signals.
//
// ===========================================================================
// app.go — RunServer (66.7%)
// ===========================================================================
//
// Lines 347-420+: OAuth handler initialization + HTTP server setup + listen.
//   The server startup sequence creates an HTTP server, registers routes,
//   and calls srv.ListenAndServe() (or ServeTLS). Testing this requires
//   starting a full HTTP server and then shutting it down. The initialization
//   paths for OAuth, billing, dashboard, and Telegram are all sequential
//   and depend on environment variables being set.
//
// ===========================================================================
// app.go — initializeServices (74.3%)
// ===========================================================================
//
// Lines 444-720+: Full service wiring (kc.Manager, MCP server, tools).
//   This function creates the Manager, sets up billing, audit trail,
//   instruments, paper trading, event sourcing, and MCP tools. Many
//   initialization branches depend on environment variables (STRIPE_KEY,
//   TELEGRAM_BOT_TOKEN, ALERT_DB_PATH, etc.). Lines not covered are
//   branches for optional features (billing, Telegram, paper trading LTP
//   adapter, event store) that require those env vars to be set.
//
// ===========================================================================
// app.go — initScheduler (63.2%)
// ===========================================================================
//
// Lines 727-840+: Briefing scheduler with morning + daily P&L tasks.
//   The scheduler creates cron-like jobs that fire at specific IST times.
//   Testing requires either:
//   (a) A running scheduler with valid Kite sessions (for P&L fetching)
//   (b) Mocking time progression
//   The scheduler callbacks reference Telegram notifier + Kite API calls.
//   Unreachable without full integration.
//
// ===========================================================================
// app.go — GetLTP (53.3%)
// ===========================================================================
//
// Lines 843-864: paperLTPAdapter.GetLTP iterates active sessions.
//   Requires active MCP sessions with valid Kite clients and access tokens.
//   Each session's Kite client must succeed on GetLTP. The success path
//   (lines 857-861) requires a real Kite API response.
//
// ===========================================================================
// app.go — setupGracefulShutdown (28.6%)
// ===========================================================================
//
// Lines 895-937: Signal handler goroutine (os.Interrupt, SIGTERM).
//   This goroutine blocks on signal.NotifyContext and runs the shutdown
//   sequence. Testing requires sending an OS signal to the process, which
//   is not practical in unit tests. The shutdown logic (scheduler stop,
//   server drain, audit flush, Telegram bot stop, manager shutdown,
//   OAuth close, rate limiter stop) is individually tested, but the
//   orchestration goroutine is not.
//
// ===========================================================================
// app.go — registerTelegramWebhook (11.5%)
// ===========================================================================
//
// Lines 1326-1380+: Telegram webhook registration with BotFather.
//   Requires:
//   - TELEGRAM_BOT_TOKEN to be set and valid
//   - A running Telegram API endpoint
//   - OAUTH_JWT_SECRET and EXTERNAL_URL
//   The function creates a BotHandler, registers commands, and calls
//   notifier.Bot().Request(webhook) — a live Telegram API call.
//   Unreachable without mocking the Telegram API.
//
// ===========================================================================
// app.go — startStdIOServer (85.7%)
// ===========================================================================
//
// Lines 1475-1520+: STDIO mode MCP server startup.
//   Requires running in STDIO mode (no HTTP). The server reads from
//   stdin and writes to stdout. Testing requires piping MCP protocol
//   messages through stdin/stdout.
//
// ===========================================================================
// app.go — initStatusPageTemplate (78.6%)
// ===========================================================================
//
// Lines 1528-1600+: Landing page template initialization.
//   Template parsing from embedded FS. Parse errors are unreachable
//   (embedded templates are valid at build time). Remaining gap is
//   template execution with specific data combinations.
//
// ===========================================================================
// app.go — ExchangeWithCredentials (83.3%)
// ===========================================================================
//
// Lines 1759-1800+: Kite token exchange with per-user credentials.
//   Requires valid request_token from Kite OAuth callback + user
//   credentials in the credential store. The Kite API call
//   (kite.GenerateSession) makes a live HTTP request.
//
// ===========================================================================
// app.go — makeEventPersister (75.0%)
// ===========================================================================
//
// Lines 1960-1990+: Event store persister creation.
//   Requires event sourcing store to be initialized (ALERT_DB_PATH set).
//   The error path on store creation is tested, but the success path
//   with actual persistence callbacks depends on the full wiring.
//
// ===========================================================================
// ratelimit.go — newRateLimiters (72.7%)
// ===========================================================================
//
// Lines 64-90+: Rate limiter configuration with env var overrides.
//   Some branches depend on specific RATE_LIMIT_* env vars being set
//   with custom values. Default values are tested; custom overrides are
//   partially tested.
//
// ===========================================================================
// Summary
// ===========================================================================
//
// The app package is the integration layer. Most uncovered code falls into:
//   1. Server lifecycle (ListenAndServe, graceful shutdown signals)
//   2. External API registration (Telegram webhook, Kite API)
//   3. Optional feature initialization (billing, paper trading, scheduler)
//   4. STDIO mode operation
//
// These are inherently integration-level operations that require either
// live services or process-level testing.
//
// Ceiling: ~82% (~100 unreachable lines across app.go + ratelimit.go).
