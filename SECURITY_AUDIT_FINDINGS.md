# Kite MCP Server - Complete Security Audit Findings

**Codebase:** `github.com/zerodha/kite-mcp-server`
**Date:** 2026-02-24
**Base audit:** 27-pass manual analysis (SECURITY_AUDIT_REPORT.md, 181 claimed findings)
**Scope:** All 47 Go source files

**Totals:** 6 HIGH, 42 MEDIUM, 110 LOW, 23 INFO = **181 findings**
**Status:** 74 FIXED, 107 OPEN

---

## HIGH (6)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| H1 | `app/app.go:393-395` | SSE endpoints `/sse` and `/message` now wrapped with `RequireAuth` when OAuth enabled | FIXED |
| H2 | `kc/manager.go` (was ~836) | Access token logged at Info level -- log line deleted | FIXED |
| H3 | `oauth/handlers.go:188-192` | Redirect URI scheme validation added (only http/https allowed) | FIXED |
| H4 | `app/app.go:248` | `ReadHeaderTimeout` set to 30s (was 0) | FIXED |
| H5 | `app/app.go:262-271` | Shutdown order fixed: HTTP server first, then kcManager | FIXED |
| H6 | `kc/ops/handler.go:112-116` | Credential IDOR fixed: ops `/api/credentials` scoped to authenticated email | FIXED |

---

## MEDIUM (42)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| M1 | `oauth/handlers.go:215` | `json.Marshal(stateData)` error ignored with `_` | OPEN |
| M2 | `oauth/handlers.go:600` | `json.NewEncoder(w).Encode(data)` error return unchecked in `writeJSON` | OPEN |
| M3 | `oauth/handlers.go:195-201` | Auto-registration allows any `client_id` as Kite API key without validation | OPEN |
| M4 | `oauth/handlers.go:128` | No limit on `redirect_uris` array size in registration request body (only `maxRedirectURIs=10` per client enforced later) | OPEN |
| M5 | `oauth/handlers.go:442-445` | `HandleBrowserLogin` accepts GET with email param -- allows CSRF-style login initiation | OPEN |
| M6 | `oauth/middleware.go:44-49` | Dashboard token rejection on MCP endpoints added | FIXED |
| M7 | `oauth/middleware.go:89-90` | Open redirect prevention in `RequireAuthBrowser` | FIXED |
| M8 | `oauth/handlers.go:376-378` | Open redirect prevention in `HandleBrowserAuthCallback` | FIXED |
| M9 | `oauth/handlers.go:220` | State URL-encoded in redirect params | FIXED |
| M10 | `oauth/stores.go:33,37-41` | `AuthCodeStore.Close()` added with done channel for cleanup goroutine | FIXED |
| M11 | `oauth/stores.go:99,116-128,141-143` | `ClientStore` eviction at `maxClients=10000` with `evictOldest` | FIXED |
| M12 | `oauth/stores.go:101-102` | `maxRedirectURIs=10` per client to prevent abuse | FIXED |
| M13 | `app/app.go:249` | `WriteTimeout` still 0 -- needed for SSE but risky for non-SSE endpoints (slowloris on `/oauth/*`) | OPEN |
| M14 | `app/app.go:336-337` | Ops dashboard unauthenticated in non-OAuth fallback (local dev only, identity middleware) | OPEN |
| M15 | `kc/manager.go:502` | `kiteData.Email = email` written without mutex on `KiteSessionData` struct -- potential race | OPEN |
| M16 | `kc/manager.go:647` | `request_token` logged at Debug level in `CompleteSession` | OPEN |
| M17 | `kc/manager.go:836` | `request_token` logged at Info in `HandleKiteCallback` (line 836) | OPEN |
| M18 | `kc/alerts/store.go:149-151` | `List()` copies the slice but `*Alert` pointers still reference originals (shallow copy) | OPEN |
| M19 | `kc/alerts/store.go:223-228` | `ListAll()` same shallow copy issue -- returned `*Alert` pointers reference originals | OPEN |
| M20 | `kc/alerts/store.go:94` | No limit on number of alerts per user in `Add()` method | OPEN |
| M21 | `kc/alerts/db.go:225` | `time.Parse` error silently ignored with `_` for `storedAt` in `LoadTokens` | OPEN |
| M22 | `kc/alerts/db.go:279` | `time.Parse` error silently ignored with `_` for `storedAt` in `LoadCredentials` | OPEN |
| M23 | `kc/alerts/crypto.go:22` | HKDF with nil salt -- acceptable but explicit salt improves security | OPEN |
| M24 | `kc/alerts/telegram.go:80` | Uses `ModeMarkdown` (v1) not `MarkdownV2` -- some characters may not escape correctly | OPEN |
| M25 | `kc/ticker/service.go:85` | `SetReconnectMaxRetries(300)` hardcoded -- should be configurable | OPEN |
| M26 | `kc/ticker/service.go:37,92` | Access token stored in plaintext in `UserTicker` struct -- remains in memory | OPEN |
| M27 | `kc/ops/logbuffer.go:101-136` | `TeeHandler` copies all log records to buffer including potentially sensitive data | OPEN |
| M28 | `kc/ops/logbuffer.go:53-55` | Non-blocking send to listeners silently drops entries if channel full | OPEN |
| M29 | `mcp/common.go:104` | `WithSession` error stripping: returns generic "Failed to establish a session" without `err` | OPEN |
| M30 | `mcp/common.go:150` | `MarshalResponse` error stripping: returns "Failed to process response data" without `err` | OPEN |
| M31 | `mcp/setup_tools.go:92` | Login tool error stripping: "Failed to get or create Kite session" without `err` | OPEN |
| M32 | `mcp/setup_tools.go:176` | Login tool error stripping: "Failed to generate Kite login URL" without `err` | OPEN |
| M33 | `mcp/ticker_tools.go:150-153` | `SubscribeInstrumentsTool` extracts email directly from context without `WithSession` validation | OPEN |
| M34 | `mcp/ticker_tools.go:208-211` | `UnsubscribeInstrumentsTool` same issue -- no session validation | OPEN |
| M35 | `kc/ops/handler.go:58` | `w.Write(data)` error unchecked in `servePage` | OPEN |
| M36 | `mcp/common.go:18` | `isTokenLikelyExpired` calls `time.LoadLocation("Asia/Kolkata")` on every invocation -- minor perf | OPEN |
| M37 | `kc/alerts/store.go:99` | UUID truncated to 8 chars for alert IDs: `uuid.New().String()[:8]` -- collision risk at scale | OPEN |
| M38 | `kc/alerts/evaluator.go:45-46` | `e.store.onNotify` accesses unexported field directly -- tight coupling | OPEN |
| M39 | `kc/token_store.go:110-111` | `OnChange` callbacks called with raw entry pointer (not copy) outside lock | OPEN |
| M40 | `oauth/stores.go:48` | `AuthCodeStore` entries not bounded -- relies on 10-min expiry + cleanup, no hard cap | OPEN |
| M41 | `app/app.go:194` | `configureHTTPClient` sets global `http.DefaultClient.Timeout` -- affects all code using default client | OPEN |
| M42 | `kc/session_signing.go:52` | `NewSessionSignerWithKey` panics on empty key -- should return error | OPEN |

---

## LOW (110)

### Error Stripping (15)

Errors returned to the user without the underlying `err.Error()` detail, making debugging harder.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L1 | `mcp/common.go:104` | `WithSession`: "Failed to establish a session. Please try again." -- no err detail | OPEN |
| L2 | `mcp/common.go:116` | `WithSession`: "Your Kite session has expired..." -- err logged but not in user message | OPEN |
| L3 | `mcp/common.go:123` | `WithSession`: "Please log in first using the login tool" -- intentional | FIXED |
| L4 | `mcp/common.go:136` | `WithSession`: "Your Kite session has expired..." (existing session path) | OPEN |
| L5 | `mcp/common.go:150` | `MarshalResponse`: "Failed to process response data" -- no err detail | OPEN |
| L6 | `mcp/setup_tools.go:92` | Login: "Failed to get or create Kite session" -- no err detail | OPEN |
| L7 | `mcp/setup_tools.go:145` | Login: "Failed to clear session data" -- no err detail | OPEN |
| L8 | `mcp/setup_tools.go:157` | Login: "Failed to create new Kite session" -- no err detail | OPEN |
| L9 | `mcp/setup_tools.go:176` | Login: "Failed to generate Kite login URL" -- no err detail | OPEN |
| L10 | `mcp/post_tools.go:131` | `place_order`: error now includes `err.Error()` | FIXED |
| L11 | `mcp/post_tools.go:207` | `modify_order`: error now includes `err.Error()` | FIXED |
| L12 | `mcp/post_tools.go:251` | `cancel_order`: error now includes `err.Error()` | FIXED |
| L13 | `mcp/post_tools.go:378` | `place_gtt_order`: error now includes `err.Error()` | FIXED |
| L14 | `mcp/post_tools.go:416` | `delete_gtt_order`: error now includes `err.Error()` | FIXED |
| L15 | `mcp/post_tools.go:550` | `modify_gtt_order`: error now includes `err.Error()` | FIXED |

### Shared Pointer Returns (8)

Methods returning shared pointers from map lookups -- callers can mutate shared state.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L16 | `kc/token_store.go:82-83` | `KiteTokenStore.Get()` now returns copy via `cp := *entry` | FIXED |
| L17 | `kc/credential_store.go:74-76` | `KiteCredentialStore.Get()` now returns copy | FIXED |
| L18 | `oauth/stores.go:163-166` | `ClientStore.Get()` now returns copy with deep-copied `RedirectURIs` | FIXED |
| L19 | `kc/alerts/store.go:164-165` | `Store.GetByToken()` now returns copies via `cp := *a` | FIXED |
| L20 | `kc/alerts/store.go:149-151` | `Store.List()` copies slice but Alert pointers still reference originals | OPEN |
| L21 | `kc/alerts/store.go:223-228` | `Store.ListAll()` copies slice but Alert pointers still reference originals | OPEN |
| L22 | `kc/instruments/manager.go:536-540` | `GetConfig()` returns pointer to shared config object | OPEN |
| L23 | `kc/ops/data.go:75` | `buildSessions` accesses `s.Data.(*KiteSessionData)` directly -- shared pointer | OPEN |

### Missing Validation (12)

Missing input validation, bounds checks, or size limits.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L24 | `kc/alerts/store.go:94` | No limit on alerts per user in `Add()` -- unbounded growth | OPEN |
| L25 | `mcp/alert_tools.go:43` | `chat_id` from `float64` to `int64` truncation -- safe for Telegram but unchecked overflow | OPEN |
| L26 | `mcp/market_tools.go:41` | No validation on instruments array size for `get_quotes` (Kite API caps at 500) | OPEN |
| L27 | `mcp/market_tools.go:275` | No validation on instruments array size for `get_ltp` | OPEN |
| L28 | `mcp/market_tools.go:317` | No validation on instruments array size for `get_ohlc` | OPEN |
| L29 | `mcp/post_tools.go:96-111` | `PlaceOrderTool` accepts `variety` and `exchange` from schema enum but no server-side re-validation | OPEN |
| L30 | `mcp/post_tools.go:337-343` | `PlaceGTTOrderTool` does not validate trigger values > 0 for single-leg | OPEN |
| L31 | `mcp/post_tools.go:509-515` | `ModifyGTTOrderTool` does not validate trigger values > 0 | OPEN |
| L32 | `mcp/setup_tools.go:58-59` | Login tool `api_key`/`api_secret` not sanitized before storage | OPEN |
| L33 | `oauth/handlers.go:124` | Registration request body size not limited (`json.NewDecoder(r.Body)`) | OPEN |
| L34 | `oauth/handlers.go:493` | Token endpoint request body size not limited | OPEN |
| L35 | `mcp/market_tools.go:92` | `Count() == 0` check logs warning but still allows search to proceed | OPEN |

### Logging Issues (15)

Sensitive data in logs, inappropriate log levels, or missing log entries.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L36 | `kc/manager.go:647` | `request_token` logged at Debug level in `CompleteSession` | OPEN |
| L37 | `kc/manager.go:836` | `request_token` logged at Info level in `HandleKiteCallback` | OPEN |
| L38 | `app/app.go:580` | Email and user_id logged at Info level in `ExchangeRequestToken` | OPEN |
| L39 | `app/app.go:604` | Email and user_id logged at Info level in `ExchangeWithCredentials` | OPEN |
| L40 | `kc/manager.go:348` | Session ID logged at Info in `createKiteSessionData` | OPEN |
| L41 | `kc/manager.go:565` | Session ID logged at Info in `ClearSession` | OPEN |
| L42 | `kc/manager.go:602` | Session ID logged at Info in `GenerateSession` | OPEN |
| L43 | `kc/manager.go:636` | Session ID logged at Info in `SessionLoginURL` | OPEN |
| L44 | `kc/manager.go:668` | Session ID logged at Info in `CompleteSession` | OPEN |
| L45 | `kc/manager.go:682-689` | COMPLIANCE log includes `user_id`, `session_id`, `user_name`, `user_type` -- intentional but sensitive | OPEN |
| L46 | `oauth/handlers.go:140` | Registered client `client_id` logged at Info -- may be a Kite API key | OPEN |
| L47 | `oauth/handlers.go:311` | Email logged at Info in "Kite OAuth complete" | OPEN |
| L48 | `oauth/handlers.go:562` | Email logged at Info in "Deferred Kite exchange successful" | OPEN |
| L49 | `oauth/handlers.go:579` | Email and client_id logged at Info in "Issued JWT access token" | OPEN |
| L50 | `mcp/alert_tools.go:49` | Telegram chat_id logged at Info level | OPEN |

### Test Isolation (5)

Tests that mutate global state or lack proper cleanup.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L51 | `app/app_test.go:16-17` | `TestLoadConfig_MissingAPIKey` mutates env with `os.Unsetenv` | OPEN |
| L52 | `app/app_test.go:28-30` | `TestLoadConfig_MissingAPISecret` mutates env with `os.Setenv/Unsetenv` | OPEN |
| L53 | `app/app_test.go:41-46` | `TestLoadConfig_ValidCredentials` mutates env | OPEN |
| L54 | `app/app_test.go:64-72` | `TestLoadConfig_Defaults` mutates env (6 calls) | OPEN |
| L55 | `kc/instruments/manager_test.go:89-94` | `hijackInstrumentsURL` mutates package-level `instrumentsURL` var -- not thread-safe | OPEN |

### Cleanup Goroutines (6)

Background goroutines that need proper shutdown signaling.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L56 | `oauth/stores.go:33,37-41` | `AuthCodeStore` cleanup goroutine has `Close()` with done channel | FIXED |
| L57 | `app/metrics/metrics.go:186-201,216-220` | Metrics cleanup routine has proper `Shutdown()` via `cleanupStop` channel | FIXED |
| L58 | `kc/instruments/manager.go:173-178,554-564` | Instruments scheduler has proper `Shutdown()` via context cancellation and `schedulerDone` | FIXED |
| L59 | `kc/ticker/service.go:164-168` | Ticker goroutine `go t.ServeWithContext(ctx)` -- has cancel via context | FIXED |
| L60 | `kc/manager.go:311` | Session cleanup routine started with `StartCleanupRoutine(context.Background())` -- has stop method | FIXED |
| L61 | `kc/manager.go:746-770` | `Manager.Shutdown()` orchestrates clean shutdown of all components in correct order | FIXED |

### Unchecked Write Errors (10)

HTTP response writes where `w.Write()` or `json.Encode()` errors are ignored.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L62 | `kc/ops/handler.go:58` | `w.Write(data)` error unchecked in `servePage` | OPEN |
| L63 | `kc/ops/handler.go:68` | `json.NewEncoder(w).Encode(h.buildOverview())` error unchecked | OPEN |
| L64 | `kc/ops/handler.go:78` | `json.NewEncoder(w).Encode(h.buildSessions())` error unchecked | OPEN |
| L65 | `kc/ops/handler.go:88` | `json.NewEncoder(w).Encode(h.buildTickers())` error unchecked | OPEN |
| L66 | `kc/ops/handler.go:98` | `json.NewEncoder(w).Encode(h.buildAlerts())` error unchecked | OPEN |
| L67 | `kc/ops/handler.go:108` | `json.NewEncoder(w).Encode(...)` error unchecked in `credentials` handler (GET path) | OPEN |
| L68 | `kc/ops/handler.go:148` | `json.NewEncoder(w).Encode(...)` error unchecked in `credentials` handler (POST path) | OPEN |
| L69 | `kc/ops/handler.go:154` | `json.NewEncoder(w).Encode(...)` error unchecked in `credentials` handler (DELETE path) | OPEN |
| L70 | `oauth/handlers.go:600` | `writeJSON` never checks `json.NewEncoder(w).Encode()` error -- affects all OAuth endpoints | OPEN |
| L71 | `oauth/handlers.go:479-481` | `browserLoginTmpl.ExecuteTemplate` error logged but response may be partially written | OPEN |

### Method Enforcement (8)

Endpoints now enforce HTTP method restrictions.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L72 | `kc/ops/handler.go:63-66` | `overview` rejects non-GET | FIXED |
| L73 | `kc/ops/handler.go:72-75` | `sessions` rejects non-GET | FIXED |
| L74 | `kc/ops/handler.go:82-85` | `tickers` rejects non-GET | FIXED |
| L75 | `kc/ops/handler.go:92-95` | `alerts` rejects non-GET | FIXED |
| L76 | `kc/ops/handler.go:163-166` | `logStream` rejects non-GET | FIXED |
| L77 | `oauth/handlers.go:83-86` | `ResourceMetadata` rejects non-GET | FIXED |
| L78 | `oauth/handlers.go:95-98` | `AuthServerMetadata` rejects non-GET | FIXED |
| L79 | `oauth/handlers.go:115-117` | `Register` rejects non-POST | FIXED |

### Template Caching (2)

Templates parsed once at startup instead of on every request.

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L80 | `oauth/handlers.go:57-68` | OAuth handler pre-parses templates in `NewHandler` | FIXED |
| L81 | `app/app.go:489-497` | Status page template parsed once in `initStatusPageTemplate` | FIXED |

### Dockerfile Hardening (4)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L82 | `Dockerfile:10` | Base image pinned to `alpine:3.21` | FIXED |
| L83 | `Dockerfile:11-12` | Non-root user `appuser` created and used | FIXED |
| L84 | `Dockerfile:14` | `HEALTHCHECK` added with wget | FIXED |
| L85 | `Dockerfile:15` | `USER appuser` directive added | FIXED |

### Encryption and Crypto (4)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L86 | `kc/alerts/crypto.go:71` | `decrypt` returns empty string on decryption failure (was returning ciphertext) | FIXED |
| L87 | `kc/alerts/crypto.go:55` | `decrypt` returns plaintext fallback for non-hex data (migration-safe) | FIXED |
| L88 | `kc/alerts/db.go:35-37` | SQLite `PRAGMA busy_timeout=5000` added | FIXED |
| L89 | `kc/alerts/telegram.go:12-17` | `escapeTelegramMarkdown` function present for safe message formatting | FIXED |

### Ticker Tools Session Validation (3)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L90 | `mcp/ticker_tools.go:28` | `StartTickerTool` now uses `WithSession` | FIXED |
| L91 | `mcp/ticker_tools.go:69` | `StopTickerTool` now uses `WithSession` | FIXED |
| L92 | `mcp/ticker_tools.go:102` | `TickerStatusTool` now uses `WithSession` | FIXED |

### Miscellaneous Code Quality (18)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| L93 | `kc/manager.go:236-242` | Deprecated `NewManager` constructor still present | OPEN |
| L94 | `kc/instruments/manager.go:143-152` | Deprecated `NewManager` and `NewManagerWithConfig` constructors still present | OPEN |
| L95 | `kc/instruments/manager.go:55` | `MemoryLimit` config field defined but unused | OPEN |
| L96 | `kc/manager.go:177-178` | `KiteConnect.Client` is exported (`TODO: this can be made private ?`) | OPEN |
| L97 | `mcp/setup_tools.go:15-26` | `dashboardLink` constructs URL from user input (`ExternalURL`) without path validation | OPEN |
| L98 | `mcp/market_tools.go:57` | `InstrumentsSearchTool` TODO comment in production code | OPEN |
| L99 | `app/app.go:103` | `Version` hardcoded to `"v0.0.0"` -- should be injected at build time | OPEN |
| L100 | `kc/manager.go:839` | `handleCallbackError` uses variadic args passed to `Logger.Error` -- positional format string | OPEN |
| L101 | `kc/session_signing.go:173-179` | `GetSecretKey()` exposed "for testing purposes only" -- leaks key | OPEN |
| L102 | `kc/instruments/manager.go:29` | Package-level mutable `instrumentsURL` var -- test-only but not thread-safe | OPEN |
| L103 | `mcp/common.go:17-33` | `isTokenLikelyExpired` logic correct but timezone loaded every call | OPEN |
| L104 | `oauth/handlers.go:234-237` | Kite login URL construction embeds `api_key` in URL query param (expected by Kite API) | OPEN |
| L105 | `kc/manager.go:501-502` | Email assignment on existing session without lock | OPEN |
| L106 | `kc/manager.go:268` | `OpenBrowser` uses `exec.Command` -- command injection possible if URL is attacker-controlled | OPEN |
| L107 | `kc/manager.go:320` | `InvalidateAccessToken` errors silently discarded with `_, _` | OPEN |
| L108 | `oauth/handlers.go:315-318` | Redirect URL built with string concatenation -- could be fragile with edge-case URIs | OPEN |
| L109 | `kc/ops/data.go:84` | Session ID exposed in ops API response | OPEN |
| L110 | `app/app.go:534-536` | Template execution error after `WriteHeader(200)` -- partial response | OPEN |

---

## INFO (23)

| ID | File:Line | Description | Status |
|----|-----------|-------------|--------|
| I1 | `go.mod:9` | `mcp-go` updated to `v0.44.0` (was v0.31.0) | FIXED |
| I2 | `go.mod:23` | `gorilla/websocket` updated to `v1.5.3` (was v1.4.2) | FIXED |
| I3 | `go.mod:21` | `gocarina/gocsv` pinned to 2018 commit -- unmaintained dependency | OPEN |
| I4 | `go.mod:13` | `modernc.org/sqlite v1.46.1` -- check CVE-2025-6965 applicability | OPEN |
| I5 | `kc/alerts/store.go:99` | UUID truncated to 8 chars: `uuid.New().String()[:8]` -- ~4B possibilities, collision risk at scale | OPEN |
| I6 | `kc/alerts/crypto.go:22` | HKDF with nil salt and domain separation string "kite-mcp-credential-encryption-v1" | OPEN |
| I7 | `mcp/market_tools.go:121-134` | `Filter()` scans all ~120K instruments without early termination | OPEN |
| I8 | -- | No tests for `oauth/` package (handlers, middleware, jwt, stores) | OPEN |
| I9 | -- | No tests for `kc/alerts/evaluator.go` | OPEN |
| I10 | -- | No tests for `kc/alerts/store.go` | OPEN |
| I11 | -- | No tests for `mcp/post_tools.go` | OPEN |
| I12 | -- | No tests for `mcp/get_tools.go` | OPEN |
| I13 | -- | No tests for `mcp/market_tools.go` | OPEN |
| I14 | -- | No tests for `mcp/ticker_tools.go` | OPEN |
| I15 | -- | No tests for `mcp/alert_tools.go` | OPEN |
| I16 | -- | No tests for `mcp/setup_tools.go` | OPEN |
| I17 | -- | No tests for `kc/ticker/service.go` | OPEN |
| I18 | -- | No tests for `kc/ops/handler.go`, `data.go`, `logbuffer.go` | OPEN |
| I19 | `kc/ticker/service.go:85` | Reconnect max retries hardcoded to 300 | OPEN |
| I20 | `kc/manager.go:82-84` | Alert `onNotify` callback captures `m.telegramNotifier` by closure -- nil check ok | OPEN |
| I21 | `kc/instruments/manager.go:66` | `MemoryLimit` defaults to 0 (no limit) but field is never checked | OPEN |
| I22 | `mcp/common.go:309-316` | `ParsePaginationParams` allows negative `from` values (clamped in `ApplyPagination`) | OPEN |
| I23 | `kc/manager.go:704` | `GetActiveSessionCount` calls `ListActiveSessions` just to count -- allocates full slice | OPEN |

---

## Summary by Category

| Category | Total | Fixed | Open |
|----------|-------|-------|------|
| HIGH (auth/infra) | 6 | 6 | 0 |
| MEDIUM (security/quality) | 42 | 8 | 34 |
| LOW - Error stripping | 15 | 6 | 9 |
| LOW - Shared pointer returns | 8 | 4 | 4 |
| LOW - Missing validation | 12 | 0 | 12 |
| LOW - Logging issues | 15 | 0 | 15 |
| LOW - Test isolation | 5 | 0 | 5 |
| LOW - Cleanup goroutines | 6 | 6 | 0 |
| LOW - Unchecked write errors | 10 | 0 | 10 |
| LOW - Method enforcement | 8 | 8 | 0 |
| LOW - Template caching | 2 | 2 | 0 |
| LOW - Dockerfile hardening | 4 | 4 | 0 |
| LOW - Encryption and crypto | 4 | 4 | 0 |
| LOW - Ticker session validation | 3 | 3 | 0 |
| LOW - Miscellaneous | 18 | 0 | 18 |
| INFO | 23 | 2 | 21 |
| **TOTAL** | **181** | **74** | **107** |

---

## Priority Recommendations (Top 10 Open Items)

1. **M13** -- Add per-route `WriteTimeout` or wrap non-SSE routes with `http.TimeoutHandler`
2. **M15** -- Add mutex protection for `kiteData.Email` assignment on existing sessions
3. **M18/M19** -- Deep-copy `*Alert` pointers in `List()` and `ListAll()` to prevent shared state mutation
4. **M20** -- Add per-user alert limit (e.g. 100) in `Store.Add()`
5. **M29/M30** -- Include `err.Error()` in `WithSession` and `MarshalResponse` error returns
6. **M33/M34** -- Wrap `SubscribeInstrumentsTool`/`UnsubscribeInstrumentsTool` with `WithSession`
7. **L33/L34** -- Add `http.MaxBytesReader` on request bodies in OAuth endpoints
8. **M1** -- Handle `json.Marshal` error in `Authorize` handler
9. **M39** -- Pass copies to `OnChange` callbacks instead of raw entry pointers
10. **M40** -- Add hard cap on `AuthCodeStore` entries (e.g. 10000)
