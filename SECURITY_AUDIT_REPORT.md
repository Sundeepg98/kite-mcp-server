# Kite MCP Server — Security & Code Quality Audit Report

**Date:** 2026-02-24
**Scope:** Full codebase (`D:\kite-mcp-temp`), 47 Go files, ~9,700 LOC
**Passes:** 27 manual analysis passes
**Total Findings:** 181 (6 HIGH, ~40 MED, ~115 LOW, ~20 INFO)

---

## Executive Summary

The kite-mcp-server is a Go MCP server providing 30 tools for AI-assisted trading via Zerodha's Kite API. It supports per-user OAuth 2.1 with PKCE, WebSocket ticker connections, price alerts with Telegram notifications, and an ops dashboard.

Six HIGH-severity issues were identified, primarily around authentication bypass and information disclosure. The most critical compound vulnerability chain combines SSE endpoint auth bypass + access token logging + ops dashboard access to enable full account takeover.

---

## HIGH Severity (6 findings)

### H1: SSE endpoints bypass OAuth in hybrid mode (#16, #162)
**File:** `app/app.go:390-391`
```go
mux.HandleFunc("/sse", withSessionType(mcp.SessionTypeSSE, sse.ServeHTTP))
mux.HandleFunc("/message", withSessionType(mcp.SessionTypeSSE, sse.ServeHTTP))
```
**Impact:** `/sse` and `/message` have no OAuth middleware while `/mcp` does. Anyone can connect without auth.
**Fix:** Wrap with `app.oauthHandler.RequireAuth()` like `/mcp` endpoint.

### H2: Access token logged in plaintext (#21, #157)
**File:** `kc/manager.go:669`
```go
m.Logger.Info("KITE_ACCESS_TOKEN for reuse", "access_token", userSess.AccessToken)
```
**Impact:** Token flows through TeeHandler → LogBuffer → SSE stream to ops dashboard. Any dashboard user can steal any user's Kite token.
**Fix:** Delete this line entirely.

### H3: Auto-registration accepts any redirect_uri scheme (#108, #118, #163)
**File:** `oauth/handlers.go:159-164`
```go
if _, ok := h.clients.Get(clientID); !ok {
    h.clients.RegisterKiteClient(clientID, []string{redirectURI})
```
**Impact:** Combined with `login_success.html` executing `window.location.href={{.RedirectURL}}`, attacker can register `javascript:` URI → XSS in server origin → steal JWT cookie.
**Fix:** Validate redirect_uri scheme is `http` or `https` before auto-registration.

### H4: Zero HTTP timeouts (#132, #160)
**File:** `app/app.go:248-250`
```go
ReadTimeout:  0,
WriteTimeout: 0,
```
**Impact:** Slowloris can exhaust server connections/memory. All endpoints affected, not just SSE.
**Fix:** Set `ReadTimeout: 30 * time.Second` with per-handler override for SSE, or use `ReadHeaderTimeout`.

### H5: XSS via javascript: redirect in login_success.html (#108, #117)
**File:** `kc/templates/login_success.html`
```html
window.location.href={{.RedirectURL}}
```
**Impact:** `html/template` auto-escaping prevents HTML injection but NOT `javascript:` URIs in JS context.
**Fix:** Validate RedirectURL starts with `http://` or `https://` before rendering.

### H6: CVE-2025-6965 — SQLite memory corruption (conditional) (#173)
**Dependency:** `modernc.org/sqlite v1.46.1` (transpiled C SQLite)
**Impact:** CVSS 9.8, affects SQLite < 3.50.2. Impact depends on which C SQLite version is transpiled.
**Fix:** Verify modernc.org/sqlite v1.46.1 includes SQLite >= 3.50.2, or upgrade.

---

## Compound Vulnerability Chains

### Chain A: Full Account Takeover (H1 + H2)
1. Connect to `/sse` (no auth, H1)
2. Call any tool — auto-creates session
3. Access token logged to LogBuffer (H2)
4. If ops dashboard accessible, observe all tokens in real-time
5. Use stolen token to trade on victim's Kite account

### Chain B: XSS via Auto-Registration (H3 + H5)
1. `GET /oauth/authorize?client_id=evil&redirect_uri=javascript:steal()&...`
2. Server auto-registers with `javascript:` URI (H3)
3. After login, template executes JS (H5)
4. Steals JWT cookie → full API access

### Chain C: Session Hijack via Token Leak (H2 + ops dashboard)
1. Any authenticated dashboard user sees `KITE_ACCESS_TOKEN` in log stream
2. Token grants full Kite API access (place orders, view portfolio)

---

## MEDIUM Severity (~40 findings, top 15 listed)

| # | Finding | File | Description |
|---|---------|------|-------------|
| 93 | GTT missing Product field | post_tools.go:504 | ModifyGTTOrderTool omits Product vs PlaceGTTOrderTool |
| 102 | Double-trigger race | alerts/evaluator.go:25 | GetByToken returns shared pointers, concurrent ticks double-trigger |
| 91 | Ticker tools bypass auth | ticker_tools.go:66 | stop_ticker/ticker_status skip WithSession |
| 98 | mcp-go 13 versions behind | go.mod | v0.31.0 vs v0.44.0 latest |
| 105 | No SQLite busy_timeout | alerts/db.go | Concurrent writers get SQLITE_BUSY |
| 119 | State not URL-encoded | oauth/handlers.go:285 | Breaks redirect if state contains & or = |
| 133 | Shutdown order wrong | app/app.go:262 | kcManager killed before HTTP server |
| 136 | Decrypt fallback returns ciphertext | alerts/crypto.go | Wrong key → returns garbage as plaintext |
| 145 | Open redirect | oauth/handlers.go:371 | Browser auth callback redirect not validated |
| 148 | JWT audience not validated | oauth/jwt.go | Dashboard cookies work as MCP Bearer tokens |
| 152 | Credential IDOR | kc/ops/handler.go | Any auth'd user manages ANY user's credentials |
| 153 | No HTTP method check | kc/ops/handler.go | GET/POST/DELETE all accepted on same endpoints |
| 158 | Email written without mutex | kc/manager.go:501 | kiteData.Email race in concurrent tool calls |
| 172 | gorilla/websocket outdated | go.mod | v1.4.2 (2020), advisory GHSA-jf24-p9p9-4rjh |
| 175 | No tests for security paths | oauth/*.go | PKCE, auto-reg, redirect validation all untested |

---

## LOW Severity (~115 findings, categories)

| Category | Count | Examples |
|----------|-------|---------|
| Error stripping (generic messages) | ~15 | modify_order, cancel_order, place_gtt_order, etc. |
| Shared pointer returns | ~8 | token_store.Get, credential_store.Get, store.GetByToken |
| Missing validation | ~10 | No limit on alerts per user, no eviction on ClientStore |
| Logging issues | ~5 | Session IDs at Info, request_token at Info |
| Test isolation | ~5 | Global env vars, package-level URL mutation |
| Cleanup goroutines never stop | ~3 | AuthCodeStore, metrics, instruments scheduler |
| Miscellaneous | ~70 | Prometheus injection, HTTP status unchecked, etc. |

---

## INFO Severity (~20 findings)

- Filter scans all ~120K instruments without early termination
- UUID truncated to 8 chars for alert IDs
- float64 for GTT quantity (correct — Kite API uses float64)
- chat_id truncation from float64 → int64 (safe for Telegram IDs)
- `MemoryLimit` config unused
- Deprecated constructors still present

---

## Top 6 Actionable Fixes (Effort/Impact)

| Priority | Fix | Lines | Eliminates |
|----------|-----|-------|-----------|
| 1 | Delete access token log line | 1 | Chain C, Chain D |
| 2 | Add OAuth to /sse + /message | 2 | Chain A |
| 3 | Validate redirect_uri scheme | ~5 | Chain B |
| 4 | URL-encode state in redirect | 1 | #119, #164 |
| 5 | Set ReadHeaderTimeout | 1 | H4 |
| 6 | Swap shutdown order (HTTP before kcManager) | ~5 | #133, #161 |

Total: ~15 lines of code to fix all HIGH-severity issues.

---

## Test Coverage Gaps

| File | Lines | Tests | Risk |
|------|-------|-------|------|
| oauth/handlers.go | 565 | 0 | HIGH — PKCE, auto-reg, redirects |
| oauth/middleware.go | 105 | 0 | HIGH — auth bypass |
| oauth/stores.go | 190 | 0 | MED — cleanup, eviction |
| kc/session.go | 404 | 0 | MED — session lifecycle |
| kc/alerts/store.go | 249 | 0 | MED — race conditions |
| kc/alerts/evaluator.go | 60 | 0 | MED — double-trigger |
| mcp/post_tools.go | 551 | 0 | MED — order validation |
| kc/manager.go | 894 | 0 | MED — callback, token cache |

---

## Dependencies

| Dependency | Version | Latest | Risk |
|-----------|---------|--------|------|
| mark3labs/mcp-go | v0.31.0 | v0.44.0 | MED — 13 versions behind |
| gorilla/websocket | v1.4.2 | v1.5.3 | MED — 2020, memory DoS advisory |
| modernc.org/sqlite | v1.46.1 | check | HIGH (conditional) — CVE-2025-6965 |
| golang-jwt/jwt/v5 | v5.3.1 | current | OK |
| google/uuid | v1.6.0 | current | OK |
| gocarina/gocsv | pinned 2018 | current | INFO — unmaintained |

---

## Files Analyzed (Complete Coverage)

```
app/app.go, app/app_test.go, app/metrics/metrics.go
kc/manager.go, kc/session.go, kc/session_signing.go
kc/token_store.go, kc/credential_store.go
kc/alerts/store.go, kc/alerts/evaluator.go, kc/alerts/db.go
kc/alerts/telegram.go, kc/alerts/crypto.go
kc/instruments/manager.go, kc/instruments/manager_test.go
kc/instruments/instruments.go, kc/instruments/search.go
kc/ops/handler.go, kc/ops/logbuffer.go
kc/ticker/service.go, kc/ticker/status.go
kc/templates/base.html, login_success.html, browser_login.html, ops.html, status.html
mcp/common.go, mcp/common_test.go, mcp/mcp.go
mcp/market_tools.go, mcp/get_tools.go, mcp/post_tools.go
mcp/setup_tools.go, mcp/ticker_tools.go, mcp/alert_tools.go, mcp/mf_tools.go
oauth/handlers.go, oauth/middleware.go, oauth/jwt.go, oauth/stores.go
main.go, go.mod, go.sum, Dockerfile, justfile
```
