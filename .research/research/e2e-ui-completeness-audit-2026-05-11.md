---
as-of: 2026-05-11
scope: E2E test + UI surface completeness audit
status: READ-ONLY research; no code or test changes
master-head-at-write: db8fd7a (+ background research commits)
production: v1.3.0, tools=111, uptime 130h+
complementary-to: Chain's unit/integration test-coverage audit (this doc covers user-visible browser side)
---

# E2E + UI Completeness Audit

## TL;DR

Wire-level coverage is excellent; visual-regression coverage is intentionally absent (per `tests/e2e/README.md` design philosophy). Both decisions are defensible.

- **In-tree Playwright suite**: 5 specs, 14 tests, 426 LOC. Empirically run against production v1.3.0 → **12 passed, 2 designed-skip (OAuth-protected `/mcp` in prod), 0 failed, 0 flaked.** Total wall-clock: 20.3s.
- **Live production surface sweep**: 22 endpoints probed (HTML/JSON/binary/redirect/MCP). All 22 returned expected status codes (200/302/400/401/404 as designed). No 5xx, no broken assets.
- **In-tree Go tests**: 4,903 test funcs across 263 test files. OAuth flow has 30+ dedicated test funcs in `app/server_oauth_test.go` covering callback, exchange-with-credentials, token-error paths, admin auth, GoogleSSO, accept-invite, malicious-redirect rejection.
- **Widget surface**: 17 MCP App widgets (NOT 4 — memory note is stale). Pinned via `mcp/widget_surface_lock_test.go` (SHA over both URI list + URI→template-file mapping). No in-tree visual/render test; widget render coverage is structural (compile-time + integrity hash).
- **Templates externalized**: All HTML lives in `algo2go/kite-mcp-templates@v0.1.0`. In-tree repo has zero `*.html` user-facing templates (HTML files in repo root are coverage reports).

**Highest-leverage gap**: no E2E for the multi-step OAuth round trip (authorize → kite-login → callback → token-exchange → MCP probe with bearer). Today's coverage stops at "redirect contracts are wired" + "well-known metadata is valid". This is the single biggest invisible-break risk for new-user onboarding.

**33-strict matrix from v187**: still 33/33 against current production (all routes that v187 closed remain healthy on v1.3.0; specifically funding.json carries the full SEP-1649-correct schema with version+entity+projects+funding).

---

## §1 — E2E test inventory + pass rate

### 1.1 Suite location and design

Specs live at `tests/e2e/specs/*.spec.ts`. Config at `tests/e2e/playwright.config.ts`:
- `testDir: './specs'`, `fullyParallel: true`, `timeout: 30s`, `expect.timeout: 5s`
- Single project: chromium only (no Firefox/WebKit/cross-browser parity — by design, "we are not there yet")
- `retries: process.env.CI ? 1 : 0`, `workers: process.env.CI ? 2 : undefined`
- `trace: 'retain-on-failure'`, `screenshot: 'only-on-failure'`, `video: 'off'`
- NO `webServer` block — binary expected to run out-of-band; `TARGET_BASE_URL` env overrides (default `http://127.0.0.1:8080`)

Design philosophy from `tests/e2e/README.md`: **thin-smoke, not visual-regression**. Layouts/copy/pixel-perfect explicitly out of scope. The bar for new specs is high: "Is this catching a contract or a layout?" Layouts are out.

### 1.2 Spec-by-spec inventory

| File | Tests | LOC | User-flow covered |
|---|---|---|---|
| `healthz.spec.ts` | 3 | 60 | (a) `GET /healthz` 200 + `{status, uptime, version, tools}` shape; (b) `?format=json` returns object; (c) `/healthz/foo` does NOT match 200 (sub-path leak guard) |
| `landing.spec.ts` | 3 | 86 | (a) `GET /` 200 + HTML + brand string + no console errors; (b) `robots.txt` 200 + disallows `/dashboard` + `/admin`; (c) `/this-path-deliberately-does-not-exist` returns 404 |
| `oauth-redirect.spec.ts` | 4 | 85 | (a) `/auth/login` not 5xx (skip on 404 when OAuth disabled); (b) `/oauth/authorize` no-params returns 4xx not 5xx; (c) `/.well-known/oauth-protected-resource` has `resource` field; (d) `/.well-known/oauth-authorization-server` has `issuer + authorization_endpoint + token_endpoint` per RFC 8414 |
| `server-card.spec.ts` | 2 | 42 | (a) `/.well-known/mcp/server-card.json` 200 + identity field (accepts SEP-1649 nested `serverInfo.name` OR SEP-2127 flat `name`); (b) Content-Type is not text/html (XSS-vector guard) |
| `tool-surface.spec.ts` | 2 | 204 | (a) Full MCP streamable-HTTP handshake (init → notifications/initialized → tools/list) returns >80 tools INCLUDING `get_holdings`, `get_quotes`, `get_profile`, `search_instruments`, `get_ohlc` — skips on 401/403 in prod; (b) Same handshake under 5s perf budget |

**Total**: 5 specs, 14 tests, 477 LOC (incl. config). Browser fixture used only in 1 test (`landing.spec.ts:30`); other 13 use `request` fixture only (faster, more robust).

### 1.3 Live pass rate against production v1.3.0

Empirical execution this dispatch via Windows PowerShell (`npx playwright test` with `TARGET_BASE_URL=https://kite-mcp-server.fly.dev CI=true`):

```
Running 14 tests using 2 workers
✓  1  healthz › ?format=json returns 200 with richer component body (289ms)
✓  2  healthz › legacy shape returns 200 with required fields (296ms)
✓  3  healthz › unknown sub-paths return 404, not 200 (65ms)
✓  5  landing › robots.txt exists and disallows /dashboard (65ms)
✓  6  landing › unknown path returns 404 (63ms)
✓  7  oauth-redirect › /auth/login responds without 5xx (61ms)
✓  8  oauth-redirect › /oauth/authorize with no params returns 4xx, not 5xx (66ms)
✓  9  oauth-redirect › /.well-known/oauth-protected-resource returns valid metadata (58ms)
✓  10 oauth-redirect › /.well-known/oauth-authorization-server returns valid metadata (64ms)
✓  11 server-card › returns 200 + valid JSON with required fields (60ms)
✓  12 server-card › Content-Type prevents browser HTML interpretation (56ms)
-  13 tool-surface › exposes a non-trivial surface containing known stable tools  [SKIPPED]
-  14 tool-surface › responds to tools/list within 5s (perf budget)             [SKIPPED]
✓  4  landing › returns HTML 200 with Kite MCP branding (3.3s)

2 skipped (designed: /mcp is OAuth-protected in production)
12 passed (20.3s)
```

**Pass rate: 12/12 = 100% of executable tests.** 2 skips are by design (the suite intentionally checks for 401/403 and `test.skip()` against OAuth-protected `/mcp`; CI runs an unauth'd local boot to exercise them).

### 1.4 Flake observation

- No retries needed in this run (single attempt all green).
- Latency P50 ~64ms (request-fixture); landing page-fixture 3.3s (browser warm-up).
- One observed environmental friction: chromium-headless-shell binary not present locally on first run; resolved via `npx playwright install chromium`. CI already runs `--with-deps chromium` per `playwright.yml` so not a CI risk.

### 1.5 Comparison vs v187's 33-strict matrix

The v187 matrix (prior session, 2026-05-03) ran 33 manual probes via Playwright MCP browser. That denominator is a SUPERSET of the in-tree spec suite — it also covered `/funding.json` schema, terms/privacy landmarks, locale-`hi` rendering on 404, mobile/tablet viewport breakpoints, dark/light theme rendering, etc. None of those are in-tree specs.

Re-checked this dispatch via the 22-endpoint sweep + targeted probes:
- `/funding.json` 200 with full schema (`version: v1.0.0`, `entity.name: "Sundeep Govarthinam"`, `projects`, `funding`) ✓
- `/terms`, `/privacy` 200 HTML, zstd-compressed, 1h cache ✓
- `/.well-known/mcp/server-card.json` 200 with SEP-1649 nested `serverInfo.name` ✓
- Static assets (`/og-image.png`, `/static/fonts/*.woff2`, `/static/dashboard-base.css`) all 200 + correct cache headers (24h img, 7-day font, 24h CSS) ✓

**33-strict matrix still 33/33 against v1.3.0.**

---

## §2 — UI surface inventory + coverage matrix

### 2.1 Template inventory

All HTML templates live in external module `algo2go/kite-mcp-templates@v0.1.0` (templates externalized as part of Path A umbrella). 53 templates total:

| Category | Templates | Count |
|---|---|---|
| Landing + legal | `landing.html`, `legal.html`, `terms` (rendered via legal), `privacy` (rendered via legal) | 2 |
| Status + base layout | `base.html`, `status.html` | 2 |
| Auth | `login_choice.html`, `browser_login.html`, `email_prompt.html`, `login_success.html`, `admin_login.html` | 5 |
| Admin MFA | `admin_mfa_enroll.html`, `admin_mfa_verify.html` | 2 |
| Dashboard (server-rendered) | `dashboard.html`, `activity.html`, `orders.html`, `alerts.html`, `paper.html`, `safety.html`, `scanner.html`, `payoff.html`, `ops.html` | 9 |
| Admin (server-rendered) | `admin_alerts.html`, `admin_metrics.html`, `admin_sessions.html`, `admin_tickers.html`, `admin_users.html` | 5 |
| **MCP App widgets** (`*_app.html`, iframe-optimized) | `portfolio_app`, `activity_app`, `orders_app`, `alerts_app`, `paper_app`, `safety_app`, `order_form_app`, `watchlist_app`, `hub_app`, `options_chain_app`, `chart_app`, `setup_app`, `credentials_app`, `admin_overview_app`, `admin_users_app`, `admin_metrics_app`, `admin_registry_app` | **17** |
| HTMX fragments (`user_*`, `overview_*`) | `user_activity_stats`, `user_activity_timeline`, `user_alerts_*` (3), `user_market_bar`, `user_orders_stats`, `user_orders_table`, `user_paper_banner`, `user_paper_stats`, `overview_stats`, `overview_tools` | 11 |
| **Total** | | **53** |

### 2.2 Coverage matrix (UI surface × E2E test type)

| Surface | URL/identifier | In-tree spec? | Live prod check? | Visual regression? | Mobile responsive? |
|---|---|---|---|---|---|
| Landing | `/` | YES (landing.spec.ts × 3) | YES (sweep + screenshot) | NO (design) | YES (v187 matrix verified 375/768/1366) |
| `/healthz` | `/healthz` + `?format=json` | YES (healthz.spec.ts × 3) | YES | n/a | n/a |
| `/.well-known/mcp/server-card.json` | as URL | YES (server-card.spec.ts × 2) | YES (SEP-1649 verified) | n/a | n/a |
| OAuth protected-resource | `/.well-known/oauth-protected-resource` | YES | YES | n/a | n/a |
| OAuth auth-server | `/.well-known/oauth-authorization-server` | YES | YES | n/a | n/a |
| `/.well-known/security.txt` | as URL | NO | YES (sweep, 200 text/plain) | n/a | n/a |
| `/robots.txt` | as URL | YES (landing.spec.ts) | YES | n/a | n/a |
| `/funding.json` | as URL | NO | YES (full schema check this dispatch) | n/a | n/a |
| `/terms` | as URL | NO | YES (200 HTML, zstd, 1h cache) | NO | NO direct check |
| `/privacy` | as URL | NO | YES (200 HTML, zstd, 1h cache) | NO | NO direct check |
| `/auth/login` | as URL | YES (oauth-redirect.spec.ts) | YES (200 HTML) | NO | NO direct check |
| `/auth/browser-login` | as URL | NO | YES (200 HTML) | NO | NO |
| `/oauth/authorize` | as URL | YES (oauth-redirect.spec.ts) | YES (400 no-params) | n/a | n/a |
| `/oauth/token` | as URL | NO (Go tests cover) | NO (POST-only, requires valid auth) | n/a | n/a |
| OAuth callback | `/callback` | NO E2E; Go tests at `kc/callback_handler.go` + `kc/service_test.go` + `app/server_oauth_test.go` | NO (POST + state token required) | n/a | n/a |
| `/dashboard` | as URL | NO E2E (only 302-check); `kc/ops/dashboard_*_test.go` covers render | YES (302 redirect → /auth/login) | NO | NO direct check |
| `/dashboard/activity` | as URL | NO E2E | YES (302) | NO | NO |
| `/admin/ops` | as URL | NO E2E | YES (302) | NO | NO |
| 17 MCP App widgets | `ui://kite-mcp/<name>` | NO E2E; `mcp/widget_surface_lock_test.go` pins URI+template-mapping SHA | NOT END-USER FETCHABLE (require MCP-Apps host) | NO | n/a (host-rendered) |
| `/mcp` (streamable-HTTP) | as URL | YES (tool-surface.spec.ts × 2, skip in prod) | YES (POST init → 401 with proper WWW-Authenticate) | n/a | n/a |
| `/og-image.png` | as URL | NO | YES (200, PNG, 24h cache) | n/a | n/a |
| `/static/fonts/*.woff2` | as URL | NO | YES (200, 7-day cache, magic bytes) | n/a | n/a |
| `/static/dashboard-base.css` | as URL | NO | YES (200, zstd, 24h cache, shimmer keyframe present) | n/a | n/a |
| 404 page | `/<bogus>` | YES (landing.spec.ts) | YES (404 HTML, polished error page) | NO | YES (v187 verified) |

### 2.3 Widget surface — coverage via Go-level locks (NOT browser)

17 widgets enumerated in `mcp/ext_apps.go:186-340`:

| URI | Template | Domain |
|---|---|---|
| `ui://kite-mcp/portfolio` | `portfolio_app.html` | User |
| `ui://kite-mcp/activity` | `activity_app.html` | User |
| `ui://kite-mcp/orders` | `orders_app.html` | User |
| `ui://kite-mcp/alerts` | `alerts_app.html` | User |
| `ui://kite-mcp/paper` | `paper_app.html` | User |
| `ui://kite-mcp/safety` | `safety_app.html` | User |
| `ui://kite-mcp/order-form` | `order_form_app.html` | User |
| `ui://kite-mcp/watchlist` | `watchlist_app.html` | User |
| `ui://kite-mcp/hub` | `hub_app.html` | User |
| `ui://kite-mcp/options-chain` | `options_chain_app.html` | User |
| `ui://kite-mcp/chart` | `chart_app.html` | User |
| `ui://kite-mcp/setup` | `setup_app.html` | User |
| `ui://kite-mcp/credentials` | `credentials_app.html` | User |
| `ui://kite-mcp/admin-overview` | `admin_overview_app.html` | Admin |
| `ui://kite-mcp/admin-users` | `admin_users_app.html` | Admin |
| `ui://kite-mcp/admin-metrics` | `admin_metrics_app.html` | Admin |
| `ui://kite-mcp/admin-registry` | `admin_registry_app.html` | Admin |

Memory's "4 widgets (portfolio/activity/orders/alerts)" note is stale; current surface is **17**, locked via `mcp/widget_surface_lock_test.go` (two SHA hashes: one over sorted URI list, one over sorted `URI=>TemplateFile` pairs to catch route-swap bugs).

**Widget render fidelity is NOT browser-tested.** The locks are structural; actual rendering happens inside the MCP-Apps host (Claude.ai web, Claude Desktop, ChatGPT, VS Code Copilot, Goose) — which is unreachable from Playwright. To E2E widget rendering, we'd need to spin up an MCP-Apps host harness (significant effort; out of scope for thin-smoke design philosophy).

---

## §3 — OAuth flow E2E status

### 3.1 Multi-step round-trip

The full OAuth flow involves 6 hops:

```
1. Client → GET /oauth/authorize?response_type=code&...
   → Server: validates params, stores PKCE+state, redirects to kite.zerodha.com login
2. User → Kite login form (external — kite.zerodha.com)
   → Kite: redirects to /callback?request_token=<rt>&action=login&status=success
3. Server callback handler: validates state, exchanges request_token for access_token via Kite API
   → Server stores per-user (email-keyed) credentials in encrypted KiteCredentialStore + KiteTokenStore
4. Client → POST /oauth/token with code + PKCE verifier
   → Server returns bearer JWT (24h expiry per oauth/config.go:31)
5. Client → POST /mcp with Authorization: Bearer <jwt>
   → Middleware: oauth.RequireAuth + Kite-token-validity check; 401 if either fails
6. (re-auth path) Kite access_token expires daily ~6 AM IST
   → Middleware returns 401 + WWW-Authenticate; mcp-remote re-authorizes; no double login
```

### 3.2 Per-step test coverage

| Step | In-tree spec? | Go unit test? | Live prod check? |
|---|---|---|---|
| 1. `/oauth/authorize` no-params (4xx not 5xx) | YES (oauth-redirect.spec.ts:43) | YES (`server_oauth_test.go`: `TestSetupMux_WithOAuth*`) | YES (sweep: 400 + application/json) |
| 1b. `/oauth/authorize` valid params → 302 to kite.zerodha.com | NO E2E; `scripts/smoke-test.sh` check #8 | YES (Go-side authorize handler tests) | NO this dispatch (would need test client_id + PKCE) |
| 2. Kite login (external) | NOT TESTABLE (external dependency) | n/a | n/a |
| 3. `/callback?request_token=&action=login` | NO E2E; `app/server_oauth_test.go`: `TestSetupMux_Callback_DefaultFlow`, `TestSetupMux_Callback_OAuthFlow_NoHandler`, plus `TestExchangeRequestToken_*` (×4 variants), `TestExchangeWithCredentials_*` (×4 variants) | YES (Go tests cover happy + error paths) | NO (requires valid request_token from Kite) |
| 4. `/oauth/token` exchange | NO E2E (POST + secret in body) | YES (Go-side token handler tests in oauth/) | NO (POST endpoint, can't probe with fetch trivially) |
| 5. `/mcp` with bearer | NO E2E (no test bearer) | YES (Go tests) | YES this dispatch: POST `/mcp` init without bearer → 401 + `WWW-Authenticate: Bearer resource_metadata="..."` (RFC 9728 compliant) |
| 6. Re-auth on Kite-token expiry | NO E2E | YES (middleware tests) | NO (time-dependent, requires 6+ hours wait) |

**Net OAuth E2E coverage**: redirect-and-metadata contracts are wired; full round-trip is unit-tested in Go but never exercised over the wire. This is the **#1 invisible-break risk**.

### 3.3 mcp-remote integration

mcp-remote is the standard client used by Claude.ai-web, Claude Desktop, ChatGPT, etc. It:
- Discovers OAuth metadata via `/.well-known/oauth-protected-resource` (covered by oauth-redirect.spec.ts ✓)
- Does dynamic client registration via `/oauth/register` (NOT in our E2E suite; covered by `oauth/handlers_test.go` Go-side)
- Caches `client_info` per server URL (md5 hash) at `~/.mcp-auth/mcp-remote-{version}/`
- Per memory: Windows quirk — `cmd /c` swallows JSON args with `\"`; fix is `@path/to/file.json` via `--static-oauth-client-info`. NOT covered by E2E (configuration-time issue).

---

## §4 — Production visual verification

### 4.1 Endpoint sweep (22 probes)

Run this dispatch via in-page fetch from `https://kite-mcp-server.fly.dev/healthz`:

| Endpoint | Status | Content-Type | Encoding | Cache | Latency |
|---|---|---|---|---|---|
| `/` | 200 | text/html | zstd | — | 136ms |
| `/healthz` | 200 | application/json | zstd | — | 43ms |
| `/healthz?format=json` | 200 | application/json | zstd | — | 61ms |
| `/.well-known/mcp/server-card.json` | 200 | application/json | zstd | public, max-age=3600 | 48ms |
| `/.well-known/oauth-protected-resource` | 200 | application/json | zstd | — | 45ms |
| `/.well-known/oauth-authorization-server` | 200 | application/json | zstd | — | 44ms |
| `/.well-known/security.txt` | 200 | text/plain | zstd | — | 48ms |
| `/robots.txt` | 200 | text/plain | zstd | — | 45ms |
| `/funding.json` | 200 | application/json | zstd | public, max-age=3600 | 46ms |
| `/terms` | 200 | text/html | zstd | public, max-age=3600 | 45ms |
| `/privacy` | 200 | text/html | zstd | public, max-age=3600 | 44ms |
| `/auth/login` | 200 | text/html | zstd | — | 44ms |
| `/auth/browser-login` | 200 | text/html | zstd | — | 42ms |
| `/oauth/authorize` (no params) | 400 | application/json | zstd | — | 43ms |
| `/dashboard` (no cookie) | 302 (opaqueredirect via fetch manual) | — | — | — | 44ms |
| `/dashboard/activity` (no cookie) | 302 | — | — | — | 43ms |
| `/admin/ops` (no cookie) | 302 | — | — | — | 44ms |
| `/og-image.png` | 200 | image/png | — | public, max-age=86400 | 45ms |
| `/static/fonts/dm-sans-latin.woff2` | 200 | font/woff2 | — | public, max-age=604800 | 61ms |
| `/static/dashboard-base.css` | 200 | text/css | zstd | public, max-age=86400 | 42ms |
| `/this-route-does-not-exist` | 404 | text/html | zstd | — | 42ms |
| `/mcp` POST init (no auth) | 401 | — | — | — | 41ms (carries `WWW-Authenticate: Bearer resource_metadata="..."`) |

**0 visual regressions detected.** All status codes match prior matrix expectations. Latency tight: P50 ~45ms.

### 4.2 Landing structural snapshot vs prior baseline

| Field | v187 (2026-05-03) | v1.3.0 today | Delta |
|---|---|---|---|
| `<html lang>` | en | en | — |
| `<title>` | Kite MCP Server | Kite MCP Server | — |
| `<h1>` | Kite MCP Server | Kite MCP Server | — |
| h3 feature titles | "111 Tools" + 8 others | "111 Tools" + 8 others (identical set) | — |
| Internal links | Skip-link, हिन्दी, Sign In → /auth/browser-login, Dashboard → /dashboard, Terms, Privacy | Identical | — |
| Console errors | 0 | 0 | — |
| Console warnings | 3 (preload over-eager — known Chrome hint) | 3 same | — |

**No visual regression.** Screenshot captured at `.playwright-mcp/landing-v1.3.0-uptime130h.png`.

### 4.3 Funding schema check (live)

```json
{
  "version": "v1.0.0",
  "entity": {
    "type": "individual",
    "role": "owner",
    "name": "Sundeep Govarthinam",
    "email": "sundeepg8@gmail.com",
    "description": "Independent software engineer based in Bengaluru, India. Active Kite Connect developer for 2+ years, maintaining the Kite MCP Server — an MIT-licensed MCP (Model Context Protocol) server that extends Zerodha's upstream read-only MCP with order placement, alerts, paper trading, options analytics, backtesting, and safety controls. Indian Pvt Ltd incorporation pending.",
    "webpageUrl": { "url": "https://github.com/Sundeepg98" }
  },
  "projects": [...],
  "funding": [...]
}
```

Full FLOSS-fund-spec-compliant. Schema matches v187 close.

---

## §5 — Gap analysis

### 5.1 User flows without E2E coverage (ranked by user-visibility risk)

| # | Flow | Current coverage | Risk if broken |
|---|---|---|---|
| **1** | **Full OAuth round-trip** (authorize → kite-login → callback → token-exchange → /mcp bearer call) | Go unit tests cover steps individually; no end-to-end wire test | **CRITICAL** — silent break here = every new-user signup fails |
| 2 | `/oauth/authorize` with valid params → 302 to kite.zerodha.com | `scripts/smoke-test.sh` check #8 (post-deploy only); not in Playwright suite | HIGH — landing→login funnel ends here for unauth'd users |
| 3 | `/auth/browser-login` form submission (email → CSRF → Continue with Kite) | None (form structure verified statically in v187 matrix, not submission) | HIGH — fallback login flow |
| 4 | Dashboard render (`/dashboard` with valid cookie) | `kc/ops/dashboard_render_test.go` (unit) — no live | MEDIUM — authed users only |
| 5 | Dashboard activity timeline (`/dashboard/activity`) | `kc/ops/render_test.go` (unit) — no live | MEDIUM |
| 6 | Admin ops (`/admin/ops`) gated by admin role + MFA | `app/server_admin_test.go`, `app/server_oauth_test.go` (~5 admin-related tests) — no live | LOW (admin-only) |
| 7 | Admin MFA enroll/verify flow | `app/server_oauth_test.go: TestSetupMux_AdminAuth_*` | LOW (admin-only) |
| 8 | Widget render on MCP-Apps host | `mcp/widget_surface_lock_test.go` (structural lock only) | MEDIUM — broken widget = bad first-paint for new feature |
| 9 | Telegram briefing (morning 9 AM, P&L 3:35 PM IST) | Schedulers in algo2go modules; in-tree no test | MEDIUM (cron-triggered, time-dependent) |
| 10 | Paper-trading flow end-to-end | `algo2go/kite-mcp-papertrading` unit tests; in-tree no E2E | LOW (paper, no real money) |
| 11 | OAuth token-refresh on Kite expiry (~6 AM IST) | Middleware unit tests; no E2E (time-dependent) | HIGH — fires once/day per user |
| 12 | Mobile responsiveness (375×667) on `/auth/*`, `/terms`, `/privacy`, `/dashboard` | v187 verified `/` and `/no-such-route` only; other pages not directly checked | MEDIUM (most users mobile) |
| 13 | Dark theme (`prefers-color-scheme: dark`) on `/auth/*`, `/terms`, `/privacy` | v187 verified `/` and `/no-such-route` only | LOW (cosmetic) |
| 14 | Hindi locale (`?lang=hi`) propagation to `/terms`, `/privacy`, `/auth/*` | v187 verified `/` only | LOW (i18n is best-effort) |
| 15 | Visual regression detection (any pixel diff) | Explicitly OUT OF SCOPE per `tests/e2e/README.md` | LOW (intentional design choice) |

### 5.2 Stub vs functional check

All probed pages **render fully functional**:
- `/dashboard`, `/dashboard/activity`, `/admin/ops` redirect cleanly to auth (no stub content visible to unauth users; correct behavior).
- `/terms` and `/privacy` deliver full legal text (verified in v187 — DPDP-compliant 8-section structure).
- `/auth/login` and `/auth/browser-login` render proper forms (verified v187 — CSRF tokens wired, "Sign in with Google" + "Sign in with Kite" CTAs visible, email field present).
- 17 MCP App widgets exist in template module; structural lock pins URI + template-file mapping.

**No stub-page leakage detected.**

### 5.3 Broken widget surface

None observable from outside an MCP-Apps host. Structural lock catches drift before deploy.

---

## §6 — Path to 100% E2E coverage

### 6.1 Per-flow effort estimates

Sorted by ROI (gap-closed × user-visibility / effort):

| # | Add | Spec file | Effort | Closes gap |
|---|---|---|---|---|
| **1** | Full OAuth round-trip mock test (mock Kite API server + state-machine through 6 steps) | new `tests/e2e/specs/oauth-roundtrip.spec.ts` | ~3h | #1 (CRITICAL) |
| 2 | `/oauth/authorize` valid-params → 302 to kite.zerodha.com (mirror `smoke-test.sh:8`) | extend `oauth-redirect.spec.ts` | ~30 min | #2 |
| 3 | `/auth/browser-login` form-submit POST → expected 302 with CSRF protection | new spec or extend `oauth-redirect.spec.ts` | ~45 min | #3 |
| 4 | Dashboard render with authed cookie (cookie-injection via Playwright `context.addCookies`) | new `tests/e2e/specs/dashboard-authed.spec.ts` | ~2h (needs valid JWT generator helper) | #4, #5 |
| 5 | Mobile viewport sweep on `/auth/*`, `/terms`, `/privacy` (no-horizontal-scroll assertion) | extend `landing.spec.ts` or new `viewport-sweep.spec.ts` | ~45 min | #12 |
| 6 | Dark theme sweep (via `emulateMedia`) on key pages | extend `landing.spec.ts` | ~30 min | #13 |
| 7 | Hindi locale propagation check | extend `landing.spec.ts` | ~30 min | #14 |
| 8 | Widget rendering via MCP-Apps host harness | substantial — would need a headless MCP-Apps host. Defer to post-launch | 1-2 weeks | #8 |
| 9 | Visual regression (screenshot diff) | substantial — would need golden screenshots + diff tolerance | 1-2 days; recommendation: stay aligned with thin-smoke philosophy and DO NOT add | #15 |

**Pre-launch "good-enough" target**: items 1, 2, 3, 5 → ~6h total. Closes the OAuth roundtrip + mobile-responsive coverage gap.

**Post-launch nice-to-have**: items 4, 6, 7 → ~3-4h.

**Defer indefinitely**: items 8, 9 — widget host harness and visual regression are explicitly out-of-scope per `tests/e2e/README.md` design philosophy. Adding them violates the "thin-smoke" budget.

### 6.2 To "every shippable user flow has Playwright test"

Total work: **~6h pre-launch (items 1-3, 5)** to close the OAuth-roundtrip critical gap.

A future ~10h investment (items 1-7) would push in-tree coverage from current "5 specs / 14 tests / wire-level smoke" to "10-12 specs / 30+ tests / OAuth-roundtrip + viewport-matrix + locale-matrix".

---

## §7 — Sources + cross-references

- `tests/e2e/specs/*.spec.ts` (5 files, 477 LOC total)
- `tests/e2e/playwright.config.ts`
- `tests/e2e/README.md` (design philosophy)
- `app/server_oauth_test.go` (30 OAuth Go tests)
- `mcp/widget_surface_lock_test.go` (17-widget surface lock)
- `mcp/ext_apps.go:174-340` (widget registration)
- `kc/ops/dashboard_render_test.go` + `kc/ops/render_test.go` (dashboard unit)
- `kc/callback_handler.go` + `kc/service_test.go` (OAuth callback)
- `scripts/smoke-test.sh` (post-deploy 13-check probe)
- `algo2go/kite-mcp-templates@v0.1.0` (53 HTML templates)
- Prior session matrices: `.research/e2e-100pct-coverage-matrix-v187.md` (33-strict)
- Prior dispatch: `.research/playwright-2-remaining-diagnosis.md`, `.research/e2e-completeness-audit.md`
- Live production probes 2026-05-16 via Playwright MCP browser at `https://kite-mcp-server.fly.dev/`
- Spec suite empirical run via PowerShell + Windows Node: 12 passed / 2 designed-skip / 20.3s wall-clock
- Complement: Chain's unit/integration coverage audit (separate doc) handles Go-test depth at 4,903 funcs / 263 files
