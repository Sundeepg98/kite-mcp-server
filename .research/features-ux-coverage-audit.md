# Features + UX + E2E Coverage Audit

**Date**: 2026-04-26
**HEAD**: master (ahead of origin by 48 commits; uncommitted riskguard/domain edits in tree)
**Method**: read-only audit across three orthogonal lenses — backend feature inventory, frontend/UI/UX, end-to-end test coverage. Cross-referenced against `.research/resume-feature-inventory.md` (94 tools / 50 routes baseline at `4b416ab`), `scorecard-final.md` (~90.04 equal-weighted), `final-138-gap-catalogue.md` (138 gaps, 13 dims), and `architecture-100-gap-current.md` (architecture gap = ZERO at `7649dfb`).
**Charter**: read-only; one doc commit only.

---

## 1. Executive Summary

The kite-mcp-server is a **feature-rich, well-architected backend** with surprisingly **complete UI** for its category, but **mature E2E coverage is the weakest of the three lenses**. Backend: ~111 MCP tools registered (smoke test floor 84; 18 gated on Path 2 hosted), 27 use cases, 9-check riskguard, 10-stage middleware, 5+ broker adapters, 15 domain event types, full per-user OAuth + AES-256 credential encryption, billing (Stripe), paper trading, scheduler with morning brief + EOD P&L, native Telegram bot. UI: 17 MCP App widgets registered as `ui://` resources (rendered on Claude.ai/Desktop, ChatGPT, VS Code Copilot, Goose), polished SSR dashboard with HTMX + dark-mode design system, 60+ HTML templates, ~50 HTTP routes, billing portal, admin pages. Tests: 345+ Go test files, comprehensive unit + integration coverage in mcp/, kc/, app/, oauth/; **but the only true subprocess-spawning E2E test is `mcp/e2e_roundtrip_test.go` (gated behind `//go:build e2e`), and there is ZERO browser-level test infrastructure** (no Playwright, Chromedp, package.json, Cypress) — the dashboard, widgets, OAuth login UX, and billing flow are entirely manually verified. The biggest absolute gap is **browser/UX automation**, not features. The product is in a "Tier-1 user journeys completely shipped, but verified by hand" state.

---

## 2. Lens 1: Backend Feature Completeness

### 2.1 MCP tool inventory (~111 registered, 84+ exposed on hosted)

Counted via `RegisterInternalTool` in `mcp/*.go` (post-Investment-J registry pattern, commits `94fe4b8`, `3c848ef`). 116 occurrences across 51 files. New tools per CHANGELOG: `analyze_concall`, `get_fii_dii_flow`, `peer_compare`, `server_version`, `composite_alert`. Smoke-test floor at `>=84` (scripts/smoke-test.sh:292).

| Category | Tools | Source files | Shipped? | Coverage |
|---|---|---|---|---|
| Market data / quotes (6) | `get_quotes`, `search_instruments`, `get_historical_data`, `get_ltp`, `get_ohlc`, `get_option_chain` | market_tools.go, option_tools.go | YES | get_tools_test.go + property tests |
| Read account (10) | profile/margins/holdings/positions/trades/orders/gtts/order_trades/order_history/pnl_journal | get_tools.go, pnl_tools.go | YES | unit-tested |
| Order writes (7) | place/modify/cancel/place_gtt/modify_gtt/delete_gtt/convert_position | post_tools.go | YES, gated Path 2 | path2_integration_test.go |
| Exit helpers (2) | close_position, close_all_positions | exit_tools.go | YES, gated | exit_tools test |
| Trailing stops (3) | set/list/cancel_trailing_stop | trailing_tools.go | YES, gated | trailing_tools test |
| Pre-trade / margin (4) | pre_trade_check, get_order_margins, get_basket_margins, get_order_charges | pretrade_tool.go, margin_tools.go | YES | tested |
| Mutual funds (7) | mf_orders/sips/holdings + place/cancel ×2 | mf_tools.go | YES, gated | tested |
| Alerts (4 app + 5 native) | setup_telegram, set/list/delete_alert; place/list/modify/delete/history native | alert_tools.go, native_alert_tools.go | YES | composite_alert + history tested |
| Watchlists (6) | create/delete/add/remove/get/list | watchlist_tools.go | YES | tested |
| Ticker (5) | start/stop/status/sub/unsub | ticker_tools.go | YES | callbacks_test, service_edge_test |
| Paper trading (3) | toggle/status/reset | paper_tools.go | YES | engine_test, monitor tests |
| Analytics / portfolio (6) | summary/concentration/position_analysis/rebalance/sector_exposure/tax_harvest | analytics_tools.go, rebalance_tool.go, sector_tool.go, tax_tools.go | YES | sector_tool_property_test, tax_tools_test |
| Technicals / options / backtest (5) | technical_indicators, options_greeks, options_strategy, backtest_strategy, dividend_calendar | indicators_tool.go, options_greeks_tool.go, backtest_tool.go, dividend_tool.go | YES | indicators_property_test, options_greeks_property_test, option_chain_greeks_test |
| Admin — users (5) | list/get/suspend/activate/change_role | admin_user_tools.go | YES | admin_tools_test, admin_integration_test |
| Admin — risk (5) | risk_status, freeze/unfreeze user/global | admin_risk_tools.go | YES | tested |
| Admin — family (3) | invite/list/remove_family_member | admin_family_tools.go | YES | family_usecases_test |
| Admin — server / observability (5) | server_status, server_metrics, sebi_compliance_status, admin_get_user_baseline, admin_stats_cache_info, admin_list_anomaly_flags, server_version | observability_tool.go, compliance_tool.go, admin_baseline_tool.go, admin_cache_info_tool.go, admin_anomaly_tool.go, version_tool.go | YES | each has _test.go |
| Setup / session / self-service (5) | login, open_dashboard, trading_context, delete_my_account, update_my_credentials | setup_tools.go, context_tool.go, account_tools.go | YES | manager_commands_account_test |
| Research copilot (3) | analyze_concall, get_fii_dii_flow, peer_compare | concall_tool.go, fii_dii_tool.go, peer_compare_tool.go | YES (Apr 2026) | each has _test.go |
| Composite alerts (1) | composite_alert | composite_alert_tool.go | YES (Unreleased per CHANGELOG) | composite_alert_tool_test.go |
| Volume spikes / projection / position history (3) | volume_spike, projection, position_history | volume_spike_tool.go, projection_tool.go, position_history_tool.go | YES | each has _test.go |

**Backend feature gaps (Kite API surface NOT wrapped):**

| Kite API surface | Wrapped? | Notes |
|---|---|---|
| `GetUserMarginsBySegment` | NO | Only generic `get_margins`. Could expose equity-vs-commodity split. |
| `GetUserSegmentMargins` | NO | (same — Kite has segment-aware variants we collapse) |
| `place_basket_order` (multiple legs single call) | PARTIAL | We have basket_margins but not basket order placement; users compose via N tool calls |
| `GetMFAllotments` / detailed SIP modify | PARTIAL | get_mf_sips works; no `modify_mf_sip` — only place + cancel |
| Order GTC/IOC/Day variants beyond LIMIT/SL/SLM | YES | place_order accepts variety |
| `GetMargins(commodity)` | NO | commodity segment is supported by Kite but no commodity-specific tool |
| Bracket orders (BO) | DEPRECATED | Kite removed BO; no gap |
| Cover orders (CO) | NOT EXPOSED | Could be wrapped (`place_co_order`) — minor |
| MarketWatch sync (cloud watchlists) | NO | watchlists are server-local only; not synced to Kite Web app |

### 2.2 Use cases (27 files in `kc/usecases/`)

All write paths route Tool→UseCase→CQRS→Broker per `.claude/CLAUDE.md` policy. Verified: place_order, modify_order, cancel_order, place_gtt, paper_trading_usecases, family_usecases, native_alert_usecases, mf_usecases, trailing_stop_usecases, etc. Documented gap: 4 read-tool callsites still use `session.Broker.*` directly (acceptable per `architecture-100-gap-current.md`).

### 2.3 Roadmap features per `.research/` not yet shipped

Per `final-138-gap-catalogue.md` and `MEMORY.md`:

| Feature | Status | Where documented | Priority |
|---|---|---|---|
| Multi-broker (Upstox/Angel/Dhan) | NOT SHIPPED | "+13 SCALE-GATED" in scorecard | only after first paying customer asks |
| Postgres adapter | NOT SHIPPED | "+16 SCALE-GATED" — current SQLite + Litestream/R2 | only at 5K+ paying users |
| Real-time alert pipeline (PagerDuty/SMS) | NOT SHIPPED | "+2 NIST CSF" gap | external $$ |
| ISMS/ISO 27001 cert | NOT SHIPPED | "+20 EntGov" | first enterprise RFP trigger |
| Real chaos test suite | NOT SHIPPED | "+2 NIST" | density-floor not met at scale |
| Wire/fx DI container | REJECTED (anti-rec'd) | scorecard-final.md §"Anti-rec'd" | permanent — regresses dev velocity |
| Logger Provider wrap | REJECTED | scorecard | permanent ceremony |
| Full Event Sourcing for ALL aggregates | REJECTED | scorecard §4 | outbox+billing+3 aggregates sufficient |
| Distributed flag service | NOT SHIPPED | 138-gap §11 | scale-gated |

---

## 3. Lens 2: Frontend / UI / UX Completeness

### 3.1 MCP App widgets — 17 `ui://` resources registered

`mcp/ext_apps.go` lines 189-385 register all widget resources. Each tool with widget data attaches `_meta["ui/resourceUri"]` AND `_meta["openai/outputTemplate"]` (the ChatGPT shim added per CHANGELOG). `clientSupportsUI()` strips these for non-widget hosts.

| Widget URI | Template file | LOC | Quality | Render type |
|---|---|---|---|---|
| `ui://kite-mcp/portfolio` | portfolio_app.html | 683 | Polished, dark-mode, charts | Read-only data + sector donut |
| `ui://kite-mcp/activity` | activity_app.html | (audit timeline) | Polished | Read-only timeline |
| `ui://kite-mcp/orders` | orders_app.html | 482 | Polished | Read-only table |
| `ui://kite-mcp/alerts` | alerts_app.html | 530 | Polished | Read-only |
| `ui://kite-mcp/paper` | paper_app.html | (paper) | Polished | Read-only |
| `ui://kite-mcp/safety` | safety_app.html | (riskguard limits) | Polished | Read-only |
| `ui://kite-mcp/order-form` | order_form_app.html | 648 | Polished, **interactive** | BUY/SELL form with pre-trade preview |
| `ui://kite-mcp/watchlist` | watchlist_app.html | (watchlist) | Polished | Read-only |
| `ui://kite-mcp/hub` | hub_app.html | (hub) | Polished | Navigation widget |
| `ui://kite-mcp/options-chain` | options_chain_app.html | (chain) | Polished | Read-only chain table |
| `ui://kite-mcp/chart` | chart_app.html | 777 | Polished | Read-only chart |
| `ui://kite-mcp/setup` | setup_app.html | (setup) | Polished | Setup wizard |
| `ui://kite-mcp/credentials` | credentials_app.html | (creds) | Polished | Form (BYO API key) |
| `ui://kite-mcp/admin-overview` | admin_overview_app.html | (admin) | Polished | Read-only |
| `ui://kite-mcp/admin-users` | admin_users_app.html | (admin) | Polished | Read-only table |
| `ui://kite-mcp/admin-metrics` | admin_metrics_app.html | (admin) | Polished | Read-only |
| `ui://kite-mcp/admin-registry` | admin_registry_app.html | (admin) | Polished | Read-only |

All widgets use a shared `dashboard-base.css` design system, AppBridge JS bridge (canonical at `kc/templates/appbridge.js`), and a flat-`_meta` registration pattern per the MCP Apps spec. `MCP_UI_ENABLED=false` kill-switch documented in `ext_apps.go:62`.

### 3.2 SSR Dashboard pages (Server-Side-Rendered, full HTML)

`kc/ops/dashboard.go::RegisterRoutes` mounts:

| Path | Quality | Interactive? |
|---|---|---|
| `/` (landing.html) | **Polished**, OG tags, theme-color, 350+ LOC inline CSS, dark | mostly informational |
| `/dashboard` | Polished, HTMX fragments | Read |
| `/dashboard/activity` | Polished, SSE stream + export | Read |
| `/dashboard/orders` | Polished | Read + drilldown |
| `/dashboard/alerts` | Polished, P&L chart | Read |
| `/dashboard/safety` | Polished, riskguard status | Read + sebi/limits/freeze |
| `/dashboard/paper` | Polished, holdings/positions/orders | Read + reset action |
| `/dashboard/billing` | Polished, tier card, Stripe portal | Read + upgrade CTA |
| `/admin/overview`, `/admin/ops`, `/admin/users`, `/admin/metrics`, `/admin/sessions`, `/admin/tickers`, `/admin/registry` | Polished | Read + admin actions |
| `/pricing`, `/terms`, `/privacy` | Polished, markdown-rendered via goldmark | Static |
| `/login_success.html`, `/admin_login.html`, `/email_prompt.html`, `/login_choice.html` | Polished | Auth flows |

61 HTML templates total. Design tokens in `dashboard-base.css` (CSS variables: bg-0..bg-3, accent, green/red/amber). HTMX for fragment updates. **Mobile responsive**: `<meta name="viewport">` present on landing + dashboard; multi-column grid uses CSS variables but no explicit media queries audited (see Gap #5).

### 3.3 User journey assessment

| Journey | Smoothness | Quality | Pain points |
|---|---|---|---|
| **Onboarding (new user → first MCP call)** | GOOD | Smithery one-click, README BYO API key, OAuth dynamic client registration | OAuth consent screen UX is browser-default Kite (not styled) |
| **Daily use (chat → tool call → response)** | EXCELLENT | All widgets render inline, AppBridge handles navigation | None observed |
| **Order placement** | EXCELLENT | Order form widget + pre-trade check + elicitation + riskguard | Path 2 hosted users see helpful "self-host for trading" copy |
| **Self-service credential management** | GOOD | `/dashboard/credentials` + `update_my_credentials` tool + `delete_my_account` | No password reset (no passwords by design — OAuth only) |
| **Billing upgrade** | GOOD | Stripe checkout + portal | Stripe webhook is wired; checkout flow is browser-only (no in-chat purchase) |
| **Family invite** | GOOD | `admin_invite_family_member` + `/auth/accept-invite` | Invite link UX is functional but plain |
| **Error recovery (token expired)** | EXCELLENT | Middleware returns 401 → mcp-remote auto re-auths → fresh token. Documented in MEMORY.md "auto re-auth (v43)" |
| **Telegram setup** | GOOD | `setup_telegram` tool + bot DM | Pairing key flow is bot-only — no UI page |
| **Paper trading toggle** | EXCELLENT | One tool call, no friction; engine intercepts via middleware |

### 3.4 Visual / accessibility gaps

| Gap | Severity | Notes |
|---|---|---|
| No mobile-first media queries audited | LOW | Most pages use viewport meta + flex/grid; phone testing not automated |
| No light-mode option | LOW | Dark-only by design — fits "trading desk" aesthetic |
| No screen-reader / a11y audit | MED | No `aria-label` audit run; no skip-links visible |
| Public OG image (`/og-image.png`) | UNKNOWN | Referenced in landing meta but not in `kc/templates/static/` listing — may 404 |
| No favicon refresh per page | LOW | Single `/favicon.ico` and `favicon.svg` in static — adequate |
| No keyboard shortcuts | LOW | Documented as nice-to-have |
| No status-page sub-domain (e.g., status.algo2go.dev) | LOW | `/healthz?format=json` exists; no public uptime page |

---

## 4. Lens 3: End-to-End / Integration Test Coverage

### 4.1 Test surface inventory

| Test class | Count | Where | Quality |
|---|---|---|---|
| Go unit tests | ~345 files | mcp/, kc/, app/, oauth/, broker/ | EXCELLENT — 338 production tests with `t.Parallel()` per scorecard, race-tested in CI, 90.04 equal-weighted score |
| Property tests | 8+ files | money_property_test, indicators_property_test, options_greeks_property_test, common_property_test, trading_fuzz_test, dedup_property_test, sector_tool_property_test, ext_apps_fuzz_test | GOOD — algebraic laws on Money VO, fuzz on indicators |
| Fuzz tests | 5+ | common_fuzz_test, ext_apps_fuzz_test, plugin_fuzz_test, trading_fuzz_test, etc. | GOOD |
| In-process integration | 3 files | `mcp/admin_integration_test.go`, `app/integration_test.go`, `app/integration_kite_api_test.go`, `kc/papertrading/engine_integration_test.go`, `kc/riskguard/guard_integration_test.go`, `mcp/path2_integration_test.go` | GOOD — full handler-level + Path 2 gating proven end-to-end |
| Subprocess E2E (compiled binary) | **1 file** | `mcp/e2e_roundtrip_test.go` — gated `//go:build e2e`; spawns server binary, pipes JSON-RPC, parses tools/list + tool dispatch | **MINIMAL** — single roundtrip + initialize handshake; opt-in only |
| Smoke test (HTTP probe of deployed server) | 1 script | `scripts/smoke-test.sh` — 13 curl-based checks against Fly.io: /healthz, /.well-known/oauth-*, /mcp 401, /oauth/authorize 302, landing IP/Path 2 copy, tool count >=84, anomaly_cache | **GOOD for what it covers — production deploy gate** |
| ChatGPT Apps validation | 1 script | `scripts/validate-chatgpt-apps-mode.sh` — OAuth dynamic registration + MCP bearer flow probe | GOOD |
| Browser/UI tests (Playwright/Chromedp/Cypress) | **0 files** | none anywhere | **MISSING — entire dashboard + 17 widgets are manually tested only** |
| `package.json` for JS test infra | **0 files** | none | (consistent with Go-only stack; widgets use vanilla JS) |
| DR drill | 1 workflow | `.github/workflows/dr-drill.yml` + `scripts/dr-drill.sh` | GOOD — exercises Litestream R2 restore |
| Mutation testing | 1 workflow | `.github/workflows/mutation.yml` | Operational |
| Race detector | 1 workflow | `.github/workflows/test-race.yml` + matrix race in CI | EXCELLENT |
| Benchmark regression gate | 1 workflow | `.github/workflows/benchmark.yml` (commit `511c198`) | EXCELLENT |

### 4.2 Coverage of user-facing flows

| User-facing flow | Unit-tested | Integration-tested | E2E-tested | Browser-tested |
|---|---|---|---|---|
| OAuth dynamic client registration | YES (oauth/) | YES (server_oauth_test.go) | smoke-test.sh check 8 | NO |
| OAuth authorize → Kite login → callback → token exchange | YES | PARTIAL | smoke-test.sh check 8 | NO |
| MCP tools/list | YES | YES (e2e_roundtrip) | YES (e2e tag) | NO |
| MCP tool dispatch (read tool) | YES | YES (admin_integration) | YES (e2e tag, single tool) | NO |
| MCP tool dispatch (write/order) | YES (path2_integration) | PARTIAL | NO | NO |
| Riskguard 9 checks end-to-end | YES (guard_integration_test) | YES | NO | NO |
| Paper trading order intercept | YES (engine_integration_test) | YES | NO | NO |
| Stripe checkout | YES (billing_webhooks_test) | NO | NO | NO |
| Stripe webhook | YES | YES | NO | NO |
| Litestream R2 restore | NO | YES (dr-drill.sh) | YES (drill workflow) | NO |
| Telegram bot commands | YES (handler_*.go tests) | YES (bot_edge_test) | NO | NO |
| Scheduler morning brief / EOD | YES (briefing_test) | YES | NO | NO |
| Widget ui:// resource fetch | YES (resources_test, ext_apps_test) | NO | NO | NO |
| Dashboard page render (HTML) | YES (render_test, dashboard_render_test, page_handlers tests) | YES (handler_test, dashboard_data_test) | NO | NO |
| Dashboard SSE stream | YES (overview_sse) | NO | NO | NO |
| Admin pages render | YES (admin_edge_*_test) | YES (admin_render_test) | NO | NO |
| Order form widget interaction | NO (no JS unit tests) | NO | NO | NO |
| Self-service credentials update | YES (api_handlers_test) | YES | NO | NO |
| Self-service account delete | YES | YES | NO | NO |

### 4.3 Coverage gap analysis

The Go test pyramid is exemplary — fast, deterministic, race-clean, covers handler + use-case + adapter layers. The TWO ZEROES are:

1. **Browser-level tests = 0 files**. No Playwright/Chromedp/Selenium for the 17 MCP App widgets, the SSR dashboard, the OAuth login UX, the Stripe checkout return-leg, the Telegram pairing browser flow, or the admin pages. Visual regressions, AppBridge JS bugs, mobile breakpoints, and a11y issues are caught only by manual eyeballing.

2. **Subprocess E2E = 1 file, opt-in**. `e2e_roundtrip_test.go` covers initialize + tools/list + a single tool dispatch. It does NOT cover: tool errors, multi-tool sessions, ticker WebSocket lifecycle, OAuth across the wire, ChatGPT Apps mode end-to-end (only smoke-tested), Telegram webhook + retry, billing webhook + state transitions, multi-user concurrency, or graceful restart. The `scripts/smoke-test.sh` partially compensates by hitting the deployed server, but it's a black-box probe, not a binary-spawning suite.

---

## 5. Top-10 Prioritized Gaps (Impact x Effort)

| # | Gap | Why it matters | LOC est | Dependencies | Priority |
|---|---|---|---|---|---|
| 1 | **Playwright suite for the 17 widgets + 8 dashboard pages** | Single biggest hole. Visual regressions on widgets land silently; AppBridge JS bugs only show up post-deploy. Pre-launch (HN/Show HN), a Playwright failure means a public refund. | 800-1500 (1 spec file per widget + 5 dashboard + helpers + auth fixture) | Add `package.json` + Playwright + GH Actions browser job; optional: visual snapshot via `expect(page).toHaveScreenshot()` | **P0** |
| 2 | **Expanded subprocess E2E covering write paths + error paths** | Currently 1 file behind a build tag covers only the happy read path. A regression in middleware order, riskguard, or elicitation is detected only when a paying user trades. | 400-600 (12-15 new test cases in e2e_roundtrip + parallel session test) | Existing scaffolding | **P0** |
| 3 | **OAuth flow end-to-end test (browser-driven)** | The full per-user OAuth flow (dynamic client registration → authorize → Kite login → callback → token exchange → MCP bearer) is the highest-risk user-touching surface. Currently smoke-tested only via curl (no Kite redirect followed). A Playwright test that completes the flow with a sandbox Kite account would catch every regression. | 200-400 + sandbox Kite developer app | Playwright (gap #1) + a CI-only Kite sandbox secret | **P0** |
| 4 | **Mobile responsiveness pass + audit** | Landing/dashboard targeted mostly desktop. Indian retail traders are 70%+ mobile. Current breakpoints are flex/grid + viewport meta but no @media queries audited; the order_form widget at 648 LOC needs touch-target review. | 100-300 (CSS @media breakpoints + touch-friendly buttons) | Playwright with `setViewportSize({width:375,height:812})` (gap #1) | **P1** |
| 5 | **A11y audit + remediation** | Zero `aria-*` audit. Screen-reader users locked out. Indian DPDP doesn't mandate but global enterprise procurement does. Catch via Playwright + `@axe-core/playwright`. | 200-400 (aria-label, focus-visible, skip-links) | Playwright (gap #1) | **P1** |
| 6 | **Light-mode toggle** | Some users prefer light. Dark-only is a deliberate aesthetic but adds unnecessary friction. CSS variables already in place — flipping is ~150 LOC + a localStorage toggle. | 150-250 | None | **P2** |
| 7 | **OG image + status page** | Landing references `/og-image.png` but it's not in `static/` — 404 on Twitter/Slack unfurl is a public credibility hit before HN launch. Status page (`status.algo2go.dev`) is nice-to-have. | 50 LOC + 1 PNG asset; status page is a separate Fly app | OG image: trivial. Status: separate deploy | **P1 (OG only), P3 (status)** |
| 8 | **Multi-broker abstraction proof (single second adapter, even mock)** | Hexagonal score capped at +13 SCALE-GATED until proven. A mock Upstox adapter (~600 LOC) demonstrating the port works would lift Compatibility from 86 to 95+. Not user-facing, but blocks enterprise procurement. | 600-800 (broker/upstox/ + adapter tests + factory wire) | broker.Client port already stable | **P2** |
| 9 | **Basket order placement tool** | Kite supports it; we don't expose it. Active traders place 5-10-leg basket orders for hedged strategies. ~200 LOC tool + use case. | 200-300 | place_order pattern | **P2** |
| 10 | **Cover order (CO) tool wrap** | Minor surface gap. Current users compose CO via separate place_order + GTT. ~150 LOC. | 150 | place_order pattern | **P3** |

---

## 6. Honest Assessment

**Is "100% feature/UX completeness" a meaningful goal? No.** The product is at a different inflection point.

The right framing is **"Tier-1 user journeys complete + verify with browser tests + close 2-3 high-impact gaps."** Specifically:

- Backend feature parity with what real users will use (orders, alerts, paper, watchlist, portfolio, options, backtest, telegram, family) is **DONE**. Remaining backend gaps (basket orders, CO, multi-broker mock) are scale-gated or nice-to-haves with no user-perceivable cost at <100 paid users.
- UI surface (17 widgets, 8 SSR pages, billing portal, admin) is **DONE in feature breadth**. Remaining UI work is depth (mobile, a11y, light-mode), not new features.
- Test coverage is **DONE on the unit + handler layers** but **MISSING on the browser layer**. This is the single biggest leverage point — 800-1500 LOC of Playwright across 17 widgets + 8 pages would make every future deploy safer than every other Indian fintech MCP server.

The product is in a "**ready to ship to early users; one Playwright sprint away from ready to launch publicly**" state. Don't chase 100% feature completeness — you'd be shipping multi-broker proofs and CO tools while the dashboard might be silently broken in mobile Safari. Chase the asymmetric leverage: the gap that costs the least and protects the most.

**Concrete recommendation**: Sprint 1 = Playwright (gaps #1, #2, #3, #4, #5) at ~2000 LOC over 1-2 weeks → Sprint 2 = OG image + light-mode + multi-broker mock as backlog at ~800 LOC. After that, the product is at the empirical-max ceiling for its stage.

---

## 7. Sources Cited

- `.research/resume-feature-inventory.md` — 94-tool baseline at `4b416ab`
- `.research/scorecard-final.md` — 90.04 equal-weighted at `562f623`
- `.research/architecture-100-gap-current.md` — architecture gap = ZERO at `7649dfb`
- `.research/final-138-gap-catalogue.md` — 138 gaps, 13 dims
- `mcp/ext_apps.go` — 17 widget URI registrations (lines 189-385)
- `mcp/path2_integration_test.go` — 18 gated trading tools enumerated
- `mcp/e2e_roundtrip_test.go` — sole subprocess E2E test
- `scripts/smoke-test.sh` — 13-check production HTTP probe; tool count floor 84
- `kc/ops/dashboard.go::RegisterRoutes` — full dashboard route table (lines 86-153)
- `kc/templates/` — 61 HTML templates including 17 `*_app.html` widgets
- `.github/workflows/ci.yml` — matrix CI with race + benchstat + 8m timeout
- `CHANGELOG.md` — Unreleased: composite_alert, per-second cap, DPDP consent log; 1.1.0 shipped Apr 18 with research copilot tools
- `docs/E2E_TEST_REPORT.md` (2026-04-02) — 21/25 prior pass rate at v76 deploy

---

*Read-only deliverable. No code edits. Single doc commit.*
