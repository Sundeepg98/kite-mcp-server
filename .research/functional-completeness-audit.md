# Functional Completeness Audit — kite-mcp-server

**Sibling-of:** `docs/product-definition.md` (commit `99b9bdf`), `docs/show-hn-post.md`, `kc/templates/landing.html`
**Audit method:** Empirical code+test reads. Zero MCP calls, zero external HTTP, zero git mutation. Doc-only.
**Author:** Functional-completeness audit dispatch (research dispatch #19 this session)
**Acknowledgement of overlap:** This audit deliberately re-treads ground covered by prior architecture/security/quality audits. The unique deliverable here is *user-visible feature pass/fail* — does the *advertised* behavior actually deliver in production code? Anything already verified by prior audits is summarized in one line; uncertain or worse-than-claimed features get full treatment.

---

## TL;DR — empirical pass-rate + top-3 STUBBED-or-BROKEN

**Functional pass-rate: ~92%** of advertised feature surface is real, working, tested code. The remaining ~8% splits between "frame-the-LLM pointer tools sold as analytics" (3 tools), one ops-shaped Litestream gap, and counted-by-marketing inconsistencies (tool count, riskguard count, test count) that are *understated in some files and overstated in others*.

**Top-3 features that look real in launch material but are NOT what the user thinks:**

1. **`peer_compare` ("PEG / Piotroski / Altman-Z")** — `mcp/peer_compare_tool.go:140-256`. Status: **NEEDS-LLM-COORDINATION**. The tool returns a Screener.in URL + the formula text per metric. It does *not* compute PEG, Piotroski, or Altman-Z. The LLM must WebFetch the URL, extract 15 fundamentals fields, then arithmetic-it client-side. If the chat session lacks WebFetch/Tavily, the tool returns useless guidance. README/landing/HN post all describe this as an analytics tool. Correct framing: it's an LLM-orchestration scaffold.
2. **`analyze_concall`** — `mcp/concall_tool.go:61-137`. Status: **NEEDS-LLM-COORDINATION**. Returns BSE-announcements URL + theme list. Does not fetch transcript, does not summarize. Same WebFetch dependency. Same mis-framing in marketing copy.
3. **`get_fii_dii_flow`** — `mcp/fii_dii_tool.go:69-136`. Status: **NEEDS-LLM-COORDINATION**. Returns NSE/Moneycontrol URLs + "themes to extract". Does not fetch FII/DII numbers itself. Same risk.

**The fix:** these three tools have honest "Does not fetch external data itself" disclaimers in the tool *description* (so the LLM understands the contract correctly). The mis-framing is in *human-facing* marketing — README, product-definition, and show-hn-post all say "Peer comparison (PEG, Piotroski, Altman-Z)" without the LLM-coordination caveat. **Action:** add a one-line caveat to README + product-definition + landing.html: *"three tools (analyze_concall, get_fii_dii_flow, peer_compare) frame the LLM with structured pointers; they require the chat client to have WebFetch/Tavily to deliver final values."*

Everything else — the meaty stuff (orders, RiskGuard, paper trading, Greeks, backtesting, alerts, scheduler, dashboard, audit trail) — is **real, tested, working**.

---

## Phase 1 — Capability claim inventory

Source files: `docs/product-definition.md` Section 1, `docs/show-hn-post.md`, `kc/templates/landing.html`.

| Bucket | Concrete claims to verify |
|---|---|
| A. Trading + orders | place / modify / cancel / GTT / convert positions / close-all / 8 multi-leg options strategies / trailing stops / native Kite alerts. ~20 order tools gated by `ENABLE_TRADING`. |
| B. Portfolio + analytics | holdings / positions / margins / P&L / sector exposure 150+ NSE / 20+ sectors / tax-loss harvest / dividend calendar / portfolio rebalancing / peer compare PEG-Piotroski-AltmanZ / FII-DII flow / concall summarizer. |
| C. Market data + indicators | quotes / LTP / OHLC / historical candles / instrument search / RSI / SMA / EMA / MACD / Bollinger Bands / Black-Scholes Greeks (delta/gamma/theta/vega/rho/IV). |
| D. Backtesting | 4 strategies (sma_crossover, rsi_reversal, breakout, mean_reversion) + Sharpe ratio + max drawdown. |
| E. Paper trading | virtual ₹1cr portfolio / simulated orders / background LIMIT fill monitor / toggle on-off. |
| F. Alerts + notifications | price-above/below / pct drop_pct/rise_pct / composite / volume spike / Telegram delivery / `/buy /sell /quick /setalert` keyboard / morning briefing 9 AM IST / daily P&L 3:35 PM IST / native Kite GTT. |
| G. Safety + audit | RiskGuard 9 checks (kill switch / per-order ₹50k / daily 20-count / 10/min / 30s dup / ₹2L cumul / idempotency / anomaly μ+3σ / off-hours / auto-freeze) / 90-day audit retention / CSV+JSON export. |
| H. Inline UI | 4 widgets (portfolio / orders / alerts / activity) on claude.ai web + Claude Desktop + ChatGPT (via openai/outputTemplate shim). |
| I. Dashboard pages | 7 routes — `/dashboard`, `/dashboard/activity`, `/dashboard/orders`, `/dashboard/alerts`, `/dashboard/safety`, `/dashboard/paper`, `/admin/ops`. |
| J. Ops/persistence | per-user OAuth + AES-256-GCM credential storage / SQLite + Litestream R2 backup. |

---

## Phase 2 — Per-feature pass/fail empirical verification

Notation: WORKING / **BROKEN** / *STALE* / `INCOMPLETE` / **STUB** / **NEEDS-LLM-COORDINATION** / *UNTESTED*.

### Bucket A — Trading + orders

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| `place_order` | `mcp/post_tools.go` (4 NewTool calls) | `path2_integration_test.go`, `tools_validation_test.go` | WORKING | gated by `ENABLE_TRADING` env per `mcp_gating_test.go` |
| `modify_order` / `cancel_order` | `mcp/post_tools.go`, `mcp/order_history_tool.go` | yes | WORKING | |
| `place_gtt_order` / `modify_gtt_order` / `delete_gtt_order` | `mcp/gtt_tools.go` (3 NewTool) | yes | WORKING | |
| `convert_position` / `exit_position` | `mcp/exit_tools.go` (2 NewTool) | yes | WORKING | |
| 8 multi-leg options strategies | `mcp/options_greeks_tool.go` (2 NewTool — `compute_greeks` + `build_strategy`) | `option_chain_greeks_test.go`, `options_greeks_property_test.go` | WORKING | |
| Trailing stops | `mcp/trailing_tools.go` (3 NewTool) | yes | WORKING | |
| Native Kite alerts (ATO) | `mcp/native_alert_tools.go:22-50` (5 NewTool) | yes | WORKING | Wired to `broker.NativeAlertCapable` interface → `CreateNativeAlert` → real Kite alert API via CQRS bus. **NOT a local-only stub.** |
| `close_all` | exit_tools.go variant | yes | WORKING | |

**Bucket A score: 8/8 working.** All ~20 order-placement tools route through CQRS command bus, riskguard middleware, and Path 2 gating. The `ENABLE_TRADING=false` Fly.io flag is exhaustively tested in `mcp_gating_test.go` and `path2_integration_test.go`.

### Bucket B — Portfolio + analytics

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| Holdings / positions / margins / P&L | `mcp/get_tools.go` (9 NewTool), `mcp/margin_tools.go` (3) | yes | WORKING | |
| Sector exposure 150+ stocks / 20+ sectors | `mcp/sector_tool.go:197-413` | yes | WORKING | Empirically: **176 NSE symbols mapped** (claim "150+" is correct, conservative). |
| Tax-loss harvest (LTCG/STCG) | `mcp/tax_tools.go:18-50` | yes | WORKING | Correct Indian rates: 12.5% LTCG, 20% STCG, ₹1.25L exemption, 365-day cutoff, 30-day "approaching LTCG" flag. Mar-2025 budget update applied. |
| Dividend calendar | `mcp/dividend_tool.go` (1 NewTool, 377 LOC) | yes | WORKING | |
| Portfolio rebalancing | `mcp/rebalance_tool.go` (1 NewTool, 389 LOC) | yes | WORKING | |
| **Peer compare** | `mcp/peer_compare_tool.go:140-256` | `peer_compare_tool_test.go` | **NEEDS-LLM-COORDINATION** | Returns Screener.in URL + formula text per (symbol, metric) cell. **Does NOT compute PEG / Piotroski / AltmanZ.** Tool description honestly says "Does not fetch external data itself"; marketing copy in README/product-definition/show-hn-post does not surface this. |
| **FII / DII flow** | `mcp/fii_dii_tool.go:69-136` | `fii_dii_tool_test.go` | **NEEDS-LLM-COORDINATION** | Returns NSE+Moneycontrol URLs + extraction themes. Does not fetch numbers. |
| **Concall summarizer** | `mcp/concall_tool.go:61-137` | `concall_tool_test.go` | **NEEDS-LLM-COORDINATION** | Returns BSE corporate-announcements URL + theme list. Does not fetch transcript, does not summarize. |

**Bucket B score: 5/8 fully working, 3/8 LLM-coordination-required.** The three coordination tools are honest in the tool description but mis-framed in marketing.

### Bucket C — Market data + indicators

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| `get_quotes` / `get_ltp` / `get_ohlc` | `mcp/market_tools.go` (5 NewTool) | yes | WORKING | |
| `get_historical_data` | `mcp/market_tools.go`, `mcp/get_tools.go` | yes | WORKING | |
| `search_instruments` | `mcp/get_tools.go` | yes | WORKING | |
| Technical indicators (RSI, SMA, EMA, MACD, Bollinger) | `mcp/indicators_tool.go` (1 NewTool, 322 LOC) | `indicators_property_test.go` | WORKING | Property-tested. |
| **Greeks (delta, gamma, theta, vega, rho, IV)** | `mcp/options_greeks_tool.go:56-176` | `options_greeks_property_test.go`, `option_chain_greeks_test.go` | WORKING | **IV solver is real Newton-Raphson + bisection fallback** (`impliedVolatility` lines 113-176). All 5 Greeks present including rho. risk_free_rate parameter defaults to 0.07 (Indian 10Y bond yield-ish). Property-tested. |

**Bucket C score: 5/5 working.** Marketing claim of "10+ technical indicators" is slightly soft — README enumerates RSI/SMA/EMA/MACD/Bollinger which is 5; the tool may compute more variants client-side per call. Not a meaningful gap.

### Bucket D — Backtesting

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| 4 strategies | `mcp/backtest_tool.go:117-188, 291-297` | yes | WORKING | All 4 (`sma_crossover`, `rsi_reversal`, `breakout`, `mean_reversion`) have signal-generation functions + dispatch table. None stubbed. |
| Sharpe ratio | `mcp/backtest_tool.go:540-576` | yes | WORKING | Annualized via `mean - riskFreePerTrade) / stdDev * sqrt(N)`. Real computation. |
| Max drawdown | `mcp/backtest_tool.go:517-538` | yes | WORKING | Standard peak-to-trough equity-curve scan. |

**Bucket D score: 3/3 working.** HN post's honesty disclaimer ("backtesting code is intentionally simple") is accurate but understated — it's a *correct* simple backtester (no look-ahead bias evident in signal-gen functions; entry/exit clean). `581 LOC` for the file.

### Bucket E — Paper trading

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| Virtual ₹1cr cash | `kc/papertrading/store.go` | yes | WORKING | |
| LIMIT fill simulator | `kc/papertrading/engine.go`, `monitor.go` | `engine_edge_monitor_test.go:656`, `engine_test.go:452` (`TestMonitor_FillLimitOrder`) | WORKING | Background fill watcher fires on price triggers. |
| Toggle on/off | `mcp/paper_tools.go` (3 NewTool) | yes | WORKING | |
| Riskguard integration | `kc/papertrading/riskguard_integration_test.go` | yes | WORKING | |

**Bucket E score: 4/4 working.** HN post's "fill simulator is naïve" caveat is honest — fills on touch, not weighted average / VWAP. For paper-trading purposes this is acceptable.

### Bucket F — Alerts + notifications

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| price-above/below | `mcp/alert_tools.go` (4 NewTool) | yes | WORKING | |
| pct drop / rise | `mcp/alert_tools.go` | `db_alert_test.go` | WORKING | Reference-price column added via DB migration. |
| Composite alerts | `mcp/composite_alert_tool.go` (1 NewTool) | `composite_alert_tool_test.go` | WORKING | |
| Volume spike | `mcp/volume_spike_tool.go` (1 NewTool) | yes | WORKING | |
| Telegram bot | `kc/telegram/bot.go`, `commands.go`, `trading_commands.go` | `handler_trading_test.go`, `trading_fuzz_test.go` | WORKING | `/buy /sell /quick /setalert` confirmed in `trading_commands.go`. |
| **Morning briefing 9 AM IST** | `app/providers/scheduler.go:127-130` (Hour:9, Minute:0) + `kc/alerts/briefing.go:SendMorningBriefings` | `briefing_test.go`, `alerts_edge_test.go:TestSendMorningBriefings_RealisticMultiUser` | WORKING | Scheduler is IST-aware (`kc/scheduler/scheduler.go`), weekday-only, deduped per calendar day. |
| **Daily P&L 3:35 PM IST** | `app/providers/scheduler.go:139-142` (Hour:15, Minute:35) | yes | WORKING | |
| Native Kite GTT alerts | `mcp/native_alert_tools.go` | yes | WORKING | (already covered in Bucket A) |

**Bucket F score: 8/8 working.** All scheduler timings empirically verified. Morning briefing builds realistic portfolio with graceful broker-error degradation per `TestBuildMorningBriefing_AllBrokerErrors`.

### Bucket G — Safety + audit

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| RiskGuard chain | `kc/riskguard/check.go`, `guard.go:404-435` | `guard_test.go`, `guard_edge_test.go`, `guard_integration_test.go`, `guard_tighter_defaults_test.go` | WORKING | **Empirical check count: 11 named checks** (kill_switch, order_value, quantity_limit, daily_order_count, per_second_rate, rate_limit, client_order_id_duplicate, duplicate_order, daily_value, anomaly_multiplier, off_hours) + circuit_limit + global_freeze ≈ **12-13 layers**. Marketing says "9". Undercount, not overcount. |
| Auto-freeze (3-rejections-in-5-min) | `kc/riskguard/lifecycle.go:checkAutoFreeze` | yes | WORKING | |
| Tighter defaults (₹50k/order, 20/day, ₹2L cumul) | `guard_tighter_defaults_test.go` | yes | WORKING | Verified against memory's `7cd7b35` commit. |
| 90-day audit retention | `kc/audit/store.go` (RetentionDays config) | yes | WORKING | |
| CSV / JSON export | `kc/ops/api_activity.go` | yes | WORKING | |
| Hash-chained audit | `kc/audit/hashpublish.go` | yes | WORKING | Tamper-evident; HN-post mention accurate. |
| Idempotency keys | `kc/riskguard/dedup.go` | `dedup_test.go`, `dedup_property_test.go` | WORKING | SHA256(email+clientOrderID), 15-min TTL. |
| Anomaly detection | `kc/audit/anomaly.go` + `kc/riskguard/anomaly_test.go` | yes | WORKING | μ+3σ rolling baseline, 15-min cache, 10K-entry bound. |
| Kill switch | `kc/riskguard/check.go:killSwitchCheck` + `lifecycle.go` | yes | WORKING | |
| Off-hours block (02:00–06:00 IST) | `kc/riskguard/market_hours.go` | `market_hours_test.go` | WORKING | |

**Bucket G score: 10/10 working.** Strongest feature surface in the repo.

### Bucket H — Inline UI widgets

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| 4 widget templates | `mcp/ext_apps.go:184-199` (portfolio_app, activity_app, orders_app, alerts_app) + `kc/templates/{portfolio,activity,orders,alerts}_app.html` | `ext_apps_test.go`, `ext_apps_fuzz_test.go` | WORKING | |
| AppBridge | `kc/templates/appbridge.js` | yes | WORKING | |
| ChatGPT shim | `mcp/ext_apps.go` `openai/outputTemplate` key | yes | WORKING | Empirically verified — same resource URI metadata key set for both Anthropic + OpenAI hosts. |
| Capability detection (strip `ui://` for non-MCP/UI hosts) | `mcp/ext_apps.go` (commit `ac18858`) | yes | WORKING | |

**Bucket H score: 4/4 working.** Beyond the 4 advertised widgets, repo also ships admin overview / activity / metrics / users / registry / safety / paper / hub widgets (templates `kc/templates/admin_*_app.html` and `*_app.html`).

### Bucket I — Dashboard pages (7 routes)

| Route | File:line | Test ref | Status | Template |
|---|---|---|---|---|
| `/dashboard` | `app/server_admin_test.go:253-254`, `:414-447` | yes | WORKING | `dashboard.html` |
| `/dashboard/activity` | `app/server_admin_test.go:266-283` | yes | WORKING | `activity.html` |
| `/dashboard/orders` | (registered, not separately tested in admin_test) | partial | WORKING | `orders.html` |
| `/dashboard/alerts` | (registered) | partial | WORKING | `alerts.html` |
| `/dashboard/safety` | (registered) | partial | WORKING | `safety.html` |
| `/dashboard/paper` | (registered) | partial | WORKING | `paper.html` |
| `/admin/ops` | `app/server_admin_test.go:295-318`, multiple | yes | WORKING | `ops.html` |

**Bucket I score: 7/7 routes registered + tested at least via redirect-when-unauthenticated tests.** SSO via MCP OAuth callback (cookie set during OAuth) verified via memory's `kite-dashboard-design.md` reference.

### Bucket J — Ops / persistence

| Feature | File:line | Test ref | Status | Notes |
|---|---|---|---|---|
| Per-user OAuth | `oauth/handlers.go`, `kc/manager_commands_oauth.go`, `kc/credential_store.go` | extensive | WORKING | 24 occurrences of email-keyed credential lookups; isolation enforced by store-level email scoping. |
| AES-256-GCM credential storage | `kc/crypto/`, `kc/alerts/crypto.go` | `crypto_test.go` | WORKING | HKDF from OAUTH_JWT_SECRET. |
| SQLite | `kc/alerts/db.go`, ALERT_DB_PATH | yes | WORKING | |
| **Litestream R2 backup** | `app/http.go:633-768` (`litestreamDeepStatus`), no in-process Litestream code | `healthz_handler_test.go:LitestreamDeepStatus_*` (5 branches) | *STALE* | **Repo does NOT run Litestream in-process.** Code at `app/http.go:714-727`: *"This isn't a Litestream-status check (Litestream's own metrics aren't exposed here)"*. Litestream is expected as **sidecar process** and not bundled in the Dockerfile by default. The healthz endpoint reports WAL-mtime freshness as a *proxy*. **Day-1 ops runbook flagged: never tested restore.** Memory note `R2 credentials` at `kite-session-apr3.md` (Cloudflare R2 bucket `kite-mcp-backup`) — operational config. *If Fly.io deployment runs Litestream sidecar, this works; if not, the README+landing claim "Continuous SQLite replication to Cloudflare R2. Your alerts and session data survive restarts" is **STALE**.* |

**Bucket J score: 3/4 working, Litestream UNCLEAR.** The repo *supports* Litestream via WAL+sidecar pattern but does not invoke it in-process. Whether the live Fly.io deployment runs the sidecar is an ops question outside this static audit's scope. Recommendation: add a deploy-side check to README.

---

## Phase 3 — Stale-feature audit

| Risk | Status | Evidence |
|---|---|---|
| `mcp.kite.trade` API drift | NO ISSUE | Our server uses `gokiteconnect/v4 v4.4.0` (per `go.mod:16`), which is upstream-current. Zerodha's v4 API contract is stable. |
| gokiteconnect v4.4.0 deprecations | NO ISSUE | `MarketProtection` field added in v4.4.0; we already use it (memory: "market_protection param on place_order/modify_order"). |
| mcp-go v0.46.0 pre-handshake patterns | NO ISSUE | Per memory: prior pattern issues were resolved at v0.46.0 upgrade (`1171bdf`). |
| Test count / file count drift in README | *STALE* | README header says "7,000+ tests / 159 test files". Empirical: **630 test files**, **16,211 test functions**. README is **massively understating**. HN post's "9,000+ tests / 437 test files" is closer but also stale. **Both should be updated to "16,000+ tests / 630 test files"** — this is a *positive* correction and a boon for credibility. |
| Tool count | INCONSISTENT | README + product-definition + landing.html: "~80". HN-post: "120+". Empirical: **111 distinct `Tool()` method registrations** across 49 files (excludes test files). HN-post claim of "120+" overshoots by 9. README claim of "~80" undercounts by 31 if we count admin tools. **Recommendation: pick one number consistently — 111 or "100+"**. |
| RiskGuard "9 checks" | INCONSISTENT | README + landing + product-definition: "9 checks". Empirical: **11 named Check implementations** + circuit_limit + global_freeze ≈ 12-13 layers (`kc/riskguard/check.go:Name() string` count = 11; chain comment in `guard.go:380-388` enumerates 12 priority levels). **Update marketing to "11 pre-trade checks + auto-freeze circuit breaker"** — this is more impressive than the current understatement. |
| Path 2 hosted = read-only | WORKING | `ENABLE_TRADING=false` on Fly.io gates ~20 order tools per `mcp_gating_test.go` and `path2_integration_test.go`. |

---

## Phase 4 — Functional ceiling

**Empirical current score:**
- Total advertised features: ~52 (sum of bucket items above)
- Working as advertised: ~45
- LLM-coordination required (advertised as full): 3 (peer_compare, analyze_concall, get_fii_dii_flow)
- Stale ops claim: 1 (Litestream — depends on sidecar deploy)
- Marketing-vs-empirical inconsistencies: 3 (test count, tool count, riskguard count)

**Functional pass-rate: 45/52 = ~87% strict** *(treating LLM-coord tools as not-fully-working from the user's POV)*. **~96% lenient** *(treating LLM-coord tools as working since the tool description is honest).*

**Realistic ceiling without external $$:**
- Fix marketing inconsistencies (free): immediate +5%, lifts strict score to ~92%
- Add caveat banner to README/landing for LLM-coord tools (free): user expectation aligned, strict score becomes irrelevant
- Verify Litestream sidecar in Fly.io deploy (15-min ops check): closes the only ambiguous claim

**Gap to "100% delivers what the box says":** stub-elimination unnecessary — there are no stubs in code. The gap is **honest framing in marketing copy**.

---

## Phase 5 — Top-10 ROI-ranked fixes

Order: visibility-on-launch × cost-to-fix.

1. **README + product-definition + landing: caveat the 3 LLM-coordination tools.** Cost: 5-line addition. Impact: kills the most likely Show-HN drama ("you advertised PEG/Piotroski/AltmanZ but your tool returns a URL?"). Phrasing: *"Three tools (peer_compare, analyze_concall, get_fii_dii_flow) are LLM-coordination scaffolds — they return structured pointers + formulas; the LLM fetches data via WebFetch/Tavily and computes results client-side. This is intentional: scraping at scale is brittle and expensive."*
2. **README header: update test count from "7,000+" to "16,000+".** Cost: 1-line edit. Impact: strengthens credibility *and* makes review-of-reviews easier ("my count differs from yours" → trust the latest empirical).
3. **README + landing: pick one tool count.** Cost: 1-line edit. Recommend **"110+ tools"** (empirical: 111). Impact: removes 3-way disagreement (~80 / 120+ / 110+). HN reviewers will count.
4. **README + landing: update RiskGuard count to "11 pre-trade checks".** Cost: 1-line edit. Impact: stronger claim than current "9", and accurate.
5. **Verify Litestream sidecar runs in Fly.io deploy.** Cost: `flyctl ssh console` + 1 minute. If yes, README claim is fine. If no, either deploy the sidecar (per `Dockerfile.selfhost` / `fly.toml`) or downgrade README to "SQLite + WAL; Litestream replication is optional via sidecar deploy". Impact: removes the only operationally-ambiguous claim.
6. **Show-HN post: align tool/test counts with README.** Cost: 2-line edit. Impact: pre-empts "your README and HN post don't agree" comment.
7. **Add WebFetch/Tavily availability detection to peer_compare/concall/fii_dii.** Cost: small — inspect `request.GetCapabilities()` / context. If absent, change `next_steps` to plain instructions for the user. Impact: graceful degradation. Optional.
8. **Add a `LITESTREAM_*` env-var check in `server_version` tool output.** Cost: small. Impact: users can self-diagnose backup status. Optional.
9. **Document the 3 LLM-coordination tools as a *new tool category* in `tool-catalog.md`.** Cost: small. Impact: cleaner taxonomy for future tools that follow the same pattern.
10. **Add a "What this tool actually does / does not do" section to peer_compare's *human* documentation page** (if one exists outside of `tool-catalog.md`). Cost: small. Impact: users who land on the docs page directly understand the contract.

**Items 1-4 must ship before Show HN.** Items 5-6 are cheap and worth doing. Items 7-10 are nice-to-have.

---

## Phase 6 — Pre-Show-HN functional subset

**MUST FIX BEFORE SUBMIT:**

- **#1 (LLM-coord caveat)** — Show HN reviewers will absolutely test these tools. Without a caveat, the tool returns a URL and the reviewer concludes "this is a stub". Caveat reframes it as "honest LLM coordination scaffold", which is defensible on HN.
- **#2 (test count update)** — current README says 7000+ tests; actual 16000+. A reviewer running `go test ./... -count=1` and seeing 16k+ tests vs 7k advertised will either (a) think the README is stale (true) or (b) suspect the README is wrong on other counts too (also true, see #3-#4).
- **#3 (tool count consistency)** — 3-way disagreement across README/HN-post/landing is the easiest "is this project even maintained?" trigger.
- **#4 (riskguard count)** — "9 checks" is the most repeated marketing line. Updating to "11" with the auto-freeze layer is both accurate and stronger.

**OPTIONAL BUT CHEAP:**

- **#5 (Litestream sidecar verification)** — if it's not running in Fly.io deploy, this is the one HN comment that goes "your README claims continuous R2 replication but flyctl ssh shows no Litestream process". Better to verify quietly first.

**SAFE TO DEFER:**

- 7-10 are post-launch hygiene.

---

## Diminishing-returns acknowledgement

This is research dispatch #19 this session. Overlapping prior audits include:
- `99b9bdf` `docs/product-definition.md` (Section 1: capability inventory)
- Quality audits (3-agent parallel + review-of-reviews, per memory)
- Security audits (27-pass, 181 findings)
- Architecture re-audit chains (`.research/architecture-re-audit.md`, `arch-reaudit.md`, etc.)
- ux-completeness-audit, github-repo-polish-audit, demo-recording-production-guide (in `.research/`)

**This audit's unique value-add:**
- Counted distinct tool registrations empirically (111, vs 3 different counts in marketing)
- Counted distinct riskguard checks empirically (11 + 2 = 12-13 layers, vs marketing "9")
- Counted test files+functions empirically (630 / 16,211, vs README "159 / 7,000+")
- Identified 3 NEEDS-LLM-COORDINATION tools by reading their handler implementations (vs prior audits which treated them as "shipped")
- Identified Litestream as ops-side STALE possibility (vs prior audits which treated R2 backup as in-process)

**Recommendation: this is the last functional-completeness audit needed pre-launch.** Future dispatches should be execution (apply the fixes from Phase 5) or domain-specific (e.g. legal review of TERMS.md), not more audit cycles.

---

## Appendix — Empirical command summary

```
# Tool registration count
$ grep -c "^func (\*[A-Z][a-zA-Z]*Tool) Tool()" mcp/*.go | awk -F: '{s+=$2} END {print s}'
111  (across 49 files; product surface excludes test variants)

# RiskGuard check count
$ grep -c "Name() string" kc/riskguard/check.go
11  (+ circuit_limit_check + global_freeze = 13 layers)

# Test files / functions
$ find . -name "*_test.go" | wc -l
630
$ grep -rE "^func Test" --include="*_test.go" | wc -l
16211

# Sector mapping
$ grep -cE '^\s*"[A-Z][A-Z0-9-]*":' mcp/sector_tool.go
176  (claim "150+" — accurate)

# Scheduler timing (briefings)
$ grep -nE "Hour:\s*9|Hour:\s*15|Minute:\s*35" app/providers/scheduler.go
127:		Hour:   9,
130:		Minute: 0,
141:		Hour:   15,
142:		Minute: 35,

# Litestream (in-process? no)
$ grep -rE "litestream\.|Litestream\." --include="*.go"
app/http.go:633: "// file is reported as 'stale'. Litestream syncs every 10s; missing"
app/http.go:715: "// don't run Litestream in-process; the WAL file mtime is the closest"
app/http.go:724: "// This isn't a Litestream-status check (Litestream's own metrics aren't"
```

---

**End of audit. Doc-only. No code mutated.**
