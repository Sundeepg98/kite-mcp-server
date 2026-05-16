# Phase 3 mcp/ Extraction — Dependency Map (research-only, 2026-05-16)

_Authored: 2026-05-16 IST_
_Status: REFERENCE — Phase 3 PAUSED per task #355 awaiting Tier B Manager-decomp Steps 3-5 completion_
_Source HEADs probed:_
- `algo2go/kite-mcp-bootstrap` @ `cff717e` (mcp/ subdirs intact)
- `Sundeepg98/kite-mcp-server` @ `c309185` (THIN deploy-repo: main.go + cmd/ only)
- `algo2go/kite-mcp-tools-common` @ Phase 2 release tag (v0.1.0+ on GOPROXY)

This doc maps the user-proposed 5-cluster Phase 3 plan (`mcp/orders`, `mcp/quotes`, `mcp/holdings`, `mcp/alerts`, `mcp/payoff`) onto the EXISTING bootstrap `mcp/` directory layout so that resumption is mechanical. Note: the user's 5-cluster naming is a NEW partition that cross-cuts the existing 7 subdirs (`trade/portfolio/analytics/admin/alerts/misc/paper`); this doc treats both axes.

---

## §INPUTS — load-bearing facts (verified 2026-05-16)

| # | Claim | Probe | Source |
|---|---|---|---|
| 1 | bootstrap HEAD: `cff717e` | `git rev-parse HEAD` | algo2go/kite-mcp-bootstrap |
| 2 | bootstrap mcp/ has **7 subpackages** (admin, alerts, analytics, misc, paper, portfolio, trade) + **3 root tool files** (market_tools, watchlist_tools, tax_tools) | `ls mcp/*.go ; ls mcp/*/` | bootstrap |
| 3 | Production tool surface: **111 tools** invariant across 66 deploys (verified `curl /healthz` 2026-05-16) | per STATE.md §2.1 | bootstrap |
| 4 | Tool count per existing subdir (non-test grep): trade=28, portfolio=20, analytics=8, admin=18, alerts=8, misc=9, paper=8, root=12 → **total 111** | `grep -cE 'mcp\.NewTool\("'` per dir | bootstrap |
| 5 | Production LOC per subdir: trade=3,710 / portfolio=1,986 / analytics=2,005 / admin=1,791 / alerts=1,170 / misc=918 / paper=1,326 / root mcp/=5,691 | `wc -l *.go` minus _test.go | bootstrap |
| 6 | `kite-mcp-tools-common` v0.1.0+ external (Phase 2 LIVE 2026-05-16). Provides: `common.ToolHandler`, `common.ToolHandlerDeps`, `common.NewToolHandler*`, `plugin.RegisterInternalTool`, middleware chain | per kite-mcp-tools-common repo | tools-common |
| 7 | `ToolHandlerDeps` (handler_deps.go:30-71) exposes **27 narrow Provider ports**: LoggerPort, TokenStore, UserStore, Sessions, Credentials, Metrics, Config, Tokens, CredStore, Browser, Alerts, Telegram, TelegramNotifier, Watchlist, Users, Registry, Audit, Billing, Ticker, Paper, Instruments, AlertDB, RiskGuard, MCPServer, BrokerResolver, TrailingStop, Events, PnL, CommandBusP, QueryBusP | per file read | tools-common |
| 8 | Residual `manager.X()` reaches across all 7 subdirs: 7 sites total (**5 hard, 2 cross-pkg**) | per-dir grep | bootstrap |
| 9 | Residual sites by subdir: **trade=2** (options_greeks_tool.go:471 `manager.GetBrokerForEmail`; pretrade_tool.go via `handler.Manager().Logger`), **admin=2** (admin_baseline_tool.go:110 + admin_cache_info_tool.go:121 — both `manager.AuditStoreConcrete()`), **misc=2** (session_admin_tools.go:93,211 — `manager.SessionManager` field), **alerts=0**, **analytics=0**, **portfolio=0**, **paper=0** | per-dir grep | bootstrap |
| 10 | Cross-subdir imports: **ZERO** (verified by `phase-3-dispatch-briefs-2026-05-16.md` empirical mapping) | grep | bootstrap |
| 11 | Phase 3 prior plan (`phase-3-dispatch-briefs-2026-05-16.md`) used **5 different cluster names** (trade/portfolio+analytics/admin+misc/alerts/paper) than the user's current proposal (orders/quotes/holdings/alerts/payoff) | doc read | .research/ |

---

## §1 — User's 5-cluster proposal mapped to existing subdirs

The user's `orders/quotes/holdings/alerts/payoff` partition cuts ACROSS the existing 7 subdirs. The mapping is not 1:1.

| User cluster | Maps to existing subdir(s) | Tool count | Source files |
|---|---|---|---|
| **mcp/orders** | subset of `trade/` + root `tax_tools.go` slice | **17** | trade: post_tools.go (place/modify/cancel/convert = 4), gtt_tools.go (3), mf_tools.go (7), native_alert_tools.go (5), trailing_tools.go (3); pretrade_tool.go (1); exit_tools.go (close_position, close_all_positions = 2) → **25 actually**. Recount below. |
| **mcp/quotes** | root `market_tools.go` | **5** | market_tools.go (get_quotes, search_instruments, get_historical_data, get_ltp, get_ohlc) |
| **mcp/holdings** | most of `portfolio/` | **15-20** | portfolio: get_tools.go (9: profile/margins/holdings/positions/trades/orders/gtts/order_trades/order_history), pnl_tools.go (1), dividend_tool.go (1), margin_tools.go (3), order_history_tool.go (1), position_history_tool.go (1), rebalance_tool.go (1), sector_tool.go (1), account_tools.go (2) |
| **mcp/alerts** | existing `alerts/` 1:1 | **8** | all 5 prod files |
| **mcp/payoff** | subset of `trade/options_*` + `option_tools.go` | **3** | trade/options_greeks_tool.go (options_greeks + options_payoff_builder = 2); trade/option_tools.go (get_option_chain = 1) |

**Tools that don't fit any of the 5 user clusters** — must go to a 6th bucket or stay at composition root:

| Bucket | Tools | Source |
|---|---|---|
| **admin/ops** (operator-facing) | 27 | admin/ (18) + misc/ (9) — invite/list/suspend/baseline/cache/etc. |
| **analytics** (research/insight tools) | 8 | analytics/ — concall, fii_dii, peer_compare, indicators, backtest, portfolio_summary, portfolio_concentration, position_analysis |
| **paper trading + auth/setup** | 8 | paper/ — login, open_dashboard, paper_trading_*, server_metrics, trading_context, test_ip_whitelist |
| **watchlists** | 6 | watchlist_tools.go (root) — create/delete/add/remove/get/list |
| **tax** | 1 | tax_tools.go (root) — tax_loss_analysis |

**Sum check**: 5 clusters total = 25 (orders) + 5 (quotes) + 20 (holdings) + 8 (alerts) + 3 (payoff) = **61 tools**. Remaining 50 tools (admin+ops 27 + analytics 8 + paper 8 + watchlist 6 + tax 1 = 50) → 6th cluster or stays at composition root.

**Recommendation per §3 below**: the 5 user-named clusters cover only ~55% of the 111 tools. The remaining 50 must be classified into a **6th "rest" cluster** (or distributed across the existing dispatch-brief clusters of `ops/analytics/paper`). The Phase 3 dispatch briefs (`phase-3-dispatch-briefs-2026-05-16.md`) already mapped these via the `trade/portfolio+analytics/admin+misc/alerts/paper` partition — that is the empirically-validated cohort partition with zero cross-subdir imports.

---

## §2 — Per-cluster dependency record (5 user-named clusters)

### 2.1 Cluster: **mcp/orders** (subset of bootstrap/mcp/trade)

| Aspect | Value |
|---|---|
| **Tool count** | 25 (trade subset, excluding 3 options/payoff tools) |
| **Tools** | place_order, modify_order, cancel_order, convert_position, place_gtt_order, modify_gtt_order, delete_gtt_order, place_mf_order, cancel_mf_order, place_mf_sip, cancel_mf_sip, get_mf_orders, get_mf_sips, get_mf_holdings, place_native_alert, modify_native_alert, delete_native_alert, list_native_alerts, get_native_alert_history, set_trailing_stop, cancel_trailing_stop, list_trailing_stops, order_risk_report, close_position, close_all_positions |
| **Source files** | post_tools.go, gtt_tools.go, mf_tools.go, native_alert_tools.go, trailing_tools.go, pretrade_tool.go, exit_tools.go |
| **LOC** | ~3,300 (trade total 3,710 minus options_greeks 750 minus option_tools 200) |
| **algo2go modules consumed** | kite-mcp-kc, kite-mcp-cqrs, kite-mcp-domain, kite-mcp-broker, kite-mcp-alerts, kite-mcp-instruments, kite-mcp-oauth, kite-mcp-ticker, kite-mcp-usecases, kite-mcp-tools-common (10) |
| **kc.Manager methods consumed** | `m.GetBrokerForEmail(email)` (1 residual at options_greeks_tool.go:471 — belongs to payoff cluster, but type-cycle puts it here); `handler.Manager().Logger.Error(...)` (1 site at pretrade_tool.go:159) |
| **Provider ports needed (Composed §1)** | BrokerResolver, RiskGuard, CommandBusP, QueryBusP, LoggerPort, Sessions, Credentials, Audit, Paper, Events, Telegram, TelegramNotifier, AlertDB, Alerts, Instruments, Ticker, BrokerResolver, TrailingStop — **all 27 ports already exposed** in `kite-mcp-tools-common/common/handler_deps.go` |
| **Cross-cluster shared deps with siblings** | shares broker resolution + CQRS dispatch with payoff, holdings, alerts. All consumed via Provider ports → no shared infrastructure code needed inside cluster. |
| **Halt conditions to extract** | (a) `m.GetBrokerForEmail` residual must change to `Deps.BrokerResolver.GetBrokerForEmail()` (1-line struct field type change at line 471) — BrokerResolverProvider port EXISTS at HEAD; (b) `handler.Manager().Logger.Error` must change to `handler.LoggerPort().Error(ctx, ...)` — LoggerPort EXISTS at HEAD; (c) NO Tier B Steps 4-5 blockers (Manager decomp is unrelated to these tools; they go through CommandBus/QueryBus + Provider ports already) |
| **Effort** | MEDIUM — 2 residual fixes (1 LOC each); large surface but mechanical extraction |

### 2.2 Cluster: **mcp/quotes** (root mcp/market_tools.go)

| Aspect | Value |
|---|---|
| **Tool count** | 5 |
| **Tools** | get_quotes, search_instruments, get_historical_data, get_ltp, get_ohlc |
| **Source files** | market_tools.go (single file at mcp/ root) |
| **LOC** | ~440 |
| **algo2go modules consumed** | kite-mcp-broker, kite-mcp-kc, kite-mcp-cqrs, kite-mcp-instruments, kite-mcp-tools-common (5) |
| **kc.Manager methods consumed** | **ZERO** (verified — grep returned 0 matches) |
| **Provider ports needed** | QueryBusP, Instruments, BrokerResolver, LoggerPort — all 4 already on ToolHandlerDeps |
| **Cross-cluster shared deps** | Instruments port shared with orders (option chain) + alerts (resolver). No shared code; just shared Provider. |
| **Halt conditions** | NONE — this is the cleanest extraction in the batch. Single file, zero residual reaches, only Provider-port consumption. |
| **Effort** | LOW — easiest of all 5 user clusters. Single file, 5 tools, ~440 LOC, zero Manager reaches, zero in-subdir tests (tests live at mcp/ root and exercise via plugin registry). |

### 2.3 Cluster: **mcp/holdings** (subset of bootstrap/mcp/portfolio)

| Aspect | Value |
|---|---|
| **Tool count** | 20 (= entire portfolio/ subdir; nothing in portfolio/ is NOT a holdings/portfolio tool) |
| **Tools** | get_profile, get_margins, get_holdings, get_positions, get_trades, get_orders, get_gtts, get_order_trades, get_order_history, get_pnl_journal, dividend_calendar, get_order_margins, get_basket_margins, get_order_charges, get_order_history_reconstituted, get_position_history_reconstituted, portfolio_analysis, sector_exposure, delete_my_account, update_my_credentials |
| **Source files** | portfolio/*.go (9 prod files: get_tools, pnl_tools, dividend_tool, margin_tools, order_history_tool, position_history_tool, rebalance_tool, sector_tool, account_tools) |
| **LOC** | 1,986 prod + 394 test (in-subdir tests) |
| **algo2go modules consumed** | kite-mcp-broker, kite-mcp-kc, kite-mcp-cqrs, kite-mcp-domain, kite-mcp-alerts, kite-mcp-oauth, kite-mcp-sectors, kite-mcp-usecases, kite-mcp-tools-common (9) |
| **kc.Manager methods consumed** | **ZERO** |
| **Provider ports needed** | QueryBusP, CommandBusP, Sessions, Credentials, BrokerResolver, PnL, Watchlist, Instruments, LoggerPort, Audit (10 ports) — all already on ToolHandlerDeps |
| **Cross-cluster shared deps** | QueryBus/CommandBus shared with all 5 clusters; PnL provider shared with alerts (P&L sparkline widget). Sectors module shared with analytics if `sector_exposure` ↔ `peer_compare` ever bundled. |
| **Halt conditions** | NONE for extraction. Tier B Steps 4-5 dependency is irrelevant here — these tools route through CQRS Bus, not direct Manager. |
| **Effort** | LOW-MED — 1,986 LOC + 9 files but uniform pattern (all CQRS dispatchers). 2 in-subdir test files must move (pure_analytics_test.go, sector_tool_property_test.go). Cleanest CQRS-pure cluster. |

### 2.4 Cluster: **mcp/alerts** (existing bootstrap/mcp/alerts 1:1)

| Aspect | Value |
|---|---|
| **Tool count** | 8 |
| **Tools** | set_alert, list_alerts, delete_alert, setup_telegram, get_alert_history_reconstituted, composite_alert, get_order_projection, volume_spike_detector |
| **Source files** | alert_tools.go, alert_history_tool.go, composite_alert_tool.go, projection_tool.go, volume_spike_tool.go |
| **LOC** | 1,170 prod + 338 test (3 in-subdir test files: composite_alert_tool_test.go, instrument_resolver_adapter_test.go, volume_spike_tool_test.go) |
| **algo2go modules consumed** | kite-mcp-broker, kite-mcp-kc, kite-mcp-cqrs, kite-mcp-instruments, kite-mcp-oauth, kite-mcp-ticker, kite-mcp-tools-common (7) |
| **kc.Manager methods consumed** | **ZERO** |
| **Provider ports needed** | Alerts, AlertDB, Telegram, TelegramNotifier, TrailingStop, Instruments, Ticker, BrokerResolver, CommandBusP, QueryBusP, LoggerPort, Sessions, Credentials — all 13 already on ToolHandlerDeps |
| **Cross-cluster shared deps** | Instruments port shared with orders, payoff, quotes. Ticker port shared with quotes (subscribe_instruments lives in misc — operationally similar). |
| **Halt conditions** | (a) instrument_resolver_adapter_test.go imports `bootstrap/testutil/kcfixture` — new module must add testutil as test-only dep (precedent: testutil already has its own go.mod at v0.1.1+). NOT a blocker, just a config item. (b) NONE related to Tier B Steps. |
| **Effort** | MED — 8 tools, 1,170 LOC, 3 in-subdir tests need careful move + testutil dep. Cleanest of the trade-adjacent clusters since zero residual reaches. |

### 2.5 Cluster: **mcp/payoff** (subset of trade/ — options + payoff tools)

| Aspect | Value |
|---|---|
| **Tool count** | 3 |
| **Tools** | options_greeks, options_payoff_builder, get_option_chain |
| **Source files** | trade/options_greeks_tool.go, trade/option_tools.go |
| **LOC** | ~750 prod |
| **algo2go modules consumed** | kite-mcp-broker, kite-mcp-kc, kite-mcp-cqrs, kite-mcp-instruments, kite-mcp-usecases, kite-mcp-tools-common (6) |
| **kc.Manager methods consumed** | `m.GetBrokerForEmail(email)` at options_greeks_tool.go:471 (1 residual — 1-line fix: change `*kc.Manager` field type to `kc.BrokerResolverProvider`) |
| **Provider ports needed** | BrokerResolver, Instruments, QueryBusP, CommandBusP, LoggerPort, Sessions — all 6 already on ToolHandlerDeps |
| **Cross-cluster shared deps** | Instruments shared with quotes + orders + alerts. BrokerResolver shared with orders. Both via Provider, not code. |
| **Halt conditions** | (a) 1 residual `m.GetBrokerForEmail` reach must be redirected through Deps.BrokerResolver (struct field type-change only, since BrokerResolverProvider port EXISTS at HEAD); (b) carving payoff tools OUT of `trade/` creates a SPLIT inside the existing `trade/` subdir — must verify the remaining 25 `trade/` tools still build after the 3 payoff tools are extracted (they should — there are no cross-file dependencies inside trade/ between options_greeks/option_tools and the other 7 files). |
| **Effort** | LOW — 3 tools, ~750 LOC, 2 files, 1 residual (1-line fix). Independent of Tier B Steps. |

---

## §3 — Cross-cluster shared infrastructure matrix

### 3.1 Shared dependencies between user clusters

| Shared dep | Used by | Notes |
|---|---|---|
| `common.ToolHandler` + `ToolHandlerDeps` | ALL 5 clusters | Already external in `kite-mcp-tools-common/common` (Phase 2 v0.1.0) — NO ACTION NEEDED |
| `plugin.RegisterInternalTool` | ALL 5 clusters | Already external in `kite-mcp-tools-common/plugin` — NO ACTION NEEDED |
| QueryBus/CommandBus dispatch | orders, quotes, holdings, alerts, payoff (5/5) | Already abstracted via `CommandBusP`/`QueryBusP` Provider ports; underlying type from external `kite-mcp-cqrs` |
| Instruments resolver | orders, quotes, alerts, payoff (4/5) | Already abstracted via `Instruments` Provider port |
| BrokerResolver | orders, quotes, holdings, alerts, payoff (5/5) | Already abstracted via `BrokerResolver` Provider port |
| LoggerPort | ALL 5 clusters | Already on ToolHandlerDeps |
| Sessions/Credentials | ALL 5 clusters (auth gate) | Already on ToolHandlerDeps |

**Verdict**: every shared helper Phase 3 needs is ALREADY in `kite-mcp-tools-common`. ZERO gaps identified. The Composed Interface pattern (§1 of architectural-patterns-record.md) is fully realized — clusters share **interfaces**, not code.

### 3.2 Cross-cluster type-identity risks

| Risk | Locus | Mitigation |
|---|---|---|
| `domain.Order`/`domain.Position` type used across orders + holdings + payoff | All three import `kite-mcp-domain` externally — type identity preserved at GOPROXY-resolved version |
| `instruments.Instrument` shared by quotes + alerts + payoff | All import `kite-mcp-instruments` externally — same |
| `cqrs.Query`/`cqrs.Command` interfaces shared | All import `kite-mcp-cqrs` externally — same |
| `alerts.DB` concrete type shared between alerts cluster + holdings (PnL uses AlertDB for state) | Both import `kite-mcp-alerts` externally — same |

**No type-cycle blockers**. The 28 algo2go modules already form a clean DAG; clusters just add 5 more leaves.

### 3.3 What about the 50 unmapped tools?

The 5 user-named clusters cover 61 of 111 tools. The remaining 50:

| Bucket | Tools | LOC | Existing Phase 3 brief mapping |
|---|---|---|---|
| **admin/ops** | 27 | 2,709 | Brief 3 (`kite-mcp-tools-ops`) |
| **analytics** | 8 | 2,005 | Brief 2 (`kite-mcp-tools-portfolio` analytics/ subpkg) |
| **paper** | 8 | 1,326 | Brief 5 (`kite-mcp-tools-paper`) |
| **watchlists** | 6 | ~600 | NOT in existing briefs — fits naturally into a `mcp/watchlists` cluster OR could join `holdings` |
| **tax** | 1 | ~200 | NOT in existing briefs — single tool; could join `analytics` or `holdings` |

**Recommendation**: when the user resumes Phase 3, decide whether to:
- (a) **Adopt the existing 5-brief partition** (trade/portfolio+analytics/admin+misc/alerts/paper) which is empirically validated (zero cross-subdir imports), OR
- (b) **Stick with the new 5-cluster partition** (orders/quotes/holdings/alerts/payoff) and add a **6th "rest" cluster** for the 50 unmapped tools.

The existing brief partition is more cohesive (each cluster owns a complete subdir). The new partition is cleaner conceptually (each cluster = a single trader-facing concern) but requires splitting `trade/` (orders vs payoff) and `portfolio/` (holdings vs holdings — i.e. all of it) and leaving administrative + analytic + paper + watchlist + tax tools in a 6th bucket.

---

## §4 — Sequencing recommendation (LOW→HIGH effort, no resumption signal)

Constraint: phase 3 is PAUSED awaiting Tier B Steps 4-5. None of these 5 user-named clusters is BLOCKED on Tier B (they all consume via Provider ports + CQRS Bus, not direct Manager reaches). Reasons for the sequence below are surface area + residual-fix count, NOT Tier B blockers.

| # | Cluster | Why this order | Effort | Halt-condition |
|---|---|---|---|---|
| 1 | **quotes** | Single file (market_tools.go), 5 tools, ~440 LOC, ZERO Manager reaches, ZERO in-subdir tests | LOW | none |
| 2 | **alerts** | 5 files, 1,170 LOC, ZERO Manager reaches, 3 in-subdir tests (testutil dep — minor) | LOW-MED | testutil dep wire-up |
| 3 | **holdings** | 9 files, 1,986 LOC, ZERO Manager reaches, 2 in-subdir tests, all CQRS-pure | LOW-MED | 2 in-subdir tests must move with code |
| 4 | **payoff** | 2 files split from trade/, ~750 LOC, 1 residual fix (line 471, BrokerResolverProvider — exists at HEAD) | LOW | 1-line type-field fix; verify remaining trade/ files still build |
| 5 | **orders** | 7 files split from trade/, ~3,300 LOC, 2 residual fixes, largest tool count (25) | MED | 2 residual fixes (1-line each); largest surface area |

**Notes on sequence**:
- All 5 clusters can be done in PARALLEL (zero cross-subdir imports verified). The ordering above is for SEQUENTIAL resumption (e.g. by a single agent over multiple sessions).
- Splitting `trade/` into orders + payoff means clusters 4 and 5 above must coordinate the side-effect-import edit in bootstrap. If parallel, they can both contribute to `_ "github.com/algo2go/kite-mcp-tools-payoff"` AND `_ "github.com/algo2go/kite-mcp-tools-orders"`; if sequential, the second extraction must verify the first's import is preserved.
- The existing `phase-3-dispatch-briefs-2026-05-16.md` plan (5 briefs by subdir) avoids splitting trade/ — it's structurally simpler if the user accepts the cluster-by-subdir partition.

---

## §5 — Halt-condition map per cluster

| Cluster | Halt # | Type | Description | Mitigation |
|---|---|---|---|---|
| **orders** | H-O1 | Code | `manager.GetBrokerForEmail` residual at options_greeks_tool.go:471 — but this file is in **payoff** cluster, not orders. Cross-cluster type-cycle? | Confirm options_greeks_tool.go is in payoff (yes — per §2.5). H-O1 is N/A for orders. |
| **orders** | H-O2 | Code | `handler.Manager().Logger.Error(...)` at pretrade_tool.go:159 | Change to `handler.LoggerPort().Error(ctx, ...)` (1 line) |
| **orders** | H-O3 | Tier B | Manager Steps 4-5 (focused-service decomp) | NOT BLOCKING — these tools go through CommandBus/QueryBus. Manager decomp affects internal Manager structure, not external tool consumption. |
| **quotes** | H-Q1 | Code | Splitting `market_tools.go` (root mcp/) into its own module changes `RegisterInternalTool` package path — root mcp/ `init()` registers, but external module would need `init()` in `kite-mcp-tools-quotes/quotes` package | Standard pattern — Phase 2 already exercises this via `plugin.RegisterInternalTool` re-export |
| **quotes** | H-Q2 | Tests | Root-level `tools_pure_math_test.go` etc. reference market tools | Tests stay at bootstrap; tool extraction is symbol-only; tests reach via plugin registry post-extraction (same as existing Phase 3 brief plan) |
| **holdings** | H-H1 | Tests | 2 in-subdir tests (`pure_analytics_test.go`, `sector_tool_property_test.go`) need to move | Move alongside code (standard Phase 3 pattern) |
| **holdings** | H-H2 | Type | `sectors.Sector` type identity if analytics + holdings both touch sectors | Both already import external `kite-mcp-sectors` — type identity preserved |
| **alerts** | H-A1 | Tests | `instrument_resolver_adapter_test.go` imports `bootstrap/testutil/kcfixture` | New module adds testutil as test-only dep (precedent: testutil submodule exists at v0.1.1+) |
| **alerts** | H-A2 | Tier B | Manager Steps 4-5 not applicable here (alerts subsystem already a focused service `AlertService`) | NOT BLOCKING |
| **payoff** | H-P1 | Code | `a.manager.GetBrokerForEmail(email)` at options_greeks_tool.go:471 | Struct field type change: `manager *kc.Manager` → `brokerResolver kc.BrokerResolverProvider`; 1-line edit |
| **payoff** | H-P2 | Cohesion | Carving 2 files (options_greeks + option_tools) out of `trade/` leaves residual 7 files in trade/ | Verify by `go build ./mcp/trade/...` after extraction; no inter-file deps between options/option vs other trade tools |

**Tier B Steps 4-5 (Manager method decomp) status vs Phase 3**: Tier B affects only the INTERNAL structure of `kc.Manager` (kite-mcp-kc module). The 7 Provider ports already on ToolHandlerDeps (Sessions/Credentials/RiskGuard/etc.) shield Phase 3 tool modules from Manager internals. **Phase 3 is NOT functionally blocked on Tier B Steps 4-5**. Task #355's pause is presumably for ordering/risk reasons (one structural change at a time), not a hard dependency.

---

## §6 — Decision points for resumption (NOT recommendations to resume)

When Phase 3 resumes, the user must decide:

1. **Partition choice**: existing 5-brief partition (`trade/portfolio+analytics/admin+misc/alerts/paper` — preserves subdir cohort) vs new 5-user partition (`orders/quotes/holdings/alerts/payoff` + 6th rest bucket — cleaner trader-concern naming but splits `trade/`). The existing brief partition has the precedent of having been planned in detail and empirically validated.
2. **Parallelism**: all 5 clusters (either partition) can extract in PARALLEL because zero cross-subdir imports. Sequential is cheaper in agent-context but slower wall-clock.
3. **6th bucket disposition**: if user-named partition adopted, the 50 unmapped tools (admin+ops/analytics/paper/watchlists/tax) need a home. Options: (a) leave them at bootstrap mcp/ root (composition root); (b) extract them as a single `kite-mcp-tools-misc` module; (c) match the existing brief partition for these 50 tools (i.e. hybrid — adopt user names for the 5 trader-facing clusters, and existing brief names for the 3 operator-facing ones).
4. **Side-effect import wire-up**: each extracted cluster needs `_ "github.com/algo2go/kite-mcp-tools-<cluster>"` in bootstrap. Standard pattern from Phase 2 cutover (`tools-common`).

---

## §7 — Effort estimate per cluster (LOW/MED/HIGH)

| Cluster | Effort | Wall-clock (single agent, WSL2) | Components |
|---|---|---|---|
| quotes | LOW | ~30-45min | 1 file, 5 tools, 0 residual, 0 in-subdir tests, 5 deps |
| alerts | LOW-MED | ~45-75min | 5 files, 8 tools, 0 residual, 3 in-subdir tests (testutil dep), 7 deps |
| holdings | MED | ~75-90min | 9 files, 20 tools, 0 residual, 2 in-subdir tests, 9 deps |
| payoff | LOW | ~30-45min | 2 files, 3 tools, 1 residual (1-line fix), 0 in-subdir tests, 6 deps; verify trade/ post-split builds |
| orders | MED-HIGH | ~75-120min | 7 files, 25 tools, 2 residuals (1-line each), 0 in-subdir tests, 10 deps; largest surface |
| **Total (sequential)** | | **~4-7h** | All 5 + bootstrap canary deletions + tag publication |
| **Total (parallel, 5 agents)** | | **~75-120min** | gated by slowest cluster (orders) |

---

## §8 — What FUTURE Phase 3 dispatch needs to verify

When Phase 3 resumes, dispatch agent should re-verify (using INDEX.md §11-style empirical probes):

1. `/healthz total_available` = current count (probably still 111) — sets baseline
2. `kite-mcp-tools-common` version is still v0.1.0+ on GOPROXY
3. bootstrap HEAD compile-clean: `go build ./... && go vet ./...` exits 0 in WSL2
4. Each cluster's residual reaches still match the §INPUTS table (re-grep `manager\.[A-Z]` per subdir — should match #9 above)
5. Tier B Steps status (this changes between sessions — re-check `kc-manager-decomp-roadmap-2026-05-16.md` §2 for Step 3/4/5 status before relying on this doc's "not blocking" claim)
6. No new tools added between this doc's publish and resumption (re-count `grep -cE 'mcp\.NewTool\("'` per dir, sum should still total 111)

---

## §9 — Out-of-scope (explicitly NOT in this doc)

- Recommendation to resume Phase 3 (paused per task #355; this doc is mapping only)
- Re-litigation of partition choice (existing 5-brief plan vs new 5-user plan) — user decides at resumption
- Tier B Manager-decomp Steps 4-5 detail (see `kc-manager-decomp-roadmap-2026-05-16.md`)
- Production deploy timing (orthogonal — Phase 3 is structural-only, tool surface invariant)
- The 50 unmapped tools (admin+ops/analytics/paper/watchlist/tax) — covered by existing phase-3-dispatch-briefs Briefs 2-5

---

## §10 — Cross-references

- `phase-3-dispatch-briefs-2026-05-16.md` — original 5-brief plan (cluster-by-subdir, dispatch-ready)
- `phase-3-ops-port-prereq-2026-05-16.md` — Provider port prereq status (LANDED at kc v0.1.2 / kite-mcp-kc `41d8bf0`)
- `kc-manager-decomp-roadmap-2026-05-16.md` — Tier B Steps 4-5 dependency context
- `STATE.md` §1.1 — current production tool count + invariant verification
- `architectural-patterns-record.md` — Composed Interface pattern §1 reference
- `algo2go/kite-mcp-tools-common/common/handler_deps.go` — 27 Provider ports surface

---

_End of dependency map. Phase 3 remains PAUSED per task #355. This doc enables mechanical resumption when the user signals._
