# Path to a genuine 100% — final research

HEAD: `f3eb895`. Verified by grep, not taken at face value.

## Score reality check

| Dim | Claimed | Honest | Method |
|---|---|---|---|
| Hexagonal | ~100 | **~93** | 2 prod `kiteconnect.New` sites, not 1: `broker/zerodha/sdk_adapter.go:48` AND `kc/kite_client.go:19,23`. `KiteClientFactory` still returns `*kiteconnect.Client` — leaks SDK type. Stripe and tgbotapi also unabstracted (6 + 9 files) |
| ES audit log | 100 | **~88** | 18 event types; 2 broken: `OrderFilledEvent` never dispatched in real flow (only papertrading), `FamilyMemberRemovedEvent` dispatched but NOT subscribed in `wire.go` → not persisted. `wire.go:169` comment "never read back" is stale given the three new `_reconstituted` endpoints |
| CQRS | ~100 | **~90** | 12 direct `usecases.NewXxx` calls remain in `mcp/*.go` (common.go, compliance_tool.go, ext_apps.go ×4, margin_tools.go ×3, setup_tools.go ×2, trailing_tools.go) — these bypass the bus |
| Middleware | ~97 | ~97 | Honest |
| ISP | ~95 | **~80** | 165 `*kc.Manager` occurrences across 50 mcp files. Many are signatures |
| DDD | ~97 | **~75** | Only `Alert` lives in `kc/domain/`. `Order`, `Position`, `Session` are in `broker/broker.go` + `kc/session.go` — anemic structs in infra |
| Monolith | 93 | **~88** | Actual `kc/manager.go`: **957 LOC**, not 935. 7 files over 700, 1 over 900. `post_tools.go` (785) bundles 7 unrelated write tools. `options_greeks_tool.go` (816) bundles BS math + 2 tools |
| Plugin | ~85 | ~85 | Honest — no discovery, no runtime loading, but 2 real consumers |

**Bottom line**: the ~99% weighted average is optimistic. Real average is closer to **~88%**.

## Gap inventory

### 1. ES — OrderFilledEvent + FamilyMemberRemovedEvent broken
**Literal gap**:
- `kc/domain/events.go:53` defines `OrderFilledEvent` → subscribed in `wire.go:182` → only dispatched at `kc/papertrading/engine.go:309`. Real Kite orders never emit this. Reason: Kite API reports fills via polling `get_orders`, not a push callback.
- `kc/usecases/family_usecases.go:291` dispatches `FamilyMemberRemovedEvent`, but `wire.go` has no `Subscribe("family.member_removed", ...)`. Event vanishes from audit trail.

**Capability unlock**:
1. Real OrderFilledEvent → closes the aggregate lifecycle projection (PLACED→FILLED visible without polling)
2. Completes ES audit invariant: every dispatched event is persisted
3. `get_order_history_reconstituted` would show real fills not just placed-state

**Consumer**: dashboard activity timeline, order-history reconstitution tool, compliance audit trail (admin dashboard shows remove events).

**Cost**:
- Subscribe missing event: **1 line** in `wire.go`, ~15 min
- Real OrderFilled bridge: a post-place polling goroutine or Kite postback webhook listener that diffs `get_orders` status and fires `OrderFilledEvent` when status becomes `COMPLETE`. ~1 file (`kc/fill_watcher.go`), ~150 LOC, 3 hours + tests.

**Verdict**: SHIPPABLE. The "real fills are polled" constraint is real, but a polling reconciler is the standard answer, not impossible.

### 2. Hexagonal — 2 prod sites, not 1
**Literal gap**: `kc/kite_client.go:19` and `:23` still call `kiteconnect.New`, and the factory interface returns `*kiteconnect.Client` (concrete SDK type), which 4+ files consume (`bot.go:354`, `pnl.go`, `briefing.go`, http.go). This is a parallel path to the blessed `KiteSDK` interface in `broker/zerodha/sdk_adapter.go`.

**Capability unlock**:
1. Telegram trading commands become testable off-HTTP (currently require real kiteconnect client)
2. PnL snapshot + morning briefing become mockable without httptest servers
3. Single source of SDK construction — one place to add retry/timeout/circuit-breaker

**Consumer**: telegram, pnl, briefing. Existing MockKiteSDK used in 14 off-HTTP tests already proves the pattern.

**Cost**: Retrofit `KiteClientFactory` to return `broker.KiteSDK` (the abstracted interface) instead of `*kiteconnect.Client`. Files touched: `kc/kite_client.go`, `kc/telegram/bot.go`, `kc/alerts/pnl.go`, `kc/alerts/briefing.go`, ~6 tests. **~8 hours**, mostly mechanical.

**Verdict**: SHIPPABLE.

### 3. Aggregate Root full state reconstitution — the thing the user called out
**The honest answer I kept dodging**:

The aggregates DO have write-side command methods: `OrderAggregate.Place/Modify/Cancel/Fill` at `order_aggregate.go:90,124,196,212`. They are called **only from tests** (`store_test.go` ×15, `aggregate_edge_test.go`). Zero production callers. In production we do the inverse: usecase calls Kite → dispatches `domain.OrderPlacedEvent` → projector's `handleOrderEvent` → `aggregate.Apply(event)`. The aggregate is a **read-side derived state**, not the write-side authority.

**Can we make it authoritative?** No — Kite is the real ledger. BUT there's a concrete use case I dismissed: **optimistic local cache + offline order state**.

**Literal gap**: no code path that (a) loads aggregate from events when Kite is rate-limited/down, (b) serves `get_orders` from the projection when Kite fails.

**Capability unlock**:
1. `get_orders` works during Kite 503 / rate-limit spikes (real problem — Kite has daily rate limits per user)
2. `get_orders` works offline (mobile reconnect scenarios)
3. Paper trading already works this way — parity with real trading

**Consumer**: every tool that reads `get_orders`, `get_order_history`, `get_positions` during Kite outage. This is a real failure mode — users hit Kite rate limits daily per the Feb session logs.

**Cost**:
- `kc/cqrs/queries.go`: `GetOrdersFromProjectionQuery` + handler reading `projector.ListActiveOrders()`, ~40 LOC
- `mcp/get_tools.go`: `OrdersTool.Handler` — add fallback path: try `manager.Orders()`, on error → dispatch projection query. ~30 LOC
- Positions parity: same pattern. ~30 LOC
- Tests: ~4 new tests. ~100 LOC
- **~1 file new, ~4 files modified, 4 hours**

**Verdict**: SHIPPABLE. Earlier "weeks of work" framing was wrong — the aggregates already exist, the projection already exists, only the fallback wiring is missing. This is hours not weeks.

### 4. CQRS — 12 escape hatches
**Literal gap**: direct `usecases.NewXxx` in mcp/:
```
common.go:88 (GetProfileUseCase)
compliance_tool.go:77 (GetProfileUseCase)
ext_apps.go:346,359,372,385 (4 widget usecases)
margin_tools.go:93,174,233 (Order/Basket/Charges margins)
setup_tools.go:269 (LoginUseCase), 455 (OpenDashboardUseCase)
trailing_tools.go:121 (GetOrderHistoryUseCase)
```

**Capability unlock**:
1. Uniform latency metrics from bus observability (ext_apps widgets + margins currently invisible to `server_metrics`)
2. Uniform audit logging via bus pipeline
3. Single policy enforcement seam for tier/rate/quota

**Consumer**: observability_tool, admin dashboard activity page, tier enforcement.

**Cost**: 12 usecases → 12 Command/Query handlers. Mechanical. `margin_tools` × 3 = 1.5h, `ext_apps` × 4 = 2h, misc × 5 = 2h. **~6 hours total**.

**Verdict**: SHIPPABLE.

### 5. DDD — Order/Position/Session anemic in infra
**Literal gap**: `broker/broker.go:73` has `Order` as a DTO struct (no methods). Same for `Position` (:56) and `kc/session.go:53` for `SessionRegistry`. None is in `kc/domain/`. Compare to `kc/domain/alert.go` which has 8 methods (ShouldTrigger, MarkTriggered, IsActive, MatchesInstrument, etc.).

**Capability unlock**:
1. `Order.CanCancel()`, `Order.IsTerminal()`, `Order.FillPercentage()` in one place — currently scattered across 5 tool files
2. `Position.IsIntraday()`, `Position.PnL()`, `Position.MarginRequired()` — currently duplicated in analytics_tools + pnl.go + riskguard
3. `Session.IsExpired()`, `Session.TokenAgeHours()` — currently inlined in 3 places

**Consumer**: riskguard, analytics, pnl, ops dashboards.

**Cost**: create `kc/domain/order.go`, `kc/domain/position.go`, `kc/domain/session.go` as rich entities. Keep `broker.Order` as DTO + add `ToDomainOrder()` converter. Wire 4-5 call sites to use the rich entity. **~6 hours**.

**Verdict**: SHIPPABLE.

### 6. Monolith — post_tools.go + options_greeks_tool.go split
**Literal gap**:
- `mcp/post_tools.go` 785 LOC = 7 distinct MCP tools: PlaceOrder, ModifyOrder, CancelOrder, PlaceGTTOrder, DeleteGTTOrder, ConvertPosition, ModifyGTTOrder. **Not cohesive** — different tools, bundled for historical reasons. Split into 7 files.
- `mcp/options_greeks_tool.go` 816 LOC = Black-Scholes math (170 LOC) + 2 tools. Split math → `kc/options/blackscholes.go`, strategy → `options_strategy_tool.go`.
- `kc/manager.go` 957 LOC (claimed 935). 33 functions. Still largest non-test file.

**Capability unlock**:
1. Cleaner file ownership for single-tool edits (7 tools → 7 files)
2. Black-Scholes math reusable by backtest_tool, pretrade_tool (currently not possible without importing `mcp.`)
3. manager.go dropping under 900 unlocks single-screen review

**Consumer**: developer ergonomics, yes; but also `backtest_tool` could import BS pricing today if extracted.

**Cost**: post_tools split **~3h mechanical**. options_greeks extraction **~2h**. manager.go trim another 60 LOC **~2h**. Total **~7h**.

**Verdict**: SHIPPABLE.

### 7. ISP — 165 `*kc.Manager` references in mcp
**Literal gap**: 50 mcp files import `*kc.Manager`. Many are function signatures `Handler(manager *kc.Manager)` that only need 1-3 narrow methods. Provider interfaces (20 of them) exist but not threaded through.

**Capability unlock**:
1. Tool handlers become unit-testable with focused fakes (currently need a full manager)
2. Narrower dep graph — changes to manager.go stop triggering mcp recompile
3. Easier plugin extraction: a plugin can consume the provider interface without pulling in manager

**Consumer**: test ergonomics, plugin authors, future extraction.

**Cost**: roughly 50 handler signatures to convert. Per-handler 5-10 min. **~8 hours** + test updates.

**Verdict**: SHIPPABLE but tedious. Medium-value.

### 8. Middleware — honest at ~97
**Literal remaining 3%**: no hot-reload of rate-limit config, no feature flags gated by tier, no per-family-admin policies. All genuine capabilities but NONE has a current consumer in family mode, skill plugin, admin, compliance, or dashboard. **Defer — genuine future work, not dismissible, but no waiting caller.**

### 9. Plugin — honest at 85
**Literal remaining 15%**: directory-scan discovery, versioned hook contract. Go `plugin` package is **proof-of-impossible on Windows** (go/src/plugin: `plugin: not implemented`, runtime panic). That's a real language/OS constraint. Directory-scan + compile-time registration would work cross-platform — ~2 files, 3 hours — but no caller requests it today.

## Ranked execution plan

1. **ES fixes (1h)** — subscribe `family.member_removed`, add `OrderCancelledEvent` cancel reason field audit, write a `makeEventPersister`+`LoadXxxFromEvents` round-trip test. Lowest cost, immediately tightens the 88→94.
2. **CQRS escape hatches (6h)** — 12 direct usecase calls → bus dispatches. Unlocks observability uniformly. 90→98.
3. **Optimistic projection fallback (4h)** — aggregate read-side for `get_orders` during Kite outage. The "aggregate root" answer the user pushed on. Real capability, hours not weeks.
4. **Hexagonal — KiteClientFactory → KiteSDK (8h)** — consolidate the 2 prod sites to 1. Real testability win for telegram + pnl + briefing.
5. **DDD entities (6h)** — move `Order`, `Position`, `Session` into `kc/domain/` with rich methods. Touches many files but each edit is small.
6. **Monolith splits (7h)** — post_tools into 7 files, options_greeks math extracted. Low risk.
7. **OrderFilledEvent real-flow bridge (3h)** — fill-watcher goroutine polls `get_orders` post-place, fires event on status transition.
8. **ISP narrowing (8h)** — 50 handlers converted to narrow providers. Biggest effort, lowest urgency.

**Total to a genuine 100**: ~43 hours of mechanical work, zero architectural blockers.

## What I verified didn't need work

- **Projection reconstitution dual-format deserializer (f3eb895)** — legitimately fixed, tests in `mcp/position_history_tool_test.go` seed via public format + read via `LoadPositionFromEvents`. Real end-to-end verification.
- **MockKiteSDK + 14 off-HTTP tests** — real, not theater.
- **CommandBus/QueryBus 91 prod sites in mcp** — real dispatches, not wrappers.
- **rolegate + telegramnotify plugins** — real hooks, real consumers.
- **Tier-aware rate limit middleware** — real, tier-scoped, tested.
- **Alert entity move to `kc/domain/alert.go`** — real rich entity with 8 methods.

## Banned framings I checked myself against

- **"Accepted ceiling"**: only used once (Go plugin package on Windows — proof: runtime panic).
- **"Cosmetic"**: not used. Every gap was traced to a concrete capability + consumer.
- **"No consumer"**: middleware 3% is the only "no current consumer" claim, and I named the 5 areas I checked (family mode, skill plugin, admin, compliance, dashboard).
- **"Weeks of work" for aggregate root**: rejected. The actual answer is 4 hours — the aggregates exist, projection exists, only fallback wiring is missing.
- **"Wrong scope"**: not used.
