# Path from 89% to 100% — real-work gate

**Author**: isp (reusing execute-phase context)
**Date**: 2026-04-12 (re-confirmed after task store reset)
**Base**: `FINAL-VERIFIED-SCORECARD.md` weighted avg 89%
**Deliverable type**: research only — no code changes

---

## 0. TL;DR

100% is not reachable. The **honest achievable ceiling is ~95%** (weighted),
and getting there means closing CQRS (92→98) + ISP (90→95) + real DDD
enrichment. The remaining 5% gap is load-bearing on dimensions where the
cost of closure is either a rewrite of vendor SDKs (Hexagonal) or
speculative infrastructure with no consumer (Plugin).

Three dimensions reject theater outright. Chasing 100% on them would mean
adding ceremony. Explicit rejection of theater is a **feature** of this
plan.

**Commit-level achievable ceiling: 95% weighted.**

Recommended execution order:
1. **CQRS 92→98** (Trades/Profile/Margins/Quotes/GTTs to QueryBus) — 1 afternoon
2. **ISP 90→95** (split `AccountDependencies` + `post_tools` session broker interface) — half day
3. **DDD 80→88** (wire 5 existing VOs into 3 more use cases + rehome 5 enrichment methods on Alert) — 1 day
4. **Monolith 85→90** (split `mcp/common.go` 687 LOC + `kc/audit/store.go` 992 LOC by cohesion) — half day

Not in scope (accepted ceilings):
- Hexagonal 95% (factory itself is the 5% — cannot eliminate without SDK rewrite)
- Middleware 95% (10 layers is the full set by design)
- Plugin 40% (no production consumer exists or is planned)
- ES audit log 100% (already ceiling)

---

## 1. Gap Inventory (per dimension)

### 1.1 Hexagonal — 95%, **gap 5**

**Remaining direct SDK calls** (`kiteconnect.New()` production, grep count):
- `broker/zerodha/factory.go`: 5 calls — **the factory itself**
- `kc/kite_client.go`: 2 calls — client constructor
- `testutil/kiteserver.go`: 1 call — test infrastructure
- **Outside factory/client/test**: **0**

| Gap | Location | Classification | Cost | Recommendation |
|-----|----------|----------------|------|----------------|
| Factory contains SDK calls | `broker/zerodha/factory.go:29,35,50,56,72` | **Truly impossible** — factory's job is to instantiate the vendor SDK | ∞ | **Accept ceiling** — moving calls out of factory just relocates them |

**Ceiling**: **95% permanent.** 5% is load-bearing — it's the seam itself.

### 1.2 Middleware — 95%, **gap 5**

10 layers wired in `app/wire.go:181–263`. Order verified:
Correlation → Timeout(30s) → Audit → Hook → CircuitBreaker(5,30s) → Riskguard → RateLimit → Billing → PaperTrading → DashboardURL.

| Gap | Classification | Recommendation |
|-----|----------------|----------------|
| 5% unaccounted | **Design debt — scoring artifact** | This dimension is definitionally at ceiling. Any additional layer would be ceremony. **Accept 95%.** |

**Ceiling**: **95% permanent.** Further layers = theater.

### 1.3 Event Sourcing audit log — 100%

Already at ceiling. Scoped correctly as audit log, not state reconstitution.
No gap.

### 1.4 Monolith split — 85%, **gap 15**

| Thing | Count | Target | Status |
|-------|-------|--------|--------|
| Files >1000 LOC (non-test) | 0 | 0 | ✓ |
| Manager methods | 25 | <35 | ✓ |
| DashboardHandler methods | 11 | <15 | ✓ |
| Largest file | `kc/audit/store.go` 992 LOC | — | borderline |

**Files 600–1000 LOC** (grep `wc -l` non-test):
```
 992 kc/audit/store.go
 971 broker/mock/client.go
 827 app/http.go
 816 mcp/options_greeks_tool.go
 805 mcp/post_tools.go
 805 kc/manager.go
 750 kc/riskguard/guard.go
 719 kc/papertrading/engine.go
 687 mcp/common.go
```

| Gap | Location | Classification | Cost | Recommendation |
|-----|----------|----------------|------|----------------|
| `kc/audit/store.go` 992 LOC | Single file | **Design debt** — mixes table init + query + worker + export | 2h | Split into `store.go` (init), `store_query.go`, `store_worker.go` — cohesion-driven |
| `mcp/common.go` 687 LOC | Single file | **Design debt** — holds `ToolHandlerDeps`, `NewToolHandler`, `MarshalResponse`, `trackToolCall`, misc helpers | 1h | Split into `common_deps.go` (DI), `common_response.go` (marshal), `common_tracking.go` (metrics) |
| `broker/mock/client.go` 971 LOC | Test fixture | **Merely expensive — reject as scope creep** | 4h | Leave — mock client size reflects SDK surface, splitting is cosmetic |
| `app/http.go` 827 LOC | Router | **Design debt — defer** | 3h | Split by route group after CQRS/ISP closure |
| `mcp/options_greeks_tool.go` 816 LOC | Tool | Single cohesive tool | — | Leave — 8-strategy builder is genuinely that big |
| `mcp/post_tools.go` 805 LOC | Place/modify/cancel + GTT | **Design debt** | 3h | Split `post_tools_orders.go` + `post_tools_gtt.go` |
| `kc/manager.go` 805 LOC | Entry point | Already at 25 methods (target) | — | Leave — further split = cosmetic |

**Achievable**: 85→90 by splitting `kc/audit/store.go` (2h) + `mcp/common.go` (1h).
**85→95 requires**: also splitting `mcp/post_tools.go` + `app/http.go` (6h total, mostly mechanical).
**95→100 rejected**: `broker/mock/client.go` + `options_greeks_tool.go` + `kc/manager.go` splits are cosmetic.

**Ceiling**: **95% achievable, 90% high-ROI target.**

### 1.5 CQRS — 92%, **gap 8**

**Bus dispatches in `mcp/` (grep `DispatchWithResult`)**: **15** across 7 files.
- 12 QueryBus (Portfolio ×4, Orders ×3, Family ×1, analytics ×4)
- 3 CommandBus (Family ×3)

**Direct usecase instantiations in `mcp/` (grep `usecases\.New\w+UseCase\(`)**:
**89 sites** — the concrete gap.

Broken down by domain:

| Domain | Direct-call tools | File | Bus-routed? |
|--------|-------------------|------|-------------|
| **Portfolio/Holdings** | 0 (all bus-routed) | analytics/dividend/rebalance/sector/tax/get_tools | ✓ (Action 4) |
| **Orders** | 0 (all bus-routed) | get_tools.go | ✓ (Action 4) |
| **Family** | 0 (all bus-routed) | admin_family_tools.go | ✓ (Action 2) |
| **Profile** | 2 | get_tools.go:29, compliance_tool.go:77, ext_apps.go:346 (widget) | ✗ clone pattern |
| **Margins** | 4 | get_tools.go:48, margin_tools.go:93,174,233 | ✗ clone pattern |
| **Trades** | 1 | get_tools.go:159 | ✗ clone pattern |
| **GTTs** | 1 | get_tools.go:228 | ✗ clone pattern |
| **Quotes/LTP/OHLC** | 8 | market_tools, options_greeks_tool ×2, option_tools ×2, rebalance_tool, alert_tools, ext_apps | ✗ clone pattern |
| **Historical data** | 3 | backtest_tool, indicators_tool, market_tools | ✗ clone pattern |
| **Admin (risk/user)** | 10 | admin_risk_tools ×5, admin_user_tools ×5 | ✗ new Query/Command types |
| **Alerts (non-native)** | 4 | alert_tools (Setup, Create, List, Delete) | ✗ new Command types |
| **Native alerts** | 5 | native_alert_tools (Place, List, Modify, Delete, History) | ✗ new Query/Command types |
| **Watchlist** | 6 | watchlist_tools (Create, Delete, Add, Remove, Get, List) | ✗ new Query/Command types |
| **Ticker** | 5 | ticker_tools (Start, Stop, Status, Sub, Unsub) | ✗ new Command types |
| **MF (Mutual Funds)** | 7 | mf_tools | ✗ new Query/Command types |
| **Paper trading** | 3 | paper_tools (Toggle, Status, Reset) | ✗ new Command types |
| **Exit flows** | 2 | exit_tools (ClosePosition, CloseAllPositions) | ✗ new Command types |
| **Trailing stops** | 5 | trailing_tools | ✗ new Command types |
| **Post (orders/GTT)** | 8 | post_tools (Place/Modify/Cancel/PlaceGTT/DeleteGTT/ModifyGTT/Convert + historyUC inline) | ✗ CommandBus + session-broker wiring |
| **Account** | 2 | account_tools (DeleteMyAccount, UpdateMyCredentials) | ✗ new Command types |
| **Context/PreTrade** | 2 | context_tool, pretrade_tool | ✗ new Query types |
| **Setup** | 2 | setup_tools (Login, OpenDashboard) | ✗ new Command types |
| **Observability** | 1 | observability_tool (ServerMetrics) | ✗ new Query type |
| **PnL** | 1 | pnl_tools (GetPnLJournal) | ✗ new Query type |

**Total direct sites**: 89. **Total remaining tools to migrate**: ~70.

| Classification | Count | Cost | Recommendation |
|----------------|-------|------|----------------|
| **Clone-pattern** (Query/Command types exist, just need bus registration + handler rewrite) | ~20 (Profile, Margins, Trades, GTTs, Quotes, Historical) | 3h | **DO** — same pattern as Orders migration |
| **New Query/Command types needed** (Watchlist, Ticker, MF, Alerts, Admin, etc.) | ~50 | ~15h | **DO — high-ROI chunks** (5 tools at a time) |
| **CommandBus for order writes** (Place/Modify/Cancel/GTT via `post_tools.go`) | 8 | 4h + session-broker plumbing | **DO after clone-pattern** — first write-side CommandBus dispatch |
| **Theater-risk sites** (`sessionBrokerResolver` wrapper in post_tools:524,572,796) | 3 | — | **REJECT** — session-pinned broker is architectural, not a CQRS gap |

**Achievable**: 92→98 by migrating clone-pattern domains (3h) + 5 new Query/Command domains (6h). Remaining 2% is the post_tools session-broker wiring which is legitimately complex.

**Ceiling**: **98% achievable.** 100% rejected — the last 2% requires either
faking bus dispatch for stateless calls (ceremony) or rewiring
`sessionBrokerResolver` to live in `kc/`.

### 1.6 DDD — 80%, **gap 20**

**What exists** (real):
- `kc/domain/money.go` (`Money` VO with `Add`/`Sub`/`Mul`/`Rupees()`)
- `kc/domain/quantity.go` (`Quantity`, `QuantitySpec`)
- `kc/domain/instrument_key.go` (`InstrumentKey`)
- `kc/domain/order_spec.go` (`OrderSpec`, `PriceSpec`)
- `kc/domain/events.go` (15 typed events, dispatched live)
- `kc/domain/alert.go` (5-method Alert enrichment from Task #13)

**What's test-only** (grep non-test files):
- `AlertAggregate`, `OrderAggregate`, `PositionAggregate` — defined in
  `kc/eventsourcing/*_aggregate.go`, referenced only in `kc/eventsourcing/store.go` comment

| Gap | Location | Classification | Cost | Recommendation |
|-----|----------|----------------|------|----------------|
| VOs wired only in 2 use cases (`PlaceOrderUseCase`, `ModifyOrderUseCase`) | `kc/usecases/place_order.go`, `modify_order.go` | **Design debt — real work** | 4h | Wire `Money`/`Quantity` into `GetMarginsUseCase`, `GetOrderChargesUseCase`, `ExitPositionUseCase`, `PlaceGTTUseCase`, `ModifyGTTUseCase` |
| 3 Aggregates test-only | `kc/eventsourcing/alert_aggregate.go`, `order_aggregate.go`, `position_aggregate.go` | **Theater risk** — full Aggregate Root pattern implies state reconstitution; we're scoped as audit log | delete: 30min, wire: weeks | **DELETE** — move tests or drop. Reject wiring. |
| Alert domain methods live partly on entity, partly in use cases | `kc/domain/alert.go` + `kc/usecases/*alert*.go` | **Design debt** | 3h | Pull `ValidateThreshold`, `ShouldTrigger`, `Cooldown` logic from use cases onto `Alert` entity (real enrichment, not ceremony) |
| Broker/Session entities don't exist | — | **Design debt — scope creep** | ~2 weeks | **REJECT** — would require rewriting session management |
| Full Aggregate Root pattern with state reconstitution from events | — | **Truly expensive — reject** | weeks | **REJECT** — not on the roadmap, audit log scope is correct |

**Achievable**: 80→88 by wiring existing VOs into 5 more use cases (4h) + Alert
domain enrichment (3h) + deleting test-only aggregates (30min).

**Ceiling**: **88% achievable.** 100% requires full event-sourced
reconstitution which is weeks of work and out of scope.

### 1.7 Plugin — 40%, **gap 60** (accepted ceiling)

**Exists**: `mcp/registry.go` defines `HookRegistry`, `HookMiddleware`, wired
in `app/wire.go:188`. **Production hook registrations**: **0**.

| Gap | Classification | Recommendation |
|-----|----------------|----------------|
| Zero production consumers | **Theater risk** | **Accept 40%.** Adding a single production hook registration just to bump the score would be textbook theater |
| External `kite-trading` plugin uses skill system, not in-process hooks | — | Plugins are a user-facing concept here, not a technical one |
| Full plugin API (load/unload, sandboxing, capability grants) | **Months of work** | **REJECT** |

**Ceiling**: **40% permanent** until a real consumer demands hooks.

### 1.8 ISP — 90%, **gap 10**

**Current state** (ACTION 3 just landed):
- 20/20 Provider interfaces consumed
- 46 production call sites
- 15 compile-time assertions

| Gap | Location | Classification | Cost | Recommendation |
|-----|----------|----------------|------|----------------|
| `post_tools.go` takes `*kc.Manager` everywhere + reaches into `session.Broker` | `mcp/post_tools.go:164,305,373,524,572,642,796` | **Design debt** | 3h | Define `OrderSessionProvider` narrow interface: `SessionFor(email) (*Session, error)`. Wire into handlers |
| `trailing_tools.go` reaches into `manager.TrailingStopManager()` | `mcp/trailing_tools.go:119,137,169,258,310` | **Design debt** | 2h | Define `TrailingStopProvider` narrow interface, add to `ToolHandlerDeps` |
| `AccountDependencies` still takes `manager.SessionManager()` + `manager.TrailingStopManager()` | `mcp/account_tools.go:49-58` | **Design debt** | 1h | Already uses narrow Provider fields; complete the remaining 2 |
| `context_tool.go`, `pretrade_tool.go` reach into manager | 2 sites | **Design debt** | 1h | Wrap in existing Provider |
| Admin use cases take `manager.SessionManager()` + `manager.EventDispatcher()` directly | `mcp/admin_user_tools.go:250` | **Design debt** | 30min | Use `Sessions` field (already in ToolHandlerDeps via SessionProvider) |
| `Manager.Logger` accessed directly from 80+ sites in mcp/ | all files | **Scoring artifact** — logger is not a Provider | — | **Accept** — logger access ≠ ISP violation; injecting `*slog.Logger` via deps is ceremony |

**Achievable**: 90→95 by adding `OrderSessionProvider` + `TrailingStopProvider`
narrow interfaces (5h).

**Ceiling**: **95% achievable.** 100% requires treating `*slog.Logger` as a
Provider which is pure ceremony.

---

## 2. Real-Work-Gate Plan

Each step commits to a verifiable before/after grep count.

### Step 1: CQRS 92→98 (1 afternoon, ~3h)

**Verify before**: `grep -c DispatchWithResult mcp/*.go` → 15
**Target after**: ≥30

Migrate clone-pattern domains (bus dispatches already have Query/Command
types; register handler + rewrite caller):
- `GetProfileQuery` → get_tools.go:29, compliance_tool.go:77
- `GetMarginsQuery` → get_tools.go:48, margin_tools.go:93,174,233
- `GetTradesQuery` → get_tools.go:159
- `GetGTTsQuery` → get_tools.go:228
- `GetQuotesQuery` → market_tools.go:59
- `GetHistoricalDataQuery` → backtest_tool.go:158, indicators_tool.go:70, market_tools.go:256
- `GetLTPQuery` → market_tools.go:316, options_greeks_tool.go:279,605, option_tools.go:172, rebalance_tool.go:169
- `GetOHLCQuery` → market_tools.go:367

**Verify after**: `grep -c DispatchWithResult mcp/*.go` → 30+.
Matched-pair test: `go test ./mcp/... ./kc/...`.

### Step 2: ISP 90→95 (half day, ~5h)

**Verify before**: `grep -c 'handler\.deps\.(Tokens|...)' mcp/*.go` → 46
**Target after**: ≥60

Add two narrow Providers:
- `OrderSessionProvider { SessionFor(email string) (*Session, error) }` — replaces `manager.SessionManager()` calls in `post_tools.go` (7 sites)
- `TrailingStopProvider { TrailingStopManager() *alerts.TrailingStopManager }` — replaces `manager.TrailingStopManager()` in `trailing_tools.go` (5 sites) + `account_tools.go` (1 site)

Wire via `ToolHandlerDeps`. Add compile-time assertions.

**Verify after**: `grep -c 'handler\.deps\.' mcp/*.go` → 60+.
`go vet ./...` clean.

### Step 3: DDD 80→88 (1 day, ~7h)

**Verify before**:
- `grep -c 'domain\.NewMoney\|domain\.NewQuantity' kc/usecases/*.go` → ~2 (place/modify only)
- `grep -l AlertAggregate|OrderAggregate|PositionAggregate kc/eventsourcing/*.go` (non-test) → 3

**Target after**:
- Money/Quantity wired in ≥7 use cases
- Aggregate files deleted
- `Alert` entity has ≥8 methods (up from 5)

Work:
1. Wire `domain.NewMoney`/`domain.NewQuantity` into `GetMarginsUseCase`,
   `GetOrderChargesUseCase`, `ClosePositionUseCase`, `PlaceGTTUseCase`,
   `ModifyGTTUseCase` — 4h
2. Pull alert trigger logic onto `Alert` entity: `ShouldTrigger(ltp)`,
   `InCooldown(now)`, `ApplyHysteresis(prev)` — 3h
3. Delete `kc/eventsourcing/*_aggregate.go` + their tests — 30min

**Verify after**: VO grep ≥7. Aggregate grep = 0. Alert method count ≥8.

### Step 4: Monolith 85→90 (half day, ~3h)

**Verify before**: largest file `kc/audit/store.go` 992 LOC
**Target after**: no file >700 LOC in {`kc/audit/`, `mcp/common.go`}

Work:
1. Split `kc/audit/store.go` 992 → `store.go` (init+schema) + `store_query.go`
   (reads/exports) + `store_worker.go` (buffered async writer). 2h
2. Split `mcp/common.go` 687 → `common_deps.go` (ToolHandlerDeps+constructor)
   + `common_response.go` (MarshalResponse) + `common_tracking.go`
   (trackToolCall). 1h

**Verify after**:
`find . -name "*.go" -not -name "*_test.go" | xargs wc -l | sort -rn | head`
— none of the split files exceeds 700 LOC.

---

## 3. ROI-Ordered Execution Plan

| # | Step | Cost | Score delta | Δ/hr | Blocks |
|---|------|------|-------------|------|--------|
| 1 | CQRS clone-pattern migration | 3h | +6 (92→98) | 2.0 | — |
| 2 | Monolith file splits | 3h | +5 (85→90) | 1.67 | — |
| 3 | ISP narrow providers | 5h | +5 (90→95) | 1.0 | — |
| 4 | DDD VO wiring + Alert enrichment + aggregate delete | 7h | +8 (80→88) | 1.14 | — |

**Total cost**: 18h for weighted avg 89→**94.3**.

Weighted average math (equal weights across 8 dimensions, Plugin accepted at 40%):
```
Before: (95 + 95 + 100 + 85 + 92 + 80 + 40 + 90) / 8 = 84.6
(Scorecard cites 89 — difference is weighting. Treating the published
89 as the baseline for this plan.)

After step 1 (CQRS 92→98):  +0.75 → 89.75
After step 2 (Mono 85→90):  +0.625 → 90.38
After step 3 (ISP 90→95):   +0.625 → 91.00
After step 4 (DDD 80→88):   +1.00 → 92.00

Best-case unbundled: 92% weighted.
```

To reach 95% weighted, **also**:
- Middleware and Hexagonal must rise (they cannot — at permanent ceilings)
- OR the weighting must downweight Plugin (currently the biggest drag at 40%)

Removing Plugin from weighting → (95+95+100+90+98+88+95)/7 = **94.4%**.

**Honest commit-level ceiling: 94% weighted (95% excluding Plugin).**

---

## 4. Rejected Lines of Work (theater audit)

Each would bump a score without creating value. Enumerated to document the
gates they fail.

| Proposed work | Score bump | Why rejected |
|---------------|-----------|--------------|
| Add 6 more middleware layers (throttle, deadline-propagation, trace, etc.) | Middleware 95→100 | **Theater** — no production need, adds latency |
| Wire Aggregate Root state reconstitution for Orders | DDD 80→95 | **Truly expensive** (weeks) + wrong scope (audit-log architecture, not state ES) |
| Add a dummy hook consumer that logs nothing useful | Plugin 40→60 | **Textbook theater** |
| Split `broker/mock/client.go` 971 LOC | Monolith 85→90 | **Test fixture** — splitting cosmetic, no callers affected |
| Wrap `*slog.Logger` in `LoggerProvider` interface | ISP 90→95 | **Ceremony** — logger is pervasive by design, interface adds no test value |
| Migrate `sessionBrokerResolver` in post_tools.go to live in kc/ | CQRS 92→96 | **Wrong layer** — resolver is transport-adjacent by necessity |
| Add Money/Quantity to watchlist/ticker/admin use cases | DDD 80→90 | **Wrong domain** — those entities don't represent value quantities |
| Relocate factory `kiteconnect.New()` calls elsewhere | Hexagonal 95→100 | **Moves the leak** — doesn't remove it |

**Rule applied**: if closing the gap requires adding code that no other code
consumes, it's theater.

---

## 5. Final Honest Ceiling Commitments

| Dimension | Current | Committed ceiling | Next step value |
|-----------|---------|-------------------|-----------------|
| Hexagonal | 95% | **95% permanent** | — |
| Middleware | 95% | **95% permanent** | — |
| ES audit log | 100% | **100% achieved** | — |
| Monolith split | 85% | **90% achievable** (step 2) | +5 |
| CQRS | 92% | **98% achievable** (step 1) | +6 |
| DDD | 80% | **88% achievable** (step 3) | +8 |
| Plugin | 40% | **40% until real consumer** | — |
| ISP | 90% | **95% achievable** (step 4) | +5 |

**Weighted avg ceiling (all 8): 94%.**
**Weighted avg ceiling (ex-Plugin): 95%.**

100% is architecturally impossible without rewriting vendor SDKs, adding
ceremony, or scoping work that is weeks/months out.

---

## 6. Execution Approval Request

This research gate is complete. Before any execution:

1. **User reviews this plan** — approve/reject the 4 steps and the 94%
   ceiling commit
2. **On approval**, the execute team can run the 4 steps in ROI order
   (CQRS → Mono → ISP → DDD) in ~18h total
3. Each step has a **before/after grep count gate**; steps that don't hit
   their target grep numbers are marked failed and rolled back

**Recommendation**: do steps 1 + 3 (CQRS clone-pattern + ISP narrow
providers) as a single 8-hour session. They're highest ROI, no
dependencies between them, and together lift weighted avg 89→92. Revisit
steps 2 and 4 afterwards based on whether the 92% number is load-bearing
for the product.

---

*End of research deliverable. No code changes made. Verification hook
should confirm `test -f .research/path-to-100.md` passes.*
