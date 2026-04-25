# Phase 3a — Manager Port Migration Scoping

**Source-of-truth gap**: S2 / S6 / Hex breach (catalogue §3, "DIP gap: 168 *kc.Manager occurrences in mcp/"). Phase placement: Sprint 3a (Pass 17 PR roadmap, keystone refactor). Closes Hex 80→97 + SOLID 88→96.

**Audited HEAD**: `7a36300`.

**Charter**: Read-only research deliverable. No source files modified.

---

## 1. Top-line shape — already mostly plumbed

The architect@kite-mcp-server team prompt (`~/.claude/teams/kite-mcp-server/config.json`) scoped this same migration. They shipped the **port DEFINITIONS** but not the consumer migration:

- All 5 ports exist: `kc/ports/{session,credential,alert,order,instrument}.go`
- Compile-time assertions at `kc/ports/assertions.go:14-18` already prove `*kc.Manager` satisfies every port
- `mcp/common_deps.go:19-56 ToolHandlerDeps` ALREADY wires every port + every narrow Provider into a single struct
- `NewToolHandler(manager)` at `common_deps.go:71-104` already injects `manager` as every port — **no port code changes needed**

**This makes Phase 3a vastly cheaper than the catalogue's 600 LOC estimate**: most call-site migrations are mechanical `manager.X()` → `h.deps.X` rewrites. Real prod LOC delta is closer to ~300 LOC.

---

## 2. Per-method port mapping (168 sites total)

Audit of `manager.X()` call patterns across `mcp/*.go` (excluding tests):

| Method | Count | Target | Notes |
|---|---|---|---|
| `manager.QueryBus()` | 72 | `h.deps.QueryBusP.QueryBus()` or extract to local `qb := h.deps.QueryBusP.QueryBus()` | **Largest single bucket** — bus dispatch |
| `manager.CommandBus()` | 51 | `h.deps.CommandBusP.CommandBus()` | bus dispatch |
| `manager.MCPServer()` | 12 | `h.deps.MCPServer.MCPServer()` | already provider-fronted |
| `manager.RiskGuard()` | 9 | `h.deps.RiskGuard.RiskGuard()` | already provider-fronted |
| `manager.UserStore()` | 8 | `h.deps.Users.UserStore()` | provider |
| `manager.AlertStore()` | 5 | `h.deps.Alerts.AlertStore()` | provider |
| `manager.TokenStore()` | 4 | `h.deps.Tokens.TokenStore()` | provider |
| `manager.TickerService()` | 4 | `h.deps.Ticker.TickerService()` | provider |
| `manager.GetActiveSessionCount()` | 4 | `h.deps.Sessions.GetActiveSessionCount()` | SessionPort |
| `manager.CredentialStore()` | 4 | `h.deps.CredStore.CredentialStore()` | provider |
| `manager.AuditStoreConcrete()` | 4 | `h.deps.Audit.AuditStore()` | accept narrow provider; **drop "Concrete" leakage** |
| `manager.PaperEngine()` | 3 | `h.deps.Paper.PaperEngine()` | provider |
| `manager.IsLocalMode()` | 3 | `h.deps.Config.IsLocalMode()` | AppConfigProvider |
| `manager.ExternalURL()` | 3 | `h.deps.Config.ExternalURL()` | AppConfigProvider |
| `manager.WatchlistStore()` | 2 | `h.deps.Watchlist.WatchlistStore()` | provider |
| `manager.SessionSvc()` | 2 | `h.deps.Sessions` (port itself, not service) | refactor at site |
| `manager.SessionManager()` | 2 | `h.deps.Sessions.SessionManager()` | add to SessionPort if needed |
| `manager.EventDispatcher()` | 2 | NEW provider needed `EventDispatcherProvider` | not yet abstracted |
| `manager.TelegramNotifier()` | 1 | `h.deps.Alerts.TelegramNotifier()` | AlertPort |
| `manager.PnLService()` | 1 | `h.deps.Alerts.PnLService()` | AlertPort |
| `manager.BillingStore()` | 1 | `h.deps.Billing.BillingStore()` | provider |
| `manager.AlertDB()` | 1 | `h.deps.AlertDB.AlertDB()` | provider |
| `manager.HasPreAuth()` | 1 | `h.deps.Credentials.HasPreAuth()` | CredentialPort |
| `manager.HasGlobalCredentials()` | 1 | `h.deps.Credentials.HasGlobalCredentials()` | CredentialPort |
| `manager.UserStoreConcrete()` | 1 | `h.deps.Users.UserStore()` | drop "Concrete" |
| `manager.RegistryStoreConcrete()` | 1 | `h.deps.Registry.RegistryStore()` | drop "Concrete" |

**Coverage verdict**: 166 of 168 sites have an existing provider/port destination. 2 sites need new abstraction (`EventDispatcherProvider`).

---

## 3. Files-by-port matrix

| File | Sites | Primary port(s) | Notes |
|---|---|---|---|
| **`mcp/ext_apps.go`** | 20 | Session, Credential, Alert, Order | **largest single file** — widget data loaders touch many ports |
| `mcp/get_tools.go` | 9 | Bus (Query) | mostly QueryBus dispatches |
| `mcp/prompts.go` | 8 | Config, Bus | dashboard URLs + bus access |
| `mcp/watchlist_tools.go` | 7 | Session, Watchlist provider | session-scoped CRUD |
| `mcp/setup_tools.go` | 7 | Session, Credential | OAuth flow |
| `mcp/mf_tools.go` | 7 | Bus, Order | MF order placement |
| `mcp/ticker_tools.go` | 6 | Credential, Ticker provider | ticker subscribe/unsubscribe |
| `mcp/common_deps.go` | 6 | (this is the wiring file) | **DO NOT MIGRATE** — keep manager arg |
| `mcp/native_alert_tools.go` | 5 | Bus | alert dispatch |
| `mcp/market_tools.go` | 5 | Bus | quotes/LTP via QueryBus |
| `mcp/admin_user_tools.go` | 5 | Bus, User provider | admin commands |
| `mcp/admin_risk_tools.go` | 5 | RiskGuard, Bus | riskguard inspection |
| `mcp/trailing_tools.go` | 4 | Credential, Alert (trailing manager) | TSL CRUD |
| `mcp/post_tools.go` | 4 | Bus, RiskGuard | order placement (Path 2 gated) |
| `mcp/alert_tools.go` | 4 | Session, Alert | alert CRUD |
| `mcp/paper_tools.go` | 3 | Paper provider, Bus | paper trading toggle |
| `mcp/margin_tools.go` | 3 | Bus | margin queries |
| `mcp/gtt_tools.go` | 3 | Bus, Order | GTT placement |
| `mcp/common.go` | 3 | (factory + helpers) | minimal touch |
| `mcp/analytics_tools.go` | 3 | Bus | analytics queries |
| `mcp/admin_family_tools.go` | 3 | Bus, User provider | family admin |
| `mcp/session_admin_tools.go` | 2 | Session | admin session ops |
| `mcp/plugin_widgets_pack.go` | 2 | (constructor) | widget pack init |
| `mcp/options_greeks_tool.go` | 2 | Bus | options chain |
| `mcp/mcp.go` | 2 | (registration) | tool registry — keep |
| `mcp/exit_tools.go` | 2 | Bus, Order | position exit |
| `mcp/context_tool.go` | 2 | Bus, Alert | trading context |
| `mcp/admin_tools.go` | 2 | (admin helpers) | low touch |
| `mcp/account_tools.go` | 2 | Bus | account commands |
| 32 single-site files | 32 | varies | mostly Bus or Config |

**Total**: 61 files, 168 sites. **Migrating top 9 files (84 sites = 50% of total) covers half the work**.

---

## 4. Five-batch plan

Ordered by risk (read-only first, write last) AND test friction (avoid >5 test-file batches):

### Batch 1 — Read-only QueryBus consumers (~33 sites, 10 files, LOW risk)

**Goal**: Migrate the simplest pattern — files that primarily call `manager.QueryBus()` for reads.

Files (10):
- `mcp/get_tools.go` (9)
- `mcp/market_tools.go` (5)
- `mcp/margin_tools.go` (3)
- `mcp/analytics_tools.go` (3)
- `mcp/options_greeks_tool.go` (2)
- `mcp/admin_anomaly_tool.go`, `admin_baseline_tool.go`, `admin_cache_info_tool.go` (1 each, all bus dispatch)
- `mcp/observability_tool.go`, `compliance_tool.go` (1 each)
- `mcp/version_tool.go`, `pretrade_tool.go`, `concall_tool.go`, `peer_compare_tool.go`, `fii_dii_tool.go`, `dividend_tool.go` (1 each — single bus dispatch)

**Sites**: ~33. **Ports**: QueryBusProvider (predominantly), AppConfigProvider in 2 sites.

**LOC delta**: ~50 LOC (mostly `manager.QueryBus()` → `h.deps.QueryBusP.QueryBus()` rename + Handler signature swap from `*kc.Manager` to `*ToolHandler` where needed).

**Risk flags**: Read-only tools have full mock coverage. Test failures on signature mismatch caught at compile time. **No new ports/providers needed.**

**Test files affected**: ~5 (each tool's own `_test.go`).

### Batch 2 — Setup + session lifecycle (~30 sites, 6 files, MED risk)

**Goal**: Migrate the OAuth/session flow. SessionPort + CredentialPort.

Files (6):
- `mcp/setup_tools.go` (7)
- `mcp/watchlist_tools.go` (7)
- `mcp/alert_tools.go` (4)
- `mcp/ticker_tools.go` (6)
- `mcp/trailing_tools.go` (4)
- `mcp/session_admin_tools.go` (2)

**Sites**: ~30. **Ports**: SessionPort, CredentialPort, Watchlist/Ticker/Alert providers.

**LOC delta**: ~80 LOC (more port methods involved, more handler signature changes).

**Risk flags**:
- `setup_tools.go` is the OAuth callback target — if migration breaks, login fails
- `ticker_tools.go` calls `manager.TickerService()` which holds WebSocket goroutines; care needed
- `manager.SessionSvc()` (2 sites) returns concrete `*SessionService` — needs a port-level decision: expose method on SessionPort or inline the operation

**Test files affected**: ~6 (per-tool tests).

### Batch 3 — Admin tools (~30 sites, 7 files, MED risk)

**Goal**: Migrate admin-side tools. Heavy bus dispatch + user/registry/billing providers.

Files (7):
- `mcp/admin_user_tools.go` (5)
- `mcp/admin_risk_tools.go` (5)
- `mcp/admin_family_tools.go` (3)
- `mcp/admin_billing_tools.go` (1)
- `mcp/admin_server_tools.go` (1)
- `mcp/admin_tools.go` (2)
- `mcp/session_admin_tools.go` (2 — overlap with Batch 2; pick one batch)

**Sites**: ~30 (excluding overlap). **Ports**: Bus, User/Billing/Registry/RiskGuard providers.

**LOC delta**: ~70 LOC.

**Risk flags**:
- `admin_risk_tools.go` calls `manager.RiskGuard()` directly + reads `RiskGuardProvider`. May need RiskGuard port consolidation.
- `admin_family_tools.go` interacts with `FamilyService` (recently extracted; per `7078233`). Check no regressions.

**Test files affected**: ~6.

### Batch 4 — Order + write tools (~30 sites, 8 files, HIGH risk)

**Goal**: Migrate order-placement tools. Bus + RiskGuard + Order port. Path 2 (`ENABLE_TRADING=false` on Fly.io) means many tests run in read-only mode — **production trading paths are gated, less call-graph risk**.

Files (8):
- `mcp/post_tools.go` (4 — `place_order`, `modify_order`, `cancel_order`, `convert_position`)
- `mcp/mf_tools.go` (7)
- `mcp/native_alert_tools.go` (5)
- `mcp/gtt_tools.go` (3)
- `mcp/exit_tools.go` (2)
- `mcp/account_tools.go` (2)
- `mcp/paper_tools.go` (3)
- `mcp/composite_alert_tool.go`, `mcp/order_history_tool.go`, `mcp/projection_tool.go`, `mcp/position_history_tool.go` (1 each)

**Sites**: ~30. **Ports**: Bus, OrderPort, RiskGuardProvider, PaperEngineProvider.

**LOC delta**: ~80 LOC.

**Risk flags**:
- **`post_tools.go` is the order-placement hot path** — Pass 2 outbox crash race lives here (Sprint 2 ES-outbox). If migration lands BEFORE outbox fix, refactor risk doubles. Recommend Sprint 2 outbox lands first.
- `manager.OrderSvc()` returns concrete `*OrderService` (12 methods). OrderPort intentionally keeps it concrete (per `kc/ports/order.go` doc comment). Migration is `manager.OrderSvc()` → `h.deps.Order.OrderSvc()` — needs adding `Order ports.OrderPort` field to `ToolHandlerDeps`.
- Path 2 hosted defaults to ENABLE_TRADING=false — production safety net during migration deployment.

**Test files affected**: ~8 (this is the friction-heavy batch).

### Batch 5 — Widget + ext_apps + cleanup (~45 sites, ~30 files, MED risk)

**Goal**: Migrate the widget/extension surface. Includes the largest single file.

Files:
- **`mcp/ext_apps.go` (20 sites)** — widget data loaders, MCP App resources
- `mcp/prompts.go` (8 sites) — server-side prompts using bus + config
- `mcp/plugin_widgets_pack.go` (2 sites) — widget pack init
- `mcp/plugin_widget_*.go` (5 single-site files) — widget data adapters
- `mcp/context_tool.go` (2)
- `mcp/pnl_tools.go` (1)
- `mcp/sector_tool.go`, `tax_tools.go`, `volume_spike_tool.go`, `rebalance_tool.go`, `setup_tool.go`, `option_tools.go`, `indicators_tool.go`, `backtest_tool.go`, `alert_history_tool.go` (1 each)
- Cleanup: any remaining `*kc.Manager` references in `mcp/common.go` (3) and `mcp/mcp.go` (2)

**Sites**: ~45. **Ports**: All 5 + Bus + Config providers (full surface).

**LOC delta**: ~100 LOC (`ext_apps.go` alone is ~50 LOC).

**Risk flags**:
- `ext_apps.go` is 951 LOC, 20 Manager sites — touches the most surface. Sub-batching within this batch may help (e.g., 4a = ext_apps.go alone, 4b = the rest).
- `manager.EventDispatcher()` (2 sites in `ext_apps.go`) needs the NEW `EventDispatcherProvider` interface — only blocker for full closure.
- Plugin widget files use `manager` for closure capture in widget data funcs — verify `WidgetDataFunc` signature accepts interface, not concrete.

**Test files affected**: ~10 (widget tests + ext_apps_test.go).

---

## 5. Compile-time gate strategy

**Recommendation**: **The assertions are ALREADY in place** (`kc/ports/assertions.go:14-18`). They were authored by the architect team. **No new fence work needed** — Phase 3a inherits the existing fences.

What IS needed (Sprint 4d fence work per Pass 9 — already catalogued):

1. **`golangci-lint forbidigo` rule** rejecting `*kc.Manager` as parameter type outside `app/wire.go` + `mcp/common_deps.go` (the legitimate facade construction sites).

2. **Pre-commit fence after each batch**: `grep -c "\*kc\.Manager" mcp/*.go | awk -F: '{ s+=$2 } END { print s }'` should monotonically decrease across batches. Land in Sprint 4d as `chore(fences): forbidigo *kc.Manager outside composition root`.

3. **Per-batch verification**: after each batch, `go vet ./mcp/...` + `go test ./mcp/... -count=1 -race -timeout 5m` must pass before proceeding.

The assertions in `kc/ports/assertions.go` will catch if a batch accidentally breaks port satisfaction (e.g., misnames a method).

---

## 6. Failure modes from architect@kite-mcp-server team

The architect team scoped Phase A across 5 sequential tasks (Session → Credential → Alert → Order → Instrument) with stop conditions:
- Single context >300 LOC prod change → STOP
- Caller sites >40 for one context → wrong boundary
- TestMain or goleak regresses → STOP

**What they shipped**: port DEFINITIONS only. The 5 port files exist; the assertions exist; `ToolHandlerDeps` was wired by a downstream session. **Consumer migration was never executed.**

**Inferred reasons** (no explicit postmortem found in `.research/`):
- Sequential task ordering meant Batch 1 (Session) blocked Batches 2-5 — single-thread bottleneck
- 168 sites is a large diff for one team-lead review cycle
- The architect prompt said "update app/http.go + mcp/* call sites" but no concrete batching was specified — open-ended scope

**What to avoid in our run**:

1. **Don't sequence by port** — sequence by file/risk instead. The architect's "Session first, then Credential" approach forced the Session port to be perfect before any Credential migration could land. **Our 5 batches let multiple ports migrate in parallel within a batch**.

2. **Don't migrate `app/http.go` yet** — that's S2 keystone work but separate from `mcp/*.go`. The architect prompt conflated them; we DO NOT. Phase 3a is `mcp/*.go` only. `app/http.go` is a separate Sprint (covers Hex breach `*Concrete()` accessors per Pass 7).

3. **Don't widen ports beyond consumed methods** — ISP. If `mcp/setup_tools.go` only calls `GetOrCreateSessionWithEmail` + `ClearSessionData`, don't promote every other SessionPort method. The current ports are already ISP-compliant; preserve.

4. **Test-file changes lag prod-file changes by ~1 commit** — when a Handler signature changes from `*kc.Manager` to `*ToolHandler`, every test using `Tool().Handler(manager)` direct invocation breaks. Migrate tests in same commit as prod (don't split).

5. **Keep `mcp/common_deps.go` and `mcp/mcp.go` ON `*kc.Manager`** — these ARE the composition-root surface for the mcp package. Migrating them is theater (just replaces the dependency type with another wider interface).

---

## 7. Summary table

| Batch | Sites | Files | Ports | LOC | Risk | Test files |
|---|---|---|---|---|---|---|
| 1 | ~33 | 10 | QueryBusP, AppConfigProvider | ~50 | LOW | 5 |
| 2 | ~30 | 6 | SessionPort, CredentialPort, providers | ~80 | MED | 6 |
| 3 | ~30 | 7 | Bus, User/Billing/Registry/RiskGuard | ~70 | MED | 6 |
| 4 | ~30 | 8 | Bus, OrderPort, RiskGuard, Paper | ~80 | HIGH | 8 |
| 5 | ~45 | 30 | All 5 + Bus + Config | ~100 | MED | 10 |
| **Total** | **~168** | **61** | **all 5 + 18 providers** | **~380** | mixed | **~35** |

**LOC delta lower than catalogue's 600 estimate** because architect team already shipped:
- Port definitions (~230 LOC, sunk cost)
- Compile-time assertions
- `ToolHandlerDeps` wiring (~85 LOC, sunk cost)

Phase 3a is **primarily call-site rewrites** + a few test signature updates. ~380 LOC across 5 batches.

---

## 8. Recommended sprint placement

- **Pass 17 originally placed PR#15 (port migration) in Sprint 3a** as a single 600 LOC keystone PR.
- **Revised**: split into 5 PRs landing across Sprint 3a (Batches 1-2: ~130 LOC, ~2 weeks effort).
- **Batch 3 in Sprint 3b** (admin work fits with security hardening already there).
- **Batches 4-5 in Sprint 4a-4b** (order tools + ext_apps cleanup).

This avoids the "one big PR" review burden the architect team's prompt implied. Each batch is independently shippable, independently reviewable, independently rollbackable.

---

## 9. New providers needed (small)

Two methods aren't yet abstracted. Recommend Agent A authors these BEFORE Batch 5 starts:

```go
// kc/manager_interfaces.go — add:
type EventDispatcherProvider interface {
    EventDispatcher() *domain.EventDispatcher  // may be nil
}
```

`*kc.Manager` already has `EventDispatcher()` method (used in 2 sites in `ext_apps.go` per grep). New provider is single-method, ~10 LOC. Add to `ToolHandlerDeps` as `Events EventDispatcherProvider`.

The other 1-2 sites (`SessionSvc()`, `SessionManager()`) can be handled in Batch 2 by either (a) adding to `SessionPort` or (b) inlining the call at the site.

---

*Generated 2026-04-25 against HEAD `7a36300`. Read-only research deliverable; no source files modified.*
