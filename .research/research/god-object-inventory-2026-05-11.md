# God-Object Inventory + Decomposition Roadmap

**Date**: 2026-05-11 IST
**as-of**: 2026-05-11
**Master HEAD audited**: `07c830c` (`docs(research): MCP ecosystem audit + prioritized install/build queue (Track 3)`)
**Dispatch role**: Track 3 of 3 parallel — god-object identification across full codebase. Chain on `zero-in-tree-feasibility-2026-05-11.md` (disjoint scope). Audit on `github-transfer-bootstrap-2026-05-11.md` (disjoint scope).
**Charter**: empirical god-object identification + per-object decomposition plan + prioritized roadmap. READ-ONLY; no source mutations.

**Methodology** (per CORPUS-MAINTENANCE-STRATEGY §"compile-and-run > grep-and-count"):
- Field counts: `awk` over struct blocks (exact line count, comments + blank lines excluded). Compile-verifiable.
- Method counts: regex `^func \(.*\*?Type\)` over non-test files. Cross-checked against `^func` per-file totals.
- LOC: `wc -l` over non-test files. Test files separated.
- Imports / fan-out: `grep -c '^\s*"'` per file.
- Churn: `git log --since="2026-04-11" --name-only` aggregated.
- Constructor signatures: `grep -E '^func New[A-Z]'` then parameter-count via `awk -F','`.
- Counter-examples: `kc/*_service.go` files known to be the clean Tier-1 decompositions.

**Headline finding**: **`kc.Manager` is the singular dominant god-object** — 63 fields, 47 methods, spread across 17 non-test files totaling 4,104 LOC. The next 3 god-objects (`app.App`, `mcp.plugin.Registry`, `app/wire.go` initializeServices megamethod) are large but each has a coherent escape hatch already partially scaffolded (lifecycle facade, App-scoped registry isolation, init-helper phase splits). Counter-examples like `kc.CredentialService` (7 fields, 22 methods) and `kc.AlertService` (5 fields, 10 methods) confirm the decomposition recipe works — Manager is the last big un-shipped piece.

**Big-picture**: The Path A externalization arc (28 algo2go modules per `go.work`) shows the decomposition pattern works in-vivo. The 5 remaining god-objects below could each shed 30-60% of their LOC into 3-5 cohesive sub-types using the same Tier-1 facade pattern that `BrokerServices`, `StoreRegistry`, `EventingService`, `SchedulingService`, and `SessionLifecycleService` already demonstrate inside Manager itself. These 5 facades are already in the struct (lines 84-88 of `kc/manager_struct.go`) — the decomposition is half-done.

---

## §1 — Inventory methodology + heuristics

### §1.1 What counts as a "god object"

For this audit, a god object scores HIGH on at least 3 of these 5 axes (empirically measured; not subjective):

1. **Field count** ≥ 25 (Effective Go suggests structs over ~15 fields warrant decomposition).
2. **Method count** ≥ 20 (single type carries too many responsibilities).
3. **LOC of the file or split set** ≥ 500 (or ≥ 1000 if split across multiple files for the same type).
4. **Fan-out (imports)** ≥ 15 packages the type pulls in (high coupling = high blast radius).
5. **Churn** ≥ 25 touches in the last 30 days (hot files compound the cost of poor decomposition).

These are not absolute — a Type with 60 fields and ALL of them are config knobs is just a verbose config; it's a god object when those fields encode 3+ DIFFERENT responsibilities (e.g., session state + persistence + scheduling + auth + risk).

### §1.2 What does NOT count

- **Config structs** — verbose by nature; the test is "is mutation observed across distinct subsystems?"
- **DTOs / transport types** — large request/response structs are normal.
- **Type-alias collections** (`kc/manager_interfaces.go` with 16 type aliases) — those are facade exports, not types-with-behavior.
- **Generated code** (none in repo per .gitignore audit).

### §1.3 Counter-example anchor

`kc.CredentialService` (kc/credential_service.go, 263 LOC, 7 fields, 22 methods) — methods are all about credential resolution (per-user lookup + global fallback + caching + invalidation). 7 fields = key store + cred store + token store + logger + config + cache + observer. Single responsibility (credential resolution); LOC is 263 not 4,104. This is the SHIPPING DECOMPOSITION TARGET shape.

`kc.AlertService` (kc/alert_service.go, 88 LOC, 5 fields, 10 methods). Even smaller. Confirms: 5-7 fields + 10-25 methods + 100-300 LOC is the cohesive-type sweet spot.

---

## §2 — Top 10 god objects (table)

Sorted by total god-score = fields + methods + (LOC/100). Each row dated 2026-05-11.

| Rank | Type / File | Fields | Methods | LOC (non-test) | Files | Imports | 30d churn | Verdict |
|---|---|---|---|---|---|---|---|---|
| 1 | **`kc.Manager`** (`kc/manager*.go` set) | **63** | **47** | **4,104** | **17** | 18 in struct.go + 20 in init.go | 46 (kc/manager.go) + 24 (kc/manager_init.go) | **GOD** — dominant offender; 3 distinct responsibility families |
| 2 | **`app/wire.go`** — `App.initializeServices` megamethod | n/a (function) | 1 method 805 LOC | 1,008 | 1 | ~50 (wire pulls everything) | **69 (#1 churn)** | **GOD** — single function builds the entire object graph |
| 3 | **`app.App`** (`app/app.go` + `app/http.go` + others) | **34** | 10 in app.go + **37 in http.go** + scattered | 825 + 1,596 + ~600 in lifecycle.go etc. = **3,000+** | ~10 | ~30 | 46 (app.go) + 42 (http.go) | **GOD** — composition root + HTTP server + lifecycle bundled |
| 4 | **`mcp.plugin.Registry`** (`mcp/plugin/plugin_registry.go`) | **26** | **39** | **693** | 1 | ~10 | (not in top-30 churn) | **GOD** — plugins + hooks + widgets + tools + events all in one |
| 5 | **`app/adapters.go`** — 21+ adapter types | mixed (per-type 1-5 each) | **36** | **884** | 1 | ~20 | 34 | **GOD-FILE** — 21+ adapter types collected; bus-of-adapters pattern |
| 6 | **`mcp/ext_apps.go`** — widget-data extractor zoo | n/a (functions) | **22 functions** (per-widget data extractors) | **998** | 1 | ~20 | 30 | **GOD-FILE** — every new widget grows this file; no decomposition pattern |
| 7 | **`kc/manager_commands_admin.go`** | n/a (Manager methods) | **8 Manager methods + 14 adapter funcs** | **788** | 1 | 14 | (in Manager 30d churn umbrella) | **GOD-FILE** — 5 distinct admin-command families packed in one file |
| 8 | **`kc.Config`** (`kc/config.go`) | **17** | 0 (config struct) | 78 | 1 | 8 | (low) | NEAR-GOD — 17 fields with optional/required mix; cf. App.Config (27 fields, app/app.go:335) |
| 9 | **`app.Config`** (`app/app.go`) | **27** | 0 (config struct) | 70+ inside app.go | 1 | 0 | (in app.go 46-churn umbrella) | NEAR-GOD — knob explosion; opt-in env-driven fields |
| 10 | **`kc/manager_init.go`** — phase init zoo | n/a (Manager methods) | **16 phase-init methods** | **538** | 1 | 20 | 24 | **GOD-METHOD-CLUSTER** — 16 ordered init phases; structurally a fixed sequence |

**Stats**:
- Manager + Manager-spilled (lines 1, 7, 10): 4,104 + 788 (already counted in 1's LOC) + 538 (already counted) → **dominant scope**.
- App + App-spilled (lines 2, 3): wire.go's `initializeServices` is THE construction site that materializes Manager's 63 fields; ergo wire.go is the inverse-side of the same god-problem.
- Registry + ext_apps + adapters (lines 4, 5, 6): the **mcp/** layer has its own 3-god triad — plugins-aggregation, app-data-extractors, adapter-bus.

---

## §3 — Per-object decomposition plan (top 3 deep dive)

### §3.1 `kc.Manager` (rank 1) — the canonical decomposition

**Current empirical state** (verified at HEAD `07c830c`):
- Struct in `kc/manager_struct.go` declares 63 fields. The first 5 are the legacy Kite credentials + logger + metrics. Fields 6-12 are **already-extracted service facades** (`CredentialSvc`, `SessionSvc`, `managedSessionSvc`, `PortfolioSvc`, `OrderSvc`, `AlertSvc`, `FamilyService` — comment "Focused service objects (Clean Architecture)"). Fields 13-17 are **further-extracted Tier-1 facades** (`stores`, `eventing`, `brokers`, `scheduling`, `sessionLifecycle` — comment "Decomposed facades over the raw fields below (Task 7 — Manager decomposition)"). Fields 18-50 are the RAW fields those facades wrap. Fields 51-63 are use-case write-side hoists (Wave D Phase 1).
- 47 methods spread across 17 non-test files. Method-name dump shows 3 distinct families:
  - **16 init phase methods** (`initAlertSystem`, `initPersistence`, `initCredentialWiring`, `initTelegramNotifier`, `initAlertEvaluator`, `initTrailingStop`, `initSideStores`, `initCredentialService`, `initTickerService`, `initFocusedServices`, `initSessionPersistence`, `initTokenRotation`, `initInjectedStores`, `initOrderUseCases`, `initProjector`, `initializeTemplates`, `initializeSessionSigner`) — ALL live in `manager_init.go` + a few in `manager.go`/`manager_lifecycle.go`.
  - **10 CQRS register methods** (`registerAdminCommands`, `registerAccountCommands`, `registerOrderCommands`, `registerExitCommands`, `registerSetupCommands`, `registerOAuthBridgeCommands`, `registerCQRSHandlers`, `registerEscapeQueries`, `registerRemainingQueries`, `registerAlertCommands`, `registerMFCommands`, `registerTickerCommands`, `registerNativeAlertCommands`, `registerAdminUserCommands`, `registerAdminRiskCommands`) — live in `manager_commands_*.go` files.
  - **~11 accessor methods** (`CommandBus`, `QueryBus`, `SessionManager`, `ManagedSessionSvc`, `SessionSigner`, `MCPServer`, `GetBrokerForEmail`, `HasBrokerFactory`, `SetFamilyService`, `SetMCPServer`, `UpdateSessionSignerExpiry`) — live in `manager_accessors.go`. Trivial getters/setters.
  - Plus: `Shutdown`, `widgetAuditStoreFromCtxOrManager`, `projectionOrdersForEmail`, `resolveNativeAlertClient`. Total = 47.

**3-5 sub-types it could split into**:

1. **`ManagerCore`** (15-20 fields): credentials + logger + metrics + templates + the 5 Tier-1 facades + use-case hoists. ~30 LOC struct. This is what callers should hold.
2. **`ManagerInit`** (separate type or package-private orchestrator): owns the 16 init phases. NewWithOptions becomes `ManagerInit.Run(opts) → *ManagerCore`. Phase ordering stays load-bearing. ~538 LOC moves out cleanly (it's already in `manager_init.go`).
3. **`ManagerCQRSWiring`** (separate type or package-private): owns the 10 register* methods. Lives in `kc/cqrs/` sub-package (or just `kc/manager_cqrs.go` with proper boundary). ~1,400 LOC moves (manager_commands_admin.go + manager_commands_oauth.go + 6 others).
4. **`ManagerAccessors`** could fold into `ManagerCore` directly OR move to a `kc/manager_facade.go` — the 11 accessors are trivial passthroughs to the facades; many become unnecessary once callers go through facades directly.
5. **`StoreRegistry`, `EventingService`, `BrokerServices`, `SchedulingService`, `SessionLifecycleService`** (the 5 Tier-1 facades already in fields 13-17): these are ALREADY EXTRACTED. The job is to push consumers from `m.field` to `m.facade.field`, then drop the raw fields. This is the "drain the raw-field block" work.

**Mutual-state constraints** (what stays together):
- `apiKey + apiSecret + accessToken` are kite-auth-identity; stay together. Already migrating to `kc/identity` per `.research/` archive.
- `Logger + metrics` are universal; on every type.
- The 16 init phases have a load-bearing order documented in `kc/manager.go:53-86` and the manager_init.go header. Reordering = breakage. Refactor must preserve sequence.
- `mcpServer any` field is stored as `any` to avoid circular import. That's a smell — pushing the MCPServer setter into a dedicated `mcp/wire` package would let it be typed.
- `commandBus + queryBus` (CQRS) are wired LATE (after wire.go calls SetCommandBus). The register* methods cannot run until the bus is set. Decomposition must preserve this two-phase wiring.

**Migration order** (recommended):
1. **First pass (low-risk)**: drain the 11 accessor methods — push every caller from `m.X()` to `m.facade.X()` for the facades that already exist. ~40-60 call sites. No behavior change. Closes ~50 LOC of accessor.go and lets us drop a layer.
2. **Second pass**: extract `ManagerInit` — move the 16 init methods into a `kc/init/` package or rename `manager_init.go` to a non-method-receiver pattern (`func InitAlertSystem(m *Manager, cfg Config) error` instead of `func (m *Manager) initAlertSystem(cfg Config)`). This makes the init phases testable in isolation and is a pure refactor.
3. **Third pass**: extract `ManagerCQRSWiring` — move the 10 register* methods to a new `kc/cqrs/wiring.go` package. Tests move with them. This is the big LOC win (~1,400 LOC moves out of `manager_commands_*.go` files).
4. **Fourth pass (ambitious)**: replace the 33 RAW fields with delegation to the 5 Tier-1 facades. Drop the raw fields. Manager struct shrinks from 63 fields to ~15.
5. **Fifth pass**: if all the above ships, the 47-method count drops to ~15-20 (init + accessors collapse; CQRS-wiring moves). At that point Manager is the "Kite session orchestrator" — a coherent single-responsibility type.

**Agent-hour estimate**: 3 agent-shifts (~12-15h total). Each pass commits independently. Risk: low (each pass is provably behavior-preserving via existing test suite of 7,000+ tests).

### §3.2 `app.App` (rank 3) + `app/wire.go.initializeServices` (rank 2) — the same problem inverted

**Why combined**: `App` is the runtime-state god-object; `initializeServices` is the construction-time god-function that builds App + Manager + everything in between. Decomposing one without the other = half-done.

**Current empirical state**:
- `App` struct: 34 fields (`app/app.go:35-156`). Top-level: Config + DevMode + Version + startTime + kcManager + oauthHandler + 3 templates + logger + metrics. Then: lifecycle + logBuffer + rateLimiters + auditStore + consentStore + scheduler + telegramBot + riskGuard + riskLimitsLoaded + shutdownCh + hashPublisherCancel + paperMonitor + invitationCleanupCancel + rateLimitReloadStop + rateLimitReloadStopOnce + rateLimitReloadDone + gracefulShutdownDone + shutdownOnce + preboundListener + outboxPump + fillWatcher + alertDB + registry.
- `App` methods: 10 in `app.go` (lifecycle + config) + **37 in `app/http.go`** (the HTTP server) + scattered in `app/lifecycle.go`, `app/legal.go`, `app/ratelimit.go`, `app/recovery.go`, `app/tls.go`, etc. Real total likely ~80 methods.
- `App.initializeServices` (in `app/wire.go:41-845`): a single 805-LOC method that builds every store, every adapter, every middleware, every wiring point. Returns `(*kc.Manager, *server.MCPServer, error)`. Currently 1 method, 805 LOC, 50+ direct dependencies imported.

**3-5 sub-types it could split into**:

1. **`AppCore`** (10-15 fields): Config + Version + startTime + logger + metrics + kcManager + oauthHandler + templates + registry. The "what app *is*" data.
2. **`AppLifecycle`** (already partially exists as `LifecycleManager`): owns the 8 shutdown-coordination fields (shutdownCh, hashPublisherCancel, invitationCleanupCancel, rateLimitReloadStop, rateLimitReloadStopOnce, rateLimitReloadDone, gracefulShutdownDone, shutdownOnce). The `lifecycle *LifecycleManager` field on App already exists — needs to absorb the loose fields.
3. **`AppHTTP`** (new — would own the 37 methods in `app/http.go`): healthz handler, status page, legal pages, SSE setup, StreamableHTTP setup, mux setup, server creation. ~1,600 LOC moves out. App holds an `AppHTTP` and delegates.
4. **`AppBackgroundServices`** (new): scheduler + telegramBot + paperMonitor + outboxPump + fillWatcher + invitationCleanup. The "background workers running because this App is up" set.
5. **`AppConfig.initializeServices` → `app/wire/` package**: split the 805-LOC megamethod into named phase-helpers (similar to `kc/manager_init.go`'s 16 phases). Each phase becomes a `func wirePhaseX(cfg Config) (PhaseXOutput, error)`. Phases compose via explicit data-flow, not implicit mutation. ~10-15 phase functions × ~50-80 LOC each.

**Mutual-state constraints**:
- All `*Once` fields (`shutdownOnce`, `rateLimitReloadStopOnce`) MUST stay with the channels they guard.
- The `preboundListener net.Listener` is a test-only seam (per the field comment); cannot be removed; keep on AppCore.
- `Config *Config` is consumed by initializeServices and never again — it could become a one-shot input to `wire.Build(cfg) → *App` and not be a field at all.
- `registry *mcp.Registry` is App-scoped (B77 isolation per its comment) — must stay on App, not in mcp package globals.

**Migration order**:
1. Move all `*shutdown*`, `*Cancel`, `*ReloadStop*` fields into `LifecycleManager`. App holds `*LifecycleManager`. App.TriggerShutdown delegates. ~15 fields → 1 field.
2. Extract `app/http/` package containing the current `app/http.go` 37-method surface. App holds an `*HTTPServer` and `app.RunServer` delegates. ~1,600 LOC moves out.
3. Decompose `initializeServices` into 10-15 phase functions in `app/wire/phases/`. Each takes typed inputs, returns typed outputs. Phase orchestrator becomes ~50 LOC.
4. Move `outboxPump + fillWatcher + paperMonitor + scheduler + telegramBot` into `AppBackgroundServices`. Lifecycle delegates to it.

**Agent-hour estimate**: 4 agent-shifts (~16-20h). Steps 1 + 3 are pure refactors; step 2 (app/http extraction) needs care because http.go has implicit cross-talk with healthz buildDeepHealthzReport which reads from MANY App fields.

### §3.3 `mcp.plugin.Registry` (rank 4)

**Current empirical state** (`mcp/plugin/plugin_registry.go`, 693 LOC, 26 fields, 39 methods):
- Owns: plugin registrations, hook registrations, widget registrations, tool registrations, event subscriptions. All 5 concerns in one type.
- The B77 isolation work (per `.research/`) gave each `App` its own Registry — that work is done. The remaining decomposition is INTRA-Registry: split the 5 concerns into 5 sub-registries.

**3-5 sub-types it could split into**:

1. **`PluginRegistry`**: plugin lifecycle (add/remove/list/lookup).
2. **`HookRegistry`**: before/after tool-execution hooks.
3. **`WidgetRegistry`**: widget registrations (the 4 widget tools).
4. **`ToolRegistry`** (or merge with `PluginRegistry`): per-App MCP tool surface.
5. **`EventSubscriptionRegistry`**: domain-event subscribers.

`Registry` struct becomes a composition of these 5 — 5 fields instead of 26.

**Mutual-state constraints**:
- All 5 are App-scoped (B77). Stay together at the App-instance level even if split into sub-types.
- Some tool-registrations trigger hook-registrations (e.g., admin tools auto-register an audit hook). Decomposition must preserve cross-registry signals.

**Migration order**:
1. Extract `HookRegistry` first (cleanest boundary; well-understood interface).
2. Extract `WidgetRegistry` (4 widgets; very contained).
3. Extract `EventSubscriptionRegistry`.
4. PluginRegistry + ToolRegistry can stay merged (they're symbiotic).

**Agent-hour estimate**: 2 agent-shifts (~8h). The 4 sub-registries are individually small.

---

## §4 — Cross-cutting god patterns

### §4.1 "Manager" pattern overuse

Empirical grep over types ending in `Manager`:

| Manager | Location | Fields | Methods | Verdict |
|---|---|---|---|---|
| `kc.Manager` | kc/manager_struct.go | 63 | 47 | GOD (this audit's #1) |
| `metrics.Manager` | app/metrics/ | (separate, small) | n/a | Fine |
| `instruments.Manager` | algo2go/instruments | external module | n/a | Fine (external) |
| `LifecycleManager` | app/lifecycle.go | (small) | n/a | Fine |
| `tgbot.BotHandler` (not named Manager but acts like one) | external | n/a | n/a | Fine |
| `papertrading.PaperEngine` | external | n/a | n/a | Fine |

**Conclusion**: only ONE actual god-Manager. The pattern is not over-used; the name `Manager` is mostly attached to small focused types. The `kc.Manager` is the outlier.

### §4.2 Configuration explosion

Two large Config structs:
- `kc.Config` — **17 fields** (kc/config.go:21). Half are optional (logger, instruments override, signer override, store overrides). Decomposition target: split into `kc.RequiredConfig` (5 fields) + `kc.OptionalConfig` (12 fields with explicit defaults). Already-functional-options pattern (`kc/options.go`) hides this — direct struct usage is the legacy path.
- `app.Config` — **27 fields** (app/app.go:335). Env-driven knobs (KiteAPIKey, OAuthJWTSecret, ExternalURL, AdminEmails, RiskguardPluginDir, etc.). Could decompose into `app.AuthConfig`, `app.NetworkConfig`, `app.FeatureFlags` but this is mostly cosmetic — it's a flat config struct that mirrors a flat env-var surface.

**Conclusion**: knob-explosion is real but low-leverage to fix. Each Config field IS a documented env-var contract; splitting risks cosmetic-only churn.

### §4.3 Registry pattern (multiple registries)

Inventory:
- `mcp.plugin.Registry` (this audit's #4).
- `kc.SessionRegistry` (kc/session.go, 647 LOC) — per-MCP-session map. Single concern; not god.
- `algo2go/kite-mcp-registry.Store` — pre-registered Kite app credentials. External; not in scope.
- `users.Store` — registered users. Decomposed already.

**Could unify?** No — these are 4 DIFFERENT registries: plugins (MCP tools/hooks), sessions (MCP runtime state), Kite-app-creds (auth), users (RBAC). Different domains. Unification would be re-coupling. Keep separate.

### §4.4 Middleware chain

`mcp/middleware/` package (84 + 233 + 178 + 37 LOC across `middleware_chain.go`, `middleware_dsl.go`, `ratelimit_middleware.go`, `timeout_middleware.go`):
- 10 middleware in chain order (per `.claude/CLAUDE.md`): X-Request-ID, Timeout, Audit, Hooks, CircuitBreaker, RiskGuard, RateLimit, Billing, PaperTrading, DashboardURL.
- Each is COMPOSABLE — middleware_chain.go owns ordering; individual middleware types are 30-300 LOC each. This is a **counter-example of GOOD decomposition** — see `mcp/middleware/middleware_dsl.go` for the composer DSL.

**Conclusion**: no god here. The middleware chain is the model of how the rest of the codebase SHOULD look.

### §4.5 Long parameter lists (god-constructor signal)

Empirical max-params survey:
- `NewManager(apiKey, apiSecret string, logger *slog.Logger)` — 4 params (deprecated, kept as test shim).
- `NewWithOptions(ctx context.Context, opts ...Option)` — 3 params with variadic options (CORRECT pattern).
- Every other `NewX` constructor in `kc/` takes 1-3 params. Most use functional-options (Config-arg pattern).

**Conclusion**: no long-parameter-list problem. The functional-options + Config-arg discipline is well-applied. The legacy `NewManager` 4-param shim is documented and on a removal path.

### §4.6 Adapter-zoo pattern (`app/adapters.go`)

`app/adapters.go` (884 LOC) contains 21+ `xAdapter` types each ~10-50 LOC. These adapt one port interface to another. Examples: `briefingTokenAdapter`, `briefingCredAdapter`, `paperLTPAdapter`, `riskguardLTPAdapter`, `instrumentsFreezeAdapter`, `signerAdapter`, `kiteExchangerAdapter`.

This is a GOD-FILE more than a god-OBJECT — each individual adapter is small + cohesive; collecting them all in one file makes the file a 884-LOC mailbox of unrelated adapters. Recommendation: split by domain — `app/adapters/briefing.go`, `app/adapters/paper.go`, `app/adapters/riskguard.go`, etc. ~10 small files instead of 1 big one. Zero behavior change; pure file move.

### §4.7 Widget-data extractor zoo (`mcp/ext_apps.go`)

`mcp/ext_apps.go` (998 LOC) contains 14 `XData` functions (portfolioData, activityData, ordersData, alertsData, paperData, safetyData, orderFormData, watchlistData, hubData, optionsChainData, chartData, setupData, credentialsData). Plus `RegisterAppResources` (130 LOC), capability detection, URL stripping, data injection helpers.

Same pattern as adapters.go: each `XData` function is small + cohesive; collecting them all is the problem. Recommendation: split into `mcp/widgets/data/portfolio.go`, `mcp/widgets/data/activity.go`, etc.

---

## §5 — Prioritized 10-step decomposition roadmap

Order = leverage (LOC moved / agent-hours). All steps are pure refactors with provable behavior preservation via existing tests.

| Step | Action | Estimated LOC moved | Agent hours | Risk | Owner-pattern |
|---|---|---|---|---|---|
| 1 | **Drain Manager accessors** — push 40-60 call sites from `m.X()` to `m.facade.X()` for the 5 already-extracted Tier-1 facades | ~120 LOC of accessor methods become obsolete | 3-4 | LOW | parallel-safe (different call sites) |
| 2 | **Split `app/adapters.go`** into per-domain files (`app/adapters/briefing.go`, etc.) — pure file move | 884 LOC redistributes; 0 behavior change | 1-2 | LOW | single-PR, single-commit |
| 3 | **Split `mcp/ext_apps.go`** into per-widget data files (`mcp/widgets/data/portfolio.go`, etc.) — pure file move | 998 LOC redistributes | 1-2 | LOW | single-PR |
| 4 | **Extract `ManagerInit`** — move 16 init phases to package-level funcs in `kc/init/` (test in isolation) | 538 LOC moves; init.go shrinks | 4-6 | LOW-MED (must preserve phase order) | sequential |
| 5 | **Extract `ManagerCQRSWiring`** — move 10 register* methods to `kc/cqrs/wiring.go` (or per-domain) | 1,400+ LOC moves out of `manager_commands_*.go` | 8-12 | MED (bus wiring is two-phase) | sequential |
| 6 | **Decompose `App.initializeServices`** — 805-LOC megamethod into 10-15 phase functions in `app/wire/phases/` | 805 LOC restructures (not deleted) | 6-10 | MED (data-flow contracts) | sequential |
| 7 | **Extract `app/http/` package** — 1,596 LOC moves from `app/http.go` to per-concern files in `app/http/` | 1,596 LOC redistributes; App struct loses HTTP concerns | 8-12 | MED-HIGH (App-method receivers cross-package) | sequential |
| 8 | **Drain Manager raw fields** — replace 33 raw fields with delegation to 5 Tier-1 facades | Manager struct shrinks from 63 → ~15 fields | 8-12 | MED (all callers must use facades) | gradual |
| 9 | **Split `mcp.plugin.Registry`** into 4 sub-registries (Hook, Widget, EventSubscription, Plugin+Tool) | 693 LOC restructures | 4-6 | LOW-MED | sequential |
| 10 | **Consolidate App shutdown-coordination fields** into `LifecycleManager` (15+ fields → 1 field on App) | App struct shrinks from 34 → ~20 fields | 3-4 | LOW | sequential |

**Total estimated**: 47-71 agent-hours across 10 steps. Recommended sequencing:

**Phase 1 (this sprint, ~10h)**: steps 1, 2, 3, 10. All LOW risk, parallel-safe, mostly file moves. ~3,000 LOC redistributed; 0 behavior change.

**Phase 2 (next sprint, ~15h)**: steps 4, 9. Manager init extracted + Registry split. Foundation for the bigger moves.

**Phase 3 (sprint 3-4, ~25h)**: steps 5, 6, 7. The big LOC moves. ~3,800 LOC restructured.

**Phase 4 (sprint 5, ~10h)**: step 8. Drain Manager raw fields once facades are the only access path.

---

## §6 — Validation strategy

For each decomposition pass, the validation gate is:

1. **`go build ./...`** must pass at every commit. No commit that breaks compile.
2. **`go test ./... -count=1 -race`** must pass at every commit. Existing test suite (7,000+ tests per project CLAUDE.md) is the regression baseline.
3. **`/healthz total_available`** must report the same tool count before + after (currently 111). Compile-and-run, not grep.
4. **Pre-deploy gates** (WSL2 `go build` + `go test ./mcp/` + `go vet`) must pass before any commit lands.
5. **Single-PR pattern** per step — each step's commit set must be reviewable in isolation; no cross-step refactors in a single PR.
6. **Coverage maintenance** — new test-files-per-extracted-package must inherit the parent's coverage levels. If `kc/manager_init.go` had X% coverage, `kc/init/` aggregate must be ≥ X%.
7. **`mcp/integrity.go` tool-hash manifest** must stay green — refactor must not change tool descriptions.

**Provable-behavior-preservation**: every step is a SYMBOL-rename + FILE-move at minimum, never a semantic change. The existing 7,000-test suite gives high confidence.

**Rollback strategy**: each step is one commit. `git revert <SHA>` undoes any single step cleanly.

---

## §7 — Counter-examples (things that LOOK like god objects but aren't)

These were flagged by raw-LOC or method-count heuristics but resolved as NON-god on closer inspection:

### §7.1 `kc.SessionRegistry` (647 LOC, kc/session.go)

Looks big. Empirically: single responsibility (MCP-session-ID → session-state map + lifecycle hooks). Methods are all session-lookup/registration/cleanup. **NOT god** — it's a single concern with mature implementation. Decomposition would create artificial seams.

### §7.2 `kc.SessionService` (566 LOC, kc/session_service.go)

Sibling of SessionRegistry. Manages Kite session state + token refresh. Single concern. **NOT god**.

### §7.3 `kc.Manager.manager_interfaces.go` (266 LOC) + `kc.interfaces.go` (526 LOC)

Type-alias collections. Re-exports for backward compatibility per the `kc.AlertStoreInterface = alerts.AlertStoreInterface` pattern. **NOT god** — facade exports, no behavior.

### §7.4 `mcp/middleware/middleware_dsl.go` (233 LOC) + middleware_chain.go (84 LOC)

The middleware composer DSL. Single-purpose. **NOT god** — actually the BEST decomposition pattern in the codebase; cite as positive example.

### §7.5 `app/wire.go` adapter section (lines 37-280)

Tempting to lump with adapters.go. But: wire.go's adapter section is the COMPOSITION ROOT — adapters constructed in `initializeServices`, then handed to subsystems. Moving them risks circularity. Keep adjacent to where they're consumed.

### §7.6 `kc/options.go` (290 LOC)

23 With* functions. Looks like a god of options. Empirically: each With* is 5-15 LOC, single responsibility (set one Config field). Total LOC is high but density is low. **NOT god** — it's the disciplined option-builder pattern.

### §7.7 `kc/credential_service.go` (263 LOC, 22 methods)

7 fields, 22 methods on a single Service. By raw method count it scores. Empirically: all 22 methods are about credential resolution (lookup-by-email, fallback to global, encrypt/decrypt, observe-mutations, invalidate-tokens-on-cred-change). Single concern, mature implementation. **NOT god** — this is the SHIPPING-DECOMPOSITION-TARGET (cited in §1.3).

### §7.8 `kc/fill_watcher.go` (381 LOC)

Background goroutine that polls broker.GetOrderHistory and dispatches OrderFilledEvent. Single concern. **NOT god**.

---

## §8 — Cross-checks against ongoing work

**Cross-check with Path A externalization** (28 algo2go modules per `go.work`):
- Path A.1-A.28 already externalized: broker, money, decorators, i18n, legaldocs, isttz, scheduler, logger, templates, aop, domain, alerts, users, oauth, billing, watchlist, instruments, registry, ticker, cqrs, eventsourcing, audit, riskguard, usecases, papertrading, telegram, sectors, clockport.
- These are SUB-MODULES of Manager's territory that have promoted out. Manager STILL references all 14 in `manager_struct.go` imports — externalization didn't eliminate Manager's coupling; it just moved the implementations.
- **Implication**: Path A solved the algo2go-side decomposition; this audit's roadmap solves the kc/manager-side decomposition (consumer-side). Both efforts are complementary — Path A's modules ARE the targets the Manager fields point to.

**Cross-check with the maintenance-strategy / Track-C work** (`.research/track-c-decisions-2026-05-11.md` + `.research/maintenance-strategy/`):
- That work focused on DOCS — verifying STATE.md is fresh, archiving resolved runbooks, surfacing secrets.
- This audit focuses on SOURCE CODE — same value-framework analogues apply: each god-object's content is re-derivable (compile-verifiable behavior) but currently lives in a non-cohesive container.
- **No conflict**.

**Cross-check with §11 INDEX.md (MCP ecosystem stream)**:
- MCP-ecosystem stream covers the protocol/registry/widget side; this audit covers the Go-type-layout side. Different layers; no overlap.

---

## §9 — Time accounting

| Phase | Time |
|---|---|
| Inventory candidates + LOC + method counts (empirical scan) | ~25 min |
| Manager struct field-count + method-name dump + cross-file aggregation | ~20 min |
| App + http + wire + Registry + ext_apps + adapters probes | ~20 min |
| Counter-example validation (CredentialService, AlertService, middleware) | ~10 min |
| Churn + fan-out + constructor-param-list surveys | ~10 min |
| Synthesis + ranking + roadmap | ~30 min |
| Write doc | ~40 min |
| Total | **~2h 35min** |

Target: 3-5h. Halt at 7h. **Under budget.**

---

## §10 — Big-picture takeaway

The codebase has ONE dominant god-object (`kc.Manager` — 63 fields, 47 methods, 4,104 LOC across 17 files) plus FOUR significant subordinate god-files/methods (`app/wire.go.initializeServices`, `app.App` runtime god, `mcp.plugin.Registry`, `app/adapters.go`+`mcp/ext_apps.go` zoo-files).

**Decomposition is half-done already**: the 5 Tier-1 facades (`stores`, `eventing`, `brokers`, `scheduling`, `sessionLifecycle`) are extracted into separate types living AS FIELDS on Manager. Step 8 of the roadmap is "use them and drop the raw fields" — a finishing move, not a green-field design.

**Counter-example anchors**: `kc.CredentialService` (7 fields, 22 methods, 263 LOC) and `mcp/middleware/middleware_dsl.go` (composable middleware) prove the cohesive-type pattern works in this codebase. The roadmap converges every god-object onto that shape.

**Sequencing**: Phase 1 (~10h, low-risk file moves redistributing ~3,000 LOC) is the highest-leverage starting point. Phase 4 (drain Manager raw fields) is the capstone — possible only after the prior phases land.

**Total estimated effort**: 47-71 agent-hours over 5 sprints. ~30% of effort goes to Manager decomposition (steps 1, 4, 5, 8); ~30% to App + wire decomposition (steps 6, 7, 10); ~20% to file-zoo splits (steps 2, 3); ~20% to Registry split (step 9).

**Validation gate**: existing 7,000-test suite + `/healthz total_available=111` + WSL2 pre-deploy gates. Every step provably behavior-preserving.

---

**End of inventory.**
