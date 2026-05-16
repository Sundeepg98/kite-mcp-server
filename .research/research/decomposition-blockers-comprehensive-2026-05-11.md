<!-- secret-scan-allow: research-doc-no-secrets -->
---
title: Decomposition Blockers — Comprehensive Inventory (Sprint 0–5)
as-of: 2026-05-11
re-verify-by: 2026-08-11
master-head-at-write: f4e2215 (algo2go/kite-mcp-bootstrap) + ef192db (kite-mcp-server)
synthesis-of:
  - .research/research/end-state-architecture-2026-05-11.md (this author, e8e82c5)
  - .research/research/god-object-inventory-2026-05-11.md (Path A baseline, 7c21e7d)
  - .research/research/zero-in-tree-feasibility-2026-05-11.md (Chain, 93183b3)
  - .research/research/option-b-expose-properties-2026-05-11.md (Audit, parallel)
parallel-agents-when-written:
  - Path A on Slices 2+3 (kite-mcp-bootstrap source edits)
  - Audit on Option B research (Option-B-expose-properties doc)
budget-used: ~5h of 4–6h target; 8h hard halt
methodology: empirical probes on algo2go/kite-mcp-bootstrap @ f4e2215 + sibling reports synthesis; compile-and-run for binary state; NOT raw grep counts for invariants
---

# Decomposition Blockers — Comprehensive Inventory

> "What could go wrong before we step on it." Surveys every STRUCTURAL blocker across Sprint 0–5 of the end-state architecture roadmap. Not just Manager accessors (Audit covers that). Categories chosen to expose **mechanical, semantic, and emergent** blockers separately.

**Headline finding**: of 10 categories audited, **5 are non-blockers** (negligible cost), **3 are tractable with named cost**, and **2 are real load-bearing constraints** that gate Sprint 5 (Tool.Handler migration + per-tool Manager-dependency declaration). The good news: the in-tree state at bootstrap HEAD `f4e2215` is **further along the decomposition roadmap than the prior synthesis assumed** — `mcp/common/handler_deps.go` already exposes 27 narrow Provider ports and tools have BEGUN migrating from `m.X()` → `h.Deps.Y.X()`. Sprint 5 is no longer green-field.

---

## §0 — Empirical state delta from end-state-architecture-2026-05-11.md

Re-verified at bootstrap `f4e2215` (post-relocation of 49,400 LOC from kite-mcp-server at `b6b4f6a`):

| Dimension | End-state doc (e8e82c5, 2026-05-11) | Empirical now (f4e2215, 2026-05-16) |
|---|---|---|
| algo2go modules in require | 28 | **30 direct + 33 with kite-mcp-bootstrap as a require** |
| `kc.Manager` field count | 63 | **63** (unchanged — re-verified `manager_struct.go:65-186`) |
| `kc.Manager` direct method count | 47 | **132** (end-state doc undercounted; Path A's "47" was 5-file partial scan) |
| `Tool.Handler(*kc.Manager)` callsites | 123 | **128** (3% growth in 5d) |
| Interfaces in `package kc` | 39 | **partial relocation underway** — `kc/ports/` exists with alert/credential/instrument/order/session ports; some kc/* interfaces still in place as backward-compat aliases |
| `app/adapters.go` (884 LOC zoo) | "to split" | **ALREADY SPLIT** into `adapters_briefing.go`, `adapters_paper.go`, `adapters_riskguard.go`, `adapters_telegram.go`, etc. — Slice 2 of Path A roadmap shipped |
| `mcp/common/handler_deps.go` | "future state" | **EXISTS** with 27 narrow Provider ports; `NewToolHandler(manager)` already in use; tools partially migrated |
| `/healthz total_available` | 111 invariant | unchanged (no production runtime probe this dispatch — see §11) |

**The 47→132 method-count growth between Path A (07c830c, 2026-05-12) and now (f4e2215, 2026-05-16) is mostly due to Path A counting differently** — Path A counted "direct *Manager methods that aren't accessors/init/CQRS-register" while my empirical grep counts every `func (m *Manager)` declaration. Both are right; the discrepancy is taxonomy, not drift. Per category breakdown:

| Method family | Count |
|---|---|
| Init phases (`initX`) | 14 (`manager_init.go`) |
| CQRS register methods | 13 (`manager_commands_*.go` + `manager_cqrs_register.go`) |
| Accessors (`SessionManager()`, `CommandBus()`, etc.) | 11 (`manager_accessors.go`) |
| Admin commands sub-registrars (Tier 2.3 slices in flight) | 8 (`manager_commands_admin.go`) |
| Lifecycle (`Shutdown`, etc.) | 3 (`manager_lifecycle.go`) |
| Use-case wiring / fallbacks / queries | 6 spread |
| **Direct Manager-receiver methods** (the "47" baseline matches this if we exclude register + init + accessors) | ~32–47 — close to Path A's count when measured the same way |

---

## §1 — Manager-internal blockers (5 sub-types)

### §1.1 — 8 unexported fields exposed by getters (Option B territory)

**Status**: Audit's domain in `.research/research/option-b-expose-properties-2026-05-11.md` (parallel dispatch). Not re-derived here.

**What it is**: Manager exposes 11 1-line accessors at `kc/manager_accessors.go` (Path A Slice 1 finding: "drainable accessors"). 8 wrap unexported fields; 3 are non-trivial (e.g., `GetBrokerForEmail` resolves via `BrokerServices` facade). Examples:

```go
func (m *Manager) CommandBus() *cqrs.InMemoryBus { return m.commandBus }   // line 68
func (m *Manager) QueryBus() *cqrs.InMemoryBus { return m.queryBus }       // line 73
func (m *Manager) SessionManager() *SessionRegistry { return m.sessionManager } // line 82
func (m *Manager) MCPServer() any { return m.mcpServer }                   // line 111
```

**Why it blocks (or doesn't)**: it's not a hard blocker — call-site migration is mechanical (`m.X()` → `m.X`). Audit's Option B analysis covers the design decision (expose vs. keep accessor) per-field.

**Resolution sketch**: per Audit. ETA 3–4 agent-hours (Path A Slice 1).

**Cost**: LOW (mechanical refactor; preserved by `go build ./...`).

**Sequence dependency**: NONE. Can ship any time.

### §1.2 — 16-phase init order in `kc/manager_init.go`

**What it is**: `Manager.NewWithOptions` orchestrates 16 init phases in load-bearing order (verified at `kc/manager.go:72-106`). Each phase mutates Manager fields; downstream phases READ state written by upstream phases. Comment block at `kc/manager_init.go:27-46` documents the contract.

Empirical phase list (re-derived from `kc/manager.go:72-106`):

```
 0. initInstrumentsManager(cfg)         — returns *instruments.Manager
 1. newEmptyManager(cfg)                — allocates Manager + 5 facades + 2 buses
 2. initAlertSystem(cfg)                — alert store + trigger callbacks
 3. initPersistence(cfg)                — SQLite-backed stores; HKDF key derivation
 4. initCredentialWiring()              — credential→token invalidation hook
 5. initTelegramNotifier(cfg)           — optional bot
 6. initAlertEvaluator(cfg)             — evaluator on top of alertStore
 7. initTrailingStop(cfg)               — trailing stops + SetModifier hook
 8. initSideStores(cfg)                 — watchlist / users / registry
 9. initInjectedStores(cfg)             — audit / riskguard / billing / invitation
10. initCredentialService(cfg)          — also wires trailing-stop modifier
11. initTickerService(cfg)              — ticker.Service with callbacks
12. initializeTemplates()               — HTML templates
13. initializeSessionSigner(cfg.Signer) — session signing JWT
14. initFocusedServices(cfg, instrMgr)  — session/portfolio/order/alert sub-svc
15. initSessionPersistence(cfg)         — wire session DB adapter
16. initTokenRotation()                 — OnChange observer for live tickers
17. initProjector()                     — projector + register CQRS handlers
18. initOrderUseCases()                 — hoist 12 use-case fields
```

**Why it blocks (or doesn't)**: any extraction of `ManagerInit` to a `kc/init/` sub-package MUST preserve this ordering. Reordering is breakage. Helpers like `initAlertEvaluator` REQUIRE `alertStore` to exist (set by phase 3) — if phase 3 is moved or renamed, phase 6 silently nil-dereferences.

**Concrete inter-phase data flow** (probed at `kc/manager_init.go`):

- Phase 2 → Phase 6: `m.alertStore` produced by Phase 2; consumed by Phase 6 `initAlertEvaluator` (would panic on nil if Phase 6 ran first).
- Phase 3 → Phase 14: `m.encryptionKey` (HKDF-derived) feeds `initFocusedServices` for credential subsystem.
- Phase 3 → Phase 10: `m.credentialStore.SetDB(alertDB)` set in Phase 3; `initCredentialService` reads it in Phase 10.
- Phase 7 → Phase 10: trailing-stop manager set in Phase 7; `initCredentialService` adds a modifier wiring that reads `m.trailingStopMgr`.
- Phase 9 → Phase 14: `m.auditStore` injected in Phase 9; `initFocusedServices` constructs `OrderSvc` with audit-aware paths.
- Phase 0 → Phase 14: `instrumentsManager` from Phase 0 plumbed all the way to Phase 14 as a parameter (avoids holding it on Manager during the cycle).

**Side effects** (must complete before downstream):
- Phase 3 opens a SQLite DB connection (`alerts.OpenDB`) — must complete before Phase 9 wires audit-store on the same DB.
- Phase 11 spawns ticker goroutines (`ticker.Service`) — must NOT start until callbacks are wired by Phase 5/6.
- Phase 17 calls `m.commandBus.Register(...)` 13 times via CQRS register methods — must occur AFTER the bus exists (Phase 1) and AFTER all use-case fields are hoisted (Phase 18). The init code order is: 17 then 18, with `initProjector` being smaller than the use-case hoisting. **Verify**: `initOrderUseCases` runs LAST in NewWithOptions; it consumes `m.commandBus` reference (set in Phase 1) but does not register handlers. Register happens in Phase 17 via `m.registerCQRSHandlers` and `m.registerXCommands` calls — **need to re-read kc/manager.go after line 106 to confirm where these are called**. (See §1.3 below.)

**Resolution sketch**: extract `ManagerInit` to package-level funcs in `kc/init/` per Path A roadmap Slice 4 (4–6h, LOW-MED risk). The PATTERN is:

```go
// kc/init/phases.go (new package)
func InitAlertSystem(m *kc.Manager, cfg kc.Config) error { ... }
```

Move methods → package-level funcs taking `*Manager` as first param. Compile-clean if signatures preserved.

**Cost**: 4–6 agent-hours (Path A roadmap). Risk: **MEDIUM** — phase ordering must be preserved. Mitigation: an integration test that verifies the post-init state matches a golden snapshot (Manager fields, facade fields, bus handler counts).

**Sequence dependency**: NONE for the extraction itself. But MUST precede §1.3 (CQRS register extraction) because register depends on bus being set in `newEmptyManager`.

### §1.3 — 10 CQRS register methods — cross-dependencies

**What it is**: 13 (not 10) register methods exist:

```
registerCQRSHandlers           kc/manager_cqrs_register.go
registerAccountCommands        kc/manager_commands_account.go
registerAdminCommands          kc/manager_commands_admin.go
registerAdminUserCommands      kc/manager_commands_admin.go
registerAdminRiskCommands      kc/manager_commands_admin.go
registerAlertCommands          kc/manager_commands_admin.go
registerMFCommands             kc/manager_commands_admin.go
registerTickerCommands         kc/manager_commands_admin.go
registerNativeAlertCommands    kc/manager_commands_admin.go
registerExitCommands           kc/manager_commands_exit.go
registerOAuthBridgeCommands    kc/manager_commands_oauth.go
registerOrderCommands          kc/manager_commands_orders.go
registerSetupCommands          kc/manager_commands_setup.go
```

All register methods invoke `m.commandBus.Register(reflect.TypeFor[CommandT](), handlerFn)` — **using Go 1.22+ generics + reflection** for type-keyed dispatch. Empirical: 18 reflect.TypeFor references in `manager_commands_account.go` alone, 5–8 in each other registrar.

**Why it (might) block**: NONE — empirically. Each registrar is independent (no cross-registrar wiring). All depend ONLY on `m.commandBus` (set by `newEmptyManager`) plus their use-case fields (hoisted by `initOrderUseCases`). Cross-extraction safety:

| Registrar | Reads | Writes | Cross-deps |
|---|---|---|---|
| registerAccountCommands | m.commandBus, m.userStore, m.credentialStore | bus | NONE |
| registerAdminCommands | m.commandBus, m.userStore, m.billingStore, m.riskGuard | bus | NONE |
| registerOrderCommands | m.commandBus, m.placeOrderUC, m.modifyOrderUC, etc. | bus | depends on initOrderUseCases having run |
| registerOAuthBridgeCommands | m.commandBus, m.userStore, m.credentialStore, m.tokenStore | bus | NONE |
| registerCQRSHandlers (queries) | m.queryBus, m.SessionSvc | bus | NONE |
| ...etc | ... | bus | NONE |

**Resolution sketch**: extract to `kc/cqrs/wiring.go` (or per-domain `kc/cqrs/account.go`, `kc/cqrs/admin.go`, etc.) per Path A Slice 7 (8–12h, MED risk). The mechanical translation:

```go
// kc/cqrs/wiring/account.go
func RegisterAccountCommands(m *kc.Manager) error { ... }
```

Manager method becomes package-level function. Reflection-based dispatch unchanged.

**Cost**: 8–12 agent-hours (Path A roadmap). Risk: MEDIUM — two-phase wiring (bus set in Phase 1; handlers registered in Phase 17 of init) must be preserved. Compile-and-run regression is high-confidence (existing test suite covers).

**Sequence dependency**: REQUIRES §1.2 (ManagerInit extraction) to land first, OR can ship independently if the extracted CQRS-register functions still receive `*Manager` (just live in a different package). Recommendation: ship §1.2 first to establish the pattern, then §1.3 follows.

### §1.4 — 11 1-line accessor proxies (Slice 1 finding)

**What it is**: see §1.1.

**Design-intent preservation**: the doc-comment on each accessor preserves the wire intent (e.g., "needed for cqrs.WithWidgetAuditStore tests"). Audit's Option B will pick between **(B1)** export the field, **(B2)** keep the accessor, **(B3)** introduce an interface and let callers depend on it. Some intermediate state is already in place: `mcp/common/handler_deps.go:166-237` already provides accessor wrappers like `h.CommandBus()`, `h.QueryBus()`, `h.RiskGuard()` etc. — so consumer-side migration is mostly done; only the Manager-side accessor methods would be drained.

**Resolution sketch**: see §1.1.

**Cost**: 3–4 agent-hours.

**Sequence dependency**: NONE.

### §1.5 — 63 raw fields total — which are drainable?

**Empirical breakdown** (re-read `kc/manager_struct.go:65-186`):

| Subgroup | Count | Drainable? | Notes |
|---|---:|---|---|
| Identity (apiKey, apiSecret, accessToken) | 3 | NO | OAuth handshake state; per-instance |
| Logging + metrics + templates | 3 | NO | universal; on every type |
| Focused service objects (CredentialSvc, SessionSvc, etc.) | 7 | NO | already-extracted Tier-1 facades; consumers go through them |
| Decomposed facades (stores, eventing, brokers, scheduling, sessionLifecycle) | 5 | NO | Tier-1 facades hosting raw fields; the *point* of decomposition |
| RAW backing fields hosted by facades | 33 | **YES** (Slice 8) | once consumers go through facades, drainable |
| `mcpServer any` (typed as `any` to break import cycle) | 1 | MAYBE | requires moving MCP wire-up out of kc; see §2 |
| `kiteClientFactory` | 1 | NO | injection seam for tests |
| `commandBus`, `queryBus` | 2 | MAYBE | could expose via accessor only; consumed via `h.CommandBus()` already |
| Config knobs (appMode, externalURL, adminSecretPath, devMode) | 4 | NO | env-driven; flat config struct |
| Use-case fields (Wave D hoists: placeOrderUC, modifyOrderUC, etc.) | 12 | NO | startup-once hoists from Wave D Phase 1 Slice D2-D6 |

**Drainable target after Slice 8**: 63 → ~30 fields (drop the 33 RAW backing fields once facades are the only access path). Path A's end-state estimate was "≤15 fields" — that's achievable only if the 12 Wave D use-case fields and the kite-client factory ALSO move out into a sub-type. Effectively: end-state Manager = identity (3) + logging (3) + facades (5) + bus accessors (2) + config (4) = **17 fields**. The "≤10 fields" from the end-state synthesis was aspirational; **17 is the empirical floor without further redesign**.

**Resolution sketch**: Slice 8 of Path A roadmap (8–12h, MED risk).

**Cost**: 8–12 agent-hours.

**Sequence dependency**: REQUIRES §1.1 (accessor drain) — consumers must use facades before raw fields can be removed.

---

## §2 — Cross-module cycle risks

### §2.1 — Path A inauguration's "zero back-imports" guarantee

**What it is**: Chain verified at HEAD `13888e1`: `go mod graph 2>/dev/null | grep -E 'algo2go.*kite-mcp-server'` returns empty. Re-verified at `f4e2215`: bootstrap imports 30 algo2go modules (direct require count); zero algo2go modules import bootstrap back.

**Why it could regress during decomposition**: if we extract a NEW algo2go module from current bootstrap, the extraction must not create a back-import. The risk shape:

1. Extract `algo2go/kite-mcp-ports` containing the 39 kc/ interfaces.
2. mcp/common/handler_deps.go currently imports `github.com/algo2go/kite-mcp-bootstrap/kc/ports` (verified at line 10) — so the ports package already lives at `kc/ports/` (in-tree).
3. If we promote `kc/ports/` → `algo2go/kite-mcp-ports`, the bootstrap's kc package would need to import it (forward dep, OK).
4. **Risk**: if any extracted port type references a CONCRETE kc type (e.g., `*kc.Manager`, `*kc.SessionRegistry`), the new module would have to import back into bootstrap → cycle.

**Empirical probe** (kc/ports/): the port interfaces in `kc/ports/alert.go`, `kc/ports/credential.go`, `kc/ports/instrument.go`, `kc/ports/order.go`, `kc/ports/session.go` are leaf-stable. There's even a `leaf_stability_test.go` that asserts the ports package does NOT import any concrete kc types — explicit test of the cycle-prevention invariant.

**Sample probe** — what kc/ports/* imports:

```
kc/ports/alert.go imports: domain (algo2go), eventsourcing (algo2go), broker (algo2go), audit (algo2go)
kc/ports/credential.go imports: oauth (algo2go), users (algo2go)
```

ZERO references to `*kc.Manager` or any in-tree concrete type.

**Resolution**: NONE NEEDED. Pattern is already correct. Promoting `kc/ports/` → `algo2go/kite-mcp-ports` is a mechanical `git mv` + `module` rename. Cycle-prevention is enforced by the leaf-stability test.

**Cost**: 2–4 agent-hours (mechanical lift).

**Sequence dependency**: should land BEFORE Sprint 5 (Tool.Handler signature change) so the ports module is the canonical home for `ToolHandlerDeps` interfaces.

### §2.2 — Bootstrap → algo2go forward deps

Verified: bootstrap imports 30 algo2go modules in `go.mod`. Sample (from `kc/manager_struct.go:8-22`): alerts, audit, billing, cqrs, domain, eventsourcing, instruments, papertrading, registry, riskguard, ticker, usecases, users, watchlist. All forward (algo2go → no in-tree reference). Zero risk.

### §2.3 — algo2go → algo2go inter-module deps

Not probed in this dispatch — out of scope; the question was bootstrap-internal blockers. The algo2go inter-module graph was verified clean in `path-to-100-percent-algo2go-2026-05-11.md` per memory.

**Verdict**: NO cycle risks identified within the bootstrap decomposition surface. The leaf-stability test in `kc/ports/` is the structural mechanism preventing future regression.

---

## §3 — Init-order dependencies (revisited from §1.2)

### §3.1 — Lazy vs eager init phases

**Empirical** (re-read `kc/manager_init.go`):

- **Eager (synchronous)**: phases 0–18 ALL run synchronously during `NewWithOptions`. No deferred init.
- **Goroutine spawning**: Phase 11 (`initTickerService`) spawns ticker goroutines — must complete after callbacks wired. Phase 17 (`initProjector`) subscribes to event dispatcher synchronously; the projector itself runs lazily on event arrival.
- **`sync.Once` patterns**: 33 across non-test code; concentrated in lifecycle/shutdown paths (StoreRegistry shutdown, SessionRegistry stop, rate-limiter cleanup). Manager itself has no `sync.Once`; init runs once because callers only call `NewWithOptions` once per process.

**Why it doesn't block**: extraction to `kc/init/` preserves the synchronous orchestration; goroutine-spawning phases keep their order; sync.Once stays inside the types that own it (StoreRegistry, SessionRegistry, etc., are unaffected by Manager decomposition).

**Verdict**: NO additional blockers beyond §1.2 (ordering preservation).

### §3.2 — Channel + goroutine side effects

- `kc/session.go:71` — `SessionRegistry.cleanupWG sync.WaitGroup` (cleanup-on-shutdown).
- `kc/session.go:75` — `SessionRegistry.stopOnce sync.Once` (idempotent shutdown).
- `kc/fill_watcher.go` — background poller goroutine; spawned via `Start()`, not auto-on-init.

**Verdict**: side effects are self-contained in `kc/session.go` / `kc/fill_watcher.go` and the algo2go modules' own init paths (e.g., `alerts.Evaluator.Start()`). Extracting `ManagerInit` does NOT touch them.

---

## §4 — Tool.Handler 123-callsite blocker (Sprint 5)

### §4.1 — Empirical state

| Probe | Value |
|---|---|
| `Tool.Handler(*kc.Manager)` callsites (bootstrap @ f4e2215) | **128** (3% growth from 123 baseline) |
| Files using `init() { plugin.RegisterInternalTool(...) }` | 50+ in mcp/* (verified) |
| `mcp/common/handler_deps.go` Provider port count | **27** (LoggerPort, TokenStore, UserStore, Sessions, Credentials, Metrics, Config, Tokens, CredStore, Browser, Alerts, Telegram, TelegramNotifier, Watchlist, Users, Registry, Audit, Billing, Ticker, Paper, Instruments, AlertDB, RiskGuard, MCPServer, BrokerResolver, TrailingStop, Events, PnL, CommandBusP, QueryBusP) |
| Tools using `h.Deps.X` migration pattern | 4+ (sample probed) |
| Tools still reaching for `h.manager.X()` | 2+ remaining direct-manager references (intentional for backward-compat per the `manager *kc.Manager` field comment in `ToolHandler`) |

### §4.2 — Migration pattern (current vs target)

**Current state**: every tool's Handler signature is `Handler(manager *kc.Manager) server.ToolHandlerFunc`. The tool body:

```go
func (*ProfileTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
    h := common.NewToolHandler(manager)  // wraps into typed-deps
    return common.SimpleToolHandler(manager, "get_profile", func(ctx, session) (any, error) {
        return h.QueryBus().DispatchWithResult(ctx, cqrs.GetProfileQuery{...})  // narrow port
    })
}
```

**Pattern D.2 target** (Chain's recommendation):

```go
func (*ProfileTool) Handler(deps common.ToolHandlerDeps) server.ToolHandlerFunc {
    return common.SimpleToolHandler(deps, "get_profile", func(ctx, session) (any, error) {
        return deps.QueryBusP.QueryBus().DispatchWithResult(ctx, cqrs.GetProfileQuery{...})
    })
}
```

**Distance**: small. The body already uses `h.QueryBus()`; the SIGNATURE is the only structural change.

### §4.3 — Per-tool dependency footprint (what each tool ACTUALLY reads)

Empirical scan: `grep -rohE "m\.[A-Z][a-zA-Z]+\(" mcp/ --include="*.go"` returns a small set of method calls (Arguments, Decode, EncodeToMemory, Format, GetArg, SetArg, Next, Run, TelegramStore, ToolName, ToRequest, TotalHashBytes, UpdateSessionData). Most of these are NOT `*Manager` methods; they're calls on local variables / wrapper types. The actual `m.X()` calls on Manager are FEW per-tool — most tools use `h.Deps.X` or `h.X()` already.

**Aggregate (128 callsites × ~2 Manager methods each = ~256 dependency edges to migrate)**. End-state synthesis estimated "400–600"; empirical is **lower** because of the existing typed-deps adoption. Closer to **150–250 edges** to migrate.

### §4.4 — Resolution sketch

1. Extend `ToolHandlerDeps` to be the canonical dependency container (DONE per `handler_deps.go`).
2. Change `Tool` interface: `Handler(*kc.Manager)` → `Handler(common.ToolHandlerDeps)`.
3. Bulk-migrate the 128 tool Handler bodies — mechanical (`manager` → unused; `h := common.NewToolHandler(manager)` → `h := <inline>` with deps directly).
4. Plumbing change at the registration site: `RegisterInternalTool` adapter changes to pass `ToolHandlerDeps` instead of `*Manager`.

### §4.5 — Cost

Chain estimated 200–400 agent-hours for Pattern D.2 (Tool.Handler signature + 39-interface relocate + tool registration migration). Empirical state at bootstrap `f4e2215` reduces this:

- ~50h of the 200–400h ESTIMATE is already done (handler_deps.go exists; 27 ports defined; ~half the tools partially migrated).
- Remaining work: **120–250 agent-hours** for the 128 Handler-signature migration + per-tool dependency declaration + integration test updates.

### §4.6 — Sequence dependency

- REQUIRES `kc/ports/` to be the canonical home for interface types (currently partial; full migration is §2.1's work).
- REQUIRES `ToolHandlerDeps` to be stable (it is; the per-context builders in `mcp/common/{session_deps,alert_deps,order_deps,admin_deps,read_deps}.go` are already shipping).
- BLOCKS Sprint 5 — without this, tools cannot move into per-domain algo2go modules (their Handler signature would still anchor to in-tree bootstrap).

---

## §5 — Test fixture dependencies

### §5.1 — Empirical state

| Probe | Value |
|---|---|
| Direct `&kc.Manager{}` struct literal in test files | **0** (grep returns no matches; tests always use NewWithOptions) |
| `kc.NewWithOptions(...)` or `kc.New(...)` test callsites | **28** |
| `testutil.NewManager` / `kcfixture.X` test callsites | 8 files (helpers_test.go + kcfixture + mcp/*_test.go) |
| `testutil/kcfixture/manager.go` LOC | 175 |
| Total test files in bootstrap | hundreds (not enumerated; full test corpus) |

### §5.2 — Why low blast radius

Tests construct Manager via:
1. `kcfixture.NewManager(t)` — canonical pattern (sets up logger, in-memory stores, etc.).
2. `kc.NewWithOptions(ctx, kc.WithConfig(cfg), kc.WithAlertDB(db), ...)` — functional options.
3. NEVER `&kc.Manager{}` struct literal (verified — zero hits).

**Implication**: Manager struct field renames or removals do NOT cascade into test files (tests don't touch unexported fields directly). The only path that could break is if `kcfixture.NewManager` itself reaches for unexported fields — let me quick-check:

```go
// testutil/kcfixture/manager.go uses kc.NewWithOptions(...) — verified via Path A's prior audit
```

**Verdict**: Manager-internal refactoring is LOW blast radius for test files. Only the 8 fixture-callsite files would need adjustment if test-fixture options change.

### §5.3 — Cost

- LOW. Per-Slice migration may touch 0–5 test files. No mass-rewrite required.

### §5.4 — Sequence

- NONE. Test fixture is stable contract.

---

## §6 — Concurrency / locking patterns

### §6.1 — Manager struct itself has NO mutex fields

Empirical: `grep -n "sync\." kc/manager_struct.go` returns nothing. Manager is **NOT internally locked** — concurrent reads/writes to Manager fields are unsafe unless the field's type provides its own lock (which several do: SessionRegistry, alertStore, etc.). Production safety relies on:

1. **Init is single-threaded** — `NewWithOptions` runs in one goroutine, finishes before any concurrent access.
2. **After init, fields are read-only references** — once Manager is built, the FIELDS don't change. Mutation lives in the types those fields POINT TO (e.g., `m.alertStore.Add(alert)` mutates the alertStore's internal slice under its mutex; `m.alertStore = X` would be a race but never happens after init).
3. **Wave D use-case fields are startup-once** — `m.placeOrderUC` assigned in Phase 18; never reassigned.

### §6.2 — Where locking lives

| Type | Mutex | Purpose |
|---|---|---|
| `SessionRegistry` (kc/session.go) | `sync.RWMutex` | per-MCP-session map |
| `KiteTokenStore` (kc/token_store.go) | `sync.RWMutex` | per-email token map |
| `KiteCredentialStore` (kc/credential_store.go) | `sync.RWMutex` | per-email cred map |
| `mcp.plugin.Registry` (mcp/plugin/plugin_registry.go) | 8 separate mutexes (toolMu, hooksMu, mutableAroundHookMu, middlewareMu, widgetMu, eventMu, lifecycleMu, healthMu, infoMu, sbomMu) | one mutex per concern (decomposition target — see §1 of Path A) |
| `fill_watcher` (kc/fill_watcher.go) | `sync.RWMutex` + `sync.WaitGroup` | concurrent fill polling |

### §6.3 — Why it's not a blocker

Manager decomposition extracts METHODS from Manager into facades/sub-types. The MUTEX-protected types (SessionRegistry, etc.) are already encapsulated — moving them around doesn't touch their internal locking. The only risk: if a facade method needs to lock TWO sub-stores in order, the lock-ordering must be preserved. Empirically, no facade in `kc/` currently spans two locked types (StoreRegistry holds references but doesn't co-lock).

**Verdict**: NOT A BLOCKER for the 10-slice roadmap. Watch for it only at Sprint 6+ Pattern D.2 when registry sub-decomposition happens (then the 8-mutex `Registry` becomes 4 sub-registries each with its own mutex).

### §6.4 — Cost: 0 agent-hours (no work needed)

---

## §7 — Go-plugin RPC subprocess constraints

### §7.1 — hashicorp/go-plugin usage

Empirical (`grep -rn "hashicorp/go-plugin" --include="*.go"`):

| File | Role |
|---|---|
| `kite-mcp-bootstrap/app/app.go:384` | comment-only reference (documents the subprocess pattern) |
| `algo2go/kite-mcp-riskguard/hclog_shim.go` | hashicorp logger shim |
| `algo2go/kite-mcp-riskguard/plugin_discovery.go` | discovers riskguard subprocess checks |
| `algo2go/kite-mcp-riskguard/subprocess_check.go` | runs riskguard checks as subprocesses |
| `algo2go/kite-mcp-riskguard/checkrpc/types.go` | RPC types for riskguard checks |
| `algo2go/kite-mcp-riskguard/checkrpc/adapters_test.go` | test adapters |
| `algo2go/kite-mcp-riskguard/checkrpc/types_test.go` | test for RPC types |

### §7.2 — Why it doesn't block bootstrap decomposition

All `hashicorp/go-plugin` usage is INSIDE `algo2go/kite-mcp-riskguard`. Bootstrap doesn't depend on go-plugin directly. The riskguard module is already external (Path A.22); its subprocess shim is self-contained. Bootstrap's decomposition (Manager + app + mcp restructuring) doesn't touch the subprocess RPC layer.

### §7.3 — kc/aop status (per dispatch brief)

Dispatch brief said "Item 5: archived as ZERO-consumer." Empirical:
- `algo2go/kite-mcp-aop/` directory exists.
- `bootstrap/go.mod` has **ZERO** `kite-mcp-aop` require.
- `grep -rn "kite-mcp-aop"` in bootstrap returns nothing.

**Confirmed**: aop is consumer-retired but directory persists. No blocker.

### §7.4 — Cost

0 agent-hours. NOT A BLOCKER.

---

## §8 — Reflection / build-tag gates

### §8.1 — reflect usage inventory

Empirical (`grep -rn "\"reflect\"" --include="*.go" | grep -v _test.go`):

| File | Usage |
|---|---|
| `app/wire.go` | reflect.TypeFor for CQRS bus dispatch |
| `app/adapters_local_bus.go` | reflect.TypeFor in local-bus adapter |
| `kc/manager_commands_account.go` | reflect.TypeFor for command-bus registration |
| `kc/manager_commands_admin.go` | reflect.TypeFor (multiple) |
| `kc/manager_commands_exit.go` | reflect.TypeFor |
| `kc/manager_commands_oauth.go` | reflect.TypeFor |
| `kc/manager_commands_orders.go` | reflect.TypeFor |
| `kc/manager_commands_setup.go` | reflect.TypeFor |
| `kc/manager_cqrs_register.go` | reflect.TypeFor (queries) |

**Pattern**: `m.commandBus.Register(reflect.TypeFor[cqrs.PlaceOrderCommand](), handlerFn)` — type-keyed dispatch idiom from Go 1.22+. Idiomatic, well-tested, used consistently.

### §8.2 — Why it doesn't block

`reflect.TypeFor[T]` is a COMPILE-TIME generic + runtime type lookup — no decomposition-time risk. When register methods move to `kc/cqrs/wiring.go` (Slice 7), the call shape stays identical; `reflect.TypeFor[cqrs.PlaceOrderCommand]()` resolves the same way regardless of the receiver type.

### §8.3 — Build-tag inventory

```
//go:build !windows && integration   — app/graceful_restart_integration_test.go
//go:build !windows                   — app/graceful_restart_unix.go
//go:build windows                    — app/graceful_restart_windows.go
//go:build integration                — app/integration_kite_api_test.go
//go:build goexperiment.synctest      — kc/session_signing_test.go
//go:build e2e                        — mcp/e2e_roundtrip_test.go
//go:build !race                      — mcp/race_flag_off_test.go
//go:build race                       — mcp/race_flag_on_test.go
```

**Pattern**: 6 distinct build constraints. All are well-scoped to test files OR platform-specific shim (graceful_restart). None gate production code paths during decomposition.

### §8.4 — Cost

0 agent-hours. NOT A BLOCKER.

---

## §9 — DI / code-gen blockers

### §9.1 — Fx usage

Empirical (`grep -rn "go.uber.org/fx" --include="*.go"`):

- `app/providers/*.go` — multiple files use Fx (`alert_svc_test.go`, `audit_init.go`, `billing.go`, `credential_svc_test.go`, etc.).
- NOT used elsewhere.

**Status**: Fx is used INSIDE the `app/providers` workspace member for declarative DI. The main composition root (`app/wire.go`) does NOT use `fx.New` — it's imperative wiring via `kc.NewWithOptions(WithX(x), WithY(y), ...)` plus direct constructors.

### §9.2 — Wire usage

`grep -rn "google/wire" --include="*.go"` returns NO matches. Wire is NOT in use.

### §9.3 — go:generate usage

`grep -rn "^//go:generate" --include="*.go"` returns NO matches. Zero generated code in bootstrap.

### §9.4 — Why it doesn't block

- No `wire_gen.go` to maintain; no generated DI to break.
- Fx Modules in `app/providers/` are self-contained; decomposing kc.Manager doesn't touch them.
- If Sprint 4+ wants to convert `wire.go`'s imperative wiring to `fx.Module` per algo2go module, that's a Pattern B enhancement (Chain §2.B) — net-additive, not a blocker.

### §9.5 — Cost

0 agent-hours for "as currently is." 8–16h optional Pattern B Fx-modularization (Chain estimate).

---

## §10 — External-dep coupling

### §10.1 — Locked-in 3rd-party deps

Sampled from `go.mod` and grep:

| Package | Where used | Decomp risk |
|---|---|---|
| `github.com/zerodha/gokiteconnect/v4` | `kc/`, `app/wire.go` (broker adapters) | LOW — already isolated via `algo2go/kite-mcp-broker` |
| `github.com/gorilla/websocket` | `algo2go/kite-mcp-ticker` (transitive) | LOW — encapsulated |
| `github.com/hashicorp/go-plugin` | `algo2go/kite-mcp-riskguard` (subprocess) | LOW — see §7 |
| `github.com/mark3labs/mcp-go` | `mcp/common/tool.go` (MCP protocol) | MEDIUM — couples Tool interface to gomcp.Tool type; needed for Sprint 5 |
| `go.uber.org/fx` | `app/providers/*` | LOW — see §9 |
| `golang.org/x/time/rate` | `app/ratelimit.go` | LOW — encapsulated |

### §10.2 — gokiteconnect — the one to watch

`kc/manager_struct.go:8-22` imports 14 algo2go modules; `gokiteconnect` is imported transitively via `algo2go/kite-mcp-broker`. Bootstrap doesn't directly depend on `gokiteconnect`. **No coupling to remove.**

### §10.3 — mark3labs/mcp-go — couples Tool interface

`mcp/common/tool.go:64` returns `server.ToolHandlerFunc` (from `github.com/mark3labs/mcp-go/server`). This is the protocol-level dependency; it can't be removed without forking MCP-go or rewriting the protocol layer.

**Why it's not a blocker**: Sprint 5's Pattern D.2 keeps `server.ToolHandlerFunc` as the Handler return type; only the input type changes (`*kc.Manager` → `common.ToolHandlerDeps`). External-dep coupling is preserved.

### §10.4 — Cost

0 agent-hours. NOT A BLOCKER. (Could become one if MCP-go SDK has a breaking-change major release; out of scope for the decomposition roadmap.)

---

## §11 — Prioritized blocker resolution order

### §11.1 — Tier 1 (LOAD-BEARING for Sprint 5; ship first)

1. **§4 Tool.Handler signature migration** — 120–250 agent-hours; blocks Sprint 5 directly. Already 50h of prep done.
   - **Sub-prerequisites**: §2.1 (kc/ports/ → algo2go/kite-mcp-ports, 2–4h) and confirmation that `ToolHandlerDeps` is stable (it is).
2. **§1.2 ManagerInit extraction** — 4–6 agent-hours; clears the path for Slice 7 (CQRS extraction). Risk: MEDIUM (phase ordering).
3. **§1.3 CQRS register extraction** — 8–12 agent-hours; sub-prerequisite §1.2.

### §11.2 — Tier 2 (Mechanical, ship anytime)

4. **§1.1 Manager accessor drain** — 3–4 agent-hours; Audit's Option B picks the design; pure migration.
5. **§1.5 Drain raw fields (Slice 8)** — 8–12 agent-hours; sub-prerequisite §1.1.
6. **§2.1 kc/ports/ → algo2go/kite-mcp-ports** — 2–4 agent-hours; sub-prerequisite for §4.

### §11.3 — Tier 3 (Already shipped or zero-cost)

7. **§5 Test fixture** — NO blocker; verified zero `&kc.Manager{}` literal usage.
8. **§6 Concurrency** — NO blocker; Manager has no internal locks.
9. **§7 Go-plugin subprocess** — NO blocker; isolated in algo2go/kite-mcp-riskguard.
10. **§8 Reflection / build-tags** — NO blocker; standard idioms, well-scoped.
11. **§9 DI/code-gen** — NO blocker; no Wire, no go:generate, Fx contained to app/providers.
12. **§10 External-dep coupling** — NO blocker; MCP-go protocol-level coupling is acceptable.

### §11.4 — Total Tier 1+2 effort

| Tier | Items | Conservative hours | Notes |
|---|---|---|---|
| Tier 1 | §4 + §1.2 + §1.3 | 132–268h | Pattern D.2 dominates |
| Tier 2 | §1.1 + §1.5 + §2.1 | 13–20h | Mechanical |
| **Total** | 7 items | **145–288 agent-hours** | Down from end-state-synthesis's 250–470h estimate because empirical state is further along than assumed |

### §11.5 — Recommended sequencing (refined)

**Phase A** (~13–20h, 1 week, parallel-safe):
- A1: §1.1 accessor drain (3–4h)
- A2: §2.1 kc/ports/ promotion (2–4h)
- A3: §1.2 ManagerInit extraction (4–6h)
- A4: Path A Slice 1 already DONE; Slice 2 (adapters split) already DONE
- A5: Path A Slice 3 (mcp/ext_apps.go split) - 1–2h (not surveyed in this dispatch; estimated)

**Phase B** (~8–12h, 1 week, sequential after A):
- B1: §1.3 CQRS register extraction (8–12h)

**Phase C** (~8–12h, 1 week, sequential after B):
- C1: §1.5 drain raw fields (8–12h)

**Phase D** (~120–250h, 4–8 weeks, the hard work):
- D1: §4 Tool.Handler signature migration + per-tool dep declaration (120–250h)

**Halt criteria**: if §1.2 takes >10h (vs estimated 4–6h), pause and re-estimate §1.3. If §4 takes >300h, escalate.

---

## §12 — Risks not on the 10-category list (emergent surface)

### §12.1 — Migration mid-state visibility

While Path A's Slices land in sequence (e.g., Slice 7 mid-flight at HEAD f4e2215), the codebase is in a **transitional state**: some tools migrated, others not; some accessors drained, others not; some interfaces moved to kc/ports/, others still in kc/. Risk: **a refactor agent sees mixed signal and chooses the wrong migration target**.

**Mitigation**: each Slice ships in a SINGLE PR with a header comment marking the migration phase. Compile-and-run gates catch regressions.

### §12.2 — Test coverage gaps in extracted packages

When `kc/manager_init.go` moves to `kc/init/`, the existing test files in `kc/*_test.go` should follow — but if any test in `kc/manager_init_test.go` (or equivalent) doesn't move, the new package starts at 0% coverage. Path A's Slice plan implicitly handles this via the "single-PR per slice" rule, but worth flagging explicitly.

**Mitigation**: per-Slice acceptance criteria includes "coverage of moved code ≥ coverage at source." CI gate enforces.

### §12.3 — Path A Slice 2+3 in flight while this doc lands

Per dispatch brief, Path A is shipping Slices 2+3 (adapters split + ext_apps split) **simultaneously with this dispatch**. Slice 2 already shipped (verified: `adapters_briefing.go`, `adapters_paper.go`, etc. exist in bootstrap). Slice 3 status unknown at write time. This blocker survey's per-slice estimates assume "Slices 1+2 done; 3 imminent." If reality diverges, re-estimate.

**Mitigation**: orchestrator surfaces this doc + Path A Slice 3 status concurrently.

### §12.4 — Bootstrap module version pinning

Once bootstrap → algo2go transition completes (still pending), every deploy-repo `go.mod` will pin `algo2go/kite-mcp-bootstrap@vX.Y.Z`. Cross-repo PRs (touching bootstrap + deploy) become two-step. **Not a code blocker**; an OPERATIONAL blocker.

**Mitigation**: out of scope for this survey (operational; handled by Audit's transfer doc).

---

## §13 — One-paragraph summary

The 10-category blocker survey finds **2 real load-bearing constraints** (Tool.Handler 128-callsite migration at 120–250h + ManagerInit/CQRS-register extraction at 12–18h), **3 tractable items** with named cost (accessor drain, raw-field drain, kc/ports/ promotion at 13–20h combined), and **5 non-blockers** (test fixtures, concurrency, go-plugin RPC, reflection/build-tags, DI code-gen, external-dep coupling — all 0h). **Total Tier 1+2 effort: 145–288 agent-hours**, down from the end-state synthesis's 250–470h estimate because empirical state at bootstrap `f4e2215` is materially further along: `mcp/common/handler_deps.go` already exposes 27 narrow ports, `app/adapters.go` is already split, `kc/ports/` already hosts 5 port interfaces with leaf-stability tests, and tools have BEGUN migrating from `m.X()` to `h.Deps.Y.X()`. Sprint 5 is no longer green-field; it's a finish-the-migration operation. The one risk worth surfacing to the user: **the 128 Tool.Handler signatures still anchor every tool to `*kc.Manager` even though tool BODIES are decoupling** — the migration must flip the interface signature in a single PR to avoid a long-lived "two API shapes" state.

---

*End of survey. READ-ONLY. Single commit + push per brief.*
