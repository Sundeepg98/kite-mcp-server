# Non-kc/* Decomposition Track — Survey + Halt Findings

Dispatched 2026-05-10 after Path A.26 closed the kc/* externalization arc.

State at survey: master HEAD `c6eea80` = production v252 LIVE (tools=111).
27 algo2go modules external. User dispatched 5 candidates (A-E) with
explicit "halt + surface findings if architectural research required"
rule.

---

## Empirical findings (all 5 candidates)

### Candidate A: testutil — **HALT (architectural research required)**

```
testutil/                — 6 .go files
testutil/kcfixture/      — 2 .go files

testutil/ imports:
  - github.com/zerodha/kite-mcp-server/kc          (production: kc/fill_watcher.go!)
  - github.com/zerodha/kite-mcp-server/testutil    (self ref via kcfixture)
testutil/kcfixture/ imports:
  - github.com/zerodha/kite-mcp-server/kc          (root)
  - github.com/zerodha/kite-mcp-server/testutil    (parent)

Reverse-deps in master: 14 files import testutil
  - 13 tests (mcp/*, kc/*_test.go, app/*_test.go)
  - 1 PRODUCTION file: kc/fill_watcher.go
```

**Architectural blocker**: `kc/fill_watcher.go` uses `testutil.Clock`,
`testutil.Ticker`, `testutil.RealClock{}` in its production struct
fields and method signatures (line 130, 143, 169, 230, 271):

```go
type FillWatcher struct {
    Clock        testutil.Clock // nil => testutil.RealClock{}
    ...
    clock        testutil.Clock
}
func (w *FillWatcher) pollLoop(placed domain.OrderPlacedEvent,
                                ticker testutil.Ticker) { ... }
```

testutil is **misnamed** — it's actually a clock-abstraction module
plus test helpers, glued together. Standard Path A leaf extraction
would publish `algo2go/kite-mcp-testutil` containing
`Clock`/`Ticker`/`RealClock` types, but those names imply test-only
when they're used in production paths.

**3 unblock options**:
1. **Rename + scope-split**: Extract `Clock`/`Ticker`/`RealClock` to a
   new `algo2go/kite-mcp-clockport` module (production-clean name).
   Keep `MockKiteServer` + `Capture/Noop logger` + `kcfixture/` in
   `algo2go/kite-mcp-testutil` (genuinely test-only). 2 modules
   instead of 1.
2. **Interface inversion**: Define `Clock`/`Ticker` as interfaces in
   an existing algo2go module (kite-mcp-domain candidate), have
   testutil provide test fakes, refactor kc/fill_watcher.go to import
   the interface from domain.
3. **Keep testutil in-tree forever**: Accept that testutil is
   orchestrator-side code (its kcfixture sub-package is the strong
   signal — it builds *kc.Manager test instances tied to root).
   Document the decision and move on.

**Recommendation**: Option 3 (keep in-tree) for now. Testutil is
already 14-file/14-reverse-dep workspace member with extensive
narration; the marginal cost of leaving it as workspace member is
much lower than the architectural-surgery cost of options 1 or 2.

---

### Candidate B: plugins/ — **HALT (bidirectional with root)**

```
plugins/                 — 3 sub-packages: example/, rolegate/, telegramnotify/
plugins/example/         — imports kc (parent)
plugins/rolegate/        — imports kc/users + mcp (parent) + oauth
plugins/telegramnotify/  — imports kc/users + mcp (parent) + oauth

Reverse-deps in master: 1 file (app/wire.go imports plugins/rolegate +
                                 plugins/telegramnotify for production
                                 hook registration)
```

**Architectural blocker**: plugins/ imports root (`kc`, `mcp`)
AND root (`app/wire.go`) imports plugins. Same shape as testutil.

The narration in plugins/go.mod admits the bidirectional shape:
"Bidirectional cross-module deps with the root module (same shape
as app/providers)".

This is workspace-member-by-design. Phase B canary deletion would
fail because plugins/rolegate and plugins/telegramnotify need
root to compile, but root needs plugins to compile.

**Unblock options**:
1. **Carve out `mcp.RegisterPlugin` + plugin-discovery hook contract
   to a new algo2go module** (e.g., kite-mcp-pluginhooks). Have
   plugins/rolegate + plugins/telegramnotify import the contract
   module and root mcp/ package separately. This breaks the cycle.
2. **Keep plugins in-tree forever**: documents the orchestrator-side
   scope. plugins/example is documentation-only; plugins/rolegate +
   telegramnotify are first-party production hooks that ship with
   the orchestrator.

**Recommendation**: Option 2 (keep in-tree). plugins/ is the
extension surface for THIS orchestrator. Future custom orchestrators
would write their own plugins anyway.

---

### Candidate C: app/providers/ — **HALT (Fx composition root)**

```
app/providers/           — Fx provider/recipe module, ~15 *.go files
                           returning typed deps (AlertSvc, AuditStore,
                           BillingStore, CredentialSvc, EventDispatcher,
                           FamilyService, LifecycleManager, LoggerPort,
                           Manager, MCPServer, OrderSvc, PortfolioSvc,
                           RiskGuard, Scheduler, SessionSvc,
                           TelegramNotifier)

app/providers/ imports:
  - github.com/zerodha/kite-mcp-server/app/metrics (root subpkg)
  - github.com/zerodha/kite-mcp-server/kc          (root)
  - github.com/zerodha/kite-mcp-server/mcp         (root)

Reverse-deps in master: 2 files
  - app/wire.go (composition root in app)
  - cmd/event-graph/main.go (CLI tool consuming the same providers)
```

**Architectural blocker**: app/providers IS the dependency-injection
composition root for kite-mcp-server. By definition it must reach
every wired type — kc parent, mcp parent, app/metrics. Extracting
it would mean publishing the orchestrator's wiring as a separate
versioned module, which adds release-coupling without any
distribution benefit.

**Unblock options**:
1. None practical. app/providers is architecturally part of THIS
   orchestrator — it composes 27 algo2go modules + root packages
   for THIS specific server's wire-graph. A different orchestrator
   would have a different providers/.

**Recommendation**: Keep in-tree. Document explicitly that
app/providers is "orchestrator-private wiring, not a reusable
algo2go module".

---

### Candidate D: kc/manager_*.go split — **DEFER (deeper architectural research)**

Surveyed kc/ root. 25+ files including:
  - kc/manager.go (god-struct, partially decomposed in prior session
    per user note: "manager.go 413→140 LOC")
  - kc/manager_accessors.go, manager_commands_*, manager_construction,
    manager_cqrs_register, manager_init, manager_interfaces,
    manager_lifecycle, manager_orders_fallback, manager_queries_*,
    manager_reconstitution, manager_struct, manager_use_cases
  - kc/options.go, kc/config.go, kc/store_registry.go, kc/interfaces.go
  - kc/alert_service.go, kc/broker_*, kc/callback_handler.go,
    kc/credential_*, kc/eventing_service.go, kc/expiry.go,
    kc/family_service.go, kc/fill_watcher*, kc/kite_*, kc/order_service.go,
    kc/portfolio_service.go, kc/session*, kc/scheduling_service.go

This is the **runtime wiring of the orchestrator** — the *kc.Manager
god-struct that owns broker clients, store handles, service
constructors. Per Path A.26 closure: "remaining in-tree code is the
runtime wiring + tool layer + HTTP/orchestration".

**No mechanical extraction is appropriate here**. Splitting would
either:
1. Continue prior session's god-struct decomposition (architectural
   refactor, not module extraction)
2. Promote individual services (e.g., kc/order_service.go) to algo2go
   — but each one has cross-cutting deps to the Manager that own
   its broker client. Without Manager extraction, services can't be
   externalized cleanly.

**Recommendation**: Halt. This is multi-week architectural work,
not a single-leaf promotion. If user wants to continue god-struct
decomposition, dispatch a research agent to survey current state
of manager.go (was 413 LOC, now 140 LOC per prior session) and
identify next decomposition step.

---

### Candidate E: kc/ports/ + kc/ops/ refactor — **DEFER (architectural research)**

```
kc/ports/                — 8 .go files (alert, assertions, credential,
                           credential_leaf_test, instrument,
                           leaf_stability_test, order, session)
                           NO own go.mod — non-module package

kc/ops/                  — 50+ .go files (HTTP handlers for /dashboard,
                           /admin, /api/* endpoints — payoff.go,
                           scanner.go, dashboard*, handler*, render*,
                           admin_edge*, api_*) + admin/ subpackage
                           NO own go.mod — non-module package
```

These are **non-go.mod packages inside the root module**. Promoting
them to algo2go would require:
- kc/ports: extracting the port interfaces (alert.Port, order.Port,
  etc.) which are already arguably duplicates of types defined inside
  individual algo2go modules. Architectural cleanup, not mechanical.
- kc/ops: this is the HTTP handler layer — 50+ files of dashboard /
  admin / API HTTP endpoints. By definition orchestrator-side code.
  Same argument as app/providers.

**Recommendation**: Halt. No mechanical promotion appropriate.
kc/ports may benefit from interface-consolidation research, but
that's separate from module extraction.

---

## Summary verdict

**ALL 5 non-kc/* candidates require architectural research, not
mechanical extraction.** The kc/* externalization arc deliberately
left these as orchestrator-side code.

The user's hand-off explicitly anticipated this with the
"halt + surface findings instead of executing blindly" rule —
correct rule fired correctly.

## What's actually done

- Path A inauguration arc CLOSED (27 algo2go modules)
- 0 in-tree kc/* modules with own go.mod
- Workspace down to 4 members: root + plugins + testutil + app/providers

The remaining 4 workspace members (root included) are the orchestrator
itself. Further decomposition is architectural surgery on the
orchestrator, requiring research dispatch — NOT mechanical Path A
playbook.

## Recommendations

1. **Accept the arc as complete** at 27 modules. The orchestrator-side
   code (testutil, plugins, app/providers, kc/ports, kc/ops, kc/manager_*,
   etc.) is by-design root-module code. Future research can revisit
   if a specific business need emerges (e.g., second orchestrator
   needs to share fill-watcher logic → invest in clock-port extraction
   THEN).

2. **OR dispatch architectural research agent** to investigate one
   specific axis if user wants to continue:
   - testutil → clock-port split (smallest unblock; ~1d research +
     1d execution)
   - kc/manager_*.go decomposition (continuation of prior god-struct
     work; multi-day research)
   - kc/ports interface consolidation (medium; ~1-2d research)

The audit agent dispatched in parallel for Phase 1.4+ infra track
(CI/Postgres/multi-cell) may be the higher-leverage next investment
than orchestrator decomposition.
