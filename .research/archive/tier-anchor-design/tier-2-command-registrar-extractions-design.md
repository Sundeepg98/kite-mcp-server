# Tier 2 Command Registrar Extractions — Design

Phase 2 follow-up to Tier 1 closure-DI sub-track (commits `34a32bf` /
`fd4b20e` / `650f4c3`). **Research-only** dispatch (~1.5h survey).

State at survey: master HEAD `650f4c3` = production v257 LIVE (chain agent
in flight on v259). Tier 1 in-tree refactor sub-track CLOSED — all 3
facade back-pointers eliminated via closure-DI pattern.

---

## 1. Empirical state of the 3 candidates

| Candidate | LOC | Test surface | Manager deps | Pattern fit |
|---|---|---|---|---|
| **2.1 Reconstitution** | 215 | indirect via mcp/*_history_tool_test.go | **0** | Trivial relocate (no service, no closures) |
| **2.2 OAuth registrar** | 311 (+ 618 test) | dedicated adapter test surface | 7 (commandBus + 4 stores + AlertDB + Logger) | Pure-function precedent already exists |
| **2.3 Admin registrar** | 533 (+ 149 test + 1879 manager_edge_test integration) | mixed dedicated + heavy integration | 13 distinct (commandBus + 5 stores + 4 services + 3 misc) | Pure-function fits but bigger surface |

### Reconstitution shape (215 LOC)

```
package-level functions, ZERO Manager dependencies:
  orderAggregateToProjectionResult(*OrderAggregate) OrderProjectionResult
  reconstituteOrderHistory(orderID string, events []StoredEvent) (OrderHistoryResult, error)
  reconstitutePositionHistory(aggregateID string, events []StoredEvent) (PositionHistoryResult, error)
  reconstituteAlertHistory(alertID string, events []StoredEvent) (AlertHistoryResult, error)

Pure data transformation. Takes serialized events, returns projection
results. No state, no Manager refs, no side effects.

Callers in master:
  - kc/manager_cqrs_register.go (the package-level dispatcher)
  - kc/manager_reconstitution.go itself

NOT a service candidate. Pure functions in a misnamed file.
```

### OAuth registrar shape (311 LOC)

```
6 commands registered on m.commandBus:
  ProvisionUserOnLoginCommand     (uses userStore via userProvisionerAdapter)
  CacheKiteAccessTokenCommand     (uses tokenStore via kiteTokenWriterAdapter)
  StoreUserKiteCredentialsCommand (uses credentialStore via kiteCredentialWriterAdapter)
  SyncRegistryAfterLoginCommand   (uses registryStore via registrySyncAdapter)
  AdminRegisterAppCommand         (uses registryStore via registryAdminWriterAdapter)
  AdminUpdateRegistryCommand      (same)
  AdminDeleteRegistryCommand      (same)
  + delegated: usecases.RegisterOAuthClientHandlers(...) registers SaveOAuthClient/DeleteOAuthClient

Manager deps consumed:
  m.commandBus, m.Logger, m.userStore, m.tokenStore, m.credentialStore,
  m.registryStore, m.AlertDB() (for OAuth client store)

Adapter types defined inline at end of file:
  userProvisionerAdapter, kiteTokenWriterAdapter, kiteCredentialWriterAdapter,
  registrySyncAdapter, registryAdminWriterAdapter, oauthClientStoreAdapter
```

### Admin registrar shape (533 LOC)

```
6 sub-functions, each registering several commands:
  registerAdminUserCommands     (user lifecycle: suspend/activate/change-role)
  registerAdminRiskCommands     (risk-state mutations)
  registerAlertCommands         (alert CRUD)
  registerMFCommands            (mutual fund operations)
  registerTickerCommands        (start/stop/subscribe ticker)
  registerNativeAlertCommands   (native alert CRUD)

Manager deps consumed (13 distinct):
  m.commandBus, m.Logger, m.userStore, m.alertStore, m.eventStore,
  m.eventDispatcher, m.eventing, m.tickerService, m.sessionManager,
  m.SessionSvc, m.RiskGuard(), m.Instruments, m.resolveNativeAlertClient

Adapter types defined inline (multiple).

Tests:
  manager_commands_admin_test.go (149 LOC) — narrow per-command tests
  manager_edge_test.go (1879 LOC) — heavy integration coverage that
    exercises admin commands end-to-end through the bus
```

---

## 2. Critical finding: registrar pattern precedent already exists

The codebase already has a **pure-function dependency-receiver registrar
pattern** in production at `algo2go/kite-mcp-usecases.RegisterOAuthClientHandlers`:

```go
// In algo2go/kite-mcp-usecases (external module)
func RegisterOAuthClientHandlers(
    bus       *cqrs.InMemoryBus,
    storeFn   func() OAuthClientStore,
    logger    *slog.Logger,
    label     string,
) error {
    // ... registers SaveOAuthClient + DeleteOAuthClient handlers
}

// Called from kc/manager_commands_oauth.go (line 104):
usecases.RegisterOAuthClientHandlers(m.commandBus, clientStore, m.Logger, "cqrs")

// Called from app/adapters_local_bus.go (line 164):
usecases.RegisterOAuthClientHandlers(bus, clientStore, logger, "local bus")
```

The pattern: **registrar function** takes (bus, dep-getters, logger, label)
as parameters; no struct-with-back-pointer; pure function. Called from
both production (Manager) and a local-bus mirror (test fixture / app
helper).

This is the canonical seam. **Tier 2 extractions should follow this
precedent**, not the Tier 1 closure-DI struct pattern.

### Why pure-function dependency-receiver is the right fit (not Tier 1's
struct closures)

| Aspect | Tier 1 closure struct | Tier 2 pure function |
|---|---|---|
| Identity | A facade with state (closures over Manager fields) | A registration step (one-shot at startup) |
| Lifetime | Lives for Manager's lifetime | Runs once during init, returns |
| State held | Closures captured at construction | None (parameters consumed inline) |
| Reusability | Limited to one Manager instance | Reusable across buses (Manager + local-bus mirror) |
| Test fixture | Needs full Manager construction | Pass a bus + minimal stores |

For Tier 2, the registrar is **stateless**. Wrapping it in a closure-DI
struct would add ceremony without benefit. The existing
`usecases.RegisterOAuthClientHandlers` shows the codebase has already
adopted the pure-function pattern — Tier 2 should ride that train.

---

## 3. Per-candidate extraction plan

### Tier 2.1 Reconstitution — TRIVIAL FILE RELOCATE (~30min, NOT 1d)

The design doc estimated 1d. **Empirically wrong** — reconstitution has
zero Manager dependencies. It's not a service candidate at all; it's
pure functions in a misnamed file.

**Recommended action**: rename `kc/manager_reconstitution.go` →
`kc/reconstitution.go` (drop the `manager_` prefix). The functions stay
package-level, callers in `kc/manager_cqrs_register.go` continue working
with no import change (same package).

**Cost**: ~15min (rename + rebuild + verify).

**Architectural value**: low — but cheapest closure of this Tier 2 sub-task
since the work is trivial. Frees one slot from the manager_*.go file
prefix grouping.

**Halt-rules**: none. Pure rename + verify.

**Recommendation**: ~~**execute as a quick-win first dispatch**~~ ALT:
**defer or skip**. The file rename has near-zero architectural payoff;
the only "win" is the cosmetic prefix removal. Better to spend the time
on Tier 2.2 or 2.3.

### Tier 2.2 OAuth Registrar Extraction — PURE FUNCTION PATTERN (~1d)

**Design**: extract `(m *Manager) registerOAuthBridgeCommands()` to a
package-level function `registerOAuthBridgeCommands(bus *cqrs.InMemoryBus,
deps OAuthRegistrarDeps, logger *slog.Logger) error`.

```go
// New struct: OAuthRegistrarDeps holds the 4-store dep set.
type OAuthRegistrarDeps struct {
    UserStore       *users.Store
    TokenStore      *KiteTokenStore
    CredentialStore *KiteCredentialStore
    RegistryStore   *registry.Store
    AlertDB         *alerts.DB  // for OAuth client store
}

// New file: kc/oauth_registrar.go (or similar location)
func registerOAuthBridgeCommands(
    bus    *cqrs.InMemoryBus,
    deps   OAuthRegistrarDeps,
    logger *slog.Logger,
) error {
    // ... 6 command registrations + adapter types
}

// Manager-level delegator (1-line, in kc/manager_commands_oauth.go or
// kc/manager_init.go):
func (m *Manager) registerOAuthBridgeCommands() error {
    return registerOAuthBridgeCommands(m.commandBus, OAuthRegistrarDeps{
        UserStore:       m.userStore,
        TokenStore:      m.tokenStore,
        CredentialStore: m.credentialStore,
        RegistryStore:   m.registryStore,
        AlertDB:         m.AlertDB(),
    }, m.Logger)
}
```

**Cost**: ~1d (mostly test re-architecture)
- Move 311 LOC: ~2h
- Move 6 adapter types (or keep them in manager_commands_oauth.go and
  the new file imports them): ~1h
- Re-architect `manager_commands_oauth_adapters_test.go` (618 LOC) so
  adapter tests no longer require a full Manager fixture: ~3-4h
- WSL2 verify + tools=111 + commit: ~30min

**Architectural value**: medium-high. The 618-LOC test file becomes
much cleaner when the registrar is pure-function — adapter tests can
construct minimal fixtures (just the adapter struct + its dep) instead
of going through Manager.

**Halt-rules**:
- If adapter types have hidden Manager-state dependencies (e.g., reading
  m.Logger inside an adapter's method body), halt + surface — those need
  to be passed in explicitly OR converted to closure-captured deps
- If `usecases.RegisterOAuthClientHandlers` parameter shape (which already
  is a registrar) doesn't compose with the new package-level
  `registerOAuthBridgeCommands` — they should mirror each other; if not,
  halt + redesign

**Risk**: medium. The 618-LOC test file is the largest risk surface. Test
re-architecture is the bulk of the work, not the registrar itself.

### Tier 2.3 Admin Registrar Extraction — PURE FUNCTION PATTERN (~1.5d)

**Design**: same shape as Tier 2.2 but with 6 sub-registrars + 13 deps.

```go
type AdminRegistrarDeps struct {
    UserStore               *users.Store
    AlertStore              *alerts.Store
    EventStore              *eventsourcing.EventStore
    EventDispatcher         *domain.EventDispatcher
    Eventing                *EventingService          // for SetEventDispatcher post-registration
    TickerService           *ticker.Service
    SessionManager          *SessionRegistry
    SessionSvc              *SessionService
    RiskGuardGetter         func() *riskguard.Guard   // closure for runtime mutation
    Instruments             *instruments.Manager
    ResolveNativeAlertClient func(email string) (usecases.NativeAlertClient, error)
}

func registerAdminCommands(
    bus    *cqrs.InMemoryBus,
    deps   AdminRegistrarDeps,
    logger *slog.Logger,
) error {
    if err := registerAdminUserCommands(bus, deps, logger); err != nil { ... }
    if err := registerAdminRiskCommands(bus, deps, logger); err != nil { ... }
    if err := registerAlertCommands(bus, deps, logger); err != nil { ... }
    if err := registerMFCommands(bus, deps, logger); err != nil { ... }
    if err := registerTickerCommands(bus, deps, logger); err != nil { ... }
    if err := registerNativeAlertCommands(bus, deps, logger); err != nil { ... }
    return nil
}
```

**Cost**: ~1.5d
- Move 533 LOC across 6 sub-functions: ~3h
- Define AdminRegistrarDeps + per-sub-function dep slicing (each
  sub-registrar takes only the deps it actually uses): ~2h
- Adapt `m.RiskGuard()` (which post-construction can mutate) via a
  getter closure parameter to preserve "read current value" semantics:
  ~1h
- Reconcile `m.eventing.SetEventDispatcher` post-registration calls
  (eventing service is already extracted; we may need to expose its
  ports through the deps struct): ~1h
- Re-architect `manager_commands_admin_test.go` (149 LOC): ~2h
- Verify integration coverage in `manager_edge_test.go` (1879 LOC) still
  passes — heavy E2E that goes through the bus: ~2h
- WSL2 verify + tools=111 + commit: ~30min

**Architectural value**: high. Largest LOC reduction in the kc/manager_*.go
file set. Eliminates 13 distinct Manager-state-as-implicit-input dep
points.

**Halt-rules**:
- If any sub-registrar's dependency surface exceeds 6 items → halt +
  consider further sub-decomposition (registerNativeAlertCommands may
  hit this)
- If `m.RiskGuard()` getter-closure pattern fails (e.g., a sub-registrar
  needs to call a setter at startup) → halt + redesign with the
  closure-with-write-back pair from Tier 1.3
- If `manager_edge_test.go` integration tests fail in non-trivial ways
  (e.g., relying on bus-handler-as-method-on-Manager for assertion
  paths) → halt + scope reduction (split into per-sub-registrar
  PRs instead of single Tier 2.3 commit)

**Risk**: medium-high. Largest of Tier 2; integration test surface is
heavy.

---

## 4. Pattern fit summary: closure-DI vs pure-function

| Tier | Pattern | Why |
|---|---|---|
| Tier 1.1-1.3 | Struct + closures | Facades with stateful read-current-field semantics across Manager's lifetime |
| Tier 2.1 | None (rename only) | Pure functions, no Manager state |
| Tier 2.2 | Pure-function dependency-receiver | One-shot registration; precedent already exists at `usecases.RegisterOAuthClientHandlers` |
| Tier 2.3 | Pure-function dependency-receiver | Same as 2.2 but bigger; closure-DI inside deps for runtime-mutable fields (RiskGuard) |

**Different patterns are correct for different concerns**. Tier 2 is
NOT "Tier 1 with more closures" — it's a different decomposition
shape (pure function vs facade struct). The codebase has already
adopted the pure-function shape elsewhere; Tier 2 follows that
precedent.

---

## 5. Recommended execution order

### Option A: Smallest first (precedent-establishing)

1. **Tier 2.1 reconstitution rename** (~15min) — quick-win cosmetic
2. **Tier 2.2 OAuth registrar** (~1d) — pure-function precedent for
   admin registrar
3. **Tier 2.3 admin registrar** (~1.5d) — applies pure-function
   precedent at scale

### Option B: Highest leverage first

1. **Tier 2.3 admin registrar** (~1.5d) — biggest LOC win
2. **Tier 2.2 OAuth registrar** (~1d) — second-biggest
3. **Tier 2.1 reconstitution rename** (~15min) — quick cosmetic close

### Option C: Skip 2.1 entirely

Tier 2.1 has near-zero architectural payoff (file rename only). The
~15min could be better spent on Tier 2.2 or 2.3.

**Recommended**: **Option A**. Sequencing reasoning:
- 2.1 (15min) is the smallest dispatch and validates "pattern is
  correct" mindset before bigger work
- 2.2 establishes the pure-function precedent at meaningful LOC (311 +
  618 test)
- 2.3 applies the established precedent at the largest scale (533 + 149
  test + 1879 integration test) with minimum surprise

---

## 6. Cumulative Tier 2 cost estimate

| Sub-task | Cost | Cumulative |
|---|---|---|
| 2.1 reconstitution rename | ~15min | ~15min |
| 2.2 OAuth registrar | ~1d | ~1.25d |
| 2.3 admin registrar | ~1.5d | ~2.75d |
| **Total Tier 2** | **~2.75d** | — |

Design doc original estimate was 3.5d. This survey updates to **~2.75d**
because:
- Tier 2.1 is 0.05d (rename only), not 1d
- Pure-function pattern precedent already exists (no new pattern
  research needed)
- Tier 1 closure-DI is NOT applied (which would have added wrapping
  ceremony)

---

## 7. Halt-rules summary

| Trigger | Response |
|---|---|
| Adapter type has hidden Manager-state field access | Halt + add explicit dep to deps struct |
| `m.RiskGuard()` getter-closure pattern fails | Halt + use closure-with-write-back from Tier 1.3 |
| Sub-registrar dep surface exceeds 6 items | Halt + further sub-decompose |
| Integration test relies on bus-handler-as-method-on-Manager | Halt + scope reduction (per-sub-registrar PRs) |
| Test re-architecture takes >50% of total dispatch time | Halt + commit registrar move only, defer test cleanup to follow-up dispatch |
| Closure-with-write-back conflict with deps struct | Halt + design alternative |

The empirical-gate methodology (tools=111 + WSL2 build/test green for
./mcp + ./app + ./kc) governs each commit, identical to Tier 1.

---

## 8. What this dispatch did NOT do (per "research-only" rule)

- No source mutations
- No new files in kc/, app/, mcp/ (only this design doc in `.research/`)
- No git commits to anything except this design doc
- No execution of any Tier 2 sub-task
- No empirical validation that any sub-task's design will hold under
  WSL2 build (that is the next dispatch's responsibility)

---

## 9. Decision tree for orchestrator

After reading this design doc:

1. **If user wants minimum-friction continuation**: dispatch Tier 2.1
   (reconstitution rename) as a 15-min warmup. Trivial close. Then
   dispatch Tier 2.2.

2. **If user wants to skip Tier 2.1**: dispatch Tier 2.2 directly.

3. **If user wants highest-leverage first**: dispatch Tier 2.3
   directly. Higher risk; bigger payoff. May halt and split into
   sub-PRs.

4. **If user wants to defer Tier 2 entirely**: accept current state as
   stable. Tier 1 closure-DI cleanup is sufficient architectural payoff
   for this session arc; Tier 3 (78-file consumer migration) becomes
   the longer-term track.

5. **If user wants more research**: deeper survey on a specific
   sub-task (e.g., "give me the per-PR migration plan for Tier 2.3
   admin registrar"). ~1h follow-up.

---

## 10. Time accounting

- Phase 2 dispatch start: ~14:30 IST (Tier 1.3 close)
- Tier 2 research dispatch start: post-orchestrator routing
- Survey + design completion: ~16:00 IST
- Total time used in Tier 2 research: ~1.5h
- Inside Tier 2 research budget (2h target / 3h halt)

The architectural-research-then-execute cycle that worked for Path A.27
applies again here: research first, validate pattern fit, halt + surface
if pattern doesn't apply, execute only when fit is empirically confirmed.

---

## Verdict

Tier 2 is **not blocked** but is **architecturally distinct from Tier 1**.
The closure-DI pattern that closed Tier 1 cleanly does NOT apply to
Tier 2; the codebase has already adopted a pure-function
dependency-receiver pattern elsewhere (`usecases.RegisterOAuthClientHandlers`)
and Tier 2 should ride that train.

Recommended dispatch sequence: Option A (2.1 → 2.2 → 2.3) for
precedent-establishing minimum-friction progress.

If user prefers to pause Tier 2 and pivot to a different track entirely
(e.g., let audit agent's Stage 1 close, or start Tier 3 78-file consumer
migration), that's also a valid choice — Tier 1 closure-DI is sufficient
architectural payoff for this Path A track's natural session-arc close.
