# Architecture Fix Integration Plan

Synthesized from: cqrs-fix-plan.md, hexagonal-fix-plan.md, ddd-es-fix-plan.md

---

## 1. Dependency Graph of Fixes

The three research streams are NOT independent. Here is the true dependency order:

```
[DDD-1] Unify event hierarchy ────────────────────────────────────┐
[DDD-2] Alert.ShouldTrigger() + User.IsAdmin() methods           │
                                                                   │
[HEX-1] broker.Client extension (16 new methods)  ──────────┐    │
[HEX-2] broker.Factory + Authenticator ──────────────────────┤    │
                                                              │    │
[CQRS-1] Fix get_order_trades + get_quotes (0 new code) ──┐ │    │
                                                            │ │    │
[HEX-3] Token probe fix (common.go:111) ────────────────┐ │ │    │
                                                          │ │ │    │
                                                          ▼ ▼ ▼    ▼
[CQRS-2] CommandBus + QueryBus implementation ─────────────────────┐
[CQRS-3] 17 new commands/queries + 17 use cases ──────────────────┤
[CQRS-4] Reroute all 42 bypassing tools ──────────────────────────┤
                                                                    │
[DDD-3] Wire VOs into aggregates ──────────────────────────────────┤
[DDD-4] Rename ES to audit log (Phase 1) ─────────────────────────┤
                                                                    │
                                                                    ▼
[HEX-4] NotificationService interface ─────────────────────────────┐
[HEX-5] Manager decomposition ────────────────────────────────────┤
                                                                    │
                                                                    ▼
                                                            Integration tests
```

### Key Dependencies
- **broker.Client extension** (HEX-1) is the #1 blocker. 17 of the CQRS-bypassing tools use `session.Kite.Client.*` directly because the methods don't exist on broker.Client yet.
- **Event hierarchy unification** (DDD-1) should happen BEFORE wiring VOs into aggregates, because the aggregates use their own internal event types that will be deleted/merged.
- **Bus infrastructure** (CQRS-2) should go in AFTER broker.Client is extended, so all tools can be routed at once.
- **Manager decomposition** (HEX-5) is the riskiest change and must go LAST, after all tools are properly routed through use cases and the bus.

---

## 2. Four-Phase Rollout Plan

### Phase 1: Foundation & Quick Wins
**Goal**: Fix obvious issues, build infrastructure. Independently deployable.

| # | Task | Source | Effort | Risk | Files Changed | Tests Updated |
|---|------|--------|--------|------|---------------|---------------|
| 1.1 | Fix `get_order_trades` to use existing `GetOrderTradesUseCase` | CQRS-1 | 0.5d | Low | `mcp/get_tools.go` | 0 (tests pass) |
| 1.2 | Fix `get_quotes` to use existing `GetQuotesUseCase` | CQRS-1 | 0.5d | Low | `mcp/market_tools.go` | 0 |
| 1.3 | Fix token probe: `session.Kite.Client.GetUserProfile()` -> `session.Broker.GetProfile()` | HEX-3 | 0.25d | Low | `mcp/common.go` | 0 |
| 1.4 | Move `shouldTrigger()` -> `Alert.ShouldTrigger()` method | DDD-2 | 1d | Low | `kc/alerts/store.go`, `kc/alerts/evaluator.go` | ~5 |
| 1.5 | Add `Alert.MarkTriggered()` entity method | DDD-2 | 1d | Medium | `kc/alerts/store.go`, `kc/alerts/evaluator.go` | ~8 |
| 1.6 | Add `NewAlert()` constructor with validation | DDD-2 | 0.5d | Low | `kc/alerts/store.go` | ~3 |
| 1.7 | Add `User.IsAdmin()`, `IsActive()`, `CanTrade()` methods | DDD-2 | 0.5d | Low | `kc/users/store.go` | ~3 |
| 1.8 | Rename/document EventStore as DomainAuditLog (Phase 1) | DDD-4 | 0.5d | Low | `kc/eventsourcing/store.go`, `app/app.go` | ~5 |

**Phase 1 total: ~5 person-days, ~8 files, ~24 test assertions updated**
**Deploy gate: all existing tests pass, `go vet` clean**

### Phase 2: Hexagonal Port Extension
**Goal**: Make broker.Client complete. Eliminate all `session.Kite.Client.*` calls. Independently deployable.

| # | Task | Source | Effort | Risk | Files Changed | Tests Updated |
|---|------|--------|--------|------|---------------|---------------|
| 2.1 | Add 11 core methods to `broker.Client` interface (MF, margins, convert position) | HEX-1 | 2d | Medium | `broker/broker.go` (+types) | New types |
| 2.2 | Add `broker.NativeAlertCapable` sub-interface (5 methods) | HEX-1 | 1d | Low | `broker/native_alerts.go` (new) | New |
| 2.3 | Implement 16 new methods in `broker/zerodha/client.go` | HEX-1 | 3d | Medium | `broker/zerodha/client.go`, `convert.go` | ~30 new |
| 2.4 | Implement 16 stub methods in `broker/mock/client.go` | HEX-1 | 1d | Low | `broker/mock/client.go`, `demo.go` | ~10 new |
| 2.5 | Create `broker.Factory` + `broker.Authenticator` interfaces | HEX-2 | 1d | Low | `broker/factory.go` (new) | ~5 new |
| 2.6 | Implement `zerodha.Factory` + `zerodha.Authenticator` | HEX-2 | 1d | Medium | `broker/zerodha/factory.go` (new) | ~8 new |
| 2.7 | Wire Factory into `SessionService` replacing `zerodha.New()` | HEX-2 | 2d | High | `kc/session_service.go` (3 callsites) | ~15 updated |
| 2.8 | Migrate 18 `session.Kite.Client.*` calls in mcp/ to `session.Broker.*` | HEX-1 | 2d | Medium | 5 mcp/*.go files | ~20 updated |

**Phase 2 total: ~13 person-days, ~15 files, ~88 tests (new + updated)**
**Deploy gate: all tools functional, `session.Kite.Client` references reduced to auth-lifecycle-only**

### Phase 3: CQRS Bus & Full Routing
**Goal**: All tools flow through bus. Unified audit, logging, and metrics. Independently deployable.

| # | Task | Source | Effort | Risk | Files Changed | Tests Updated |
|---|------|--------|--------|------|---------------|---------------|
| 3.1 | Implement `InMemoryBus` (CommandBus + QueryBus) | CQRS-2 | 2d | Low | `kc/cqrs/bus.go` (new) | ~15 new |
| 3.2 | Add LoggingMiddleware + AuditMiddleware for bus | CQRS-2 | 1d | Low | `kc/cqrs/middleware.go` (new) | ~8 new |
| 3.3 | Add 9 new command structs (ConvertPosition, MF, NativeAlert) | CQRS-3 | 1d | Low | `kc/cqrs/commands.go` | 0 (types only) |
| 3.4 | Add 8 new query structs (MF, margins, NativeAlerts) | CQRS-3 | 0.5d | Low | `kc/cqrs/queries.go` | 0 |
| 3.5 | Create 17 new use cases | CQRS-3 | 4d | Medium | `kc/usecases/*.go` (new files) | ~50 new |
| 3.6 | Register all use cases with bus in `app/app.go` | CQRS-4 | 1d | Medium | `app/app.go` | ~10 |
| 3.7 | Reroute 17 Kite-specific tools through bus | CQRS-4 | 3d | Medium | 5 mcp/*.go files | ~20 updated |
| 3.8 | Reroute `convert_position` through bus | CQRS-4 | 0.5d | Low | `mcp/post_tools.go` | ~3 |
| 3.9 | Unify event hierarchy (single domain events) | DDD-1 | 3d | Medium | `kc/domain/events.go`, `kc/eventsourcing/*.go` | ~25 updated |

**Phase 3 total: ~16 person-days, ~20 files, ~131 tests (new + updated)**
**Deploy gate: all tools route through bus, single event hierarchy, go vet clean**

### Phase 4: Clean Architecture Polish
**Goal**: Wire VOs, decompose Manager, add notification abstraction. Independently deployable.

| # | Task | Source | Effort | Risk | Files Changed | Tests Updated |
|---|------|--------|--------|------|---------------|---------------|
| 4.1 | Wire VOs into AlertAggregate (simplest) | DDD-3 | 1d | Medium | `kc/eventsourcing/alert_aggregate.go` | ~8 |
| 4.2 | Wire VOs into PositionAggregate | DDD-3 | 1.5d | Medium | `kc/eventsourcing/position_aggregate.go` | ~8 |
| 4.3 | Wire VOs into OrderAggregate (most complex) | DDD-3 | 2d | Medium | `kc/eventsourcing/order_aggregate.go` | ~20 |
| 4.4 | Add User state transition methods | DDD-2 | 1d | Medium | `kc/users/store.go` | ~10 |
| 4.5 | Create `notification.Service` interface | HEX-4 | 1d | Low | `kc/notification/notification.go` (new) | ~5 new |
| 4.6 | Adapt `TelegramNotifier` to implement `notification.Service` | HEX-4 | 1.5d | Medium | `kc/alerts/telegram.go` | ~10 updated |
| 4.7 | Replace concrete `*TelegramNotifier` refs with interface | HEX-4 | 1d | Medium | 5+ files | ~10 updated |
| 4.8 | Manager decomposition Phase 1: tool handlers receive focused deps | HEX-5 | 3d | High | `mcp/*.go` (all tools), `kc/manager.go` | ~40 updated |
| 4.9 | Manager decomposition Phase 2: extract remaining stores | HEX-5 | 3d | High | `kc/manager.go`, new service files | ~30 updated |

**Phase 4 total: ~15 person-days, ~25 files, ~141 tests (new + updated)**
**Deploy gate: Manager under 15 fields, all VOs wired, notification abstracted**

---

## 3. Risk Assessment

### High Risk Items
| Item | Phase | What Could Break | Mitigation |
|------|-------|-----------------|------------|
| SessionService broker.Factory wiring (2.7) | 2 | Login flow, session creation, token caching | Exhaustive integration test; keep old code behind feature flag first |
| Manager decomposition (4.8-4.9) | 4 | Every tool handler, all HTTP endpoints | Incremental: one tool file at a time, run full test suite after each |
| Event hierarchy unification (3.9) | 3 | Event persistence, audit trail, any subscriber | Keep dual-dispatch during transition: emit both old and new types, verify both paths work, then remove old |

### Medium Risk Items
| Item | Phase | What Could Break | Mitigation |
|------|-------|-----------------|------------|
| broker.Client extension (2.1-2.4) | 2 | Compilation (all implementations must satisfy interface) | Add methods to mock + zerodha simultaneously |
| Tool rerouting through bus (3.7) | 3 | Tool responses may differ (use case wraps errors differently) | Compare old vs new responses in shadow mode first |
| OrderAggregate VO wiring (4.3) | 4 | Event serialization, reconstitution | Purely test-infrastructure change (aggregates not used in production) |
| Alert.MarkTriggered entity method (1.5) | 1 | Alert triggering in live trading | Run evaluator tests + manual test with real alerts |

### Low Risk Items
Quick wins in Phase 1 (1.1-1.3, 1.6-1.8), new type definitions (3.3-3.4), new use cases (3.5), new interfaces (2.5, 4.5).

---

## 4. What Should Be REMOVED

### Dead Code
| File/Code | Reason | Phase |
|-----------|--------|-------|
| `eventsourcing.LoadOrderFromEvents()` production export | Never called in production; only tests | 3 (during event unification) |
| `eventsourcing.LoadPositionFromEvents()` production export | Same | 3 |
| `eventsourcing.LoadAlertFromEvents()` production export | Same | 3 |
| Internal event types in `order_aggregate.go` (`orderPlacedEvent`, etc.) | Replaced by unified domain events | 3 |
| Internal event types in `position_aggregate.go`, `alert_aggregate.go` | Same | 3 |
| `ToStoredEvents()` in `order_aggregate.go` | Only used in tests; persistence goes through `makeEventPersister` | 3 (or keep for tests) |
| `session.Kite` field on `KiteSessionData` | After all `session.Kite.Client.*` calls migrate to `session.Broker.*` | 2 (end) |
| `Manager.NewManager()` deprecated alias | Dead constructor | 4 |
| ~30 pass-through methods on Manager | After tool handlers receive focused deps | 4 |

### Over-engineering to Simplify
| Pattern | Current | Simpler | Phase |
|---------|---------|---------|-------|
| `*Concrete()` accessor variants on Manager | `AlertStoreConcrete()`, `TokenStoreConcrete()`, etc. — return concrete types alongside interface accessors | Keep only interface accessors; remove concrete variants | 4 |
| Dual accessor pattern in Manager | `UserStore()` returns interface, `UserStoreConcrete()` returns `*users.Store` | Return interface only; callers that need concrete should use type assertion (rare) | 4 |
| QueryDispatcher (query_dispatcher.go) | Custom pub/sub for query audit | Replace with bus middleware (LoggingMiddleware handles this) | 3 |

---

## 5. Execution Order Summary

```
Week 1-2:  Phase 1 — Quick wins + entity enrichment + ES rename
           Deploy #1

Week 3-5:  Phase 2 — broker.Client extension + Factory + migration
           Deploy #2

Week 5-8:  Phase 3 — Bus + 17 new use cases + rerouting + event unification
           Deploy #3

Week 8-11: Phase 4 — VO wiring + notification + Manager decomposition
           Deploy #4 (v2.0)
```

---

## 6. Effort Estimates

| Phase | Person-Days | Files Changed | New Tests | Updated Tests |
|-------|-------------|---------------|-----------|---------------|
| Phase 1: Foundation | 5 | ~8 | ~5 | ~19 |
| Phase 2: Hexagonal | 13 | ~15 | ~53 | ~35 |
| Phase 3: CQRS Bus | 16 | ~20 | ~73 | ~58 |
| Phase 4: Polish | 15 | ~25 | ~15 | ~126 |
| **Total** | **~49** | **~68** | **~146** | **~238** |

**Grand total: ~49 person-days, ~68 files, ~384 test changes across 4 independently deployable phases.**

Current test count: ~330 tests, 6226 test functions. After all phases: estimated ~480+ test functions added/modified.

---

## 7. Phase Verification Gates

Each phase must pass ALL gates before deployment:

### Phase 1 Gate
- [ ] `go vet ./...` clean
- [ ] `go test ./...` passes (all 330+ existing tests)
- [ ] `Alert.ShouldTrigger()` method works with existing evaluator
- [ ] No `shouldTrigger` free function remains
- [ ] EventStore documented as audit log

### Phase 2 Gate
- [ ] `broker.Client` has 33+ methods (22 existing + 11 new)
- [ ] `broker.NativeAlertCapable` sub-interface works via type assertion
- [ ] Zero `session.Kite.Client.*` calls in `mcp/*.go` (except auth lifecycle)
- [ ] `zerodha.New()` not called directly (all through Factory)
- [ ] Mock broker implements all new methods
- [ ] Full tool regression: all 80+ tools return expected responses

### Phase 3 Gate
- [ ] All command/query types registered with bus
- [ ] Bus middleware produces audit entries for every dispatched message
- [ ] All 17 Kite-specific tools route through use cases
- [ ] Single event hierarchy in `kc/domain/events.go`
- [ ] No internal event types in `kc/eventsourcing/*.go`
- [ ] `go test ./... -race` passes

### Phase 4 Gate
- [ ] All aggregate fields use domain VOs
- [ ] Manager has <15 fields
- [ ] Tool handlers don't import `*kc.Manager` directly (use focused dep structs)
- [ ] `notification.Service` replaces all concrete `*TelegramNotifier` references
- [ ] Test coverage >= 85% on all modified packages
- [ ] `go vet`, `go test -race`, `staticcheck` all clean
