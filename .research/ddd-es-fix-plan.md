# DDD + Event Sourcing Fix Plan

Research findings for task #3 AND implementation log for task #7.

## Implementation Status (Task #7)

### DONE:
1. **Alert entity enriched**: `ShouldTrigger()`, `MarkTriggered()`, `IsPercentageAlert()` methods added. Free function `shouldTrigger()` removed. Evaluator updated to use entity methods.
2. **User entity enriched**: `IsAdmin()`, `IsActive()`, `CanTrade()`, `HasPassword()` methods added. `Store.IsAdmin()` and `Store.HasPassword()` delegate to entity methods.
3. **VOs wired into all 3 aggregates**:
   - `OrderAggregate`: `Quantity`->domain.Quantity, `Price`->domain.Money, `FilledPrice`->domain.Money, `FilledQuantity`->domain.Quantity, `Exchange+Tradingsymbol`->domain.InstrumentKey
   - `PositionAggregate`: `Quantity`->domain.Quantity, `AvgPrice`->domain.Money, `Symbol+Exchange`->domain.InstrumentKey
   - `AlertAggregate`: `TargetPrice`->domain.Money, `Symbol+Exchange`->domain.InstrumentKey
4. **Payload structs unchanged** (serialization boundary stays as primitives)
5. **Missing domain events added**: `OrderFilledEvent`, `PositionOpenedEvent`, `AlertCreatedEvent`, `AlertDeletedEvent`
6. **All tests updated** to use VO accessors (`.Int()`, `.Amount`, `.Instrument.Tradingsymbol`)
7. **`go build ./...` and `go vet ./...` pass** on entire project
8. **Tests pass**: alerts (2.7s), users (12.3s), domain (0.7s). Eventsourcing tests blocked by Windows SAC (not code issue).

### REMAINING (not in scope for task #7):
- Event hierarchy unification (rename internal events to use dotted format, replace internal events with domain events) — deferred to avoid breaking stored event deserialization
- Event naming alignment ("OrderPlaced" vs "order.placed") — needs migration story

---

Original research findings below.

---

## 1. Value Objects in Aggregates: Primitive-to-VO Migration

### Current State

Three VOs exist in `kc/domain/`:
- **Money** (`money.go`): `{Amount float64, Currency string}` with `NewINR()`, arithmetic ops, Indian formatting
- **Quantity** (`quantity.go`): `{value int}` with `NewQuantity()` validation (must be >0)
- **InstrumentKey** (`instrument.go`): `{Exchange, Tradingsymbol string}` with `NewInstrumentKey()`, `ParseInstrumentKey()`

**Usage today**: VOs are used ONLY in:
1. `kc/domain/events.go` — `OrderPlacedEvent`, `PositionClosedEvent`, `AlertTriggeredEvent` use `Money`, `Quantity`, `InstrumentKey`
2. `kc/usecases/place_order.go:129-135` — constructs VOs when dispatching `OrderPlacedEvent`
3. `kc/manager.go:116-118` — constructs VOs when dispatching `AlertTriggeredEvent`

**Not used in**: Any aggregate, any store, the `broker.OrderParams` struct, or the event sourcing package.

### Fields to Migrate in Each Aggregate

#### OrderAggregate (`kc/eventsourcing/order_aggregate.go`)
| Current Field | Type | VO Target | Notes |
|---|---|---|---|
| `Quantity` (line 32) | `int` | `domain.Quantity` | Validation already inline at line 92 (`<= 0`) — VO absorbs this |
| `Price` (line 33) | `float64` | `domain.Money` | Always INR in this context |
| `FilledPrice` (line 34) | `float64` | `domain.Money` | Filled execution price |
| `FilledQuantity` (line 35) | `int` | `domain.Quantity` | Fill quantity |
| `Exchange` + `Tradingsymbol` (lines 27-28) | `string` | `domain.InstrumentKey` | Combine into single VO |

Internal event types must also change:
- `orderPlacedEvent.quantity` (int->Quantity), `.price` (float64->Money)
- `orderModifiedEvent.newQuantity` (int->Quantity), `.newPrice` (float64->Money)
- `orderFilledEvent.filledPrice` (float64->Money), `.filledQuantity` (int->Quantity)

#### PositionAggregate (`kc/eventsourcing/position_aggregate.go`)
| Current Field | Type | VO Target |
|---|---|---|
| `Quantity` (line 26) | `int` | `domain.Quantity` |
| `AvgPrice` (line 27) | `float64` | `domain.Money` |
| `Symbol` + `Exchange` (lines 23-24) | `string` | `domain.InstrumentKey` |

#### AlertAggregate (`kc/eventsourcing/alert_aggregate.go`)
| Current Field | Type | VO Target |
|---|---|---|
| `TargetPrice` (line 25) | `float64` | `domain.Money` |
| `Symbol` + `Exchange` (lines 23-24) | `string` | `domain.InstrumentKey` |

### What Breaks

1. **Serialization/deserialization** (`OrderPlacedPayload`, `OrderModifiedPayload`, `OrderFilledPayload`, `PositionOpenedPayload`, `AlertCreatedPayload`): These JSON payload structs use raw `int`/`float64`. When aggregate fields become VOs, the payload structs can stay as raw primitives (they are the wire format), but the conversion code between payloads and internal events needs updating.

2. **Apply methods**: `OrderAggregate.Apply()` (line 235-265) directly assigns `e.quantity` to `o.Quantity`. If `o.Quantity` becomes `domain.Quantity`, the assignment becomes `o.Quantity = domain.Quantity{value: e.quantity}` (or use constructor). Same for all Apply methods in all 3 aggregates.

3. **Command methods**: `OrderAggregate.Place()` reads from `broker.OrderParams` which uses raw `int`/`float64`. Need conversion at the boundary: `qty, err := domain.NewQuantity(params.Quantity)`.

4. **Comparison logic**: `OrderAggregate.Modify()` line 128 compares `newQty == o.Quantity` — with VOs this becomes `newQty.Int() == o.Quantity.Int()` or implement `Equals()`.

5. **Tests**: 
   - `kc/eventsourcing/store_test.go` — reconstitution tests compare raw fields
   - `kc/eventsourcing/*_test.go` — all aggregate tests check primitive fields
   - `app/server_test.go` — integration tests
   - `app/adapters_test.go` — event persistence tests
   - Estimated 20-30 test assertions need updating

### Recommended Approach

**Keep payload structs as primitives** (they are the serialization boundary). Add VO conversion in:
- Internal event types: store VOs instead of primitives
- Apply methods: assign VOs
- Command methods: create VOs from params, validation moves to VO constructors
- Add `.Int()` / `.Amount` accessors where raw values are needed (JSON, comparisons)

**Migration order**: AlertAggregate (simplest, 2 fields) -> PositionAggregate (3 fields) -> OrderAggregate (5 fields, most complex).

---

## 2. Dual Event Hierarchy: domain.Events vs eventsourcing Events

### The Problem

There are TWO parallel, disconnected event hierarchies for order events:

#### Hierarchy A: `kc/domain/events.go` (public, VO-rich)
```
OrderPlacedEvent    — EventType: "order.placed"    — uses Money, Quantity, InstrumentKey
OrderModifiedEvent  — EventType: "order.modified"   — minimal (Email, OrderID, Timestamp)
OrderCancelledEvent — EventType: "order.cancelled"  — minimal (Email, OrderID, Timestamp)
PositionClosedEvent — EventType: "position.closed"  — uses Quantity, InstrumentKey
AlertTriggeredEvent — EventType: "alert.triggered"  — uses Money, InstrumentKey
+ 5 more: RiskLimitBreachedEvent, SessionCreatedEvent, UserFrozenEvent, UserSuspendedEvent, GlobalFreezeEvent, FamilyInvitedEvent
```

#### Hierarchy B: `kc/eventsourcing/order_aggregate.go` (internal, primitive)
```
orderPlacedEvent    — EventType: "OrderPlaced"    — raw int/float64/string
orderModifiedEvent  — EventType: "OrderModified"   — raw primitives
orderCancelledEvent — EventType: "OrderCancelled"  — raw primitives
orderFilledEvent    — EventType: "OrderFilled"     — raw primitives (NO domain counterpart!)
```
Plus `kc/eventsourcing/position_aggregate.go`:
```
positionOpenedEvent — EventType: "PositionOpened"  — NO domain counterpart
positionClosedEvent — EventType: "PositionClosed"  — NO domain counterpart
```
Plus `kc/eventsourcing/alert_aggregate.go`:
```
alertCreatedEvent   — EventType: "AlertCreated"    — NO domain counterpart
alertTriggeredEvent — EventType: "AlertTriggered"  — NO domain counterpart
alertDeletedEvent   — EventType: "AlertDeleted"    — NO domain counterpart
```

### Key Differences

| Aspect | domain events | eventsourcing events |
|--------|---------------|----------------------|
| Naming | `"order.placed"` (dotted) | `"OrderPlaced"` (PascalCase) |
| Visibility | Public (exported structs) | Private (unexported, package-internal) |
| Types | Use VOs (Money, Quantity) | Use primitives (int, float64) |
| Coverage | 11 event types | 9 event types (no overlap except conceptual) |
| Who dispatches | Use cases, admin tools, manager | Aggregate command methods |
| Who subscribes | `makeEventPersister` in app.go | `Apply()` in aggregate |
| Persistence path | dispatcher -> makeEventPersister -> EventStore.Append | Aggregate.PendingEvents -> ToStoredEvents -> EventStore.Append |

### Critical Issue: Two Persistence Paths

**Path 1** (actually used in production): `usecase.Execute()` -> `eventDispatcher.Dispatch(domain.OrderPlacedEvent{...})` -> `makeEventPersister()` -> serializes the whole domain event as JSON payload -> `EventStore.Append()`.

**Path 2** (exists but NEVER called in production): `OrderAggregate.Place()` -> `o.Apply(event)` + `o.raise(event)` -> `ToStoredEvents()` -> `EventStore.Append()`. This is test-only infrastructure.

The aggregates are **not used** in the actual order placement flow. The use case (`place_order.go`) calls `broker.Client.PlaceOrder()` directly and dispatches a `domain.OrderPlacedEvent`. The `OrderAggregate` is never instantiated in production.

### Unified Design

**Option A: Single Event Hierarchy** (recommended)
1. Move all event types into `kc/domain/events.go` using VOs
2. Make aggregate `Apply()` methods accept `domain.Event` (already the interface) and type-switch on the public domain types
3. Delete the internal event types from eventsourcing package
4. Unify naming to dotted format (`"order.placed"`) everywhere
5. Add missing events to domain: `OrderFilledEvent`, `PositionOpenedEvent`, `AlertCreatedEvent`, `AlertDeletedEvent`

**Naming reconciliation**:
- `"OrderPlaced"` -> `"order.placed"` (break stored events or add migration alias)
- `"OrderModified"` -> `"order.modified"`
- `"OrderFilled"` -> `"order.filled"` (new in domain)
- etc.

**Serialization concern**: Existing `domain_events` rows in SQLite use `"order.placed"` (from makeEventPersister) for real data and `"OrderPlaced"` (from ToStoredEvents) only in tests. So unifying on the dotted format is safe — no production migration needed.

**Option B: Keep Dual but Align** (conservative)
Keep both hierarchies but ensure:
- Internal events delegate to domain VOs
- Same event type naming
- Aggregate events are the source, domain events are projections

Recommendation: **Option A**. The internal events add complexity with zero benefit since aggregates aren't used in production flows yet.

---

## 3. Event Sourcing: Real or Remove?

### Evidence: Are Events Ever Read Back in Production?

Searched all production code (excluding `*_test.go`):
- `EventStore.LoadEvents()` — **0 production callers** (only in tests)
- `EventStore.LoadEventsSince()` — **0 production callers** (only in tests)
- `LoadOrderFromEvents()` — **0 production callers** (only in tests)
- `LoadPositionFromEvents()` — **0 production callers** (only in tests)
- `LoadAlertFromEvents()` — **0 production callers** (only in tests)

### What Actually Happens in Production

1. `app/app.go:558-577`: Creates `EventDispatcher`, subscribes `makeEventPersister` for 11 event types
2. `makeEventPersister` (app.go:1955-1978): Serializes domain events as JSON and appends to `domain_events` SQLite table
3. Events flow: use case/admin tool -> `Dispatch()` -> `makeEventPersister()` -> `EventStore.Append()`
4. **Events are never read back**. No projections, no reconstitution, no queries against the event store.

### Aggregate Usage in Production

- `OrderAggregate`: **Never instantiated** in production. `PlaceOrderUseCase` calls broker directly.
- `PositionAggregate`: **Never instantiated** in production. Position closing goes through use cases that call broker directly.
- `AlertAggregate`: **Never instantiated** in production. Alerts are managed by `alerts.Store` (CRUD store).

The aggregates exist only as test infrastructure and dead code.

### Assessment: This is an Audit Log, Not Event Sourcing

True Event Sourcing requires:
- State derived exclusively from events (no separate state store) -- **NOT MET** (state is in broker API responses + alerts.Store + users.Store)
- Events as source of truth for reads -- **NOT MET** (reads go to broker API or in-memory stores)
- Reconstitution from events -- **NOT MET** in production (only in tests)

What it actually is:
- **Append-only audit log** of domain-significant actions
- Events are written but never read in production
- Useful for compliance, debugging, and the activity dashboard (`/dashboard/activity` uses the `tool_calls` table, not `domain_events`)

### Recommendation: Hybrid Approach

**Phase 1: Rename to clarify intent** (no behavior change)
- Rename `EventStore` -> `DomainAuditLog` (or keep name but document clearly)
- Keep `domain_events` table as-is (it's a valuable audit trail)
- Remove aggregate `Load*FromEvents` functions from production exports (keep for tests)

**Phase 2: Make ES real for Order lifecycle** (optional, high effort)
- Wire `OrderAggregate` into `PlaceOrderUseCase` — aggregate validates, emits events, events are persisted, broker call happens as side effect
- Add projection that builds read models from events
- This is only worth doing if you need temporal queries ("what did this order look like at time T?") or want to support multi-broker undo/replay

**Phase 3: Keep audit log for everything else**
- Non-order events (user.frozen, risk.limit_breached, session.created, etc.) are naturally audit events, not aggregate lifecycle events
- These should remain as simple audit log entries

**Verdict**: Phase 1 (rename/clarify) is the right immediate action. Phase 2 only if temporal queries or multi-broker replay becomes a real requirement.

---

## 4. Anemic Entities: Alert and User

### Alert Entity (`kc/alerts/store.go:39-53`)

**Current state**: 13 fields, 0 methods. Pure data struct.

```go
type Alert struct {
    ID, Email, Tradingsymbol, Exchange string
    InstrumentToken uint32
    TargetPrice float64
    Direction Direction
    ReferencePrice float64
    Triggered bool
    CreatedAt, TriggeredAt, NotificationSentAt time.Time
    TriggeredPrice float64
}
```

**Behavior that should move IN**:

1. **Trigger evaluation** (`evaluator.go:57-78`, `shouldTrigger` function):
   ```go
   // Currently a free function:
   func shouldTrigger(alert *Alert, currentPrice float64) bool { ... }
   
   // Should be a method on Alert:
   func (a *Alert) ShouldTrigger(currentPrice float64) bool { ... }
   ```
   The function already takes `*Alert` as first parameter — classic anemic entity pattern. It reads `Direction`, `TargetPrice`, `ReferencePrice` — all Alert fields.

2. **Mark triggered** (currently in `Store.MarkTriggered`, store.go:229-252):
   ```go
   // The state mutation belongs on the entity:
   func (a *Alert) MarkTriggered(currentPrice float64) bool {
       if a.Triggered { return false }
       a.Triggered = true
       a.TriggeredAt = time.Now()
       a.TriggeredPrice = currentPrice
       return true
   }
   ```
   Store would then just persist the already-mutated entity.

3. **Percentage direction check** (`IsPercentageDirection` free function, store.go:34-36):
   ```go
   // Should be on Alert or Direction:
   func (a *Alert) IsPercentageAlert() bool {
       return a.Direction == DirectionDropPct || a.Direction == DirectionRisePct
   }
   ```

4. **Validation on creation** (currently in `Store.AddWithReferencePrice`, store.go:121-148):
   - Max alerts check stays in Store (it's a collection invariant)
   - But field validation (direction valid? target price > 0? reference price required for pct alerts?) should be in a constructor:
   ```go
   func NewAlert(email, symbol, exchange string, token uint32, target float64, dir Direction, ref float64) (*Alert, error) { ... }
   ```

### User Entity (`kc/users/store.go:29-42`)

**Current state**: 11 fields (ID, Email, KiteUID, DisplayName, Role, Status, PasswordHash, CreatedAt, UpdatedAt, LastLogin, OnboardedBy, AdminEmail), 0 methods.

**Behavior that should move IN**:

1. **Role checks** (currently on Store):
   ```go
   // Store.IsAdmin (store.go:212-217):
   func (s *Store) IsAdmin(email string) bool { ... }
   
   // Should be on User:
   func (u *User) IsAdmin() bool { return u.Role == RoleAdmin && u.Status == StatusActive }
   func (u *User) IsActive() bool { return u.Status == StatusActive }
   func (u *User) CanTrade() bool { return u.Role != RoleViewer && u.Status == StatusActive }
   ```

2. **Status transitions** with validation:
   ```go
   func (u *User) Suspend() error {
       if u.Status == StatusSuspended { return fmt.Errorf("already suspended") }
       u.Status = StatusSuspended
       u.UpdatedAt = time.Now()
       return nil
   }
   
   func (u *User) Activate() error { ... }
   func (u *User) Offboard() error { ... }
   ```
   Currently `Store.UpdateStatus` (store.go:283-307) validates status values but the entity has no say in transitions.

3. **Password management**:
   ```go
   func (u *User) HasPassword() bool { return u.PasswordHash != "" }
   func (u *User) SetPasswordHash(hash string) { u.PasswordHash = hash; u.UpdatedAt = time.Now() }
   ```
   Currently these are Store methods that do lock+unlock+DB update. The entity mutation should be separate from persistence.

4. **UpdateLastLogin**:
   ```go
   func (u *User) RecordLogin() { u.LastLogin = time.Now(); u.UpdatedAt = time.Now() }
   ```

### Impact Assessment

| Change | Files Affected | Risk |
|--------|---------------|------|
| `Alert.ShouldTrigger()` method | `evaluator.go`, `evaluator_test.go` | Low — simple refactor |
| `Alert.MarkTriggered()` method | `store.go`, `evaluator.go`, tests | Medium — touches Store logic |
| `NewAlert()` constructor | `store.go` (AddWithReferencePrice) | Low — validation moves |
| `User.IsAdmin()` method | `store.go`, callers of `Store.IsAdmin()` | Low — add method, keep Store version as convenience |
| `User.Suspend/Activate/Offboard()` | `store.go` (UpdateStatus) | Medium — split mutation from persistence |
| `User.RecordLogin()` | `store.go` (UpdateLastLogin) | Low |

### Recommended Approach

1. **Alert first** (highest value): Move `shouldTrigger` to `Alert.ShouldTrigger()` and `MarkTriggered` mutation to entity. This is the most clear-cut anemic entity fix — a pure function operating on entity fields becomes a method.

2. **User second**: Add `IsAdmin()`, `IsActive()`, `CanTrade()` methods. These are read-only so zero risk. Status transition methods are nice-to-have but lower priority since they touch the Store's persistence logic.

3. **Store stays as repository**: The Store handles concurrency (mutex), persistence (SQLite), and collection queries. Entity methods handle field validation and state transitions. Clean separation.

---

## Summary: Priority-Ordered Action Items

| # | Action | Effort | Risk | Blocked By |
|---|--------|--------|------|------------|
| 1 | Unify event hierarchy (Option A: single domain events) | Medium | Medium | None |
| 2 | Move `shouldTrigger` -> `Alert.ShouldTrigger()` | Small | Low | None |
| 3 | Add `User.IsAdmin()`, `IsActive()`, `CanTrade()` methods | Small | Low | None |
| 4 | Rename ES to audit log / clarify intent (Phase 1) | Small | Low | #1 |
| 5 | Wire VOs into AlertAggregate (simplest) | Medium | Medium | #1 |
| 6 | Wire VOs into PositionAggregate | Medium | Medium | #5 |
| 7 | Wire VOs into OrderAggregate | Large | Medium | #6 |
| 8 | Add `Alert.MarkTriggered()`, `NewAlert()` constructor | Medium | Medium | #2 |
| 9 | Add `User.Suspend()` / state transition methods | Medium | Medium | #3 |
| 10 | Make ES real for Order lifecycle (Phase 2) | Large | High | #1, #7 |

Items 1-4 can be done independently and immediately. Items 5-7 are sequential. Item 10 is optional.
