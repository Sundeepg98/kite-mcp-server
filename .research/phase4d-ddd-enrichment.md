# Phase 4d — DDD Enrichment Audit

Scope: kc/domain/, kc/alerts/, kc/users/, kc/eventsourcing/. Read-only inventory + targeted entity enrichment.

## 1. Alert entity (kc/alerts/store.go)

**Before:** `ShouldTrigger`, `MarkTriggered`, `IsPercentageAlert` — good core behavior but several call sites were reaching into raw fields to compute derived values.

**Added behavior methods (all pure, no dependencies):**
- `IsActive()` — replaces scattered `!a.Triggered` checks.
- `MatchesInstrument(instrumentToken)` — replaces `a.InstrumentToken == X` checks in evaluator/store.
- `NeedsNotification()` — `a.Triggered && a.NotificationSentAt.IsZero()`, a clearer intent than the raw field combo.
- `InstrumentKey()` — returns `Exchange + ":" + Tradingsymbol`, previously string-concatenated at 3+ call sites (evaluator, telegram, dashboards).
- `PercentageChange(currentPrice)` — returns signed percentage change from reference; duplicated across DropPct/RisePct branches of `ShouldTrigger`. Now reusable for logging.

**Not moved into entity:** `Store.MarkTriggered`/`Store.MarkNotificationSent` remain on Store — they need DB write-through + mutex coordination, which is infrastructure, not domain.

## 2. User entity (kc/users/store.go)

**Before:** `IsAdmin`, `IsActive`, `CanTrade`, `HasPassword` — good start, but status/role checks and family billing predicates were inlined in handlers and use cases.

**Added behavior methods:**
- `IsSuspended()`, `IsOffboarded()` — symmetric counterparts to `IsActive`.
- `IsViewer()`, `IsTrader()` — role predicates (previously `u.Role == RoleTrader` scattered across code).
- `IsFamilyMember()` — `AdminEmail != ""` check, currently duplicated in `family_service.go:38`, `page_handlers.go:44`, `service_test.go:1220`.
- `IsBillingOwner()` — inverse, for tier billing logic.
- `BelongsToAdmin(adminEmail)` — `strings.EqualFold` comparison, used by `ListByAdminEmail` logic.
- `CanBeOnboardedByGoogleSSO()` — `OnboardedBy == "google_sso"`.

**Intentionally not added:**
- `IsFrozen()` — there is no "frozen" status field on User. The `UserFrozenEvent` exists in domain/events.go but freeze state currently lives in riskguard (circuit breaker), not on User. Adding `IsFrozen()` here would be misleading. If a `frozen_at` column is added later, this method should land then.
- `CanAccessFamily()` / `IsBillingAdmin()` — these are cross-entity (involve looking up children); they belong on a `FamilyService` or `BillingPolicy`, not on User alone.

## 3. Aggregates usage in production

**Confirmed test-only** (grep across codebase):
- `OrderAggregate`, `PositionAggregate`, `AlertAggregate`: referenced only in `kc/eventsourcing/*_test.go` and `store_test.go`. **Zero production call sites.**
- Architecture note at `kc/eventsourcing/aggregate.go:11-16` and `kc/eventsourcing/store.go:1-14` already explicitly acknowledges this: "Aggregates are currently used as test infrastructure only. In production, order/position/alert state comes from broker APIs and CRUD stores, not from event replay."
- The `EventStore` itself IS used in production via `makeEventPersister` in `app/adapters.go:382` — events are appended for compliance/audit but never replayed.

**Verdict:** System is **event-logged**, not event-sourced. Aggregates are retained as executable documentation of state machine invariants. This is a deliberate, documented architectural choice — not tech debt. Phase 4e (task #11) should confirm the log is complete (all mutations produce events).

## 4. Value Object usage at boundaries

**VOs in active use:**
- `domain.Money`, `domain.Quantity`, `domain.InstrumentKey` are fields on cqrs commands (`kc/cqrs/commands.go:18-21, 38-92`) — they travel through the command API.
- Use cases (`kc/usecases/place_order.go`, `modify_order.go`, `close_position.go`, `close_all_positions.go`) receive VOs in commands.
- `domain.OrderPlacedEvent`, `PositionOpenedEvent`, `AlertTriggeredEvent` etc. use `Quantity`/`Money`/`InstrumentKey` as fields (`kc/domain/events.go:19-116`).

**Leakage at boundary** (intentional):
- `place_order.go:60-63` immediately unwraps VOs: `qty := cmd.Qty.Int()`, `price := cmd.Price.Amount`, etc. Downstream (`broker.OrderParams`, `riskguard.OrderCheckRequest`) takes primitives.
- Reason: broker adapter and riskguard were designed pre-DDD and speak primitives. Full propagation would require changing `broker.Client`, `riskguard.Guard`, and every persistence adapter — high blast radius for low payoff given primitives round-trip safely through one translation layer.

**Recommendation:** Acceptable as-is. The boundary for VOs sits at the use case entry. Pushing deeper would be a separate phase and requires touching the broker interface and riskguard package signatures.

## 5. Specification pattern wiring

**Production call sites (confirmed by grep):**
- `kc/usecases/place_order.go:66-80` — `NewOrderSpec(NewQuantitySpec, NewPriceSpec)` + `IsSatisfiedBy(OrderCandidate)` → rejects invalid orders before riskguard.
- `kc/usecases/modify_order.go:55, 62` — `NewQuantitySpec` + `NewPriceSpec` used directly for modify validation.

**Verdict:** Wired in the 2 main write paths. Additional use cases (close_position, close_all_positions) don't need OrderSpec because they derive qty/price from existing positions.

Other predicates (And/Or/Not composition) exist in `kc/domain/spec.go` but are not currently composed in production — only in `spec_test.go`. That's acceptable (infrastructure ready for future rules like "large order AND non-market hours").

## Enrichment Summary

| File | Entity | Methods added | Replaces |
|---|---|---|---|
| kc/alerts/store.go | Alert | IsActive, MatchesInstrument, NeedsNotification, InstrumentKey, PercentageChange | 5 scattered inline checks |
| kc/users/store.go | User | IsSuspended, IsOffboarded, IsViewer, IsTrader, IsFamilyMember, IsBillingOwner, BelongsToAdmin, CanBeOnboardedByGoogleSSO | 8 scattered inline checks |

**Build:** `go build ./kc/alerts/... ./kc/users/... ./kc/domain/...` — clean.
**Tests:** `go test ./kc/alerts/... ./kc/users/... ./kc/domain/...` — all passing.

**Not refactored:** Existing call sites that inline these checks are left alone. This audit's charter is enrichment (add methods, verify they compile and the existing test suite still passes); replacing call sites should be a follow-up or bundled with unrelated edits to avoid conflicts with concurrent Phase 2 splitter tasks. New call sites and the next person touching those files can migrate.

## Score update vs. remember.md Apr 2026 audit

- DDD score (was 62%): Alert and User anemia partially resolved. OrderSpec confirmed wired. VO usage confirmed at command boundary. Aggregates confirmed test-only (documented, not dead). Recommend **raise to ~75%**.
- Event Sourcing score (was 35%): defer until task #11 verification.
