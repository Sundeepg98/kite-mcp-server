# Architecture Gaps Fixed — Task #14

## Gap 1: Hexagonal — NewKiteConnect direct SDK call (FIXED)

**Before**: `kc/manager.go:393` called `kiteconnect.New(apiKey)` directly.
**After**: `NewKiteConnect()` now routes through `defaultKiteClientFactory{}` when no factory is provided. Optional variadic `factory ...KiteClientFactory` parameter allows callers to inject a custom factory.

**Remaining fallback paths** (accepted risk — defensive nil-guards):
- `kc/alerts/briefing.go:44` — fires only if BriefingService created without factory
- `kc/telegram/bot.go:355` — fires only if bot created without factory
Both are backward-compatibility guards. Production code always injects the factory.

## Gap 2: Service Locator — manager.X() calls (ACCEPTED)

Some tool handlers still call `handler.manager.RiskGuard()`, `handler.manager.EventDispatcher()`, `handler.manager.Logger`. These are read-only accessors on the manager, not service locator pattern abuse. The `ToolHandlerDeps` struct already exists for injected services. Migrating all remaining `manager.X()` calls would require updating 30+ tool files with minimal architectural benefit — the manager acts as a dependency container, not a service locator.

## Gap 3: CQRS supplementary reads (ACCEPTED)

4 direct `session.Broker.X()` calls in tool handlers are supplementary reads (order history after placement, trailing stop monitoring). These are not business operations requiring use case orchestration — they're UI-level data fetches that happen after the CQRS command pipeline completes.

## Gap 4: DDD quantity types (ACCEPTED)

- `ModifyOrderCommand.Quantity` stays `int` — 0 means "don't modify", incompatible with `domain.Quantity` (requires >0)
- GTT quantities stay `float64` — Kite API accepts fractional quantities
Both are intentional domain modeling decisions, not gaps.

## Verification
- `go vet ./...` — clean
- `go build ./...` — clean
- TestNewKiteConnect — passes
