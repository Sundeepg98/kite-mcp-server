# Phase 4f — ARCHITECTURE.md written

Date: 2026-04-12
Agent: docs

## Deliverable

`D:\kite-mcp-temp\ARCHITECTURE.md` — ~440 lines, reality-based architecture doc.

## Sections covered

1. High-level diagram (ASCII): MCP clients → app/ → {mcp, kc, oauth} → broker/ → adapters
2. Directory layout (top-level + `kc/` sub-packages + `app/` file breakdown)
3. Hexagonal architecture
   - `broker.Client` composite (9 sub-interfaces, 31 methods)
   - `broker.Factory` + `broker.Authenticator`
   - Zerodha + mock adapters
   - 4 known SDK leaks listed honestly
4. CQRS
   - `kc/cqrs/` bus, 27 use cases in `kc/usecases/`
   - `BrokerResolver` interface
   - Accepted direct-broker reads listed
5. DDD
   - VOs: Money, Quantity, InstrumentKey
   - Specs wired into PlaceOrder/ModifyOrder use cases
   - 13+ domain events
   - Aggregates as verification infrastructure only
   - "Practical DDD" framing — no repositories, Kite API is source of truth
6. Middleware chain — all 10 layers in wire.go order with purpose
7. Event sourcing — scoped as audit log, NOT state reconstitution
8. Testing patterns
   - `testutil/MockKiteServer` + `testutil/kcfixture/`
   - Per-package helpers and mocks
   - 8 test categories in `mcp/`
   - Windows SAC caveat
9. **9 dependency injection points** (explicit table):
   1. KiteClientFactory
   2. broker.Factory
   3. usecases.BrokerResolver
   4. EventDispatcher
   5. EventStore
   6. RiskGuard
   7. PaperEngine
   8. BillingStore
   9. TelegramNotifier
10. Manager service locator wart (honest)
11. How to add a new MCP tool (8 steps)
12. How to add a new broker (8 steps)
13. Not implemented / known gaps
14. Pointers to `.research/` for detail

## Sources used

- `.research/final-arch-verification.md`
- `.research/arch-reaudit.md`
- `.research/hexagonal-fix-plan.md`
- `.research/broker-isp.md`
- `.research/store-accessor-split.md`
- `.research/integration-verification.md`
- `app/wire.go` (middleware chain, event subscriptions, service wiring)
- `app/app.go` (App struct, Config)
- `kc/kite_client.go` (KiteClientFactory interface)
- `kc/broker_services.go` (BrokerServices facade)
- `kc/usecases/place_order.go` (use case shape + BrokerResolver)
- `kc/manager.go` (grep for factory setters)
- `broker/broker.go` (port types)
- `mcp/mcp.go` (Tool interface, RegisterTools, tool list)
- `testutil/kiteserver.go` (MockKiteServer)
- Directory listings for `kc/`, `kc/usecases/`, `kc/cqrs/`, `kc/domain/`, `kc/eventsourcing/`, `mcp/`, `app/`

## Reality-based choices

- Flagged Manager as still-service-locator (not pretending it's decomposed)
- Listed the 4 remaining `kiteconnect.New()` SDK leaks
- Listed the 4 accepted direct-broker reads outside CQRS
- Called out DDD as "practical DDD" — no repositories, no aggregate write-path
- Noted multi-broker is "feasible but not done" — only zerodha + mock exist
- Noted notification abstraction is not yet implemented
- Listed Windows SAC test issue that affects 4 packages
- Documented remaining large files (user_render.go, ext_apps.go, manager.go)

## Not aspirational

Nothing in the doc claims a pattern is at 100% when it isn't. Every honest
gap from `.research/arch-reaudit.md` and `.research/final-arch-verification.md`
is preserved in section 13 "Not implemented / known gaps".
