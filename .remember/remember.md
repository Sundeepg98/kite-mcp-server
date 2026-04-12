# Handoff

## State
Build is vet-clean (`go vet ./...` passes). Architecture fix COMPLETE (arch-fix team, 9 tasks, 4 agents). All implementation merged, verification done.

## Architecture Audit Results (COMPLETE)
| Pattern | Score | Verdict |
|---------|-------|---------|
| Hexagonal | 82% | REAL — clean ports, 33 SDK bypasses |
| Middleware | 85% | REAL — true decorators |
| DDD | 62% | PARTIAL — rich aggregates, anemic entities |
| Event Sourcing | 35% | COSMETIC — audit log only, never replayed |
| Plugin | 35% | COSMETIC — static tool registry |
| CQRS | 33% | FAILING — 76% of 158 tools bypass it |

## Architecture Fix — Completed (2026-04-11, team arch-fix)

### What was done (9 tasks, 4 agents)
- **CQRS bus**: InMemoryBus with reflect.Type routing + middleware, 17 new command/query types + use cases, 13 tools rerouted through use cases (MF, margins, convert_position)
- **Broker abstraction**: Extended broker.Client interface with missing methods, created broker.Factory + broker.Authenticator for multi-broker support
- **DDD enrichment**: Alert entity got ShouldTrigger/MarkTriggered/IsPercentageAlert; User got IsAdmin/IsActive/CanTrade/HasPassword. VOs wired into aggregates (OrderAggregate, PositionAggregate, AlertAggregate). 4 new domain events added.
- **Event Sourcing → Audit log**: Documented as write-only audit trail, not real ES. Aggregates documented as test-only infrastructure.
- **Verification**: go vet clean, 17/17 executable packages pass, 4 SAC-blocked (pre-existing Windows issue)

### Research artifacts
- `.research/cqrs-research.md` — tool mapping, bus design
- `.research/hexagonal-research.md` — SDK bypasses, broker extension plan
- `.research/ddd-es-research.md` — VO wiring, event unification, ES decision
- `.research/integration-plan.md` — phased rollout, dependency graph, risk assessment
- `.research/integration-verification.md` — final verification report

## Coverage (post arch-fix + integration tests, 2026-04-12)
100%: cqrs, usecases, domain, mock, registry, ticker, watchlist, scheduler, plugins/example (9)
99%+: zerodha 99.6%, telegram 99.8%, riskguard 99.7%, metrics 99.3%, eventsourcing 99.2% (5)
95%+: instruments 98.3%, users 98.0%, papertrading 97.8%, rotate-key 97.5%, audit 97.2%, billing 97.1%, alerts 96.9% (7)
90%+: kc 93.9%, oauth 90.6% (2)
80%+: ops 89.2%, mcp ~84%, app 81.5% (3)
75%+: isttz 75% (ceiling) (1)
Total: ~1500+ tests, ~27 packages. SAC blocks 5 packages intermittently (billing, cqrs, eventsourcing, riskguard, mcp) — all pass go vet.

## Agent Management Rules
- NEVER use Explore agents for multi-iteration work — they die on completion
- Use general-purpose agents with "stay alive" for reusable agents
- Use Agent Teams for structured multi-agent workflows (best option)
- SendMessage to completed agents is a no-op — don't bluff about it
- User can see agent activity in terminal — if nothing's happening, agents are dead

## Context
- Codebase at D:\kite-mcp-temp
- Team hooks at C:\Users\Dell\.claude\hooks\agent-teams\
- Reference team: round-18 (6 agents, 20 tasks, 2037 tests)
- Clock injection for time-dependent tests
- DevMode stub Kite client + newFullDevModeManager
- Mock Kite HTTP server pattern: httptest + kiteconnect.SetBaseURI
