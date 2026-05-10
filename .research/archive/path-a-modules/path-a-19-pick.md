# Path A.19 Pick — kc/cqrs

**Date**: 2026-05-10
**Selected**: `kc/cqrs` -> `algo2go/kite-mcp-cqrs`
**Master HEAD at dispatch**: `72303cd` (= production v243 + Path A.18 kc/ticker external)

## Decision: kc/cqrs (single promotion)

20th algo2go module promotion. CommandBus + dispatcher + query
handlers — moderate-fan-in module (134 consumer files).

### Empirical scoring

| Module | Files | LOC | algo2go .go imports | Risk |
|---|---:|---:|---|---|
| **kc/cqrs** | 15 | 2251 | 2 (domain, logger — both external) | LOW |
| kc/eventsourcing | 16 | 5264 | 3 | LOW-MED |
| kc/audit | 30 | 10562 | 4 | LOW-MED |

### Pick rationale

- **All deps external**: `algo2go/kite-mcp-domain` (Path A.10) +
  `algo2go/kite-mcp-logger` (Path A.7). Transitive (broker, isttz,
  money) all v0.1.0.
- **Stale `replace zerodha/kite-mcp-server => ../..` workspace
  artifact**: drop during rewrite (same as kc/users/registry pattern).
- **Heavier sweep than recent**: 134 consumer files (vs ticker 25,
  registry 25) — but mechanically identical pattern.
- **Smaller LOC than kc/audit**: 2251 vs 10562.

### Type-identity safety

kc/cqrs exports `CommandBus`, `QueryDispatcher`, command/query
interfaces. domain types appear in command/query payloads (e.g.,
`CreateOrderCommand` carries `domain.Order` fields). domain is
external — single module identity. No type-identity blocker.

## Cross-session domain

`Path A inauguration owner` — 19 modules promoted; **cqrs IN
FLIGHT (20th)**.
