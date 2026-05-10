# Path A.18 Pick — kc/ticker

**Date**: 2026-05-10
**Selected**: `kc/ticker` -> `algo2go/kite-mcp-ticker`
**Master HEAD at dispatch**: `3f73a3f` (= production v242 + Path A.17 kc/registry external)

## Decision: kc/ticker (single promotion)

19th algo2go module promotion. Single algo2go module dep
(`algo2go/kite-mcp-broker` — both subpackages `/zerodha` and `/ticker`
share the same module path). 25 consumer files, 11 .go files in
module, 2772 LOC.

### Empirical scoring

| Module | Files | LOC | algo2go imports | Risk |
|---|---:|---:|---|---|
| **kc/ticker** | **11** | **2772** | **2 subpkgs of 1 module (broker)** | **LOW** |
| kc/cqrs | 15 | 2251 | 2 (domain, logger) | LOW |
| kc/eventsourcing | 16 | 5264 | 3 | LOW-MED |
| kc/audit | 30 | 10562 | 4 | LOW-MED |

### Pick rationale

- **All deps external**: `algo2go/kite-mcp-broker/zerodha` +
  `algo2go/kite-mcp-broker/ticker` (Path A inauguration commit
  `6626812`); transitive `algo2go/kite-mcp-money` (Path B `b92173b`).
- **No testutil deps**: clean.
- **No stale workspace artifacts**: go.mod's replace block is empty
  (already at "all-deps-external" state).
- **Smaller sweep than kc/cqrs/audit**: 25 consumers vs 30+ for
  kc/audit.

### Type-identity safety

kc/ticker exports `Service` (websocket ticker lifecycle) with
`broker.Ticker` type-conformance. broker is external, single
identity. No type-identity blocker.

## Cross-session domain

`Path A inauguration owner` — 18 modules promoted; **ticker IN
FLIGHT (19th)**.
