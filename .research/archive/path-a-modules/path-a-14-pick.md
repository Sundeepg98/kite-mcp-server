# Path A.14 Pick — kc/billing (FINAL billing-chain step)

**Date**: 2026-05-10
**Selected**: `kc/billing` -> `algo2go/kite-mcp-billing`
**Master HEAD at dispatch**: `7d3a3ce` (= production v238 + Path A.13 oauth external)

## Decision: kc/billing — FINAL billing-chain step

15th algo2go module promotion, step 4 of 4 in the billing-chain
unblock. Closes the original Path A.8 halt at commit `71f17eb`.

### Original halt → resolution

Per `.research/path-a-8-halt.md`, kc/billing had a 5+ internal-dep
cluster:

| Blocker | Status now |
|---|---|
| kc/templates | EXTERNAL (Path A.8' `1db565a`) |
| kc/domain | EXTERNAL (Path A.10 `9ee8212`) |
| kc/alerts | EXTERNAL (Path A.11 `fd9d9fb`) |
| kc/users | EXTERNAL (Path A.12 `e96b1c0`) |
| oauth | EXTERNAL (Path A.13 `6f2a2b0`) |
| kc/billing | TARGET TODAY |

### Empirical

- 15 .go files, 5852 LOC, 37 consumer files
- 4 algo2go .go imports: alerts, domain, oauth, logger (all v0.1.0)
- Stale `replace ../..` + `replace ../../testutil` workspace artifacts (drop during rewrite)
- Zero testutil .go imports

### Type-identity safety

kc/billing's exposed types (from halt research):
- `Store.SetEventDispatcher(d *domain.EventDispatcher)`
- `TierMonthlyINR(t Tier) domain.Money`
- `NewStore(db *alerts.DB, ...)`
- `e.(domain.TierChangedEvent)`

All cross-package types come from external algo2go modules. Single
module identity. No type-identity blocker.

## Cross-session domain

`Path A inauguration owner` — 14 modules promoted; **kc/billing IN
FLIGHT (FINAL billing-chain step; closes original Path A.8 halt)**.
