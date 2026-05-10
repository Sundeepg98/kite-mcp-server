# Path A.15 Pick — kc/watchlist

**Date**: 2026-05-10
**Selected**: `kc/watchlist` -> `algo2go/kite-mcp-watchlist`
**Master HEAD at dispatch**: `9259e1c` (= production v239 + Path A.14 kc/billing external; billing-chain CLOSED)

## Decision: kc/watchlist (single promotion)

This is the **16th** algo2go module promotion. Selected after dep-graph
audit across all remaining 13 in-tree modules — kc/watchlist is the
cleanest leaf (zero internal kc/* imports, zero algo2go imports, only
stdlib + uuid + testify + sqlite externally).

### Empirical scoring

| Module | Production zerodha imports | algo2go .go deps | LOC | Risk |
|---|---:|---:|---:|---|
| **kc/watchlist** | **0** | **0** | **1463** | **LOWEST** |
| kc/instruments | 0 | 1 (isttz) | 2816 | LOW |
| kc/registry | 0 | 1 | 1519 | LOW |
| kc/ticker | 0 | 2 | 2772 | LOW |
| kc/cqrs | 0 | 3 | 2251 | LOW |
| kc/audit | 0 | 4 | 10562 | LOW-MED |
| kc/eventsourcing | 0 | 3 | 5264 | LOW-MED |
| kc/riskguard | 1 | 5 | 10191 | MED |
| kc/papertrading | 1 | 6 | 10236 | MED |
| kc/telegram | 19 | 5 | 8000 | HIGH |
| kc/usecases | 80 | 8 | 19307 | HIGHEST (massive root coupling) |

### Pick rationale: kc/watchlist over kc/instruments

- **Truer leaf than even kc/instruments**: kc/watchlist has ZERO algo2go
  deps in source. kc/instruments imports algo2go/kite-mcp-isttz.
- **Smallest sweep among low-risk candidates** (1463 LOC vs 2816+).
- **Same shape as kc/legaldocs / kc/decorators**: pure leaf with stdlib
  + a few pure-external libs. No type-identity hazards possible.
- **Fast budget**: ~1.5h estimated based on prior leaf sizes.

### Type-identity safety

kc/watchlist exports:
- `Store` — SQLite-backed CRUD with `*DB` field
- `DB` — schema + migrations + queries
- Pure `Item` / `WatchlistID` value types (uuid-keyed)

No cross-package types-as-data. After cutover, all consumers will
import via algo2go path → single module identity. **No type-identity
blocker possible** (zero algo2go transitive deps).

## Stop-rule observations

- ~1.5-2h budget — well within 3-4h limit
- No anticipated halts (cleanest candidate scored)

## Forward-looking impact

After kc/watchlist ships:

| Module | Status |
|---|---|
| kc/watchlist | EXTERNAL (this dispatch) |
| kc/instruments | Still single-feasible (1 algo2go-isttz) |
| kc/registry | Still single-feasible (1 algo2go dep) |
| kc/ticker | Still single-feasible (2 algo2go deps) |
| kc/cqrs / kc/eventsourcing | Need closer audit |
| kc/audit | Single-feasible (4 algo2go deps, all external) |
| kc/riskguard / kc/papertrading | 1 zerodha root import each (testutil-class strip if test-only) |
| kc/telegram / kc/usecases | High zerodha import counts; defer or cluster |

Path A.16 candidate: **kc/instruments** (next cleanest single-leaf).

## Cross-session domain

`Path A inauguration owner` — 15 modules promoted post-billing-chain;
**watchlist IN FLIGHT (16th)**.
