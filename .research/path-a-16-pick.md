# Path A.16 Pick — kc/instruments

**Date**: 2026-05-10
**Selected**: `kc/instruments` -> `algo2go/kite-mcp-instruments`
**Master HEAD at dispatch**: `d23dcea` (= production v240 + Path A.15 kc/watchlist external)

## Decision: kc/instruments (single promotion)

17th algo2go module promotion. Highest-priority single-leaf
candidate from the 12 remaining post-A.15 modules — same shape as
kc/scheduler (Path A.6.2): 1 algo2go-isttz dep, all production
imports clean.

### Empirical scoring

| Module | Files | LOC | algo2go .go deps | Consumer files | Risk |
|---|---:|---:|---|---:|---|
| **kc/instruments** | **7** | **2816** | **1 (isttz, external)** | **61 (66 occurrences)** | **LOW** |

### Pick rationale

- **Single algo2go .go dep**: only `github.com/algo2go/kite-mcp-isttz`
  (already external from Path A.6.1 commit `bbb31da`).
- **Zero zerodha .go imports**: clean leaf in source.
- **Zero testutil deps**: no inline-replace / strip pattern needed.
- **Same shape as kc/scheduler**: kc/scheduler (Path A.6.2 commit
  `b2315cd`) shipped cleanly with the identical 1-algo2go-isttz-dep
  pattern. Mechanical replication.
- **Mid-size sweep** (61 consumers) — comparable to kc/billing's
  37 + kc/scheduler's 50+. Within ~3-4h budget.

### Type-identity safety

kc/instruments exports:
- `Manager` — instrument fetcher with `Cache` field
- `Cache` — symbol-to-token map with TTL-based refresh
- `Instrument` — DTO struct (string + int fields)
- Time-window helpers via `isttz` (already external)

`isttz` is the only cross-package type, already external. Consumers
post-cutover will import same algo2go path → single module identity.
**No type-identity blocker.**

### Pre-existing test caveat

kc/instruments/go.mod comment notes WSL2 DNS-bound test failures
(`TestNew_*InstrumentsManager*`, `TestNewConfigConstructor`,
`TestManager_MoreAccessors`) that hit `api.kite.trade` for live
instrument fetch. They fail under WSL2 DNS resolution but pass on
Fly.io BOM region. **Orthogonal to extraction** — already documented
across F1-F7 + 5/5 module dispatches as a known WSL2-only flake. The
upstream module will inherit the same test surface; tests run
correctly in CI environments with direct egress.

## Stop-rule observations

- ~2-3h budget — within 3-4h target
- No anticipated halts (1 algo2go dep already external, clean leaf)
- Watchdog: commit + push + surface immediately if stalling

## Forward-looking impact

After kc/instruments ships (via Path A.16), 11 in-tree kc/* modules
remain. Top remaining single-leaf candidates:

| Module | algo2go deps | Risk |
|---|---:|---|
| kc/registry | 1 | LOW |
| kc/ticker | 2 | LOW |
| kc/cqrs | 3 | LOW |
| kc/audit | 4 | LOW-MED |
| kc/eventsourcing | 3 | LOW-MED |

Path A.17 candidate: kc/registry or kc/ticker (smaller surfaces).

## Cross-session domain

`Path A inauguration owner` — 16 modules promoted; **kc/instruments
IN FLIGHT (17th)**.
