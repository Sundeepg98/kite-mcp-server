# Path A.17 Pick — kc/registry

**Date**: 2026-05-10
**Selected**: `kc/registry` -> `algo2go/kite-mcp-registry`
**Master HEAD at dispatch**: `161301c` (= production v241 + Path A.16 kc/instruments external)

## Decision: kc/registry (single promotion)

18th algo2go module promotion. Smallest single-leaf among 11
remaining post-A.16 candidates — only 2 .go files, 1519 LOC, 1
algo2go dep (kc/alerts, already external).

### Empirical scoring

| Module | Files | LOC | algo2go .go deps | Risk |
|---|---:|---:|---|---|
| **kc/registry** | **2** | **1519** | **1 (alerts, external)** | **LOWEST** |
| kc/ticker | 9 | 2772 | 2 | LOW |
| kc/cqrs | 15 | 2251 | 3 | LOW |
| kc/eventsourcing | 16 | 5264 | 3 | LOW-MED |
| kc/audit | 30 | 10562 | 4 | LOW-MED |

### Pick rationale

- **Single algo2go .go dep**: only `algo2go/kite-mcp-alerts` (Path A.11
  external).
- **Stale go.mod artifact**: `require zerodha/kite-mcp-server` +
  `replace ../..` — same pattern as kc/users (Path A.12), kc/billing
  (Path A.14), oauth (Path A.13). Drop during rewrite.
- **No testutil deps**: clean.
- **Smallest sweep among remaining candidates**: 25 consumer files.
- **Same shape as kc/users**: 1 alerts dep + stale root replace.
  Mechanical replication.

### Type-identity safety

kc/registry exports:
- `Store` — credential CRUD with `*alerts.DB` field
- `Credential` — DTO struct (string fields + uuid)

`*alerts.DB` is the only cross-package type, already external.
Single module identity post-cutover. **No type-identity blocker.**

## Stop-rule observations

- ~1.5-2h budget — well within 3-4h limit
- No anticipated halts (cleanest remaining candidate)

## Forward-looking impact

After kc/registry ships, 10 in-tree kc/* modules remain. Top
candidates:
- kc/ticker (2 algo2go deps)
- kc/cqrs / kc/eventsourcing (3 deps each)
- kc/audit (4 deps)

## Cross-session domain

`Path A inauguration owner` — 17 modules promoted; **registry IN
FLIGHT (18th)**.
