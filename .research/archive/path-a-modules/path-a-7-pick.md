# Path A.7 Pick — kc/logger

**Date**: 2026-05-10
**Selected**: `kc/logger` -> `algo2go/kite-mcp-logger`
**Master HEAD at dispatch**: `f560dcb` (= production v232)

## Decision: kc/logger (single promotion)

Per orchestrator brief, this is the **8th** algo2go module promotion.
Single-promotion (not dual) chosen because kc/logger is a pure leaf
with zero internal kc/* deps — no dependent module needs co-promotion.

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer .go | Tests |
|---|---:|---:|---|---:|---|
| **kc/logger** | 5 | 535 | NONE (stdlib + testify only) | 101 | yes |

### Pick rationale

- **Pure leaf**: zero internal go.mod deps. Public API is the `Logger`
  interface (port.go) + 3 implementations (SlogAdapter, Noop, Capture).
- **Largest sweep yet**: 101 consumer .go files + 17 peer go.mods.
  Mechanical but big. Comparable to broker (112) in scale.
- **No type-identity risk**: `Logger` is an interface. Interfaces in
  Go are structurally typed (satisfied by any type with matching
  methods), so module-path identity doesn't propagate. Consumers using
  `logger.Logger` post-cutover will accept any type implementing the
  interface — including types from the upstream module path.
- **Test coverage exists**: logger_test.go (262 LOC, ~50% of module).
  Preserves invariant during cutover.
- **2 commits in history**: tight, stable shape.

### Why interface API makes Phase B safe

Most modules promoted so far (broker.Order with money.Money field,
i18n.Locale newtype) had concrete struct/newtype boundaries that
created type-identity risk. kc/logger's `Logger` is an interface —
any type implementing the methods satisfies it regardless of which
module path the interface is imported from. Phase B canary deletion
should work cleanly because:

1. After cutover, all consumers import `algo2go/kite-mcp-logger`
2. The `SlogAdapter` from upstream implements the upstream `Logger`
3. Consumers using upstream `Logger` accept upstream `SlogAdapter`
4. No transitive deps from other algo2go modules cross logger types

Confirmation via scratch viability test before applying Phase B on
master (decorators methodology — standard since Path A.3).

## Scripts to mirror

- `path-a-legaldocs-prep-dryrun.sh` -> `path-a-logger-prep-dryrun.sh`
- `path-a-legaldocs-rewrite-dryrun.sh` -> `path-a-logger-rewrite-dryrun.sh`
- `path-a-legaldocs-bootstrap-extracted-repo.sh` -> `path-a-logger-bootstrap-extracted-repo.sh`
- `path-a-legaldocs-consumer-cutover-apply.sh` -> `path-a-logger-consumer-cutover-apply.sh`
- `path-a-legaldocs-phase-b-test.sh` -> `path-a-logger-phase-b-test.sh`
- `path-a-legaldocs-canary-delete.sh` -> `path-a-logger-canary-delete.sh`

## Stop-rule per orchestrator brief

- ~3h single-module budget
- Halt + surface at ~4h
- If type-identity blocker surfaces (unlikely given interface API),
  halt at first surfacing
- Watchdog: if sensing stalling mid-burst, commit + push + surface

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE,
**logger IN FLIGHT**.
