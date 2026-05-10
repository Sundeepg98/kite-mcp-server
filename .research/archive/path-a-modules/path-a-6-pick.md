# Path A.6 Pick — kc/isttz + kc/scheduler dual-promotion

**Date**: 2026-05-10
**Selected**: `kc/isttz` -> `algo2go/kite-mcp-isttz` THEN `kc/scheduler` -> `algo2go/kite-mcp-scheduler`
**Master HEAD at dispatch**: `4ffbba7` (= production v231)

## Decision: dual-promotion, isttz first

Per orchestrator brief, this is the **6th + 7th** algo2go module promotions.
Dual-promotion required because kc/scheduler's go.mod has
`require kc/isttz` — promoting kc/scheduler alone would replicate the
kc/money halt scenario (broker required algo2go/kite-mcp-money before
kc/money was published).

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer .go | Tests |
|---|---:|---:|---|---:|---|
| **kc/isttz** (foundation) | 2 | 48 | NONE | 7 | yes |
| **kc/scheduler** (dependent) | 7 | 1329 | 1 (kc/isttz) | 4 | yes |

### Order rationale

1. **kc/isttz first**: pure leaf with zero internal deps. After publishing
   v0.1.0 to algo2go, kc/scheduler's go.mod can declare
   `require algo2go/kite-mcp-isttz v0.1.0` which resolves via GOPROXY.
2. **kc/scheduler second**: now the ONLY external require kc/scheduler
   needs is `algo2go/kite-mcp-isttz v0.1.0` (already published in step 1).
   No further chain blockers.

### Phase B viability prediction

- **kc/isttz Phase B**: pure leaf, type-identity-safe. Same shape as kc/i18n.
- **kc/scheduler Phase B**: depends on algo2go/kite-mcp-isttz being published.
  After isttz v0.1.0 is on GOPROXY, kc/scheduler's upstream go.mod will have
  `require algo2go/kite-mcp-isttz v0.1.0` — and consumer-side will also import
  algo2go path post-cutover. Type identity should hold (both broker+consumer
  see same Locale-style newtypes from same module path). Verify via scratch
  viability test before applying Phase B on master.

### Type-identity stop-rule check

kc/isttz exports `time.Location` wrappers (no struct types stored across
boundaries). kc/scheduler exports scheduler.* types but its consumers
(`app/providers/scheduler.go`, `mcp/paper/context_tool.go`) use them
locally. No transitive pattern like broker -> kc/money where unpublished
deps would chain.

If scratch viability test reveals a hidden second blocker (e.g.,
kc/scheduler imports more than just kc/isttz transitively), halt at
first surfacing per stop-rule, fall back to single-promotion or surface.

## Scripts to mirror

### For kc/isttz (foundation, simpler)
- `path-a-i18n-prep-dryrun.sh` -> `path-a-isttz-prep-dryrun.sh`
- `path-a-i18n-rewrite-dryrun.sh` -> `path-a-isttz-rewrite-dryrun.sh`
- `path-a-i18n-bootstrap-extracted-repo.sh` -> `path-a-isttz-bootstrap-extracted-repo.sh`
- `path-a-i18n-consumer-cutover-apply.sh` -> `path-a-isttz-consumer-cutover-apply.sh`
- `path-a-i18n-phase-b-test.sh` -> `path-a-isttz-phase-b-test.sh`
- `path-a-i18n-canary-delete.sh` -> `path-a-isttz-canary-delete.sh`

### For kc/scheduler (dependent)
- Same 6 scripts but kc/isttz->algo2go path is already in place
- Phase A canary cutover script will need to handle the kc/isttz transitive dep —
  kc/scheduler's go.mod's existing `require ... kc/isttz` line gets rewritten to
  `algo2go/kite-mcp-isttz v0.1.0` (matching what isttz Phase A landed)
- Phase B canary delete script needs to rewrite both kc/scheduler's own replace
  AND its require kc/isttz (which still points at the canary path).
  After both Phase Bs land: kc/scheduler@v0.2.0 will be tagged with the
  upstream-only require kc/isttz — but for v0.1.0 release tag, the in-tree
  kc/isttz path may still be referenced. Re-check during scheduler bootstrap.

## Stop-rule per orchestrator brief

- ~6h budget for dual
- Halt + surface at ~8h
- If type-identity blocker surfaces, halt at first surfacing
- Watchdog: if sensing stalling mid-burst, commit + push + surface immediately

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators DONE,
i18n DONE, legaldocs DONE, **isttz + scheduler IN FLIGHT (dual-promotion)**.
