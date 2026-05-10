# Path A.5 Pick — kc/legaldocs

**Date**: 2026-05-10
**Selected**: `kc/legaldocs` -> `algo2go/kite-mcp-legaldocs`
**Master HEAD at dispatch**: `813ae46` (= production v230)

## Decision: kc/legaldocs (single promotion)

Per orchestrator brief, my pick from the candidates:
- **Picked**: `kc/legaldocs` — single 5th promotion
- **Deferred**: `kc/scheduler + kc/isttz` dual-promotion (next dispatch)

### Empirical scoring

| Candidate | Internal deps | Consumer files | LOC | Tests | Risk | Notes |
|---|---:|---:|---:|---|---|---|
| **kc/legaldocs** | **0** | **1 (app/legal.go)** | **11** | **none (embed)** | **LOWEST** | **PICKED** |
| kc/isttz | 0 | (paired with scheduler) | 48 | n/a | LOW | Defer to dual w/ scheduler |
| kc/logger | 0 | (paired with registry) | 535 | n/a | LOW | Defer to triple w/ registry |
| kc/scheduler | 1 (isttz) | (n/a) | 1329 | yes | LOW dual | Defer to dual |
| kc/registry | 3 + cyclic root | (n/a) | 1519 | yes | MED-HIGH | Defer; cyclic root |

### Pick rationale: kc/legaldocs

- **Pure leaf**: zero internal go.mod deps. Only consumer is `app/legal.go`.
- **Trivially small**: 11 LOC `embed.go` exposing `legaldocs.Privacy []byte` +
  `legaldocs.Terms []byte` as byte slices via `//go:embed`. 229 LOC of
  embedded .md content (TERMS.md, PRIVACY.md) travels with the module.
- **No exported types-as-data**: just byte-slice variables. Type-identity
  issue (Phase B kc/money halt scenario) is structurally impossible —
  you cannot have a "wrong-path Money" version of `[]byte`.
- **Fastest demonstration**: ~2h end-to-end target, well within the
  ~4h single-module budget.
- **No cliff signals**: 3 commits in history, last touched at extraction
  time. Stable shape.

### Why single (not dual w/ scheduler+isttz)

Per orchestrator's watchdog warning: "your last dispatch (Path A.4 kc/i18n)
stalled at 600s no-progress mid-evidence-commit. If you sense stalling:
commit immediately, push, then surface — don't try to chain further work
in the same long burst."

Single promotion fits comfortably in budget. Dual w/ scheduler+isttz
(~6h) would chain through a second extraction + viability test + cutover
+ canary delete in the same dispatch — exactly the burst-overrun pattern
to avoid. Better to surface clean after legaldocs, let orchestrator
re-ping for scheduler+isttz dual in a fresh dispatch.

## Scripts to mirror

- `path-a-i18n-prep-dryrun.sh` -> `path-a-legaldocs-prep-dryrun.sh`
- `path-a-i18n-rewrite-dryrun.sh` -> `path-a-legaldocs-rewrite-dryrun.sh`
- `path-a-i18n-bootstrap-extracted-repo.sh` -> `path-a-legaldocs-bootstrap-extracted-repo.sh`
- `path-a-i18n-consumer-cutover-apply.sh` -> `path-a-legaldocs-consumer-cutover-apply.sh`
- `path-a-i18n-phase-b-test.sh` -> `path-a-legaldocs-phase-b-test.sh`
- `path-a-i18n-canary-delete.sh` -> `path-a-legaldocs-canary-delete.sh`

## Stop-rule per orchestrator brief

- ~4h single-module budget
- Halt + surface at ~6h regardless
- If type-identity blocker surfaces, halt at first surfacing
- **Watchdog**: if sensing stalling mid-burst, commit + push + surface
  immediately rather than chaining further work

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators DONE,
i18n DONE, **legaldocs IN FLIGHT**.
