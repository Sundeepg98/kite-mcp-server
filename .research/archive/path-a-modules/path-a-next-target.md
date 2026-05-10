# Path A Next Target — kc/decorators

**Date**: 2026-05-06
**Selected**: `kc/decorators` -> `algo2go/kite-mcp-decorators`
**Master HEAD at dispatch**: `9b6209b`

## Empirical scoring

| Candidate | Internal deps | Consumer files | LOC | Tests | Risk |
|---|---:|---:|---:|---|---|
| testutil | 16+ kc/* deps + cyclic root | (n/a) | 1463 | yes | HIGH (cascade) |
| kc/i18n | 0 | 12 | 458 | yes | LOW-MED |
| kc/legaldocs | 0 | 5 | 11 | no | LOW (but trivial) |
| **kc/decorators** | **0** | **7** | **388** | **yes** | **LOW** |
| kc/registry | 3 (root + isttz + logger) + cyclic | (n/a) | 1519 | yes | MED |
| kc/scheduler | 1 (isttz) | (n/a) | 1329 | yes | LOW (if isttz stable) |

## Pick rationale: kc/decorators

- **Pure leaf**: zero internal `kc/*` Go-dep imports per `go.mod` inspection. Only stretchr/testify external (same as kc/money pattern).
- **Real test coverage** (`decorators_test.go`) preserves invariants during cutover.
- **Active consumer**: `mcp/plugin/decorator_chain.go` exercises the public API at runtime (not a dead module).
- **Compact codebase**: 388 LOC across 2 .go files — extraction + rewrite agent-quick.
- **Moderate consumer count** (7 files): big enough to exercise the sweep, small enough to keep risk low. Larger sample than legaldocs (5) but smaller than i18n (12).
- **No cliff signals**: 2 commits in history, module last touched at extraction time + a single follow-up. Stable shape.

## Why NOT the other candidates

- **testutil**: 16+ internal deps + cyclic to root module. Promotion would force chain-promotion of instruments + logger + riskguard + alerts + audit + billing + cqrs + ... — that's the high-risk "cascade promotion" pattern. Defer until each leaf below it lands.
- **kc/i18n**: Pure leaf but 12 consumers vs decorators' 7. Mechanically identical, but decorators is the smaller blast radius for the first post-broker/money promotion. i18n becomes a logical 2nd or 3rd candidate.
- **kc/legaldocs**: 11 LOC across 1 .go file (an `embed` pointing at TERMS.md + PRIVACY.md). Trivially small — promoting it wouldn't validate "scaling to more consumers" pattern. Better as a later confidence-check.
- **kc/registry**: 3 internal deps + cyclic root. Mid-risk, not leaf-shaped.
- **kc/scheduler**: 1 internal dep on `kc/isttz`. Could work, but adds a transitive chase (isttz → scheduler) we don't need first.

## Scripts to mirror

- `path-a-prep-dryrun.sh` -> `path-a-decorators-prep-dryrun.sh`
- `path-a-prep-rewrite-dryrun.sh` -> `path-a-decorators-rewrite-dryrun.sh`
- `path-a-bootstrap-extracted-repo.sh` -> `path-a-decorators-bootstrap-extracted-repo.sh`
- `path-a-consumer-cutover-apply.sh` -> `path-a-decorators-consumer-cutover-apply.sh`
- `path-b-resume-canary-delete.sh` (Phase B) -> `path-a-decorators-canary-delete.sh` (if Phase B viable in same dispatch)

## Stop-rule per orchestrator brief

- ~4h budget end-to-end
- Halt + surface at ~6h
- If Phase A canary works but Phase B reveals SECOND type-identity blocker, halt at first surfacing

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators IN FLIGHT.
