# Path A.4 Pick — kc/i18n

**Date**: 2026-05-09
**Selected**: `kc/i18n` -> `algo2go/kite-mcp-i18n`
**Master HEAD at dispatch**: `52204eb` (4 commits past v228; v229 deploy in flight)

## Decision: kc/i18n over kc/legaldocs

**Pick: kc/i18n**

Both candidates are pure leaves (zero internal `kc/*` deps). Decision matrix:

| Trait | kc/i18n | kc/legaldocs |
|---|---|---|
| Internal deps | 0 | 0 |
| External deps | stretchr/testify | none (stdlib only) |
| LOC | 458 | 11 |
| Consumer .go files | 3 (app/http.go + kc/riskguard/middleware.go + kc/riskguard/rejection_message_test.go) | 1 (app/legal.go) |
| Peer go.mod sweep scope | 5 (incl. kc/riskguard) | 4 |
| Tests | i18n_test.go (real coverage) | none (just embeds) |
| Embedded assets | locales/*.yaml | TERMS.md + PRIVACY.md |
| Demonstrates | cross-peer sweep + tests | trivial-leaf flow |

**Reasoning**:
- kc/i18n has REAL test coverage (i18n_test.go) — preserves invariant during cutover
- 3 distinct consumer files INCLUDING a kc/* peer (kc/riskguard) — exercises the cross-peer sweep that broker + money + decorators all touched
- Larger sweep is BETTER for demonstrating "it scales" — the brief said "kc/i18n is more substantive (better velocity demonstration)"
- 458 LOC compact codebase — extraction agent-quick
- locales/*.yaml in subdirectory — exercises filter-repo's subtree handling beyond just root files

**Why not kc/legaldocs**:
- Trivially small (11 LOC) — wouldn't validate "scaling to more consumers" or cross-peer sweep
- No Go tests, only embedded markdown — invariant test wouldn't cover much
- Better as a confidence-check post-i18n if user wants a rapid 5th promotion

## Type-identity Phase B preview

kc/i18n exports `Locale` as a string-newtype + `T()`/`ParseAcceptLanguage()`/etc. functions. Consumers (app/http.go, kc/riskguard/middleware.go) use `i18n.Locale(...)` casts.

**Phase B viability**: no other algo2go module currently imports kc/i18n (broker/money/decorators are independent). Consumer module is just kite-mcp-server, so dropping the in-tree replace + going to upstream-only fetch should work without type-identity blocker.

Confirmation via scratch viability test (decorators methodology) before applying Phase B on master.

## Scripts to mirror

- `path-a-decorators-prep-dryrun.sh` -> `path-a-i18n-prep-dryrun.sh`
- `path-a-decorators-rewrite-dryrun.sh` -> `path-a-i18n-rewrite-dryrun.sh`
- `path-a-decorators-bootstrap-extracted-repo.sh` -> `path-a-i18n-bootstrap-extracted-repo.sh`
- `path-a-decorators-consumer-cutover-apply.sh` -> `path-a-i18n-consumer-cutover-apply.sh`
- `path-a-decorators-phase-b-test.sh` -> `path-a-i18n-phase-b-test.sh`
- `path-a-decorators-canary-delete.sh` -> `path-a-i18n-canary-delete.sh`

## Stop-rule per orchestrator brief

- ~4h budget end-to-end
- Halt + surface at ~6h
- If Phase B reveals type-identity blocker, halt at first surfacing

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators DONE, **i18n IN FLIGHT**.
