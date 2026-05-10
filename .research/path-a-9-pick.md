# Path A.9 Pick — kc/aop

**Date**: 2026-05-10
**Selected**: `kc/aop` -> `algo2go/kite-mcp-aop`
**Master HEAD at dispatch**: `76ae3dc` (= production v233 + Path A.8' kc/templates external)

## Decision: kc/aop (single promotion)

Per orchestrator dispatch authorizing Tier 1 single-leaf candidate.
This is the **10th** algo2go module promotion. Single-promotion
because kc/aop is a true pure leaf — zero internal kc/* deps AND
zero algo2go transitive deps.

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer .go | Tests |
|---|---:|---:|---|---:|---|
| **kc/aop** | 6 | 2424 | NONE (pure leaf, no algo2go transitive deps) | 0 outside kc/aop itself | yes |
| kc/instruments (alt) | 7 | 2816 | 1 (algo2go/kite-mcp-isttz already external) | 50+ | yes |

### Pick rationale

- **Truest leaf yet**: zero internal kc/* deps in go.mod, zero algo2go
  transitive deps. Only stretchr/testify external. Simpler than even
  kc/decorators (which had 1 algo2go-isttz indirect dep).
- **Zero external consumers**: only kc/aop's own 3 test files import
  the package. No mcp/, kc/, or app/ consumer needs rewriting. This
  will be the smallest sweep yet (smaller than kc/legaldocs's 5 files).
- **Real test coverage**: aop_test.go + proxy_test.go +
  example_audit_riskguard_test.go (4/6 files are tests). Preserves
  invariant during cutover.
- **2424 LOC is substantial** but mechanically irrelevant: filter-repo
  doesn't care about file size, just import-path identity.
- **Type-identity safety**: kc/aop's exported types are generic proxy
  types. Even if consumers used them, they'd reference upstream
  algo2go path post-cutover — and there are no consumers.

### Why kc/aop over kc/instruments

Both are clean Tier 1 candidates per future-candidates research, but:
- kc/aop has **0 external consumers** vs kc/instruments's 50+
- Smaller blast radius for the cutover sweep
- kc/instruments brings 50+ rewrite operations + the kc/* peer
  go.mods, comparable to kc/logger (118-file sweep). Still mechanical
  but bigger.
- Pick the smaller one first (kc/aop), defer kc/instruments to A.10
  if needed.

### Dep-graph audit (per orchestrator stop-rule)

```
kc/aop
└── (NONE — zero internal deps, zero algo2go transitive deps)
```

`grep -rE '"github\.com/zerodha/kite-mcp-server/kc/aop"' --include='*.go'`
returns only 3 files — all kc/aop's own test files. No external
consumers exist. The 3 peer go.mod files (root, plugins, app/providers)
listed kc/aop as a workspace-resolved indirect — those were artifacts
of go.work mechanics, not real Go-import sites.

**Verdict: structurally type-identity-safe at every layer.** No
kc/billing-style cluster cliff possible.

## Scripts to mirror

- `path-a-templates-prep-dryrun.sh` -> `path-a-aop-prep-dryrun.sh`
- `path-a-templates-rewrite-dryrun.sh` -> `path-a-aop-rewrite-dryrun.sh`
- `path-a-templates-bootstrap-extracted-repo.sh` -> `path-a-aop-bootstrap-extracted-repo.sh`
- `path-a-templates-consumer-cutover-apply.sh` -> `path-a-aop-consumer-cutover-apply.sh`
- `path-a-templates-phase-b-test.sh` -> `path-a-aop-phase-b-test.sh`
- `path-a-templates-canary-delete.sh` -> `path-a-aop-canary-delete.sh`

## Stop-rule per orchestrator brief

- ~3h single-module budget
- Halt + surface at ~4h
- If type-identity blocker surfaces (unlikely given zero consumers),
  halt at first surfacing
- Watchdog: if sensing stalling mid-burst, commit + push + surface

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger
DONE, templates DONE, **aop IN FLIGHT**.
