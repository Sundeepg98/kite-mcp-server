# Path A.10 Pick — kc/domain

**Date**: 2026-05-10
**Selected**: `kc/domain` -> `algo2go/kite-mcp-domain`
**Master HEAD at dispatch**: `f16ad85` (= production v234 + Path A.9 kc/aop external)

## Decision: kc/domain (single promotion, Tier 2 foundation)

Per orchestrator dispatch authorizing kc/instruments OR kc/domain.
Picked kc/domain because the original "transitive type exposure"
concern is **mooted**: all 3 of kc/domain's internal deps are
already external (algo2go/kite-mcp-broker + kite-mcp-isttz +
kite-mcp-money, all v0.1.0 published).

This is the **11th** algo2go module promotion. Single-promotion
because kc/domain's go.mod has zero unpromoted internal kc/* deps.

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer files | Tests |
|---|---:|---:|---|---:|---|
| **kc/domain** | 33 | 7721 | 3 ALL EXTERNAL (broker, isttz, money) | 165 (186 occurrences) | yes |
| kc/instruments (alt) | 7 | 2816 | 1 (algo2go/kite-mcp-isttz already external) | ~50 | yes |

### Pick rationale: kc/domain over kc/instruments

**Strategic value**:
- kc/domain unblocks **the kc/billing chain** (kc/alerts depends on
  domain; kc/users depends on alerts; oauth depends on users +
  alerts + domain; kc/billing depends on alerts + domain + oauth).
  Promoting kc/domain takes the first step on that chain.
- kc/instruments unblocks 0 future modules — it's a pure leaf with
  no downstream chain.

**Type-identity safety**:
- kc/domain's 3 internal deps (broker, isttz, money) are ALL ALREADY
  EXTERNAL on algo2go. The original "broker.Order/Position transitive
  exposure" concern from .research/path-a-future-candidates.md is
  resolved — broker types resolve via GOPROXY, not via in-tree
  workspace replace.
- Verified empirically: kc/domain/*.go imports include
  "github.com/algo2go/kite-mcp-broker", "github.com/algo2go/kite-mcp-isttz",
  "github.com/algo2go/kite-mcp-money" already (the in-tree go.work
  resolves these to upstream versions for builds).

**Sweep size**:
- 165 consumer files (186 occurrences) — bigger than kc/logger's 118
- Mechanically identical to kc/logger pattern (proven 10×)
- ~3-4h budget (matches Tier 2 estimate)

### Why not kc/instruments

kc/instruments would be cleaner (~50 consumers vs 165) but provides
ZERO unblocking value for the kc/billing chain. We can promote it
in Path A.11 if needed — it's not going anywhere. kc/domain has
strategic-value compounding.

### Dep-graph audit

```
kc/domain
├── algo2go/kite-mcp-broker v0.1.0 (external — resolves via GOPROXY)
├── algo2go/kite-mcp-isttz v0.1.0 (external — resolves via GOPROXY)
└── algo2go/kite-mcp-money v0.1.0 (external — resolves via GOPROXY)
```

**All deps external. Phase A canary works (in-tree replace short-
circuits + workspace mode resolves via go.work). Phase B works
(upstream go.mod requires only algo2go paths, all of which are
GOPROXY-fetchable).** No type-identity blocker possible.

### Type exposure surface

kc/domain exports:
- DDD value objects (Money, Quantity wrapper, etc. — money type
  comes from algo2go/kite-mcp-money, so identity propagates through)
- DDD entities (Order, Position, Holding, Profile, Session, Alert,
  Family, Glossary)
- Event types (TierChangedEvent, OrderPlacedEvent, etc.)
- EventDispatcher

After promotion, all consumers will import via algo2go path,
resolving to the same upstream module's types. No identity split.

## Scripts to mirror

- `path-a-logger-prep-dryrun.sh` -> `path-a-domain-prep-dryrun.sh`
- `path-a-logger-rewrite-dryrun.sh` -> `path-a-domain-rewrite-dryrun.sh`
- `path-a-logger-bootstrap-extracted-repo.sh` -> `path-a-domain-bootstrap-extracted-repo.sh`
- `path-a-logger-consumer-cutover-apply.sh` -> `path-a-domain-consumer-cutover-apply.sh`
- `path-a-logger-phase-b-test.sh` -> `path-a-domain-phase-b-test.sh`
- `path-a-logger-canary-delete.sh` -> `path-a-domain-canary-delete.sh`

(kc/logger had 118 consumers — most directly comparable scale.)

## Stop-rule per orchestrator brief

- ~3-4h budget
- Halt + surface at ~5h
- If hidden cluster surfaces (e.g., a transitive dep nobody noticed),
  halt at first surfacing
- Watchdog: if sensing stalling mid-burst, commit + push + surface

## Forward-looking impact

After kc/domain ships, the future-candidates table updates:

| Module | Direct internal deps | Status after kc/domain external |
|---|---|---|
| kc/alerts | kc/domain | **Single-promotion candidate** (1 dep external) |
| kc/users | kc/alerts | Still needs alerts external |
| oauth | kc/templates ✅ + kc/users + kc/alerts + kc/domain | Still needs users + alerts external |
| kc/billing | kc/alerts + kc/domain + oauth | Still needs alerts + oauth external |

Path A.11 most viable: kc/alerts (single-leaf after domain external).

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger
DONE, templates DONE, aop DONE, **domain IN FLIGHT**.
