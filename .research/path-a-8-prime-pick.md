# Path A.8' Pick — kc/templates

**Date**: 2026-05-10
**Selected**: `kc/templates` -> `algo2go/kite-mcp-templates`
**Master HEAD at dispatch**: `71f17eb` (= production v233 + Path A.8 halt research)

## Decision: kc/templates (single promotion)

Per orchestrator authorization of alt-2 from Path A.8 halt-research.
This is the **9th** algo2go module promotion. Single-promotion (not
dual) because kc/templates is a pure leaf with zero internal kc/* deps.

### Empirical scoring

| Module | Files | LOC | Internal deps | Consumer .go | Tests |
|---|---:|---:|---|---:|---|
| **kc/templates** | 1 .go + ~62 .html + 1 .js + static/ | 11 (Go) | NONE (stdlib `embed` only) | 11 | none |

### Pick rationale

- **Pure leaf**: zero internal kc/* deps. go.mod has only stdlib +
  embed directive.
- **Same shape as kc/legaldocs** (Path A.5): single Go file exposing
  `embed.FS` as a byte-data variable. Structurally type-identity-safe.
- **Largest embedded asset bundle yet**: 60+ HTML templates +
  CSS + JS + static/ subdir. Mechanically irrelevant to the
  promotion — go:embed handles them transparently.
- **23 consumer reference points**: 11 .go files + 12 peer go.mods.
  Comparable to kc/legaldocs's footprint.
- **Partially paves billing path**: kc/templates is one of oauth's
  direct deps (oauth -> templates + users). After templates ships
  external, oauth has 1 fewer in-tree dep. Future kc/billing
  promotion needs oauth, so this is preparatory work.

### Type-identity exposure analysis

`kc/templates/templates.go` (11 LOC):
```go
package templates

import "embed"

//go:embed [60+ HTML files] static/*
var FS embed.FS
```

Public API surface = 1 variable (`templates.FS`) of type `embed.FS`.
`embed.FS` is from Go stdlib; identity is invariant across module
paths. No struct types-as-data, no exported function signatures
referencing kc/* types. **Phase B mechanically safe** (same shape
as kc/legaldocs).

### Why kc/templates after the kc/billing halt

kc/billing halt (.research/path-a-8-halt.md) revealed billing's
3-direct-dep cluster (kc/domain + kc/alerts + oauth). To promote
billing safely, those 3 must come first. kc/templates is one of
oauth's deps — promoting it now is FORWARD progress on the
multi-module path eventually leading to billing, even though
templates itself is unrelated to billing's direct exposure.

## Scripts to mirror

- `path-a-legaldocs-prep-dryrun.sh` -> `path-a-templates-prep-dryrun.sh`
- `path-a-legaldocs-rewrite-dryrun.sh` -> `path-a-templates-rewrite-dryrun.sh`
- `path-a-legaldocs-bootstrap-extracted-repo.sh` -> `path-a-templates-bootstrap-extracted-repo.sh`
- `path-a-legaldocs-consumer-cutover-apply.sh` -> `path-a-templates-consumer-cutover-apply.sh`
- `path-a-legaldocs-phase-b-test.sh` -> `path-a-templates-phase-b-test.sh`
- `path-a-legaldocs-canary-delete.sh` -> `path-a-templates-canary-delete.sh`

## Stop-rule per orchestrator brief

- ~2h single-module budget
- Halt + surface at ~3h
- Watchdog: if sensing stalling mid-burst, commit + push + surface

## Cross-session domain

`Path A inauguration owner` — broker DONE, money DONE, decorators
DONE, i18n DONE, legaldocs DONE, isttz DONE, scheduler DONE, logger
DONE, **templates IN FLIGHT**.
