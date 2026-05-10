# Path A.8 Halt — kc/billing Has 5+ Internal Dep Cluster

**Date**: 2026-05-10
**Master HEAD audited**: `bb9e747` (= production v233)
**Halt trigger**: type-identity / dep-graph stop-rule per orchestrator brief — "If billing has hidden complexity (cross-package state, money-coupling cliff) — halt at first surfacing."

---

## TL;DR

**Path A.8 single-promotion of kc/billing is NOT viable.** kc/billing has 3 direct internal kc/* deps (kc/domain, kc/alerts, oauth) plus indirect/transitive deps on kc/templates, kc/users, and testutil — none of which are externalized to algo2go yet. This is a structural cliff far exceeding the ~3h single-promotion budget.

The original "money-coupling concern" the orchestrator flagged is RESOLVED (kc/money is external, kc/billing's go.mod correctly requires `algo2go/kite-mcp-money v0.1.0`). But promotion exposes a **deeper cluster** of internal deps that wasn't visible from the money perspective alone.

Recommendation: **Halt + surface**. Defer kc/billing until at least kc/domain + kc/alerts + oauth are externalized as a unit (or one-by-one in dependency order).

---

## Empirical evidence

### 1. kc/billing has 3 DIRECT internal kc/* deps

From `kc/billing/go.mod` require block:
```
require (
    ...
    github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-...   // DIRECT
    github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-...   // DIRECT
    github.com/zerodha/kite-mcp-server/oauth v0.0.0-...       // DIRECT
)
```

Verified via `grep -hE 'kite-mcp-server/(kc/(alerts|domain)|oauth)' kc/billing/*.go`:
```
"github.com/zerodha/kite-mcp-server/kc/alerts"
"github.com/zerodha/kite-mcp-server/kc/domain"
"github.com/zerodha/kite-mcp-server/oauth"
```

### 2. Type-identity exposure (the kc/money halt scenario at scale)

kc/billing exports the following cross-package types-as-data:

```go
// kc/billing/store.go
func (s *Store) SetEventDispatcher(d *domain.EventDispatcher) { ... }
//                                    ^^^^^^^^^^^^^^^^^^^^^^^^
//                                    pointer to kc/domain struct

func NewStore(db *alerts.DB, logger *slog.Logger) *Store { ... }
//                ^^^^^^^^^^
//                pointer to kc/alerts struct

// kc/billing/tiers.go
func TierMonthlyINR(t Tier) domain.Money { ... }
//                          ^^^^^^^^^^^^
//                          kc/domain.Money (which transitively wraps
//                          algo2go/kite-mcp-money.Money via re-export)

// kc/billing/billing_test.go (and prod paths)
e.(domain.TierChangedEvent)
//   ^^^^^^^^^^^^^^^^^^^^^^^
//   kc/domain.TierChangedEvent (struct type — fully exposed)
```

If we promote kc/billing alone:
- Upstream `algo2go/kite-mcp-billing@v0.1.0` will have `require github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-...`
- Per Go's module rules, the upstream's `replace ../domain` is silently dropped when consumed as a dep
- Go will try to fetch `zerodha/kite-mcp-server/kc/domain@v0.0.0-...` from GOPROXY → fails because that pseudo-version doesn't exist as a published tag

This is the EXACT kc/money halt scenario from Path B-pre, just at a larger scale (3 unpromoted deps vs 1).

### 3. Transitive cluster expansion

The cluster doesn't stop at billing's direct 3 deps:

```
kc/billing
├── kc/domain (DIRECT)
├── kc/alerts (DIRECT)
│   └── kc/domain (transitive)
└── oauth (DIRECT)
    ├── kc/templates (DIRECT — oauth requires templates for OAuth UI)
    ├── kc/users (DIRECT — oauth requires users for identity)
    │   └── kc/alerts (transitive)
    ├── kc/alerts (transitive)
    └── kc/domain (transitive)
```

### 4. testutil cyclic-cluster bonus risk

kc/billing's tests import testutil. testutil itself has 16+ internal deps — including a cyclic dep on the root module. Promoting kc/billing's test surface would either require omitting tests OR pre-promoting testutil. Per prior research notes, **testutil is the highest-risk module in the codebase** and explicitly deferred.

### 5. Census of other-direction reverse-deps

`grep github.com/zerodha/kite-mcp-server/kc/billing` returns 36 files. These are CONSUMERS of kc/billing — Phase A canary cutover would need to sweep them all. Mechanical, not a halt blocker on its own, but adds to the workload.

---

## Why Phase A canary "would work" but Phase B wouldn't

Phase A canary creates a workspace `replace github.com/algo2go/kite-mcp-billing => ./kc/billing` so the in-tree directory remains canonical. In workspace mode, the replace + go.work entries make all type-identity work cleanly.

But **Phase B canary deletion** (drop replace + delete in-tree directory) requires the upstream module to be self-resolving via GOPROXY. The upstream's `require zerodha/.../kc/domain` with a workspace-pseudo-version simply won't resolve.

The kc/money halt-research methodology demonstrates this exactly: when broker required `algo2go/kite-mcp-money` and that module wasn't published, Phase B failed. The fix was to promote kc/money first as a foundation. Same fix applies here, but at 3-5x the scale.

---

## Resolution paths (any one unblocks Path A.8)

### alt-1 (preferred): Multi-module promotion in dep order

Promote in this order (mirror Path A.6 dual-promotion mechanic, scaled to quad/penta):

1. **kc/templates** (pure leaf, 10 LOC embed) — ~1h
2. **kc/users** (1 internal dep on kc/alerts, but alerts also needed; promote AFTER alerts) — defer
3. **kc/domain** (DDD entities, foundation for billing+alerts+oauth) — ~1.5h
4. **kc/alerts** (depends on domain) — ~1.5h
5. **oauth** (depends on templates + users + alerts + domain) — ~2h
6. **kc/billing** (depends on alerts + domain + oauth) — ~2h

Total: ~10h spread across 4-6 dispatches. Single-dispatch budget would be ~1-2 modules at most.

### alt-2: Skip kc/billing, pick a simpler 9th candidate

Lower-risk leaves still available:
- kc/templates (10 LOC embed leaf, similar to legaldocs) — ~1.5h
- kc/aop (need to audit, probably leaf)

### alt-3: Promote billing-as-cluster

Treat kc/templates + kc/users + kc/domain + kc/alerts + oauth + kc/billing as a single
6-module dispatch. ~10h. Far exceeds single-dispatch budget. Would require explicit
authorization from orchestrator.

### alt-4: Defer kc/billing indefinitely

Mark kc/billing as "non-leaf, deep cluster, not viable for solo single-promotion". Move
to next candidate.

---

## Recommendation

**Halt Path A.8 (kc/billing single).** Surface to orchestrator. Default recommendation:

- **Path A.8' (alt-2)**: pick kc/templates as the actual 9th promotion. Pure-leaf embed
  module (10 LOC, like kc/legaldocs). ~1.5h budget. Follows the proven single-leaf
  pattern. Externalization of kc/templates also unblocks oauth's direct dep, partially
  paving the path toward a future kc/billing promotion in a deeper sprint.

If alt-1 is authorized: schedule kc/domain + kc/alerts as a Path A.9 dual (mirror
isttz+scheduler dual). After both ship, kc/users + oauth become viable. After ALL FOUR
ship, kc/billing becomes viable. ~10h total spread across multiple dispatches.

---

## Production state (unchanged)

- v233 LIVE: tools=111, version v1.3.0
- master HEAD: `bb9e747` (this halt research will be the next commit)
- algo2go org: 8 published modules (broker, money, decorators, i18n, legaldocs, isttz, scheduler, logger)
- No mutations to broker / billing / go.mod / go.work

## Cross-session domain (unchanged)

`Path A inauguration owner; 8 modules promoted; Path A.8 (kc/billing) halted on
deep-cluster dep-graph at first surfacing.` Idle until orchestrator decides on
alt-1 (multi-module promotion) vs alt-2 (skip billing, pick simpler candidate).

---

**End. Doc-only. No master mutations beyond this halt research commit. No
deploy-ready signal.**
