# Path A Future Candidates — post-templates state

**Date**: 2026-05-10
**Master HEAD audited**: `10b30a3` (= post-Path A.8' kc/templates external)
**Promotions complete**: 9 — broker, money, decorators, i18n, legaldocs, isttz, scheduler, logger, templates

## Updated dep-graph for kc/billing (the deferred A.8 candidate)

After kc/templates promotion (Path A.8'), kc/billing's remaining internal kc/* deps are:

```
kc/billing
├── kc/domain (DIRECT — Money, EventDispatcher, TierChangedEvent)
├── kc/alerts (DIRECT — *alerts.DB pointer)
│   └── kc/domain (transitive)
└── oauth (DIRECT — function calls only)
    ├── kc/templates ✅ EXTERNAL (algo2go/kite-mcp-templates v0.1.0)
    ├── kc/users (DIRECT — still in-tree)
    │   └── kc/alerts (transitive)
    ├── kc/alerts (transitive)
    └── kc/domain (transitive)
```

**1 of 5 transitive deps now external.** Still 3 direct + 1 indirect (kc/users) blocking
single-promotion of kc/billing. **kc/billing remains in cluster-promotion territory.**

To unblock kc/billing single-promotion, need:
1. kc/domain promoted (foundation for billing+alerts+oauth)
2. kc/alerts promoted (depends on domain)
3. kc/users promoted (depends on alerts)
4. oauth promoted (depends on users + alerts + domain + templates [done])
5. THEN kc/billing single-promotion becomes safe

That's a 4-module sprint before billing. Total ~8h spread across 2-3 dispatches.

## Other candidates by safety

### Tier 1: Pure-leaf singles (~1.5-2h each, low risk)

Lookup with `cat kc/<mod>/go.mod | grep -E 'kite-mcp-server|algo2go' | grep -v '^//'`:

| Module | LOC | Internal deps | Phase B safety |
|---|---:|---|---|
| **kc/aop** | (audit needed) | TBD | likely leaf — needs verification |
| **kc/instruments** | (audit needed) | TBD | likely leaf — needs verification |

### Tier 2: Single-internal-dep singles (deferred, need foundation first)

| Module | Internal deps | Foundation needed |
|---|---|---|
| kc/domain | none direct, but transitively pulls broker, money | broker + money external (DONE) — but check broker fields for domain types |
| kc/users | kc/alerts | kc/alerts external |
| kc/alerts | kc/domain | kc/domain external |

### Tier 3: Multi-internal-dep modules (cluster-promotion territory)

| Module | Internal deps count | Recommendation |
|---|---:|---|
| kc/billing | 3 direct + transitive | Cluster (after kc/{domain,alerts,users,oauth}) |
| kc/registry | 3 + cyclic root | Audit before attempting |
| kc/audit | varies | Audit before attempting |
| kc/riskguard | varies | Audit before attempting |
| kc/eventsourcing | likely heavy | Audit before attempting |
| kc/cqrs | likely heavy | Audit before attempting |
| kc/papertrading | varies | Audit before attempting |
| kc/telegram | varies | Audit before attempting |
| kc/usecases | many — central app logic | Last to promote |
| testutil | 16+ + cyclic root | DEFER indefinitely |

## Recommended next dispatches

### Path A.9 — kc/domain (single, foundation-shape)

If kc/domain has no remaining internal kc/* deps after broker + money external,
promote it as the next foundation module. Unblocks kc/alerts → kc/users → oauth → kc/billing chain.

**Audit kc/domain first** — it may have transitive deps via broker (Order, Position
fields) that surface even though the package go.mod looks clean.

### Path A.10 — kc/alerts (depends on kc/domain external)

After kc/domain ships, kc/alerts becomes a single-internal-dep candidate
(workflow same as Path A.6.2 kc/scheduler-after-isttz).

### Path A.11+ — sprint pipeline

Continue: kc/users → oauth → kc/billing.

## Metrics summary at HEAD 10b30a3

- **Modules promoted**: 9 (broker, money, decorators, i18n, legaldocs, isttz,
  scheduler, logger, templates)
- **Modules in workspace**: 21 (was 30 pre-Path-A; -9 promoted, +0 added)
- **Phase A canaries deleted**: 7 events (5 single + 1 dual + 1 single = covers
  9 modules: broker, money, decorators, i18n, legaldocs, isttz, scheduler,
  logger, templates — money was paired with broker in alt-1)
- **Per-promotion agent cost**: stable at ~1.5-2.5h for single-leaf, ~3-4h for
  dual-promotion
- **Largest sweep observed**: 118 files (kc/logger)
- **Smallest sweep observed**: 5 files (kc/legaldocs)
- **Production deploys**: tools=111 invariant held across all 9 promotions
- **External GitHub repos under algo2go/**: 9 (all v0.1.0)
- **GOPROXY-fetchable + sum-DB-verified**: 9/9
