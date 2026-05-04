# 100% Decomposition Strategy — empirical re-frame post-commit-3

**Date**: 2026-05-04
**HEAD**: `9ce2248` (commit 3 of 5/5 grind)
**Charter**: read-only re-frame; commit + push doc only.

---

## Q1 — What does "100% decomposition" mean? (1 answer)

**(f) Hybrid: separate go.mod for the bounded contexts that have a
genuinely standalone consumer story (`kc/money`, `broker/`, riskguard
spin-out for second-broker future, `kc/audit` as observability lib);
keep the rest as packages inside the root module.**

**Why**: Empirically, "module boundary" buys exactly two things — (i)
external `go get` discoverability, (ii) per-module CI scope isolation.
Neither benefit applies to packages that have ONE consumer (the root
module itself). Options (b) full granularity / (d) microservices /
(e) hexagonal-pure all add complexity faster than they add capability
at our 64,705-LOC + solo-team scale. (c) Multi-repo split was
correctly rejected in `1848a96`; commit-3 evidence reinforces — see Q2.

---

## Q2 — Marginal cost-curve from real data

| Commit | Module | Internal deps | Replace lines in NEW module's go.mod | Dockerfile COPY layers added | Setup time |
|---|---|---:|---:|---:|---:|
| `b7fedcc` | `kc/money` | 0 | 0 | 1 | ~45 min |
| `5d74acf` | `broker` | 1 (`kc/money`) | 1 | 1 | ~30 min |
| `9ce2248` | `kc/audit` | 4 (`kc/alerts`, `kc/domain`, `kc/logger`, `oauth`) + 2 transitive (`broker`, `kc/money`) | **3** | 1 | ~50 min |

**Trajectory**: replace count grows ~linearly with already-extracted-and-
transitively-imported set. For commit 4 (`kc/riskguard`, same 4 internal
deps + same 2 transitive) the count is **3** again. For commit 5
(`kc/billing`, same shape) also **3**. After that, future extractions
of `kc/alerts`/`kc/domain`/`kc/logger`/`oauth` would each force a
GLOBAL update of every prior module's replace block — N modules × N
replace blocks = N² maintenance.

**Marginal lift to agent-concurrency**: zero observable. Per
`feedback_decoupling_denominator.md` Axis B, isolation pays off when
N agents work on disjoint scopes. Empirically, kc/audit / riskguard /
billing have shared upstream deps (kc/alerts, kc/domain) — touching
those forces test-runs across all dependent modules anyway. Module
boundaries don't enable concurrency for THIS dep graph.

**Marginal complexity**: every commit adds 1 Dockerfile layer + 1
go.work entry + N replace lines. Commit 3's transitive-replace
discovery added ~20 min vs commit 2 even though both are "nominally
the same effort". Curve is super-linear.

---

## Q3 — ROI cliff identification

**The cliff is between commits 3 and 4.** Empirical thresholds:

1. **Replace-line count: 3 was the breakpoint.** Commits 1-2 had ≤1
   replace per new module; commit 3 needed 3. Future kc/riskguard +
   kc/billing also need 3 each. The N² maintenance threshold hits at
   the FIRST extraction of a "shared upstream" (kc/alerts or
   kc/domain) — which currently sits in the root module. Every prior
   extracted module's replace block updates simultaneously.
2. **Standalone-consumer test: only kc/money + broker pass it
   today.** kc/audit COULD pass it (audit-as-library is a real story
   per `5437c32` §4.1.10), but no external consumer has asked.
   kc/riskguard / kc/billing fail the test — billing is Stripe-tier
   gating specific to OUR product; riskguard is meaningful only with
   a 2nd broker integration which doesn't exist yet.
3. **Dockerfile layer growth: N pre-COPY layers per N modules.** At
   N=5 (planned grind) cache-busting risk is manageable; at N=10
   (full granularity) cache invalidation cascades on every go.mod
   touch.

**Conclusion**: ROI cliff at commit 4. Commits 4-5 add ceremony
without buying capability that the existing 3 modules don't already
provide.

---

## Q4 — Dispatchable next step

**Stop multi-module work at 3/5. Pivot to Show HN.**

Rationale: the user's stated goal is "100% decomposition" but the
empirical denominator (Q1's hybrid definition) is **already at 3/3
of the modules that have a defensible standalone-consumer story**.
kc/riskguard + kc/billing are root-module-internal infrastructure;
extracting them is ceremony at this scale.

**Recommended dispatch sequence (orchestrator)**:

1. **Commit 0 (no scope change)**: ping chain agent for v189
   redeploy validating commit 3 in production. Confirms multi-module
   Dockerfile path holds at 3 modules.
2. **Pre-launch close-out** (≤2 hrs solo budget):
   - Update `README.md` with the "3 extracted modules" framing as
     architecture credit (FLOSS-fund / Rainmatter pitch material;
     commits b7fedcc + 5d74acf + 9ce2248 are now Git-history evidence
     of in-tree workspace decomposition).
   - Add `.research/disintegrate-and-holistic-architecture.md`'s
     trigger conditions to README's "future work" section so the
     deferred extractions read as intentional, not abandoned.
3. **Show HN dispatch** — different agent. Multi-module work is no
   longer in the Show HN critical path.
4. **Future trigger-driven extraction (NOT pre-launch)**: when one
   of the deferred modules accumulates an external consumer (e.g.,
   another team requests `riskguard-go` standalone after Show HN),
   do that extraction THEN per the Q1 hybrid criterion.

**Push-back on user's "100%" framing**: per
`feedback_decoupling_denominator.md`, state preconditions explicitly.
The "100%" goal is achievable only at option (b) full-granularity
(~50 modules) which has zero ROI at our scale. The hybrid
interpretation (Q1) reads "100%" as "100% of modules with defensible
standalone-consumer story" — and we're at 3/3 today.

If user insists on (a) 5/5 of original plan: estimate +1.5 hrs +
+2 Dockerfile layers + 6 more replace lines for marginal-zero
benefit. Document as ceremony in the commit messages.

---

## Sources

- Commit `b7fedcc` (kc/money) — empirical 0-replace baseline
- Commit `5d74acf` (broker) — empirical 1-replace
- Commit `9ce2248` (kc/audit) — empirical 3-replace (transitive)
- `.research/disintegrate-and-holistic-architecture.md` (`5437c32`) —
  prior trigger framework: 50 stars, 2nd consumer, FLOSS pitch
- `.research/multi-product-and-repo-structure.md` (`39577c3`) — Q4+Q5
  hybrid (5E) landed; this doc reinforces hybrid 3/3 today
- `feedback_decoupling_denominator.md` — Axis B agent-concurrency
  framework; marginal lift = 0 for shared-upstream dep graph

---

*2026-05-04. Read-only. Cliff at commit 4; pivot to Show HN.*
