# Minimum-LOC Path to Score 98

**Synthesis of**: `final-138-gap-catalogue.md`, `agent-state.md`, `c1-ctx-propagation-plan.md` (`7a36300`), `phase-3a-manager-port-migration.md` (`d9fdd06`), `ctx-background-audit.md` (`2a6e62b`).

**Baseline (HEAD `2a6e62b`)**: ~96 honest aggregate (per `agent-state.md` line 95 — Sprint 1+2 already shipped). **Catalogue baseline of 89.5 is stale** — Agent A has merged ~46 gaps' worth of fixes since Pass 25.

**Charter**: Read-only research deliverable. No source files modified.

---

## 1. Current state per dim (HEAD `2a6e62b`)

Estimates account for closed gaps post-Sprint 1+2 merge. Catalogue baseline → today reflects work shipped by Agent A across the PR-A through PR-MR + Block 1-4 + G99/G132 batches.

| # | Dimension | Catalogue baseline | Today (~96 aggregate) | Cost-Just ceiling | Distance to 98 |
|---|---|---|---|---|---|
| 1 | CQRS | 92 | 96 (kc/ops admin via bus, OAuth/login via bus) | 99 | +2 |
| 2 | Hexagonal | 80 | 88 (broker DTO partial unwrap) | 97 | +10 |
| 3 | DDD | 92 | 95 (Family + Credential aggregates extracted) | 98 | +3 |
| 4 | Event Sourcing | 85 | 92 (DPDP §11 export, FamilyMemberRemoved event subscribed) | 97 | +6 |
| 5 | Middleware | 95 | 96 | 97 | +2 |
| 6 | SOLID | 88 | 90 (FamilyService thinner) | 96 | +8 |
| 7 | Plugin | 95 | 97 (Plugin#9/14 critical, manifest hygiene shipped) | 100 | +1 |
| 8 | Decorator | 95 | 96 | 98 | +2 |
| 9 | Test Architecture | 92 | 93 (28 t.Setenv unchanged) | 99 | +5 |
| 10 | Compatibility | 78 | 80 | 95 | +18 |
| 11 | Portability | 72 | 75 (sin region documented as deferred) | 90 | +15 |
| 12 | NIST CSF 2.0 | 74 | 78 (chaos test stub, restore validation noted) | 92 | +14 |
| 13 | Enterprise Governance | 45 | 50 (DPDP doc, agent-state) | 95 | +48 |

**Aggregate honest today: ~96.0**. Catalogue's published Sprint 1+2 progression (`92→95`) was conservative — actual is closer to `96` because Agent A's merges hit multiple dims simultaneously per commit.

**Path to 98 requires +2.0pt aggregate**. Several dims are already at/above 95 — leverage is in dims with low LOC-cost-per-point.

---

## 2. Score-lift density per shipped scope

LOC : dim-pts ratio. Higher = more efficient. Computed against today's baseline.

| Item | LOC | Dims lifted | Pts lifted | Density (pts/100 LOC) | Status |
|---|---|---|---|---|---|
| **C1 ctx propagation** (commit `7a36300` plan) | 100 | Go-idiom, Sec | +0.5 | **0.50** | Plan shipped, not coded |
| **ctx.Background audit** (commit `2a6e62b` plan, 19 Cat-B sites) | 50 | Go-idiom, Obs | +0.4 | **0.80** | Plan shipped, not coded |
| **Phase 3a Batch 1** (`d9fdd06` Batch 1, ~33 sites) | 50 | Hex, SOLID | +0.6 | **1.20** | Plan shipped, not coded |
| **Phase 3a Batch 2** (~30 sites session/cred) | 80 | Hex, SOLID | +0.5 | 0.63 | Plan shipped, not coded |
| **Phase 3a Batch 3** (~30 sites admin) | 70 | Hex, SOLID | +0.4 | 0.57 | Plan shipped, not coded |
| **Phase 3a Batch 4** (~30 sites order/write) | 80 | Hex, SOLID | +0.4 | 0.50 | Plan shipped, not coded |
| **Phase 3a Batch 5** (~45 sites widget/cleanup) | 100 | Hex, SOLID | +0.3 | 0.30 | Plan shipped, not coded |
| Plugin#22 RegisterFullPlugin convenience | 40 | Plugin, DX | +0.3 | 0.75 | catalogue, no plan |
| ES-billing webhook events (catalogue) | 120 | ES | +0.6 | 0.50 | catalogue, no plan |
| ES-paper Reset/Disable/Modify events (catalogue) | 80 | ES | +0.4 | 0.50 | catalogue, no plan |
| Plugin#6 subprocess SBOM helper (catalogue) | 25 | Plugin, Sec | +0.2 | 0.80 | catalogue, no plan |
| G108 docs/adr/ skeleton + 5 ADRs | 400 | EntGov | +1.5 | 0.38 | catalogue, no plan |
| G110 data classification doc | 80 | EntGov, Reg | +0.5 | 0.63 | catalogue, no plan |
| G118 26 doc.go files | 500 | EntGov | +1.0 | 0.20 | catalogue, no plan |
| G120 tool-surface lock test | 30 | TestArch, Gov | +0.4 | **1.33** | catalogue, no plan |
| G124 chaos test suite | 200 | DR/NIST | +0.6 | 0.30 | catalogue, no plan |
| G126 R2 restore validation | 100 | DR/NIST/Reg | +0.5 | 0.50 | catalogue, no plan |
| Sprint 4c env-interface refactor | 250 | TestArch | +0.5 | 0.20 | catalogue, no plan |

**Highest-density items** (≥0.75 pts/100 LOC):
1. **G120 tool-surface lock test** — 30 LOC for +0.4 pts (1.33 density)
2. **Phase 3a Batch 1** — 50 LOC for +0.6 pts (1.20 density)
3. **ctx.Background audit Phase 1-3** — 50 LOC for +0.4 pts (0.80 density)
4. **Plugin#6 subprocess SBOM helper** — 25 LOC for +0.2 pts (0.80 density)
5. **Plugin#22 RegisterFullPlugin convenience** — 40 LOC for +0.3 pts (0.75 density)

---

## 3. Minimum-LOC path to honest 98.0

Sequence highest-density first; stop when marginal density < 0.4 pts/100 LOC.

### Sequenced PR list (target +2.0 pts)

| # | Item | LOC | +Pts | Cumulative | Cumulative LOC |
|---|---|---|---|---|---|
| 1 | **G120 tool-surface lock test** | 30 | +0.4 | 96.4 | 30 |
| 2 | **Phase 3a Batch 1** (read-only QueryBus consumers) | 50 | +0.6 | 97.0 | 80 |
| 3 | **ctx.Background audit Phases 1-3** (B1-B17, ~17 Cat-B sites) | 50 | +0.4 | 97.4 | 130 |
| 4 | **Plugin#6 subprocess SBOM helper** | 25 | +0.2 | 97.6 | 155 |
| 5 | **Plugin#22 RegisterFullPlugin convenience** | 40 | +0.3 | 97.9 | 195 |
| 6 | **G110 data classification doc** | 80 | +0.5 | 98.4 | 275 |

**Stops at PR #6**: cumulative score 98.4, cumulative LOC 275.

**Marginal density of next-best PR (Phase 3a Batch 2, 0.63)**: still above 0.4 threshold — could continue to 99 if appetite remains. Stops at 98 because the goal was honest 98, not 99.

### Total budget: **~275 LOC for 96.0 → 98.4** (overshoots target by 0.4pt — gives margin for rounding-down on partial-shipped items).

### Risk profile

- **#1 G120 (lock test)**: LOW risk. Pure test addition. Detects future regressions; doesn't change runtime.
- **#2 Phase 3a Batch 1**: LOW risk. Read-only QueryBus migration, mock-friendly, mechanical rewrites.
- **#3 ctx.Background Phases 1-3**: LOW risk. No semantic changes, just plumbing.
- **#4 Plugin#6**: LOW risk. Adds new helper, no breaking change.
- **#5 Plugin#22**: LOW risk. Pure DX addition.
- **#6 G110**: LOW risk. Documentation only.

**100% LOW risk**. Total exec time at 1 PR/day pace: ~6 working days. Can run in parallel by file (#1 + #4 + #5 + #6 share zero touchpoints).

---

## 4. What 98 → 100 would actually cost

| Dim | Distance to 100 | Gap shape | Reason it's not trivial |
|---|---|---|---|
| CQRS 99→100 | 1pt | Custom go-vet analyzer enforcing zero `.Save/.Delete` outside bus | Tooling cost; doesn't change behavior |
| Hex 97→100 | 3pt | Wire/fx DI container generation | Pure ceremony per Pass 18 — adds code-gen step, replaces manual wire-up with generated wire-up; same semantics |
| DDD 98→100 | 2pt | Multi-broker proof (Upstox/Groww adapter) | Requires new broker integration; structural |
| ES 97→100 | 3pt | Full event-sourced reconstitution + replay-over-network | Weeks of work; out of scope for current scale |
| Middleware 97→100 | 3pt | (permanent ceiling per Apr-2026 audit) | Acknowledged — no consumer demand |
| SOLID 96→100 | 4pt | Wrap *slog.Logger as LoggerProvider, treat every dep as port | Pure ceremony per Pass 17 — accepted |
| Plugin 100 | 0pt | (already at ceiling) | — |
| Decorator 98→100 | 2pt | (permanent ceiling) | Acknowledged |
| TestArch 99→100 | 1pt | Final 5 t.Setenv tests are env-reading-by-design | Irreducible without testing-the-test-itself |
| Compat 95→100 | 5pt | Multi-broker proof (~600 LOC) | Structural — requires Upstox SDK integration nobody has demanded |
| Port 90→100 | 10pt | Postgres adapter + ARM CI matrix + helm chart | Ceremony for Fly.io+SQLite stack at current scale |
| NIST 92→100 | 8pt | Real-time alert pipeline + Prometheus/Grafana infra | Scale-blocked; need separate infra investment |
| EntGov 95→100 | 5pt | Quarterly access review + external pen-test + ISMS doc | Scale-blocked / cost-blocked ($5-15K external audit) |

**Total LOC for honest 100**: ~3500 LOC of architectural ceremony + ~$15K+ external costs.

**Why ≥98 is the practical ceiling**:
1. Most distance-to-100 is **rubric-driven not code-driven** (NIST, EntGov, FedRAMP, SOC 2 = process maturity, not code quality)
2. Ceremony work has **negative engineering ROI** — adds maintenance burden without user/auditor-perceivable value
3. Scale-blocked dims require **business growth** before they're worth pursuing (multi-region, Postgres, multi-broker)
4. **An auditor reviewing at 98 will not perceive a difference vs 100** — both pass any reasonable enterprise procurement review at current Indian fintech scale

---

## 5. What NOT to do (high-LOC, low-score-lift, hidden costs)

### Items that LOOK high-ROI but have hidden costs

| Item | Catalogue LOC | Hidden cost | Recommendation |
|---|---|---|---|
| **Phase 3a Batch 5** (widget/ext_apps cleanup) | 100 | `ext_apps.go` is 951 LOC; touching it cascades into `EventDispatcherProvider` new-port work. Density drops as batches progress. | Defer to post-98 |
| **Sprint 4c env-interface** | 250 | Touches 28 test sites + 80 prod env-reads. Mechanical but high-friction; Pass 18 over-promised "real value". | Worth it for fence work, NOT for score |
| **Hex DI container** | 600 | Pure ceremony (Pass 18 verdict stands). Replaces hand-written wire-up with generated wire-up; same semantics. | NEVER ship for score |
| **Multi-broker proof (Compat 95→100)** | 600 | Requires Upstox SDK; adapter alone is 600 LOC; integration test + ongoing maintenance burden. No demand. | Wait for first paying customer asking |
| **Postgres adapter (Port 90→100)** | 800 | Schema portability, query rewrite (SQLite-specific INSERT OR IGNORE), Litestream incompatibility. Whole new ops story. | Wait for 5K+ paying users |
| **G118 26 doc.go files** | 500 | Density 0.20 — low score lift relative to LOC. godoc value is real for external contributors but bus factor = 1 means low ROI today. | Defer until 2nd contributor joins |
| **G124 chaos test suite** | 200 | High value for SEBI claim defense BUT requires CI-time chaos infra (process kill, DB corruption sim). Maintenance burden for solo maintainer. | Defer or scope down to single test |
| **Real-time anomaly alert pipeline (NIST 92→100)** | 500 | Requires external alerting (Telegram/email/SMS). Operations-side complexity. | Wait for Pass 8 D2 metrics dashboard first |

### Items that look like ROI traps

1. **"Just add another middleware"** — Middleware dim at 96 today, ceiling 97. Adding 6 more layers (throttle, deadline-propagation, trace) bumps Middleware to 99 but adds latency, code complexity, no production demand. Pass 17 Sprint 17 Rejected.
2. **"Wrap *slog.Logger as LoggerProvider"** — pushes ISP/SOLID +5 but makes every test a mock-injection drag. Pure ceremony. Logger is pervasive by design.
3. **"Add per-tool A/B-test flag"** — sounds high-value but no user has asked; G117 listed as low-priority. Don't ship until Sprint 4d feature-flag work creates the substrate.
4. **"Migrate sessionBrokerResolver in post_tools.go to live in kc/"** — Pass 17 audit explicitly rejected: wrong layer, transport-adjacent by necessity.

---

## 6. Recommended landing order for Agent A

**Day 1-2**: PR #1 (G120 lock test) + PR #4 (Plugin#6 SBOM helper) in parallel — no overlap.
**Day 3-4**: PR #2 (Phase 3a Batch 1) — depends on Sprint 3a kickoff guardrails (staging deploy + canary).
**Day 5**: PR #3 (ctx.Background Phases 1-3) — depends on PR #2 finalizing handler signatures.
**Day 6**: PR #5 (Plugin#22) + PR #6 (G110) in parallel — no overlap, both LOW risk.

**End state** (HEAD `2a6e62b` + 6 PRs ≈ 275 LOC): aggregate score **98.4**.

**Stop rule**: if any PR's actual LOC exceeds estimate by >50%, recompute density. Below 0.4 pts/100 LOC, defer.

---

## 7. The honest minimum

**~275 LOC across 6 PRs, ~6 working days, all LOW risk** lifts honest score from `~96.0` to `~98.4`.

The remaining 1.6pt to literal 100 is **predominantly rubric-driven and scale-blocked**, not code-driven. Pursuing it requires business growth (multi-broker, Postgres scale, external pen-test budget) or pure ceremony (DI container, godoc cosmetic). Neither is cost-justified at current Indian fintech solo-maintained scale.

**Recommendation: ship the 275 LOC, declare honest 98, document the ceiling acceptances in `.research/final-138-gap-catalogue.md` §5, move on to product work.**

---

*Generated 2026-04-25 against HEAD `2a6e62b`. Read-only synthesis deliverable; no source files modified.*
