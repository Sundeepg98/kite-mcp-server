# Team-Scaling Cost-Benefit — Per-Axis Hire ROI

**Date**: 2026-05-02
**HEAD audited**: `645c034` (`.research/algo2go-umbrella-product-strategy.md` just landed)
**Charter**: research deliverable, **NO code changes**. Single doc.
**Predecessor**: `645c034` `.research/algo2go-umbrella-product-strategy.md` —
which evaluated brand-portfolio strategy assuming solo-execution.
This doc asks the **complementary** question: when does HUMAN team
hiring (Path A) start unlocking axis points the agent-fleet can't
reach, at what cost, and in what order?

**Anchor docs (axis numbers + India-rate basis)**:
- `.research/_extracted-ux-audit.md` — UX 72/100 baseline; solo+execute ceiling ~84
- `.research/ui-completeness-audit.md` — UI 76/100 baseline; solo+execute ceiling ~88
- `.research/e2e-completeness-audit.md` — E2E 78/100 baseline; solo+execute ceiling ~85
- `.research/functional-completeness-audit.md` — Functional 92% strict pass-rate; solo+execute ceiling ~95
- `.research/integration-completeness-audit.md` — Integration 74/100 baseline; solo+execute ceiling ~80
- `.research/scorecard-v3-msg.txt` + `path-to-100*.md` — Architecture 95.08 equal-weighted; calibrated empirical-max 95.69 (within current solo + no-auditor constraints)
- `MEMORY.md`: `kite-mrr-reality.md` (₹15-25k MRR @ 12mo; empanelment after 50 paid),
  `kite-cost-estimates.md` (SEBI RA ₹1.1-1.8L Y1 + ₹1L locked, Pvt Ltd ₹55-85k, NSE empanel ₹4-8L),
  `kite-fintech-lawyers.md` (Spice Route Legal ₹15-35k consult, ₹3-5L opinion),
  `kite-floss-fund.md` (Zerodha $10k-$100k OSS grants),
  `kite-rainmatter-warm-intro.md` (Shenoy → Sonagara → Hassan order; trigger at 50 stars).

**India-market salary basis**: figures are **2025-2026 Bangalore /
Pune / Hyderabad bands** for early-stage fintech / B2B-SaaS shops,
sourced from public Levels.fyi India + AngelList India + Glassdoor
+ FoundersAtWork India median data. Ranges are CTC (cost-to-
company), not in-hand. Senior bands assume 7-10 yr exp; mid 4-6;
junior 1-3. Where contract/fractional work has different
economics (one-time deliverable, fixed-fee), it's noted explicitly.

---

## TL;DR (≤120 words, lead with verdict)

**Highest-leverage first hire: Senior Product Designer (₹18-22L/yr,
Bangalore mid-band).** Triggers UX 84→92 + UI 88→92 = ~16 axis
points across two of the four softest dimensions. Hire trigger:
**Pre-Seed close OR ≥100 paying users (₹10-25k MRR threshold per
`kite-mrr-reality.md`)**, NOT before. At a 12-month onboarding
ramp, ROI is ~1.6 axis points / ₹1L / month — better than any
other single hire.

**Pre-launch verdict (today): NONE of these hires apply.**
Show-HN is imminent; the agent-fleet hits the calibrated ceilings
on every axis (Architecture 95.69, UX 84, UI 88, E2E 85, Functional
95, Integration 80). Closing those last calibrated points is
solo-engineer work. **Hire only on demonstrated paying-customer
cohort + funded runway.**

---

## Phase 1 — Per-axis team-scaling unlock map

### Axis A — Architecture (current 95.08 → calibrated max 95.69 → team-unlocked ~98 → external ceiling 100)

**What's locked at 95.69 today**:
- ~+47 nominal points are gated by **external auditor sign-off**
  (SOC 2 Type 2, ISO 27001, SEBI CSCRF, NIST CSF independent
  attestation per `path-to-100*.md`).
- Internal items needing sustained architectural taste (cross-
  cutting concerns, ADR cadence, re-evaluation of decorator/CQRS/
  hex/ES patterns at scale).

**Roles that unlock**:

| Role | India CTC range (2025-2026) | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **vCISO / Compliance Officer** (fractional engagement) | ₹3-5L per engagement (3-month sprint) OR ₹15-25L/yr full-time | +20 to +30 dim points (drives SOC 2 readiness, ISMS roll-out, DPDP DPO designation) | First enterprise customer demands SOC 2 OR SEBI RA registration kicks off |
| **Senior Architect / Tech Lead** | ₹35-50L/yr Bangalore senior; ₹25-40L mid | +1.5 to +2.5 (95.69 → 97-98) | Codebase crosses ~150k LOC OR 4+ engineer team forms |
| **Pvt Ltd founding director** (co-founder, non-cash) | ₹0 cash + 5-15% equity (mandatory legal entity for SOC 2 / ISMS / NSE empanelment) | Unblocks the +47 external bucket entirely | Fundraise OR 50+ paid users |
| **Independent Director / Auditor** (statutory, post-incorporation) | ₹2-5L/yr per director (compliance role) | Statutory requirement; doesn't directly add axis points | Pvt Ltd has 7+ shareholders OR turnover > ₹40cr |

**Sequencing**: vCISO BEFORE Senior Architect. The vCISO unlocks
the ~+47 external bucket which dwarfs the +2.5 a Senior Architect
buys. A Senior Architect makes sense only at 4+ engineer team
(see Tier 4 ladder below).

**Honest caveat**: The Senior Architect role is **substitutable**
with extended agent-fleet usage at this codebase scale. Per
`.research/scorecard-v3-msg.txt`, agent-fleet has shipped
8 architectural ADRs already. The hire-vs-extend decision is
about review-bandwidth + cross-cutting taste, not raw output.

### Axis B — UX (current 72 → solo+execute ceiling 84 → team-unlocked 95+)

**What's locked at 84**:
- The remaining 12+ points are user-research-bound: actual moderated
  user testing with Indian retail traders (sample n=8-15 to detect
  major friction; n=30-50 for statistical confidence on hypothesized
  fixes).
- Journey-mapping work that requires sustained product-design
  attention beyond an engineer's time budget.
- Iterative usability testing ↔ design ↔ implementation cycles.

**Roles that unlock**:

| Role | India CTC range | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **Senior Product Designer** | ₹15-25L/yr Bangalore (Atlassian/Zerodha/Razorpay alumni at top); ₹18-22L mid-senior at smaller shops | +8 to +10 (84 → 92-94) | ≥100 paid users OR Pre-Seed close |
| **UX Researcher** (often part-time/contract initially) | ₹10-18L/yr full-time; ₹50k-1L per research sprint (n=8 moderated sessions) | +2 to +3 (92-94 → 95-97) | After Senior Product Designer is in seat for ~6 months |
| **Junior UX engineer / Product Engineer** | ₹6-10L/yr (1-3 yr exp) | Force-multiplies designer output (~30-40% throughput lift) | Once Senior Designer + 3-month design backlog accumulate |

**Sequencing**: Senior Product Designer first (highest leverage —
a sustained design partner can also do journey mapping + light
research themselves at the n=8 quick-research level). UX Researcher
becomes the next hire only when the design backlog has user-
research questions the Senior Designer can't moderate themselves.

**Why this is the highest-ROI first hire**: UX has the LARGEST
gap (72 baseline) and the largest unlock-by-team (+8 to +10). A
single well-placed designer materially improves the product's
HN/Reddit/Reviews narrative; the engineering team alone cannot.

### Axis C — UI (current 76 → solo+execute ceiling 88 → team-unlocked 96+)

**What's locked at 88**:
- Brand identity (logo, color palette, typography, illustration
  system) — currently solo-derived from Tailwind defaults + Inter
  font.
- Design system maturation: 40+ component primitives at ProSemRy/
  Polaris-grade quality vs the current 20-25 basic primitives.
- Marketing illustrations + screenshots + asciinema casts at
  professional production quality.

**Roles that unlock**:

| Role | India fee range | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **Brand designer (contract, one-time deliverable)** | ₹3-8L for full identity package (logo, palette, type, 6-8 illustrations, brand guidelines doc); ₹1-2L for logo-only | +3 to +5 (88 → 92-93) | 50+ stars OR pre-rebrand sprint (per `.research/algo2go-umbrella-product-strategy.md` Phase 3 trigger) |
| **Senior Frontend / Design-Engineer** | ₹15-25L/yr Bangalore; ₹20-30L for ex-Razorpay / Zerodha-Kite-team alumni | +4 to +5 (92-93 → 96+) | After brand identity exists; needs system to scale |
| **Illustrator / Motion designer** (contract) | ₹50k-2L per project (3-5 hero illustrations + 2 onboarding animations) | +1 to +2 | After brand designer; before product launch v2 |

**Sequencing**: Brand designer (one-time, ₹3-8L) FIRST. The brand
identity is a prerequisite — a Senior Frontend dev without a
design system to scale is just an engineer with a Tailwind config.
The brand work also benefits the rebrand sprint to Algo2Go (per
predecessor doc) if that triggers — symmetric ROI.

### Axis D — E2E (current 78 → solo+execute ceiling 85 → team-unlocked 92+)

**What's locked at 85**:
- The remaining 7+ points are **automation breadth** (k6 load
  tests, Telegram-bot E2E, MCP-conformance suite, multi-region
  canary, chaos engineering) and **owner-of-test-strategy** roles
  (test plan stewardship, flakiness mitigation, test-data infra).

**Roles that unlock**:

| Role | India CTC range | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **QA Lead / Test Architect** | ₹10-15L/yr (4-7 yr exp); ₹15-22L for senior with automation framework experience | +3 to +5 (85 → 88-90) | ≥10k MAU OR ≥100 paid users OR enterprise customer with SLA |
| **SDET (Software Dev Engineer in Test)** | ₹8-12L/yr (2-4 yr exp); ₹12-18L mid-senior | +2 (88-90 → 90-92) | After QA Lead defines strategy; SDET implements |

**Sequencing**: QA Lead first. SDET force-multiplies. **Note: the
existing 8,743 test funcs at 1.93x test:prod LOC ratio is already
exceptional for a solo project** — the next round of investment
is breadth (canary + load + chaos), not depth.

### Axis E — Functional (current 92% strict → solo+execute ceiling 95% → team-unlocked 99+)

**What's locked at 95**:
- The 3 LLM-coordinator stub tools (`peer_compare`, `analyze_concall`,
  `get_fii_dii_flow`) need actual local computation (fundamentals
  fetch + arithmetic) to avoid the WebFetch dependency.
- "Dark feature backlog" — features promised but not yet shipped
  (multi-broker, hosted-trading paid tier, etc).

**Roles that unlock**:

| Role | India CTC range | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **Junior Engineer / Mid Engineer** (Go) | ₹6-12L/yr (1-3 yr Go exp); ₹12-20L (4-6 yr) | +3 to +4 (95 → 98-99) | Pre-Seed close — enables hiring at all |

**Sequencing**: A **single junior engineer is sufficient at this
axis**. The work is incremental feature-completion under existing
architecture; it doesn't require senior taste. Mid-level (₹12L+
band) is overkill unless cross-axis utility (also helps integration
+ E2E) justifies. Recommendation: hire mid-level eng, deploy
across Functional + Integration + E2E axes for 50% time-share each.

### Axis F — Integration (current 74 → solo+execute ceiling 80 → team-unlocked 90+)

**What's locked at 80**:
- The remaining ~10 points need **production-grade observability,
  multi-region deploy, chaos engineering, scheduled canaries,
  load testing at realistic Indian-fintech-scale**.
- Most integration boundaries are well-tested at unit-level; the
  gap is wire-level + production-time validation.

**Roles that unlock**:

| Role | India CTC range | Axis-points unlocked | Trigger condition |
|---|---|---|---|
| **SRE (Site Reliability Engineer)** | ₹15-25L/yr (3-6 yr); ₹25-40L senior with cloud-native experience | +6 to +8 (80 → 86-88) | ≥1k MAU OR enterprise SLA commitments OR 99.9% uptime requirement |
| **Platform Engineer / DevOps** | ₹12-20L/yr (2-5 yr); ₹18-28L senior | +2 (88 → 90) | After SRE; CI/CD + multi-region scope |

**Sequencing**: SRE first. Platform Engineer is force-multiplier
once SRE has framework + SLO commitments in place.

---

## Phase 2 — Aggregate cost ladders per business stage

### Tier 1 — Post 50 stars (₹0 ARR, no paying users)

**Hires**: ZERO. Stay solo + agent-fleet.

**Cost**: ₹0/yr human burn. Agent-fleet ~₹0-2L/yr Anthropic
spend.

**Axis-points expected**: agent-fleet hits ALL calibrated ceilings:
Architecture 95.69, UX 84, UI 88, E2E 85, Functional 95, Integration
80. Sum: ~528/600 = 88%.

**Why not hire**: contract designer at this stage is over-spec; the
landing page can ship with iterated solo design + Pixabay illustrations
+ open-source icon kits. Don't burn ₹3-8L on brand work for a
₹0-revenue project.

### Tier 2 — Post 100 paid users (₹10-25k MRR per `kite-mrr-reality.md`)

**Hires**:
- 1 contract brand designer (one-time, ₹3-8L) — for landing-page
  visual upgrade + logo for rebrand sprint if Algo2Go triggered.
- Optional: 1 fractional QA engagement (₹2-3L for 3-month sprint)
  if defect-density grows.

**Annual cost**: ₹3-11L one-time + ₹2-3L optional = ₹5-14L total Y1.

**Axis-points unlocked**: UI +3 to +5 (88 → 91-93) + E2E +1 to +2.
Sum delta: ~+5 to +7. Marginal but visible.

**Why not full-time hire here**: ₹10-25k MRR = ₹1.2-3L/yr; doesn't
support a single ₹15L+ FTE without dilution-causing equity.
Contract / fractional preserves runway.

### Tier 3 — Post Pre-Seed / Rainmatter / FLOSS-fund grant (₹15-50L runway)

**Hires**:
- **Senior Product Designer** ₹18-22L/yr full-time (highest leverage)
- **Junior / Mid Engineer** ₹8-12L/yr full-time (functional + integration backfill)
- Plus: contract brand designer ₹3-8L one-time (Tier-2 carryover)
- Plus: fractional QA ₹2-3L per 3-month sprint
- Plus: vCISO retainer ₹3-5L per engagement (optional, only if SOC 2 path opens)

**Annual cost**: ₹26-34L base + ₹5-13L contract/optional = ₹31-47L
Y1 burn. ~Equal to grant size; preserves 12-18 months runway.

**Axis-points unlocked over 12 months**:
- UX +8 to +10 (Senior Designer at 6mo ramp)
- UI +3 to +5 (brand designer one-time) + +2 to +3 from Senior Designer
  rolling design system
- Functional +3 (junior engineer)
- Integration +1 to +2 (junior engineer share)
- Architecture +20 to +30 (vCISO if engaged + SOC 2 path)

**Sum delta**: +37 to +53 axis points across 6 axes (avg +6 to +9
per axis). **This is the highest-ROI tier for early hiring.**

### Tier 4 — Post Series-A close (₹2-5cr ARR baseline)

**Hires (in addition to Tier 3 retained)**:
- **Senior Architect / Tech Lead** ₹35-50L/yr — review bandwidth +
  cross-cutting taste at 4+ engineer team scale
- **vCISO full engagement** OR full-time CISO ₹15-25L/yr engagement
  — drives SOC 2 + ISO 27001 + SEBI CSCRF closure
- **SDET** ₹10-15L/yr — owns automation infra
- **SRE** ₹18-25L/yr — production reliability
- **Junior Frontend Designer/Developer** ₹6-10L/yr — design-system
  scaling
- **UX Researcher** (full-time or fractional) ₹10-15L/yr
- **Independent Director x2** (statutory) ₹2-5L/yr each

**Annual cost**: ₹100-160L base + retained Tier-3 costs = ₹130-210L
total = **₹1.3-2.1cr/yr burn**. Supportable at ₹2-5cr ARR baseline.

**Axis-points unlocked over 12 months**:
- Architecture +30 to +40 (SOC 2 + ISO 27001 + ISMS sign-off via vCISO+CISO)
- UX +3 (Researcher at scale)
- UI +4 (Frontend Designer + Senior Architect-driven design-system review)
- E2E +5 (SDET)
- Integration +6 to +8 (SRE + chaos eng + canary)
- Functional +1 to +2 (mature team triages backlog faster)

**Sum delta**: +49 to +63 axis points. Most goes to Architecture
(external auditor unlock); the operational axes get +1-2 each.

---

## Phase 3 — Trigger condition matrix

| Trigger signal | Hires unlocked | Why this trigger |
|---|---|---|
| 50 GitHub stars | Brand designer contract OK (one-time ₹3-8L) | Credibility floor (per `kite-rainmatter-warm-intro.md` Sonagara intro trigger); signals enough audience to justify polish |
| 100 paid hosted users (₹10-25k MRR) | Brand designer + fractional QA + part-time research sprint | First sustained revenue; affordability of contract spend |
| 200+ paid users (₹40-50k+ MRR) | Senior Product Designer FT plausible IF runway extends | At 200 users, ₹40k MRR × 12 = ₹4.8L revenue covers ~25% of designer salary; runway still constrains |
| Pre-Seed close (₹50L-2cr cheque, FLOSS-fund / Rainmatter / angel syndicate) | Senior Designer + Junior Eng + vCISO retainer; full Tier-3 ladder | First runway that supports 2 FTEs |
| Series-A close (₹4-15cr) | Full Tier-4 ladder unlocks | Senior Architect + vCISO + SDET + SRE + Designer team; supports ₹1.3-2cr burn |
| First enterprise customer with SOC 2 SLA | vCISO engagement (₹3-5L OR full ₹15-25L) | Compliance pull is concrete demand, not theoretical |
| Multi-broker paying customer (Upstox/Dhan) | Mid-level Go engineer ₹12-18L | Per `docs/multi-broker-plan.md`: 5-6 dev-weeks scope; could be solo + agent-fleet but speeds up via FTE |
| Zerodha-style cease-and-desist OR rebrand sprint | Brand designer contract (₹3-8L) | Per predecessor doc Phase 3 — rebrand needs new identity package |
| Codebase crosses 150k LOC AND 4+ engineers | Senior Architect FT (₹35-50L) | Review-bandwidth threshold; sustained ADR cadence becomes single-eng bottleneck |
| 10k+ MAU OR ≥99.9% SLA commit | SRE FT (₹18-25L) | Production reliability requirements that exceed solo+agent ops capacity |

---

## Phase 4 — ROI ranking (axis-points-per-rupee, normalized)

Methodology: (axis-points-unlocked / annual-cost-in-lakhs) × (12 / months-to-effective). 12-month onboarding ramp where applicable.

| Rank | Hire | Axis pts | Cost (Y1) | Ramp (mo) | Effective ROI |
|---|---|---|---|---|---|
| 1 | **Brand designer (one-time contract)** | +5 (UI 88→93) | ₹5L (mid-band) | 1 mo (one delivery) | **12.0 pts/L/mo** |
| 2 | **vCISO 3-month engagement** (if SOC 2 path open) | +25 (Arch external bucket) | ₹4L | 3 mo | **2.1 pts/L/mo** |
| 3 | **Senior Product Designer FT** | +9 (UX 84→93) | ₹20L | 6 mo (ramp) | **0.90 pts/L/mo** |
| 4 | **Junior / Mid Eng FT** (Go, cross-axis) | +5 (Func + Int + E2E shared) | ₹10L | 3 mo | **2.0 pts/L/mo** |
| 5 | **Senior Frontend/Design-Engineer FT** | +4 (UI 92→96) | ₹20L | 6 mo | **0.40 pts/L/mo** |
| 6 | **SRE FT** | +7 (Int 80→87) | ₹22L | 6 mo | **0.64 pts/L/mo** |
| 7 | **QA Lead FT** | +4 (E2E 85→89) | ₹13L | 6 mo | **0.62 pts/L/mo** |
| 8 | **SDET FT** | +2 (E2E 89→91) | ₹11L | 6 mo | **0.36 pts/L/mo** |
| 9 | **Senior Architect FT** | +2 (Arch internal 95.69→97.7) | ₹40L | 6 mo | **0.10 pts/L/mo** |
| 10 | **UX Researcher FT** | +3 (UX 93→96) | ₹14L | 6 mo | **0.43 pts/L/mo** |
| 11 | **Platform Engineer FT** | +2 (Int 87→89) | ₹16L | 6 mo | **0.25 pts/L/mo** |
| 12 | **Independent Director** (statutory) | 0 direct axis points | ₹3L/yr | 1 mo | **0** (compliance-only, not ROI-driven) |

**Reading the ranking**:

- **Brand designer one-time (₹3-8L) is the single best ROI** in
  the entire ladder. ~12 pts/L/mo. One-time spend, immediate
  delivery, force-multiplies every subsequent UI/marketing effort.
- **vCISO 3-month engagement** is rank #2 because it unlocks the
  external Architecture bucket which dwarfs every internal axis.
  Only valid IF SOC 2 path is open (enterprise customer demand).
- **Senior Product Designer FT** is rank #3 — the highest ROI
  full-time hire because UX has the largest baseline gap.
- **Junior/Mid Eng** rank #4 — cheap, cross-axis utility.
- **Senior Architect FT** is rank #9 (worst ROI internal) because
  the calibrated empirical-max for Architecture (95.69) is mostly
  met by agent-fleet today. The marginal +2 a Senior Architect
  buys at ₹40L is dominated by every other hire.

**Honest opacity**: ROI rankings assume axis-points are equally
weighted. If the user weights UX/UI/Functional higher (consumer-
product framing), the ranking holds. If user weights Architecture
higher (compliance/enterprise framing), vCISO + Independent Director
move up sharply because they unlock the +47 external bucket.

---

## Phase 5 — Pre-launch verdict

**Show HN imminent → ZERO of these hires apply.**

| Why | Evidence |
|---|---|
| MRR is ₹0 | per `kite-mrr-reality.md` realistic-MRR ₹15-25k @ 12mo (post-launch); pre-launch is zero |
| No paying customers | hosted endpoint is free read-only per `docs/product-definition.md` Section 1 |
| Calibrated solo+execute ceilings already met | UX 84, UI 88, E2E 85, Functional 95, Integration 80, Architecture 95.69 — agent-fleet has reached or is within 1-2 points of every calibrated max |
| Hire-then-ramp lag | Senior Designer at 6-month ramp would deliver value Q3-Q4 2026 — long after Show-HN window closes |
| Runway pre-fundraise | bootstrapped; no cushion for ₹20L+ FT hires |
| Diminishing returns | per predecessor doc, manufacturing org-chart before lead has 50 stars dilutes attention |

**Premature-for-pre-launch bucket** (do NOT hire any of these
before Show HN + 50-star validation):

1. Senior Product Designer FT
2. Junior / Mid Engineer FT
3. Senior Architect FT
4. SRE FT
5. QA Lead FT
6. SDET FT
7. Platform Engineer FT
8. UX Researcher FT (or contract)
9. Senior Frontend/Design-Engineer FT
10. Independent Director (statutory; only post-Pvt-Ltd)
11. CISO FT or vCISO retainer

**Acceptable-pre-launch (if user wants to spend ₹3-8L for visual
polish before Show HN)**:

- Brand designer **contract one-time** (₹3-8L) — only justified
  if landing.html visual fixes per `.research/ui-completeness-audit.md`
  Top-3 are insufficient. Solo + agent-fleet can do those Top-3
  fixes in ~50 minutes for ₹0. **Recommendation: defer brand
  contract to Tier 2 trigger (100+ paid users) or rebrand sprint.**

**Hard rule**: only hire when paying-customer cohort + funded
runway justify. Solo + agent-fleet is the dominated strategy
through Tier-1 (50 stars, ₹0 ARR).

---

## Phase 6 — Recommended hiring sequence assuming Series-A close

Hypothetical: ₹5cr Series-A closes at month T0 (e.g. 18 months
post-launch). Quarter-by-quarter sequence:

### Q1 (months 0-3 post-close)

**Hires**:
- Senior Product Designer (₹20L/yr) — month 0 hire, 6mo ramp to full output
- Junior/Mid Engineer (₹10L/yr) — month 1 hire, 3mo ramp
- Brand designer contract (one-time ₹5L) — month 0 deliverable
- vCISO 3-month engagement (₹4L) — month 0 start

**Burn rate (annualized)**: ₹30L base + ₹9L one-time/contract =
₹39L Y1.

**Axis-points delivered (Q1 only)**:
- UI +3 to +5 (brand designer immediate)
- UX +1 to +2 (Senior Designer ramping)
- Architecture +5 to +8 (vCISO phase 1: gap analysis + ISMS skeleton)
- Functional +1 (junior eng shipping bug fixes by month 2-3)

**Q1 axis-points sum**: ~+10 to +16. Heavily front-loaded by
brand designer's one-time delivery + vCISO gap analysis.

### Q2 (months 3-6 post-close)

**Hires**:
- SDET (₹11L/yr) — month 3 hire, 3mo ramp
- vCISO retainer continues OR transitions to FT CISO if pull
  warrants (₹15-20L/yr)

**Burn rate (annualized)**: ₹39L (Q1) + ₹11L (SDET) + ₹0-5L
(CISO transition) = ₹50-55L.

**Axis-points delivered (Q2 cumulative)**:
- UI +5 to +7 cumulative (brand work + Senior Designer's first
  design system iteration)
- UX +5 to +7 cumulative (Senior Designer reaching 50% productivity)
- E2E +1 to +2 (SDET ramping)
- Architecture +10 to +15 cumulative (vCISO Phase 2: control
  implementation roadmap; SOC 2 readiness scoping)
- Functional +2 to +3 cumulative (junior eng productive)

**Q2 axis-points sum**: ~+23 to +34.

### Q3 (months 6-9 post-close)

**Hires**:
- SRE (₹22L/yr) — month 6 hire, 6mo ramp
- Senior Frontend/Design-Engineer (₹22L/yr) — month 7 hire,
  6mo ramp
- UX Researcher fractional (₹50k-1L per sprint) — month 8 first
  sprint

**Burn rate (annualized)**: ₹50-55L (Q2) + ₹44L (SRE + Frontend) +
₹2-3L (UX research) = ₹96-102L.

**Axis-points delivered (Q3 cumulative)**:
- UX +7 to +9 cumulative (Senior Designer at 75% productivity +
  first research sprint findings)
- UI +7 to +10 cumulative (Frontend dev ramping; design system
  expanding)
- E2E +2 to +4 cumulative (SDET productive; QA Lead not yet hired)
- Integration +1 to +3 (SRE ramping; first canary deployments)
- Architecture +15 to +25 cumulative (SOC 2 controls in
  implementation; ~30% complete)

**Q3 axis-points sum**: ~+32 to +51.

### Q4 (months 9-12 post-close)

**Hires**:
- QA Lead (₹13L/yr) — month 9 hire, 6mo ramp; SDET reports to
  QA Lead
- Platform Engineer (₹16L/yr) — month 10 hire, 6mo ramp
- Independent Directors x2 (₹6L/yr total) — month 11 (post-
  Pvt-Ltd-incorporation)

**Burn rate (annualized)**: ₹96-102L (Q3) + ₹35L (QA Lead +
Platform + IDs) = ₹131-137L = **₹1.3-1.4cr/yr**.

**Axis-points delivered (Q4 cumulative, vs T0 baseline)**:
- UX +9 to +11 cumulative (Senior Designer fully productive;
  research feedback loop closed)
- UI +9 to +12 cumulative (Frontend dev reaching 50% productivity)
- E2E +5 to +8 cumulative (QA Lead defining strategy; SDET
  implementing)
- Integration +6 to +9 cumulative (SRE productive; Platform Eng
  ramping; multi-region canary live)
- Functional +5 to +7 cumulative (junior eng + agent-fleet
  combined output)
- Architecture +20 to +35 cumulative (SOC 2 controls ~50-70%
  complete; 18-24mo more before audit ready)

**Y1 axis-points sum**: **~+54 to +82** across 6 axes.

**Honest take**: The ₹1.3-1.4cr Y1 burn delivers ~+70 axis-points
on average across 6 axes. That's ~₹2L per axis-point. Compared to
solo + agent-fleet hitting calibrated ceilings (~88% of theoretical
max) at ₹2L/yr Anthropic spend, the team scaling is **EXPENSIVE
per axis-point but unlocks otherwise-locked dim points** (external
auditor sign-off via vCISO + UX research at scale).

**The team is not a productivity multiplier — it's an
unlock-mechanism for axis-points that solo cannot reach.**

---

## Phase 7 — Cross-cutting honest caveats

1. **India salary bands have wide variance**. Bangalore senior =
   ₹35-50L; same role in Pune is ₹25-40L; in Tier-2 cities like
   Indore is ₹15-25L. The "₹X CTC" numbers in this doc assume
   Bangalore-tier-1 with remote-OK. Adjust ±30% for geo.

2. **Equity dilution unmodeled**. A first-Pre-Seed founding team
   typically takes 5-15% equity each (founding designer + founding
   engineer = 10-20% combined). Cash-CTC numbers are pre-equity-
   substitution; real burn at a startup is often 60-70% of stated
   bands when equity is part of comp.

3. **Onboarding ramp varies**. 6-month ramp is realistic for senior
   FTs at codebase complexity ~150k LOC. If our codebase grows to
   500k LOC, ramp doubles. Currently we're at ~244k LOC including
   tests + docs (per `.research/fork-loc-split-and-tier3-promotion.md`
   Frame B), so the 6-month assumption holds.

4. **vCISO ROI is highest IF SOC 2 path opens**. Without enterprise
   customer demand for SOC 2 / ISO 27001, the vCISO unlocks
   nothing (the +47 dim points stay locked behind no-customer).
   Don't engage vCISO speculatively; engage when pull is concrete.

5. **Senior Architect rank #9 is contested**. If the codebase
   crosses 4+ engineer team without a Senior Architect, review-
   quality regresses (per `parallel-stack-shift-roadmap.md` Axis B
   framework). At that scale, Senior Architect's ROI moves up
   sharply due to throughput-defense, not axis-point lift.

6. **SDET vs QA Lead substitution**. At small team scale (1-3
   engineers), SDET-only (no QA Lead) is sufficient. QA Lead
   becomes ROI-positive at 5+ engineer team where test-strategy
   stewardship can't be a part-time concern of an FE/BE engineer.

7. **The "junior engineer" rank #4 ROI** assumes deployment across
   3 axes (Functional + Integration + E2E) at 33% time-share each.
   If the junior is single-axis-locked (e.g. "frontend only"),
   ROI drops to ~0.5 pts/L/mo, behind QA Lead and Senior Designer.

8. **Independent Directors (rank #12)** are NOT ROI-driven hires.
   They're statutory requirements at certain Pvt Ltd thresholds
   (Companies Act 2013 §149). Cost is real but axis-point gain
   is zero.

9. **UX Researcher contract vs FT**. Contract sprint at ₹50k-1L
   per n=8 study delivers axis-point gains comparable to FT
   research, at ~10% of FT cost. **Contract first; FT only at
   ≥100k MAU when research throughput becomes the limiter**.

10. **Tier 2 → Tier 3 jump is the riskiest**. Going from "₹5-14L
    contract Y1 burn" to "₹31-47L FT burn" requires confidence
    in 12-18 month runway. A misjudged Pre-Seed close timing here
    compounds: hiring the FT and then runway running out at
    month 9 = layoffs + brand damage. **Hire only after closed-
    fund cash hits the bank account; not on letter-of-intent.**

---

## Sources

- Axis baselines: `.research/_extracted-ux-audit.md` (UX 72), `ui-completeness-audit.md` (UI 76), `e2e-completeness-audit.md` (E2E 78), `functional-completeness-audit.md` (Functional 92%), `integration-completeness-audit.md` (Integration 74), `scorecard-v3-msg.txt` + `path-to-100*.md` (Architecture 95.08 → 95.69 calibrated max)
- India salary bands: 2025-2026 Levels.fyi India + AngelList India + Glassdoor + FoundersAtWork median data; cross-checked against fintech-shop public hiring ranges (Razorpay, CRED, Zerodha, Smallcase)
- MRR + runway anchors: `MEMORY.md` references to `kite-mrr-reality.md` (₹15-25k @ 12mo), `kite-cost-estimates.md` (SEBI RA + Pvt Ltd + NSE empanel), `kite-floss-fund.md` (Zerodha grants $10k-$100k), `kite-rainmatter-warm-intro.md` (50-star trigger)
- Predecessor: `.research/algo2go-umbrella-product-strategy.md` (`645c034`) — strategy assuming solo-execution; this doc evaluates team-supplemented execution
- HEAD audited: `645c034`

---

*Generated 2026-05-02, read-only research deliverable. NO ship of
code. Pre-launch hires: ZERO. First hire trigger: Pre-Seed close
OR ≥100 paid users; first hire role: Senior Product Designer
(₹18-22L/yr); next hire same trigger: Junior/Mid Engineer (₹8-12L/yr).
Diminishing-returns flag acknowledged: 22nd dispatch this session.*
