# Why we cannot literally reach 100 — concrete blockers, costs, triggers

**Date**: 2026-04-28 night, end-of-architectural-cycle.
**Charter**: Read-only research deliverable. NO ship.
**Question**: "I know literal 100 isn't the same goal — but why are we NOT able to achieve it?"
**Build base**: `eff33c7` `.research/state-and-100pct-reconciliation.md` (the prior closing artifact). This document goes deeper per blocker with cost, time-to-acquire, and prerequisite.

The honest answer in one line: **the remaining 4.92 dim-points to literal 100 are not "code we haven't written yet" — they are organizational, contractual, and regulatory artefacts that money + time + paying customers must purchase**, and we have none of those at current state.

---

## Section 1 — The 4 dims still <100, with quantified gaps

### 1.1 Compatibility (current 86 / max 100 / gap −14)

**What 100 actually looks like for this dim** (per `.research/blockers-to-100.md` §10): a real second broker adapter shipped under `broker/<name>/` (Upstox, Angel One, Dhan, or similar) with all 9 sub-interface methods of `broker.Client` implemented, conversion of broker-specific SDK types to the broker-agnostic DTOs in `broker/broker.go`, and at least one paying customer using it in production. The interface is multi-broker-ready today (`broker/broker.go:622`); only one production adapter ships (`broker/zerodha/`); `broker/mock/` is test-only. The dim does NOT score a synthetic stub adapter — it grades the rubric as "second broker actually integrated and used".

**Quantified sub-blockers and costs** (all INR, 2026 India market rates):

| Sub-blocker | Cost | Time-to-acquire | Hard prerequisite |
|---|---|---|---|
| Second-broker adapter implementation (~600 LOC + tests + retry semantics + error mapping) | ₹0 — internal Go work, ~3-6 weeks single-developer | 3-6 weeks | None on the code side. SCALE-GATED: needs one paying customer who specifically demands a non-Zerodha broker. Per `kite-mrr-reality.md`: at projected ₹15-25k/month MRR ceiling at 12 months, no enterprise contract is plausibly demanding multi-broker. |
| Partnership-engineering coordination with the second broker | ₹0 (broker side) — but commercial discussion adds opportunity cost | 4-8 weeks elapsed (their cadence, not ours) | Their formal acceptance of us as an integration partner. They have no obligation to engage. |
| Ongoing maintenance of the second adapter (SDK upgrades, breaking-change tracking) | ~20 hours/quarter per adapter | continuous | Headcount or attention budget that does not exist at solo-developer scale |

**Net for Compatibility**: −14 dim-points are blocked by absence of a paying customer who demands a second broker. Cost in pure INR is low (~₹0 in subscriptions; the cost is opportunity-cost of engineering time on a feature no current customer asked for). Trigger: first paying customer asking for non-Zerodha broker. None today.

---

### 1.2 Portability (current 88 / max 100 / gap −12)

**What 100 actually looks like for this dim** (per `.research/blockers-to-100.md` §11): a production-grade Postgres adapter implementing `kc/sqldb` port (which already exists per ADR 0002), schema portability proven via at least one production deployment running on Postgres, AND cross-runtime executable proof per `parallel-stack-shift-roadmap.md` Track A or Track B (TypeScript widgets or Python analytics actually running outside the Go monolith). +2 was reclaimed from 86 → 88 by `b474681` TLS-self-host hybrid (Fly.io edge + autocert + reverse-proxy = three deployment paths); the remaining −12 needs storage-portability AND/OR runtime-portability.

**Quantified sub-blockers**:

| Sub-blocker | Cost | Time-to-acquire | Hard prerequisite |
|---|---|---|---|
| Postgres adapter (production-ready, not stub) | ~1500-2500 LOC code + ~600 LOC tests (per v3 §"Other dim candidates") | 4-6 weeks | SCALE-GATED to ≥5K users per ADR 0002 trigger. SQLite-on-Litestream-replica is the safe operating envelope below that. Below the trigger, Postgres is theoretical work. |
| Managed Postgres hosting (e.g., Supabase, Neon, RDS) | ~$200-500/month ongoing | continuous | Operational headcount to monitor and migrate; ~₹16-40k/month after 5K users justifies it |
| Migration script + dual-write window | ~400 LOC + manual smoke testing | 2 weeks | Existing data + downtime window. Below 1K users, a stop-the-world migration is acceptable. Above 1K, dual-write is mandatory. |
| Track A (TypeScript) port of mcp/ outer ring + widgets per `parallel-stack-shift-roadmap.md` §2 | **34-49 weeks single-developer** (8-12 months) | best case 8 months / worst case 1 year | Foundation phase (4-5 weeks shared), THEN B.1-B.4 ports + B.5 new analytics. Per the roadmap §2.5: "Track A only pays if user specifically authorizes the no-feature year." User has not. |
| Track B (Python) port of analytics + backtest | 7-9 weeks excluding Foundation | 2-3 months | Foundation phase first (4-5 weeks), so 11-14 weeks total |

**Net for Portability**: −12 dim-points are mostly storage-side (Postgres adapter, scale-gated) and runtime-side (cross-runtime port, ~8-12 months single-dev). Total cost in pure INR: Postgres infra ~₹4-6L/year ongoing + 4-6 weeks engineering. Track-shift cost is overwhelmingly opportunity-cost of one full year of feature work foregone. Triggers: 5K+ users (Postgres) AND/OR a Series-A milestone that funds a 6-month no-feature engineering investment (track-shift).

---

### 1.3 NIST CSF 2.0 (current 94 / max 100 / gap −6)

**What 100 actually looks like for this dim** (per `.research/blockers-to-100.md` §12): all 6 NIST CSF Functions (Govern, Identify, Protect, Detect, Respond, Recover) evidenced not only with internal documents (which we have) but with **third-party attestation that those documents reflect operational reality**. SOC 2 Type II is the canonical attestation in this category. Real-time alert pipeline (PagerDuty / Twilio / commercial SIEM) covers the DE.AE-3 row. Formal pen-test covers the ID.RA-1 sub-row beyond self-assessment.

**Quantified sub-blockers**:

| Sub-blocker | Cost (INR, 2026) | Time-to-acquire | Hard prerequisite |
|---|---|---|---|
| **SOC 2 Type II audit** (closes ~+3 NIST + ~+12 EntGov simultaneously, total ~+15) | **₹15-25 lakh / year** ongoing (~$18-30k initial + ongoing). Includes auditor fees + readiness consultant + automation tooling like Vanta / Drata / Sprinto (~₹8-12 lakh/yr standalone). | **6-12 months** for Type II observation window. Type I is a 1-day point-in-time attestation; Type II requires 6+ months of operational evidence. | Auditor engagement + operational evidence over the observation window. Cannot self-attest. Triggered by FLOSS/fund grant per `2a1f933` Class 1, OR enterprise contract that requires SOC 2. |
| Commercial SIEM (DataDog / Splunk / Elastic Security) | **₹4-8 lakh / year** ($5-10k/yr base + per-GB ingest fees) | 1-2 weeks integration | None on the code side. Required for "real-time alert pipeline" rubric row in NIST CSF 2.0 DE.AE-3. |
| Formal third-party pen-test | **₹3-8 lakh per engagement** ($4-10k) | 4-6 weeks engagement window | Annual cadence for SEBI-regulated entities. Engagement only valuable post-launch with real users; pre-launch pen-test is theoretical. |
| Real-time alert pipeline subscription (PagerDuty / Opsgenie) | **₹3-5 lakh / year** ($4-7k/yr seat licenses) | 1 week wiring | Process-maturity ask: an actual on-call rotation. Single-developer projects can buy the subscription but cannot honestly claim 24x7 coverage. |
| CERT-In VAPT (mandatory for many fintech categories per `kite-cost-estimates.md`) | **₹3-5 lakh / year** (₹1-2L per cycle, 2 cycles/year for regulated entities) | continuous | Engagement only mandatory if SEBI-RA-registered. Path-2 (`ENABLE_TRADING=false`) keeps us out of this category today. |

**Net for NIST**: −6 dim-points blocked by external-$$ purchases. SOC 2 Type II is the highest-impact single buy (closes ~+3 NIST + ~+12 EntGov). Cumulative: ~₹25-40 lakh Y1 + ~₹15-25 lakh/year ongoing. Triggers: FLOSS/fund grant approval, OR first enterprise contract demanding SOC 2 evidence, OR ₹50L+ ARR justifying audit expense.

---

### 1.4 Enterprise Governance (current 68 / max 100 / gap −32)

**What 100 actually looks like for this dim** (per `.research/blockers-to-100.md` §13): an **operational** ISMS (Information Security Management System) per ISO 27001, with quarterly governance committee review, formally signed risk-acceptance memos, executive risk-register review cadence, third-party-attested governance program, and formal vendor-risk-management procedures with supply-chain audit evidence. The dim is NOT about adding more documents — it is about evidence that documented governance is **practiced** at organizational cadence.

**Quantified sub-blockers**:

| Sub-blocker | Cost | Time-to-acquire | Hard prerequisite |
|---|---|---|---|
| **ISO 27001 certification** | **₹8-15 lakh** initial cert + **₹3-5 lakh / year** surveillance audit (year 2 onward); India-domiciled certifying body (BSI / TÜV Nord) | 6-9 months ISMS preparation + audit cycle | Formal ISMS implementation: 14 mandatory documents, evidence of governance committee meetings, risk-treatment plan executed. Not a paperwork exercise — auditors interview staff and verify operational reality. |
| **Governance committee + cadence** | ~₹15-30k/month (board secretary or committee secretary) + 4-8 hours/month executive time (opportunity cost) | continuous | At least 3 distinct people (CEO + CTO + Independent Director or equivalent). Solo founder cannot honestly claim a governance committee. Triggered by Pvt Ltd incorporation (₹55-85k Y1 per `kite-cost-estimates.md`) at minimum. |
| **Independent Director on board** | ~₹50k-1L/month retainer or ~₹5-10L/year fixed | continuous | Pvt Ltd already incorporated. Audit-grade governance requires at least one board member who is NOT the founder. |
| **Formal third-party security review** | **₹5-10 lakh** per review (sibling to pen-test but broader scope: covers governance + operational + technical) | 6-8 weeks | Requires existing security program documentation (we have it; SECURITY_POSTURE.md + threat-model.md + risk-register.md) for review baseline. The review itself is mostly external-attestation effort. |
| **Internal audit function** (SOC 2 / ISO 27001 prerequisite) | ~₹3-5 lakh / year (part-time CA / CS retainer) | continuous | Pvt Ltd. The CA / CS cannot be the founder's own personal CA. |
| Legal opinion letter (Spice Route Legal or Finsec Law per `kite-fintech-lawyers.md`) | **₹3-5 lakh** for a 5-10 page written opinion | 4-6 weeks | Triggers when monetization activates + multiple users. Required to defend against DPDP / sub-broker allegations. |

**Net for EntGov**: −32 dim-points, of which ~−28 are external-$$ + organizational structure (ISO 27001 + governance committee + independent director + internal audit + opinion letter) and ~−4 are internal documents already below the 0.4 density floor (CHANGELOG with semver, additional retrospective ADRs). Cumulative cost: ~₹15-30 lakh Y1 + ~₹10-15 lakh/year ongoing. Triggers: Pvt Ltd incorporation, then SOC 2 readiness consultant engagement.

---

## Section 2 — Why "external-$$" is not a single category

The phrase "external-$$" obscures three meaningfully distinct buckets, each with different unlock conditions. Treating them as one bucket leads to bad budgeting decisions.

### 2.1 Auditor-gated (cannot self-attest, requires third-party engagement)

| Item | Cost | Trigger condition that unlocks the spend |
|---|---|---|
| **SOC 2 Type II audit** | ₹15-25 lakh / year | First enterprise contract demanding SOC 2 evidence (typically a B2B SaaS deal worth ≥₹50L ACV), OR FLOSS/fund grant disbursement (since the grant proposal has SOC 2 as a Y1 milestone). |
| **ISO 27001 certification** | ₹8-15 lakh + ₹3-5 lakh/year surveillance | Same as SOC 2 — typically bundled. Often a precondition for selling into Indian banks, RBI-regulated FIs, large corporates. |
| **SEBI CSCRF formal attestation** | (varies; not a single fee — staged compliance audits via empanelled auditors) | Triggered by SEBI registration as RA / RIA / Algo Provider. Per `kite-mrr-reality.md`: ₹1.1-1.8L Y1 + ₹1L locked deposit for individual RA; ₹4-8L Y1 for NSE empanelment. Path-2 (`ENABLE_TRADING=false`) keeps us OUT of this audit pipeline today. |
| **CERT-In VAPT** | ₹3-5 lakh / year (mandatory for many fintech categories) | Triggers if we register as a fintech entity that the CERT-In Directions cover. Path-2 architecture means we are not yet in scope. |

**Trigger generalisation**: auditor-gated spend unlocks at the *enterprise-contract* tier (B2B revenue) or at the *registered-entity* tier (SEBI / RBI registration). Below ~₹50L ARR, there is no ROI for the spend; it is pure cost without payback.

### 2.2 Vendor-gated (commercial subscription buys the capability)

| Item | Cost | Trigger condition |
|---|---|---|
| **Commercial SIEM** (DataDog / Splunk / Elastic) | ₹4-8 lakh / year | First sustained alerting need beyond what `flyctl logs` + audit trail provides. Trigger: ≥1K daily-active users producing enough log volume that grep-and-jq becomes operationally infeasible. |
| **Pen-test engagement** | ₹3-8 lakh per cycle | Annual for SEBI-regulated entities. For us today: triggers at SOC 2 readiness or first pre-empanelment audit. |
| **Code-signing certificate** (Microsoft Trusted Signing, Certum) | **₹15k / year** ($200-300/yr) — **CHEAPEST external item** | Anytime — eliminates SmartScreen warnings on the few Windows users who run our binary. Trigger: first Windows-self-host user complaint about SmartScreen blocks. |
| **PagerDuty / Opsgenie** | ₹3-5 lakh / year (seat licenses) | Honestly: requires actual on-call team. Solo developer cannot claim 24x7 coverage. Trigger: team size ≥3 with rotation plausibility. |
| **Vanta / Drata / Sprinto** (compliance-automation tooling) | ₹8-12 lakh / year standalone | Only valuable when SOC 2 readiness phase begins. Not useful before. |

**Trigger generalisation**: vendor-gated spend unlocks at the *operational-volume* tier (SIEM at log-volume threshold, PagerDuty at on-call team threshold). The cheapest item (code-signing ₹15k/yr) is also the lowest-impact (~+0.5 dim-point in the worst-case analysis); not worth doing in isolation.

### 2.3 Scale-gated (require paying customers / users we don't have yet)

| Item | Cost | Trigger condition |
|---|---|---|
| **Multi-broker partnership** | ₹0 nominal (engineering opportunity-cost ~3-6 weeks per adapter) | First paying customer specifically demanding a non-Zerodha broker. At our ₹15-25k MRR ceiling at 12 months, this is implausible. |
| **Postgres at scale** | ₹4-6 lakh / year ongoing infra + 4-6 weeks engineering | ≥5K users per ADR 0002. Below: SQLite + Litestream is the safe operating envelope. |
| **On-call rotation team** (3+ engineers) | ₹15-30 lakh / year per engineer | Team headcount funded by Series-A or recurring enterprise contracts. Below: solo developer cannot honestly run on-call. |
| **Independent Director on board** | ₹5-10 lakh / year retainer | Pvt Ltd incorporation first (₹55-85k Y1), THEN board formation. Triggered when monetization activates and the founder personally is no longer the only board member. |
| **Internal audit / compliance officer** | ₹3-5 lakh / year (part-time CA / CS) | ISO 27001 / SOC 2 readiness. Pvt Ltd prerequisite. |

**Trigger generalisation**: scale-gated spend unlocks at the *paying-customer-volume* tier (multi-broker, Postgres, headcount) or at the *funded-entity* tier (board, internal audit, governance committee). All require *something else to fire first* — typically a Series-A round or enterprise contract — before the spend is ROI-positive.

### 2.4 Why the distinction matters for budgeting

A naive read of "external-$$ ~₹50-80 lakh" treats the entire spend as one block. The trigger analysis shows it is staged:

```
Stage 1 (today): code-signing ₹15k/yr  — only one cheap unlock
Stage 2 (post-FLOSS-grant): SOC 2 Type II + Vanta ₹25-30L/yr — unlocked by grant disbursement
Stage 3 (post-50-paid-subs): Pvt Ltd + board ₹2-5L Y1 — unlocked by initial revenue
Stage 4 (post-1000-users): SIEM + on-call ₹15-20L/yr — unlocked by operational volume
Stage 5 (post-Series-A): ISO 27001 + governance committee + independent director ₹15-25L Y1 — unlocked by external capital
```

Stages 2-5 are sequenced. Skipping ahead is possible but inefficient — Stage 5 spend without Stage 2-4 evidence does not produce Stage 5 dim-points (an ISO 27001 cert without a real ISMS in operation is a piece of paper, not a +10 dim-point lift).

---

## Section 3 — Why architectural work alone cannot close the gap

The pivotal insight: **the 4 remaining dims at <100 are not "code we haven't written yet."** They are organizational, contractual, and regulatory artefacts that no amount of Go work produces.

### 3.1 Compatibility = standards-body certifications + integration partnerships

A second broker adapter is ~600 LOC of Go. The dim-point lift requires:
- The adapter shipped (Go work — ours)
- The broker company formally accepting us as an integration partner (contract-side — theirs)
- A real customer using the adapter in production (revenue-side — market's)

We can write the Go. We cannot make a partnership materialise, and we cannot manufacture a paying customer who happens to demand the second broker. The dim measures the THREE conditions together, not just the first.

### 3.2 Portability = cross-runtime executable proof

Per `.research/parallel-stack-shift-roadmap.md`, the dim-100 close requires running a track end-to-end: TypeScript widgets in production OR Python analytics in production. The roadmap explicitly notes (§2.5):
> "Track A only pays if user specifically authorizes the no-feature year."

8-12 months of single-developer time devoted to no-customer-visible work, in a context where projected MRR ceiling is ₹15-25k/month, is not authorisable without external funding.

### 3.3 NIST = auditor sign-off + ongoing compliance program

You cannot self-attest SOC 2 Type II. The dim explicitly grades third-party attestation. The cost is not just the audit fee (₹15-25L) but:
- 6-12 months of operational evidence accumulated over the observation window
- Internal documentation effort to map controls to SOC 2 trust principles (most automated by Vanta / Drata at ₹8-12L)
- Operational discipline that survives the auditor's interview-based verification

This is months of work spent purchasing a certificate, with no customer-facing feature output during the window.

### 3.4 EntGov = governance committees + executive review cadence

A solo developer cannot honestly claim a governance committee meets quarterly. The rubric grades evidence that documented governance is **practiced** at organizational cadence. That requires:
- Pvt Ltd incorporation (so a "company" exists to be governed)
- Multiple roles (CEO + CTO + Independent Director, NOT all the same person)
- Quarterly meeting minutes with non-trivial agenda items
- Risk-acceptance memos signed by accountable executives

Engineering work cannot manufacture this. Pvt Ltd incorporation is the ₹55-85k Y1 trigger, but on its own it does not satisfy the rubric — it is a precondition for satisfying the rubric.

### 3.5 The misframing to correct

When someone asks "why aren't we at literal 100?", the answer they hope for is "because we haven't shipped X feature yet." That answer would imply: ship feature → reach 100 → goal achieved.

The actual answer is: **we are at 99.4% of the constrained empirical max because the remaining gap measures things money + time + customers + auditors + boards purchase**. None of those are engineering tasks. The architectural cycle is materially complete; the remaining gap is a *business cycle* that requires a different set of inputs.

---

## Section 4 — What WOULD it cost to literally reach 100?

Three scenarios. All assume continuous operation through the period; opportunity-cost of forgone feature work not separately monetised.

| Scenario | INR cost | Timeline | Notes |
|---|---|---|---|
| **Best-case** (everything goes right, parallel-track the audits, leverage FLOSS/fund disbursement to defray Y1) | ~₹50 lakh out-of-pocket Y1 + ₹20-25 lakh / year ongoing | **18 months** end-to-end (SOC 2 Type II observation window + ISO 27001 cycle + multi-broker partnership engineering + Postgres deployment + governance-committee establishment) | Requires FLOSS/fund grant approval to fund SOC 2 prep; first paying customer specifically demanding multi-broker; Pvt Ltd already incorporated; >5K user volume to justify Postgres |
| **Realistic-mid** (sequenced, customer-driven, no parallel audits) | **~₹80 lakh Y1-Y2 cumulative + ₹25-35 lakh / year ongoing** | **24-30 months** | One audit at a time; Postgres adapter built when 5K users demand it; multi-broker shipped when first customer asks; ISO 27001 follows SOC 2 in Year 2; track-shift runtime port deferred to post-Series-A |
| **Worst-case** (every audit slips, partnerships stall, scale-gating doesn't trigger) | **~₹1.2-1.5 crore Y1-Y3 cumulative + ₹30-40 lakh / year ongoing** | **36-48 months** | Pen-test repeats due to findings; ISO 27001 surveillance requires re-cert; partnerships fall through and need re-pitch; team headcount expansion (₹15-30L/yr per engineer) added to make on-call honest |

**The cost ratio to current MRR**: at projected ₹15-25k/month MRR ceiling at 12 months (~₹2-3 lakh ARR), the realistic-mid spend (₹80L cumulative) is **30-40× ARR**. That is not a side-project task. That is a **Series-A milestone** (typical Indian fintech Series-A: ₹6-12 crore over 18-month runway, of which compliance-program spend is a budgeted line item).

A reasonable interpretation: literal 100 is what you *grow into* after raising capital, not what you *purchase* before the first paying customer.

---

## Section 5 — Counter-recommendation and pivot priorities

**Continue at 95.08 / 99.4% empirical-max under no-external-$$ constraint.** This is the materially-complete state of the architectural cycle.

The remaining +5 dim-points to literal 100 cost ~₹50-80 lakh and 12-24 months — that is a Series-A milestone, not an architecture-side task. The right move is to grow into the spend justification, not invest the spend speculatively.

### Pivot priorities — ranked by ROI per hour-of-effort

Per `eff33c7` `.research/state-and-100pct-reconciliation.md` Q1, three items remain DRAFTED + one is UNDONE. Ordered by ROI / cost (since the user asked "are these pending — should we install [handle] before that?"):

| Rank | Item | Cost (effort + INR) | ROI | Concrete action |
|---|---|---|---|---|
| **1** | **Compliance email to `kiteconnect@zerodha.com`** | ~30 minutes effort + ₹0 | Highest. Establishes paper trail with Zerodha as the broker we depend on; defuses the largest landmine (Nithin disapproval per `incident-response.md` Scenario 1). Required precondition for FLOSS/fund grant credibility, Rainmatter warm-intro, and any future partnership conversation. | Replace `<product-email-placeholder>` in `docs/drafts/zerodha-compliance-email.md` with the canonical product email (per `MEMORY.md` rule: NEVER the Foundation address). Send. Log response in `docs/evidence/compliance-emails-sent.md`. |
| **2** | **FLOSS/fund grant submission** (manifest is published; submission not made) | ~2 hours effort + ₹0 | Second-highest. $10k-$100k non-dilutive grant per `kite-floss-fund.md`. Individuals eligible — no Pvt Ltd prerequisite. Approval funds Stage-2 spend (SOC 2 prep + audit) which closes ~+15 dim-points. Prerequisite for warm-intro to Rainmatter ecosystem per `kite-rainmatter-warm-intro.md`. | Visit https://floss.fund/, complete the submission form referencing the published `funding.json` URL, attach `docs/floss-fund-proposal.md` as the 1-page pitch. Wait for monthly review cycle. |
| **3** | **Public launch sequencing** (drafts in `docs/launch/` are ready) | ~1-2 days effort + ₹0 | Triggers the 50-star Rainmatter unlock per `kite-rainmatter-warm-intro.md`. Without launch, the 50-star trigger never fires. Show HN + Reddit r/Algotrading_India + Twitter thread (drafts exist). Risk: HN front-page hits cannot be re-attempted; do this when launch-blockers are clean (DONE per `eff33c7` Q1 §4). | Post Show HN; Reddit cross-post; Twitter thread. Monitor for first wave of stars. |
| **4** | **Algo2Go rename filing** | ~2 weeks effort + ~₹15-25k INR (domain + TM Class 36+42 filing) | Lowest immediate ROI. Trademark protection for our project name. Per `MEMORY.md`: Zerodha's "Kite" was REFUSED by IP India (no registered monopoly), so the rename is *defensive*, not blocking. Can be done after launch when name-claim signals matter. | Run TM search per `docs/algo2go-tm-search.md`. Buy `algo2go.com` + `algo2go.in`. File trademark Class 36+42. Total ₹15-25k. |

**Recommended sequence**:
1. Send the Zerodha compliance email **first** (30 min, ₹0). This is the cheapest paper-trail establishment.
2. Submit FLOSS/fund **second** (2 hours, ₹0). Application review cycle is monthly; queue early.
3. Public launch **third** (1-2 days), only after items 1+2 are in flight. Launch with the FLOSS/fund submission already pending establishes credibility.
4. Algo2Go rename filing **last** — defer to post-50-stars. Filing before name has any reputational signal is wasted defensive spend.

The user-MRR axis becomes positive at items 2 and 3 (grant approval; launch traction). Item 1 is the precondition that unblocks 2 and 3. Item 4 is post-traction defensive work.

---

## Honest opacity

1. **All cost estimates are INR 2026 nominal market rates** sourced from `kite-cost-estimates.md`, `kite-fintech-lawyers.md`, `kite-floss-fund.md`, `kite-mrr-reality.md`, `kite-rainmatter-warm-intro.md`, and the v3 scorecard. Real quotes from auditors (Vanta, Drata, Sprinto, BSI, TÜV) would refine ±20%. No quotes have been gathered for this project specifically; estimates are interpolated from published standards-body fee schedules and Indian-fintech-grade audit norms.

2. **The 6-12 month SOC 2 Type II observation window is the floor**, not the typical timeline. Typical SOC 2 Type II takes 12-18 months total (3-6 months readiness + 6-12 months observation + 1-2 months audit). Best-case 18 months in §4 assumes parallel-track readiness + observation; conservative readers should add a 6-month buffer.

3. **Multi-broker partnership timing is fully external**. Broker companies have their own integration roadmaps. We have no signal on Upstox / Angel / Dhan integration cadence. The 4-8 week elapsed in §1.1 is optimistic for first-time partnerships; real timelines run 3-6 months from first contact to live integration.

4. **Track-shift cost (8-12 months single-dev)** assumes no scope creep. Per `.research/parallel-stack-shift-roadmap.md` §2.5, the 49-week worst case assumed empirical thoroughness, not feature-equivalence. A pure feature-equivalent port may take longer if the TS / Python ecosystems lack the kind of typed-message handling Go provides.

5. **The "Series-A milestone" framing is interpretive, not asserted as fact**. A reasonable Indian fintech Series-A is ₹6-12 crore over 18 months runway; ₹80 lakh of compliance spend is 7-13% of that — a plausible budget line item. But Series-A funding for a solo founder pre-revenue is itself uncertain. The framing should be read as "this is the kind of investment that is normally made post-funding", not as "this is the only possible path".

6. **The 4-item pivot recommendation in §5 is ordered by ROI / cost**. The user could reasonably pick a different ordering if their goal is, e.g., maximum optionality (file rename first to lock the name) vs maximum revenue-pull (launch first to test market demand). My recommendation prioritises the cheapest unblocking actions first (paper trail with Zerodha; grant submission), then growth signals, then defensive work.

7. **Cross-agent awareness**: hex agent (`a67d647b28371a855`) is in flight on observability bundle (disjoint scope); decorator agent (`a83bda9069cbd21fd`) is in flight on team-hooks analysis in a different repo (disjoint scope). This document does not anticipate or fold their findings.

---

## Stop condition

Per the user's brief: *"Single doc commit, push to origin. NO code changes."* This file IS the single doc. Next: `git add` (`.research/` not gitignored), `commit -o` path-form, push, honest-stop. WSL2 sanity already established at HEAD `eff33c7` (`go vet ./...` clean).

---

*Generated 2026-04-28 night, deeper companion to `.research/state-and-100pct-reconciliation.md` (`eff33c7`) and `.research/scorecard-final-v3.md` (`1081684`). All three together are the closing artifacts of this session's architectural-hardening dispatch.*
