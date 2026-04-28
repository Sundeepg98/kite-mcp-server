# ADR 0010: Stack-Shift Deferral — All Three Parallel Tracks

**Status**: Accepted (2026-04-28)
**Author**: kite-mcp-server architecture
**Decision drivers**:
- Cost-benefit asymmetry: stack-shift parallel-tracks is 800-4000×
  more expensive per dim-point than the queued NIST internal items
  (per `parallel-stack-shift-roadmap.md` §10).
- Empirical 13-dim ceiling reached: 9 dims at 100, aggregate 94.08
  equal-weighted at 99.4% of the 94.62 calibrated empirical max
  (`scorecard-final-v2.md` `8361409`).
- Tier-3 promotion-trigger matrix (`d0e999d`): P(≥2 components
  promote within 24mo) ≈ 31%; foundation-phase ROI marginally
  positive only at the 2+ inflection.
- Three-axis ROI verdict per `feedback_decoupling_denominator.md`:
  user-MRR axis negative for all three tracks; agent-concurrency
  axis at marginal threshold; tech-stack-portability axis positive
  but speculative without trigger fires.

---

## Context

Three architectural pressures converged across April 2026:

1. **Decorator dim 97 ceiling** prompted exploration of language
   alternatives via `decorator-stack-shift-evaluation.md` (`809edaf`).
   Six languages were evaluated for the +3 closure: TypeScript,
   Python, Rust, Java, Kotlin, Scala.

2. **Per-component swap freedom** (Axis C of the three-axis ROI
   framework, per `feedback_decoupling_denominator.md`) prompted
   `component-language-swap-plan.md` (`a03694a`) — a 24-month per-
   component shortlist of the components that COULD productively
   leave Go.

3. **Parallel-tracks framing** consolidated the per-component
   shortlist into three coherent tracks (TS / Python / Rust) per
   `parallel-stack-shift-roadmap.md` (`8361409`), surfacing the
   cumulative cost of activating multiple tracks vs the dim-points
   gained.

The three deliverables together asked: should we invest in
parallel-language-track infrastructure NOW so that any future
trigger-driven track activation is unblocked, OR should we defer all
three tracks and revisit when triggers fire?

This ADR captures the decision to defer all three.

---

## Decision

**Defer all three parallel-language tracks indefinitely.** No
foundation-phase infrastructure is built; no per-language CI is
provisioned; no IPC wire-format implementation is shipped (the
spec ratified in ADR 0009 stays draft).

The codebase stays single-language Go for the 24-month horizon.

### Per-track verdicts

| Track | Counter-recommendation (stay-in-Go) | Why deferred |
|---|---|---|
| **A — TypeScript (mcp/ outer ring → widgets)** | 0 LOC + dev-tooling iteration; Decorator dim 97→100 closed via Option 2 (`710c011`) + Option 4 (ADR 0008) | Customer demand for new widgets <1/month; Go-template iteration cost <6 hours; no measured TS advantage today |
| **B — Python (analytics → backtest)** | ~200-400 LOC per gonum integration; small analytics roadmap absorbs that | 4 analytics tools shipped; 3-5 deferred (PCA, factor models, MC VaR); below 10-feature gonum-cost-compounding threshold |
| **C — Rust (riskguard → oauth/credstore)** | 0 LOC; ~300 LOC GC tuning if latency demand grows | <100 concurrent users; no paying-customer demand for second broker (Compatibility) or sub-1ms tick latency (Portability) |

### Cost-benefit math

Per `parallel-stack-shift-roadmap.md` §10:

- **Best-case parallel calendar at 4-person team**: 16-18 weeks for
  +0.6 equal-weighted gain across the three tracks. Density:
  **0.04 dim-pts per developer-week**.
- **Realistic single-developer calendar**: 72-103 weeks for the same
  +0.6. Density: **0.008 dim-pts per developer-week**.
- **Comparable internal-tractable items** (MFA admin, JWT rotation
  CLI, hash-publish default-on, TLS self-host) per
  `scorecard-final-v2.md` §2.4: density **2.0 dim-pts per
  developer-week** (or higher individually) — **at LEAST 50× higher
  than the parallel-tracks average**, and **800-4000× higher per
  dim-point won at the same calendar position**.

Density ratio interpretation: every developer-week spent on parallel-
tracks produces 0.008-0.04 dim-points; the same week spent on the
queued NIST internal items produces 1-3 dim-points. The opportunity
cost of activating tracks today is exhausting the higher-density
internal items first.

### Foundation-phase amortization analysis

Per `parallel-stack-shift-roadmap.md` §1.6, the Foundation phase is
4-5 weeks calendar at single-developer scale (IPC contract spec +
per-language CI + deploy targets + observability + SBOM). Foundation
costs are sunk regardless of how many tracks activate within
24 months.

| Tracks activated | Foundation amortization |
|---|---|
| 0 | Wasted (~4-5 dev-weeks of pre-investment with zero payoff) |
| 1 | Marginal (single-track payoff is 8-14 dev-weeks; foundation overhead is 30-60% of track cost) |
| 2 | Positive (foundation cost spread across 2 tracks; per-track overhead halves) |
| 3 | Strongly positive (foundation per-track cost ~1.5-2 weeks; competitive with same-language refactor cost) |

Per `d0e999d` Tier-3 promotion-trigger matrix:

- P(0 promotions in 24mo) ≈ 31%
- P(exactly 1) ≈ 38%
- P(exactly 2) ≈ 19%
- P(≥3) ≈ 12%

**P(foundation amortizes — ≥2 tracks activate) ≈ 31%**.

Combined with the 800-4000× density disadvantage even when foundation
amortizes, the expected ROI of building Foundation now is negative.

### Three-axis ROI per `feedback_decoupling_denominator.md`

| Axis | Track A | Track B | Track C |
|---|---|---|---|
| **User-MRR** | Negative — widgets ship at <1/mo | Negative — current analytics roadmap fits in Go + gonum | Negative — no paying customer demand for the multi-broker / sub-1ms scenarios this would unblock |
| **Agent-concurrency** | Marginal — Go-template iteration is the actual bottleneck, not language | Positive but speculative — agents have to learn Python idioms | Negative — Rust learning curve outweighs concurrency win at current scale |
| **Tech-stack-portability** | Positive but speculative — only matters if MRR-positive demand surfaces | Positive but speculative — same shape | Positive but speculative — same shape |

Per `feedback_decoupling_denominator.md`'s "two-of-three positive
threshold for sustained investment", none of the three tracks clears
the threshold today.

---

## Consequences

### What this enables

1. **Engineering bandwidth stays focused on the high-density queue**.
   The four NIST internal items (MFA admin, JWT rotation CLI,
   hash-publish default-on, TLS self-host) ship at density ~2.0
   dim-pts/100 LOC; these continue to absorb the available bandwidth
   ahead of speculative track activation.

2. **Triggers are documented and stable**. Future contributors who
   wonder "should we ship Track X?" check the trigger conditions
   below; if none fires, this ADR holds. If one fires, this ADR is
   revisited per the trigger-condition section.

3. **Foundation work is not wasted on unused infrastructure**. ADR
   0009 ratifies the IPC wire-format choice (JSON-RPC 2.0 over
   stdio) so the FORMAT decision is stable, but the IMPLEMENTATION
   sits in spec form until first activation. ~4 weeks of dev-time
   not spent building unused per-language CI / deploy targets /
   observability shims.

4. **`kc/aop` (Decorator Option 4, ADR 0008) becomes the canonical
   path for paths A/B/C closure**. Track A's TS-native @decorator
   alternative is superseded; the Go-internal AOP at `kc/aop`
   absorbs that surface.

### What this constrains

1. **Triggers may fire and we won't be ready**. If a paying customer
   demand for second broker support lands tomorrow, we have to spend
   4-5 weeks on foundation before any Rust track work starts. This
   is accepted — the alternative (foundation-prebuild) has 31%
   amortization probability and is worse expected value.

2. **Decorator dim 97 holds**. Without Track A's TS-native @decorator
   path, the +3 closure relies entirely on Option 4 (`kc/aop`)
   per ADR 0008. If Option 4's reflective AOP runtime cost proves
   prohibitive in production, the Track A reactivation conversation
   re-opens.

3. **Compatibility and Portability dims stay 86**. Both are
   SCALE-GATED at +14 each; closing them requires either second
   broker integration (Compatibility) or 1k+ concurrent users
   (Portability). Neither is feasible without Track activation.

4. **Stack-shift research artifacts go stale**. The spec in ADR 0009
   may drift from the JSON-RPC ecosystem state by the time a track
   activates. Acceptable: spec drift is cheaper to fix than premature
   implementation drift.

### What this rejects

1. **Track A activation now**. Rejected — widgets ship at <1/mo,
   Go-template iteration is not the velocity bottleneck, no
   measured TS advantage today.
2. **Track B activation now**. Rejected — analytics roadmap fits
   in Go + gonum at current size; Python ecosystem advantage doesn't
   compound until 10+ deferred tools.
3. **Track C activation now**. Rejected — concurrent user count
   <100; no paying customer demand for second broker; ticker
   latency well within Go's GC ceiling at current load.
4. **Foundation-only investment without track commitment**. Rejected —
   31% amortization probability + 800-4000× density disadvantage
   even when amortized makes pre-investment negative expected value.
5. **Single-track activation as proof-of-concept**. Rejected —
   single-track foundation overhead is 30-60% of track cost; runs
   counter to the parallel-tracks framing's whole-portfolio cost
   logic.

---

## Trigger conditions for revisiting

This ADR is revisited when ANY of the following fires. Each track
has independent triggers; firing one track's trigger reactivates
that track's evaluation without forcing the others.

### Track A reactivation triggers

ALL THREE must hold:

1. Customer demand for new widgets ≥ 1 per week sustained for 6+
   weeks
2. Current Go-template iteration cost ≥ 4 hours per widget
   (measured via PR cycle time)
3. TS ecosystem advantage measured at 4× faster iteration via
   prototype experiment (not assumed)

### Track B reactivation triggers

EITHER:

1. Analytics roadmap exceeds 10 deferred tools AND each tool has
   genuine numpy/pandas/scipy benefit (not just "could be done in
   Python") OR
2. gonum-port cost on the deferred analytics roadmap exceeds
   2000 cumulative LOC

### Track C reactivation triggers

EITHER:

1. Concurrent user count exceeds 1000 (Portability dim demand
   becomes user-MRR-positive via Rust ticker latency hedge) OR
2. Paying customer demand for Upstox/Fyers/Dhan integration
   (Compatibility dim demand becomes user-MRR-positive) OR
3. Riskguard subprocess latency p99 exceeds 5ms under realistic
   load (Rust hedge becomes user-experience-critical)

### Cross-track reactivation triggers

EITHER:

1. Engineering team scales to 4+ developers with cross-stack
   bandwidth (parallel-tracks calendar collapses from 72-103 weeks
   solo to 16-18 weeks team) AND ≥1 track-specific trigger above
   fires OR
2. Compatibility or Portability dim becomes product-critical
   (regulator mandate, anchor customer demand) AND track-specific
   counter-rec (gonum / Go-internal) fails to absorb the demand

### Stop-rules per track if ever activated

Per `parallel-stack-shift-roadmap.md` §8.4:

| Track | Stop-rule |
|---|---|
| A | Cumulative cost > 30 weeks AND mcp/ port stalls; abort, revert deltas |
| B | Cumulative cost > 12 weeks AND no new analytics tool ships from Python track; abort, gonum-port the deferred features back |
| C | Cumulative cost > 30 weeks AND riskguard subprocess fails latency SLO (>5ms p99); abort, keep Go-side riskguard |

---

## Relationship to other ADRs

- **ADR 0006 (fx adoption)**: same "anti-rec'd, reluctantly accepted
  for agent-concurrency-axis" framing applied at a smaller scale.
  This ADR rejects the larger sibling investment (parallel-tracks)
  on the same three-axis math but with negative expected ROI rather
  than positive marginal ROI.
- **ADR 0007 (canonical cross-language plugin IPC)**: pattern
  remains in force for the existing riskguard plugin domain.
  Stack-shift deferral does not affect ADR 0007.
- **ADR 0008 (Decorator Option 4 — Go reflection AOP)**: the
  canonical closure path for rubric paths A/B/C. Track A's
  TS-native @decorator alternative is superseded by ADR 0008's
  in-Go AOP shipped at `kc/aop`.
- **ADR 0009 (IPC contract spec — JSON-RPC 2.0 over stdio)**:
  ratifies the wire-format decision so first track activation
  doesn't restart the encoding-format debate. This ADR cites
  ADR 0009 for the trigger-condition framework.

---

## References

- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — three-track
  cost analysis + per-track verdicts + Foundation phase calendar math
- `.research/decorator-stack-shift-evaluation.md` (`809edaf`) — six-
  language Decorator dim closure evaluation; KEEP-GO-ACCEPT-97-CEILING
  verdict (superseded by ADR 0008 for the +3 closure)
- `.research/component-language-swap-plan.md` (`a03694a`) — per-
  component shortlist; preserved in roadmap §2-4 sequencing
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  per-component promotion-trigger matrix; informs P(amortization)
  calculation
- `.research/scorecard-final-v2.md` (`8361409`) — current 13-dim
  state (94.08 / 94.62 = 99.4% of empirical-max); §2.4 internal-
  tractable items density
- `feedback_decoupling_denominator.md` — three-axis ROI framework
- `docs/adr/0006-fx-adoption.md` (`d3d2cce`) — same anti-rec'd-
  acceptance framing at smaller scale
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`)
- `docs/adr/0008-decorator-option-4-go-reflection-aop.md` (`e8ccd34`)
- `docs/adr/0009-ipc-contract-spec-jsonrpc.md` (this batch) — wire-
  format choice for the deferred tracks
