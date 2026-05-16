---
title: Track 2.B Position adoption empirical re-survey
date: 2026-05-16
agent_uuid: ab5d0c66d7bc673d4
session: 2026-05-16 Show HN red-team follow-on
status: COMPLETE — RECOMMEND RETIRE
supersedes: kc-manager-decomp-roadmap-2026-05-16.md §8.7 ("63 broker.Position sites, ~14-22h consumer migration")
empirical_count: 6 consumer sites (vs Audit's claimed 63)
migration_candidates: 0
real_work_remaining: ~0 min (vs Audit's forecast 14-22h)
inflation_factor: >10x
---

# Track 2.B Position adoption empirical re-survey (2026-05-16)

## §0 Headline finding (read first)

**Audit's "63 sites" claim is inflated >10×. Strict empirical count: 6 consumer sites across 4 modules; ALL 6 are already-wrapped or DTO-boundary code. Track 2.B real work: ~0 minutes. Recommend RETIRE from execution roadmap.**

Compare Track 2.A (Order, 53 → 26 strict, ~30min real work) — Track 2.B is even further along the adoption curve. The pattern Audit measured was the **type-name-mention surface**, which includes:
- 9 mentions inside `domain/position.go` itself (the wrapper's own definition file — these are the canonical wrap functions, not consumer sites)
- Sibling DTO types (`Positions`, `PositionConverter`) that share the prefix but are distinct types not mapped to `domain.Position`
- Test fixtures (excluded by the strict count — brief's `_test.go` filter)

Strip those, and 6 consumer sites remain. Every one already uses `domain.NewPositionFromBroker`. **The codebase fully internalized the wrap-at-consumer pattern during Slice 6.**

Zero migration candidates found:
- Zero string-literal `"LONG"`/`"SHORT"`/`"FLAT"` direction comparisons
- Zero `.Product == "MIS"` checks (no `IsIntraday()` candidates)
- Zero direction-derivation patterns where `pos.Direction()` would replace inline logic

## §1 Per-site enumeration with migration recommendation

### Module: `algo2go/kite-mcp-bootstrap` — 2 sites

| # | File:line | Site signature | Classification | Recommendation |
|---|---|---|---|---|
| 1 | `mcp/analytics/analytics_tools.go:399` | `func computePositionAnalysis(netPositions []broker.Position) *positionAnalysisResponse` | **Already-wrapped** — line 409 lifts via `domain.NewPositionFromBroker(p)`; lines 417, 421, 432 read `.PnL()` through the domain entity. `broker.Position` reference is the input-type parameter (required DTO boundary). | **NO CHANGE.** The function takes the DTO slice and lifts each at point-of-use. Replacing the parameter type with `[]domain.Position` would force every caller (presumably `client.GetPositions().Net`) to pre-wrap — pushes work outward without value. |
| 2 | `mcp/trade/pretrade_tool.go:276` (comment line; actual ref at :272 `for _, p := range data.Positions.Net`) | Pre-trade check scanning `Positions.Net` for an existing position on the same symbol | **Already-wrapped** — line 280 lifts via `domain.NewPositionFromBroker(p)`; line 285 uses `pos.PnL().Float64()` for the response field. | **NO CHANGE.** Same pattern as #1. |

### Module: `algo2go/kite-mcp-kc` — 0 sites

Zero `broker.Position` references in non-test code. The kc-tree has been fully decoupled from the Position DTO; it threads broker types through interfaces (`Client.GetPositions()`) without naming the type at use-sites.

### Module: `algo2go/kite-mcp-usecases` — 4 sites

| # | File:line | Site signature | Classification | Recommendation |
|---|---|---|---|---|
| 3 | `close_all_positions.go:102` | `var toClose []broker.Position` (filter accumulator for positions to close) | **DTO-boundary** — the slice holds raw DTOs that feed into `broker.OrderParams` construction (lines 124+ derive `txnType`, `qty`, `Product`, `Tradingsymbol`, `Exchange` from each). The downstream call is `client.PlaceOrder(broker.OrderParams{...})` — broker DTO in, broker DTO out. | **NO CHANGE.** Wrapping here would force unwrap immediately on every iteration to build OrderParams. The 4 fields read (`Tradingsymbol`, `Product`, `Quantity`, `Exchange`) are pure DTO projections, not domain behaviour. |
| 4 | `close_position.go:92` | `var matched *broker.Position` (single-result lookup pointer) | **DTO-boundary + already-wrapped on emit** — pointer holds raw DTO during the find-and-build-order phase (lines 109-163, fed into `broker.OrderParams`). Then at emit-time, line 201 lifts to `domain.NewPositionFromBroker(*matched)` for the response payload's PnL field. | **NO CHANGE.** Exactly the canonical pattern: pointer to DTO during the broker-API construction phase, wrap at the response-emit boundary. |
| 5 | `close_position.go:196` (comment line) | (comment marker for the wrap at :201) | **Already-wrapped** — annotation for the `domain.NewPositionFromBroker(*matched)` lift on the next line. | **NO CHANGE.** |
| 6 | `widget_usecases.go:191` (comment line; actual ref at :190 `for _, p := range positions.Net`) | Widget portfolio response builder iterating net positions | **Already-wrapped** — line 198 lifts via `domain.NewPositionFromBroker(p)`; line 201 uses `pos.PnL().Float64()` for the widget field. | **NO CHANGE.** Identical pattern to bootstrap sites #1 and #2. |

### Module: `algo2go/kite-mcp-domain` — 9 sites (NOT consumer sites)

All 9 references are inside `domain/position.go` itself — these are the canonical wrapper's own definition:

| Line | What |
|---|---|
| 27, 32, 38, 50, 83 | Docstring mentions of `broker.Position` explaining the lift/unwrap semantics |
| 35 | `dto broker.Position` — the embedded DTO field |
| 39 | `func NewPositionFromBroker(b broker.Position) Position` — primary lift constructor |
| 45 | `func ToDomainPosition(b broker.Position) Position` — ergonomic alias |
| 51 | `func (p Position) DTO() broker.Position` — unwrap accessor |

**NOT consumer sites; these are the wrap-API surface itself. Excluded from migration scope by definition.**

## §2 Aggregate verdict

| Bucket | Count |
|---|---|
| Audit's claimed "Position adoption sites" | **63** |
| Empirical strict count (non-test refs to `broker.Position`) | **15** |
| Wrapper-definition refs (inside `domain/position.go`) | **9** |
| **Consumer sites requiring inspection** | **6** |
| → Already-wrapped (use `domain.NewPositionFromBroker`) | **4** |
| → DTO-boundary (raw DTO needed for broker API construction) | **2** |
| → Marginal cosmetic-wrap candidates | **0** |
| → Clear migration wins (string-literal `.Direction == "LONG"`) | **0** |
| **Real adoption work remaining** | **0 minutes** |

**Inflation factor**: Audit 63 → strict consumer 6 → migration-candidate 0. **The codebase is at 100% adoption already.** Every consumer site that touches `broker.Position` either:
- (a) wraps at point-of-use to read PnL through the currency-aware Money accessor (4 sites), OR
- (b) holds the raw DTO precisely because it needs to feed it back into `broker.OrderParams` construction (2 sites — exactly the kind of DTO-boundary code where wrapping would be anti-value).

## §3 Re-scoped execution brief

**Recommendation: RETIRE Track 2.B from the parallel-execution roadmap.**

Rationale:
1. **Zero migration candidates exist.** Unlike Track 2.A which had 1 marginal cosmetic-wrap, Track 2.B has none — the adoption is cleaner because `Position` was introduced in Slice 6 with the wrap pattern as the established convention, and there's no legacy `.Direction == "LONG"` code anywhere to retrofit.
2. **The 2 DTO-boundary sites are correct-as-is.** `close_position.go` and `close_all_positions.go` hold raw `broker.Position` slices because the downstream call (`PlaceOrder(broker.OrderParams{...})`) requires DTO field projection (Quantity, Product, Exchange, Tradingsymbol). Wrapping then unwrapping is pure ceremony.
3. **The 4 already-wrapped sites are canonical examples** of the Slice 6 pattern: loop the DTO slice, wrap each at point-of-use for PnL emission, never store the wrapper longer than the per-iteration scope. This IS the pattern Audit's Manager-decomp roadmap §2 wanted teams to adopt. Mission accomplished.

**If Track 2.B has any forward-work at all**, it's at the documentation layer:
- Add a one-line ADR or `kc/domain/README.md` snippet citing `analytics_tools.go:409`, `widget_usecases.go:198`, and `close_position.go:201` as the three canonical wrap-at-emit examples to learn from.
- Effort: ~15 min, no code changes.

**Reframed Track 2 total estimate**:
- Original Audit forecast: 28-42h (Track 2.A + 2.B consumer adoption)
- Empirical: Track 2.A ~30min (Show HN red-team), Track 2.B ~0min (this survey)
- Net: **~30min, not 28-42h.** Major scope correction stands.

## §4 Empirical methodology notes

### Probes run (all 2026-05-16)

| Probe | Result |
|---|---|
| `grep -rnE "broker\.Position[^a-zA-Z]" --include="*.go"` excluding `_test.go` across 4 modules | 15 lines |
| Subtract `domain/position.go` lines (wrapper's own definition) | 6 consumer sites |
| Read each of the 6 consumer sites in surrounding context (Read tool, 30-120 line windows) | All 6 classified |
| `grep "[LONG\|SHORT\|FLAT]" comparison patterns` across all 4 modules | 0 hits |
| `grep .Product == "MIS"/"NRML"/"CNC"` patterns | 0 hits |
| `grep .Quantity > 0 ? ... : ...` direction-derivation in position context | 0 hits (the 2 hits in usecases derive ORDER txn-type from POSITION quantity — different semantic, not a Direction() candidate) |

### Scope correctness checks

- **Cross-repo coverage verified**: 4 trees probed (`kite-mcp-bootstrap`, `kite-mcp-kc`, `kite-mcp-usecases`, `kite-mcp-domain`). Brief said `algo2go/kite-mcp-bootstrap`, `algo2go/kite-mcp-kc`, `algo2go/kite-mcp-usecases`, `algo2go/kite-mcp-domain` — exact match.
- **Boundary-char regex** (`[^a-zA-Z]`) prevents false-positive matches against sibling DTOs like `broker.Positions` (the plural container) or `broker.PositionConverter` (the interface in `broker.go:509`). Sibling-DTO noise correctly excluded.
- **Test-file exclusion** confirmed via `grep -v "_test.go"`.
- **No `_test.go` sites inspected** per READ-ONLY scope; if test-fixture wraps exist they're outside the production-code adoption question.

### Confidence note

This is a stricter survey than Track 2.A's. Track 2.A reduced 53 → 26 (~50% noise). Track 2.B reduced 63 → 6 (~90% noise), because:
- `broker.Positions` (plural — the container with Day + Net slices) is referenced more frequently than `broker.Position` (singular); Audit's grep likely captured both.
- `domain.Position` was introduced LATER (Slice 6) with the wrap pattern already established, so the codebase never accumulated the legacy `.Quantity > 0 ? "LONG"` patterns that Order had.

### Caveat

This survey did NOT enumerate `broker.Positions` (plural — the container struct holding `Day []Position + Net []Position`). That's a separate adoption question if Audit ever wants to wrap the container too. From the 6 consumer sites surveyed, the consistent pattern is to iterate `positions.Net` and wrap each element — the container itself doesn't need wrapping because there are no behavioural methods on it. Not in this dispatch's scope.

### Date-stamps

- Audit's "63 sites" claim — citing `kc-manager-decomp-roadmap-2026-05-16.md` §8.7 (today's roadmap synthesis)
- This survey's strict count — **6 consumer sites (verified 2026-05-16)**
- This survey's "0 migration candidates" — **verified 2026-05-16**
