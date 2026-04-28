# ADR 0008: Decorator Option 4 — Go Reflection AOP for Rubric Closure

**Status**: Accepted (2026-04-28)
**Author**: kite-mcp-server architecture
**Decision drivers**:
- 13-dim rubric Decorator dim sat at 97/100 after Option 2 ship
  (`710c011`); the +3 residual mapped to rubric paths A/B/C
  (reflective composition / annotation-driven decorators / aspect
  weaving).
- Stack-shift evaluation (`809edaf`,
  `.research/decorator-stack-shift-evaluation.md`) concluded that
  no language swap is cheaper than ~2400 LOC of in-Go reflection
  AOP for closing the +3.
- User explicitly accepted the empirical anti-Go-idiom signal cost
  for score-rubric reasons; the prior "non-goal" verdict in
  `.research/go-irreducible-evaluation.md` (`e84a8f4`) and the
  recommended-against verdict in
  `.research/decorator-stack-shift-evaluation.md` §7 are
  super­seded by this ADR.

---

## Context

The 13-dim architecture rubric (codified in
`.research/blockers-to-100.md` `4b0afd2`) measures the codebase
against six "rubric paths" for decorator-shape decoupling:

| Rubric path | Description | Closure mechanism | Empirical answer in this codebase |
|---|---|---|---|
| A | Reflective composition | Runtime hook discovery via reflection over annotated types | Closed by Option 4 (this ADR) |
| B | Annotation-driven decorators | `@Cacheable` / `@Retryable`-style tag-driven wrappers | Closed by Option 4 via `aop:"audit,riskguard"` struct tags |
| C | Aspect weaving | Pointcut + advice DSL combining intercept locations | Closed by Option 4 via Phase + Pointcut composition |
| D | Compile-time decorator generation | Code-gen produces wrapped methods from annotations | NOT pursued — anti-rec'd per Wire/fx evaluation |
| E | Auto-applied decorators by metadata | Middleware ordering via type tags rather than registration order | Partial via PointcutByTag; full closure not pursued |
| F | Decorator factory composition | Generic typed wrappers (`Decorator[T]` from method handles) | Closed by Option 2 in `kc/decorators` (`2cc31a9`/`710c011`) |

After the Option 2 ship at `710c011`, paths F was closed; paths
A/B/C were the +3 residual. The
`.research/decorator-code-gen-evaluation.md` (`0d92590`) audit
enumerated the available closure mechanisms:

| Option | LOC | Score-rubric paths closed | Density (pts/100 LOC) | Risk |
|---|---|---|---|---|
| 1. AST codegen + magic comments | ~6500 | B, D | 0.05 | HIGH |
| 2. Generic typed decorators | ~500 | F | 0.40 | LOW |
| 3. Wire-style codegen | ~1000+ | D (anti-rec'd) | 0.20 | HIGH |
| **4. AOP via reflection** | **~2400** | **A, B, C** | **0.21** | **VERY HIGH** |
| 5. Struct-tag wire-up | ~700 | E | 0.14 | MEDIUM |

Option 2 shipped at `710c011`. Option 4 is the only remaining
mechanism that closes paths A/B/C; this ADR ratifies the decision
to pursue it despite the recommendations in three prior research
artifacts:

1. `e84a8f4` (`.research/go-irreducible-evaluation.md` §2) declared
   Decorator's syntactic gap "Go-ergonomic-issue-but-fixable-in-Go"
   and concluded "the +5 gap is cosmetic, not architectural… not
   worth a swap". Verdict was "non-goal".
2. `0d92590` (the code-gen evaluation) listed Option 4 as "NOT
   RECOMMENDED" with density 0.21 below the 0.4 floor.
3. `809edaf` (`.research/decorator-stack-shift-evaluation.md` §7)
   reinforced "KEEP-GO-ACCEPT-97-CEILING" — neither Go-internal AOP
   nor stack-shift is cheaper than accepting the 97 ceiling.

This ADR captures the user's explicit override of all three.

## Decision

Adopt Option 4 (AOP via reflection) by introducing a new package
`kc/aop` with the reflective dispatch primitives + a runnable
demonstration consumer chain. Ship in 4 slices of ~500 LOC each:

| Slice | Commit | Surface |
|---|---|---|
| A.1 | `e45924d` | Foundation: `Phase`, `Pointcut`, `Aspect`, `Weaver`, `InvocationContext`, `composeChain` |
| A.2 | `96ab3e0` | Reflective `WeaveStruct` proxy + step-driven dispatch driver |
| A.3 | `db735a0` | Consumer demo — audit + riskguard chain via `aop:"..."` struct tags |
| A.4 | (this ADR) | Decision documentation |

Total LOC at A.3: ~1916 (foundation 715 + proxy 732 + demo 469).
Under the ~2400 estimate, in part because the heavy doc-comment
convention of this codebase amortises the "explanation" surface
that the original aspect-go-style estimate counted as separate.

### Why Option 4 over the prior recommendations

The user's reasoning (verbatim, paraphrased from the dispatch
reversal): the standing 100% directive overrides empirical
Go-idiomatic ceilings. A score that materially measures
"all 13 dims at 100 except external-$$" is the operational target;
"empirical Go-idiomatic 97 ceiling" is a research-finding artifact
of one auditor's rubric-mapping choice (paths A/B/C as the
remaining +3) and not a hard limit. Closing it is worth the cost.

The cost is real and surfaced honestly:

- **~2400 LOC of anti-Go-idiom code**, dominated by `kc/aop/`'s
  reflection machinery + the consumer demo. Density 0.21 pts/100
  LOC — well below the historical batch-average of 1.5-3.0.
- **Per-call reflection overhead** ~100 ns + 5 ns × N(matched
  aspects). Acceptable for audit / riskguard / billing surfaces;
  documented as unacceptable for broker-DTO marshalling and
  ticker dispatch hot paths in `kc/aop/aop.go`'s package-doc
  WARNING.
- **Stack-trace opacity** — every aspect-wrapped method shows
  `(*aop.proxy).callMethod` frames before the real implementation.
  Mitigation noted but not implemented (`WeaverDebug = true`
  hook) — landed as future-work.
- **Anti-Go-community-preference signal** — Go reviewers broadly
  reject reflective AOP. The package doc-comment leads with a
  WARNING block explaining the rubric-driven exception and
  recommending `kc/decorators` (Option 2) for new code.

### What was rejected

- **Production cutover of riskguard / audit / billing paths to
  AOP.** Re-routing the existing function-typed
  `mcp.HookMiddleware` and `riskguard.Middleware` chains through
  `kc/aop` would impose the ~100ns/call reflection cost on the
  order-placement hot path — explicitly forbidden by the
  `kc/aop/aop.go` package-doc WARNING. The rubric mandate is
  "DEMONSTRATE on at least one consumer chain"; the consumer
  demo at A.3 (TradingService with `aop:"audit,riskguard"`
  tags) satisfies this without imposing the cost on production.
- **Conversion of all 80+ MCP tool handlers to function-typed
  struct fields.** The aspect-go-style estimate counted ~600 LOC
  for "convert all tool handlers to interfaces"; this is the
  production-cutover form, not the demonstration form, and is
  rejected on the same hot-path-cost grounds.
- **Generic AOP runtime (e.g., adopting `goldsmith/aspect`
  upstream).** External dependency adds a maintenance vector;
  the AOP machinery is small enough (~700 LOC of foundation +
  proxy) that in-house implementation is comparable in cost
  and avoids the supply-chain coupling.

### What stayed

- **`kc/decorators`** (Option 2 typed-generic factory) remains
  the preferred path for new cross-cutting concerns. Per the
  package-doc WARNING in `kc/aop/aop.go`: "For new cross-cutting
  concerns, prefer `kc/decorators`'s typed-generic
  `Decorator[Req, Resp]` surface — it is the Go-idiomatic answer
  and has identical capability for the function-typed middleware
  shape."
- **`mcp.HookMiddleware` around-hook chain** (already migrated to
  `kc/decorators` at `710c011`) stays on Option 2. The AOP
  consumer demo is intentionally a separate, parallel
  demonstration — not a replacement for the production around-
  hook surface.
- **All existing function-typed middleware chains** (audit,
  riskguard, billing, papertrading, dashboardurl) remain on the
  function-typed pattern. Production runtime cost is not paid
  for the rubric-closure decision.

## Consequences

### Positive

- **Decorator dim closes 97 → 100.** Rubric paths A/B/C are
  empirically demonstrated by the TradingService consumer chain
  in `kc/aop/example_audit_riskguard.go` + the 5 path-A/B/C tests
  in `kc/aop/example_audit_riskguard_test.go`. Equal-weighted
  aggregate moves from 92.85 → 93.08 (+0.23). Six dims still at
  100 (CQRS, DDD, ES, SOLID, Plugin, Test-Arch); seventh (Decorator)
  joins.
- **Plugin authors gain a third decoration option.** Some plugin
  authors prefer struct-tag annotations to function composition;
  the `aop:"..."` form serves that audience without forcing it on
  the in-tree codebase.
- **Rubric reviewers get all three A/B/C paths concretely
  demonstrated.** Future audits of "where does this codebase do
  reflective AOP?" point at `kc/aop/` and find a complete
  answer rather than "we did Option 2 and called it good".

### Neutral

- **Per-call reflection overhead applies only to opted-in surfaces.**
  Production paths that didn't opt in pay nothing. The cost
  surface is exactly the demo (in tests) until a production
  consumer registers a Weaver — and the package doc-comment
  WARNING tells them not to (for hot paths).
- **Stack-trace opacity** is documented as known. Debug-build
  callers can install panic-with-attribution via a future
  `WeaverDebug` hook (deferred — minor convenience, not on the
  critical path).

### Negative

- **+1916 LOC of explicitly-anti-Go-idiom code.** Future
  reviewers MUST read the package doc-comment WARNING + this
  ADR before extending or imitating the pattern. Mitigation: the
  WARNING is the literal first ~50 lines of `kc/aop/aop.go`;
  extension by accident requires actively skipping past it.
- **Density 0.21 pts/100 LOC** is well below the 0.4 floor the
  prior batches honoured. This ADR explicitly accepts the
  density miss for score-rubric reasons; future similar
  decisions should be evaluated against this precedent
  (anti-rec'd density miss + score-driver authorisation
  required).
- **Implementation correctness fragility.** The composeChain
  step-driver had two correctness bugs surfaced during impl
  (closure-recursion idempotency + reflect-value-aliasing
  infinite recursion). Both are fixed and tested; the
  Implementation Notes section below preserves the lessons.
- **One more research artifact superseded.** This ADR is the
  fourth document on this topic
  (`851baa1` → `0d92590` → `809edaf` → ADR 0008). Future
  contributors MUST treat ADR 0008 as the canonical answer;
  the prior research artifacts are preserved for historical
  context but their recommendations are explicitly overridden.

## Implementation notes — correctness lessons

Two non-obvious bugs surfaced during the A.2 slice; preserved here
for posterity in case a future refactor regresses.

### Bug 1: reflect.Value aliasing in WeaveStruct

The naive form `original := fv` aliases the field's reflect.Value.
After `fv.Set(wrapped)` replaces the field with the wrapper,
calling `original.Call(...)` from inside the wrapper dispatches to
the wrapper itself — infinite recursion (stack overflow at first
call).

**Fix**: capture a standalone reflect.Value via the field's
`.Interface()`:

```go
original := reflect.ValueOf(fv.Interface())
```

This forces a copy of the underlying function value before
`fv.Set(wrapped)` overwrites the field. Documented in `proxy.go`'s
WeaveStruct in-line comment.

### Bug 2: closure-recursion idempotency race in composeChain

The original composeChain wrapped Around aspects via per-level
closures that each reset `ic.proceeded` to false at entry. The
intent was "each Around's Proceed-twice should be idempotent";
the actual effect was that the OUTER Around's idempotency check
saw the INNER level's reset and re-fired.

Symptom: TestComposeChain_ProceedIdempotent saw the real method
called twice instead of once.

**Fix**: replaced the closure-recursion chain with an explicit
step-counter dispatch driver. The driver tracks per-level advance
state in `advanced[level]`; each Proceed call from a given level
advances exactly once, second-and-onward calls from the same level
are no-ops. The `currentLevel` save+restore is necessary because
nested Around frames share the same IC.

Pinned in TestComposeChain_ProceedIdempotent +
TestComposeChain_AroundOrdering_FirstRegisteredOutermost.

## References

- `.research/decorator-code-gen-evaluation.md` (`0d92590`) — the
  Option 1-5 enumeration; this ADR ratifies Option 4.
- `.research/decorator-stack-shift-evaluation.md` (`809edaf`) —
  proves no stack-shift is cheaper than Option 4 for closing
  paths A/B/C; recommends KEEP-GO-ACCEPT-97-CEILING which this
  ADR overrides.
- `.research/go-irreducible-evaluation.md` (`e84a8f4`) §2 — the
  prior "non-goal" verdict for Decorator +5 (referring to the
  pre-Option-2 5-point gap; this ADR closes the post-Option-2
  +3 residual).
- `.research/non-external-100-final-blockers.md` (`851baa1`) §3 —
  the original "Go-irreducible permanent" verdict, retired by
  this ADR.
- `kc/aop/aop.go` — package foundation; package doc-comment
  WARNING leads with the anti-Go-idiom honesty + recommendation
  of `kc/decorators` for new code.
- `kc/aop/proxy.go` — reflective WeaveStruct + dispatch driver;
  in-line comments document the two correctness fixes.
- `kc/aop/example_audit_riskguard.go` — the consumer demo
  satisfying the "demonstrate on at least one consumer chain"
  rubric mandate.
- `kc/decorators/decorators.go` (`2cc31a9`) — Option 2 typed-
  generic factory; the preferred surface for new code.
- `mcp/decorator_chain.go` (`710c011`) — Option 2 production
  consumer; the typed-generic path that Decorator dim 97 was
  graded on.
- ADR 0005 (`docs/adr/0005-tool-middleware-chain-order.md`) —
  production middleware order; the demo's aspect registration
  mirrors this order at the AOP layer for parity.
- ADR 0006 (`docs/adr/0006-fx-adoption.md`) — Wire/fx adoption
  for the composition-root; the AOP path is independent of the
  Fx graph (Weavers are not Fx providers; demo wiring is
  manual).
