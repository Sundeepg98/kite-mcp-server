# Decorator Stack-Shift Evaluation — Native AOP via language swap vs Go reflection Option 4

**Date**: 2026-04-26
**HEAD**: `3501a11` (post-audit-shim closeout, SOLID 100, scorecard `01078bf` published)
**Anchor docs**:
- `.research/decorator-code-gen-evaluation.md` (`0d92590`) — Option 1-5 spec; Option 4 (AOP via reflection, ~2400 LOC, density 0.21) is the only +5 path inside Go.
- `.research/non-external-100-final-blockers.md` (`851baa1`) — original "Go-irreducible permanent" verdict for Decorator +5 (which `0d92590` partly overrode for Option 2).
- `.research/go-irreducible-evaluation.md` (`e84a8f4`) — "ZERO truly Go-irreducible items — every 'Go limit' was design-choice or anti-rec'd ideology."
- `.research/component-language-swap-plan.md` (`a03694a`) — concrete 24-month per-component swap shortlist.
- `feedback_decoupling_denominator.md` — three-axis ROI (user-MRR / agent-concurrency / tech-stack-portability).

This doc resolves the user pushback against my dispatch on Item A: **before shipping ~2400 LOC of anti-Go-idiom reflection AOP, has anyone considered swapping the stack on the decorator-needing component to a language with native AOP?** That is exactly the Axis C question that `e84a8f4` and `a03694a` framed but never closed for Decorator specifically.

**Methodology**: For each candidate language, I ask:

1. **Does it actually have native AOP?** What does the rubric criterion (reflective composition / aspect weaving / annotation-driven decorators) look like in the language's idiomatic shape?
2. **Which component(s) in our codebase would naturally swap?** Avoid pure rubric-chasing — the swap has to make the component itself better for some independent reason.
3. **Does the swap give us native AOP for free?** I.e., does adopting the language for that component close Decorator +3 (the residual after Option 2 ships) without ceremony?
4. **Migration cost** — LOC, weeks, ecosystem discontinuity.
5. **24-month feasibility** — does this fit inside the realistic-MRR (₹15-25k) trajectory or assume scale we're not at?

Then aggregate: **Stack-shift cleaner than Go reflection Option 4, or worse?**

---

## 1. Empirical state at HEAD `3501a11`

The Decorator dim sits at 97 per the `710c011` re-grade in `.research/scorecard-final.md`. Path:

- `kc/decorators/` (`2cc31a9`): typed-generic `Decorator[Req, Resp]` / `Handler[Req, Resp]` / `Compose` / `Apply` factory. 388 LOC, 100% statement coverage, 10 tests. Closes Option 2 (rubric path F).
- `mcp/decorator_chain.go` + `mcp/decorator_chain_test.go` (`710c011`): consumer migration — `mcp.HookMiddlewareFor`'s around-hook chain composed via `decorators.Compose` instead of hand-written reverse iteration loop. 252 LOC, 3 new tests, 8 prior `around_hook_test.go` regression tests pass unchanged.

**The +3 residual blocking 100 is rubric paths A/B/C** (per `decorator-code-gen-evaluation.md` §3 table):

| Rubric path | Closure mechanism | Go availability |
|---|---|---|
| A — reflective composition | Runtime hook discovery via reflection over annotated types | `reflect.StructField.Tag.Get("decorate")` works; semantics ARE expressible. |
| B — annotation-driven decorators | `@Cacheable`, `@Retryable`-style tag-driven wrappers | Magic comments + codegen (Option 1) OR struct tags (Option 5). Both have density issues. |
| C — aspect weaving | Pointcut + advice DSL combining intercept locations | Possible via reflective interface proxies (Option 4). |

The `0d92590` doc concluded: **+5 closure (i.e., A/B/C all together) is mathematically possible only via Option 4 — full AOP via reflection — at 2400 LOC and 0.21 density** (well below the 0.4 rubric-floor that `non-external-100-final-blockers.md` §2 documented). The `e84a8f4` evaluation reinforced: "Decorator dim ceiling at 95 [now 97 with Option 2 shipped] is honest about syntax cost; closing it is a non-goal" — explicitly recommending against Go-internal AOP machinery.

This doc asks: **does swapping stack do better than Option 4?**

---

## 2. Per-language native-AOP feasibility

### 2.1 TypeScript (Nest.js interceptors / stage-3 decorators)

**Native AOP form**:

```typescript
@UseInterceptors(AuditInterceptor, RiskguardInterceptor, BillingInterceptor)
@Tool('place_order')
async placeOrder(@Body() req: PlaceOrderReq): Promise<PlaceOrderResp> {
    return this.kite.placeOrder(req);
}
```

Stage-3 decorators (TC39 finalized 2023, TS 5.0+ first-class) ARE the rubric's path B. Class-method decorators run at class-definition time; parameter decorators thread through metadata reflection (`reflect-metadata`); Nest.js `@UseInterceptors` is a wholesale aspect-weaving pattern — pointcut declared at the decoration site, advice runs around the method via the framework's `Interceptor` abstraction. **All three rubric paths (A/B/C) collapse into one ergonomic syntax.**

**Component fit in our codebase**: Per `a03694a` §2.6, **widget bodies + (optionally) the analytics microservice** are the two TypeScript candidates. The *widget* swap is genuinely high-ROI (MCP Apps SDK widgets render in JS-only host environments — Claude.ai / Claude Desktop / ChatGPT). However, **widgets don't need AOP**. The widget surface is presentation-layer code with no cross-cutting concerns to weave.

The *Nest.js* swap target would be the **MCP tool handler surface itself** — `mcp/*_tool.go` (~80 tool handlers). That IS where the around-hook chain lives. A Nest.js port would express the entire 10-layer middleware chain (`audit → hooks → circuitbreaker → riskguard → ratelimit → billing → papertrading → dashboardurl`) as `@UseInterceptors` decorations, plus per-tool `@Tool` registration via class methods. **The around-hook chain BECOMES the decorator chain natively.**

**Migration cost**:
- `mcp/` is the single largest package: 201 files, ~20k LOC prod incl tests per `a03694a` §1.
- TypeScript port: ~12-15k LOC (TS is more verbose per concern but lighter on type-erasure ceremony — broker DTOs would need re-declaration).
- IPC seam: every tool currently calls into `kc/usecases/` use cases. Either (a) the use case layer ALSO swaps to TS, or (b) tools call Go use cases via gRPC/HTTP. Option (b) means wire-format coupling for ~80 use cases.
- Plugin contract: `OnToolExecution` / `OnBeforeToolExecution` / `OnAfterToolExecution` (in `mcp/registry.go`) are Go-side hooks consumed by `kc/rolegate/`, `kc/telegramnotify/`, etc. Swap forces RPC seam there too.

**Realistic effort**: 6-9 months full-time engineering. Compare to Option 4's 2400 LOC + ~2 weeks.

**Ecosystem benefit beyond decorator-rubric closure**:
- Nest.js dependency injection container is mature (matches our Fx adoption goal).
- Decorators-for-validation (`class-validator`) collapse our hand-written `NewArgParser` ceremony.
- Native MCP SDK in TS (modelcontextprotocol/typescript-sdk) is upstream; some features land in TS first.

**24-month feasibility**: **Not realistic** at current MRR (₹15-25k per `kite-mrr-reality.md`). 6-9 months engineering against negative user-MRR axis (Axis A in `feedback_decoupling_denominator.md`) is the kind of investment that only pays at SaaS-scale (10+ paying customers, dedicated frontend / backend split). We're not there.

**Smaller TS scope — widgets only**: separately viable per `a03694a` §2.6 ("highest-ROI swap" item). But widgets-only does NOT close Decorator +3 — widgets aren't where the around-hook chain lives. Closing Decorator via TS demands the *tool handler* swap, not the widget swap.

**Verdict — TypeScript**: Pretty native AOP, but the swap target that DOES need AOP is `mcp/` tool handlers, which is the costliest possible component to rewrite (largest package + use-case + plugin coupling). **WORSE than Option 4** if the goal is closing Decorator +3.

### 2.2 Python (native `@decorator` syntax + aspectlib + ContextVar)

**Native AOP form**:

```python
@audit
@circuit_breaker
@riskguard
@ratelimit
@billing(tier_required=Tier.PRO)
@app.tool("place_order")
async def place_order(req: PlaceOrderReq) -> PlaceOrderResp:
    return await broker.place_order(req)
```

Python `@decorator` syntax IS the rubric's path B and partial path C (the `@app.tool` / `functools.wraps` patterns can do aspect weaving — `aspectlib.weave(target, aspect)` does runtime injection into method calls). Path A (reflective composition) has equivalents via `inspect.signature` + AST-walking decorators.

**Component fit in our codebase**: Per `a03694a` §2.5, **analytics + backtest** is the strongest Python candidate. The reasoning was ecosystem (numpy / pandas / scipy / pandas-ta / vectorbt / quantlib / scipy.stats are unmatched). **But analytics doesn't need AOP either** — it's pure compute over DataFrames, with no cross-cutting concerns to weave.

The component that DOES need AOP — the `mcp/` tool handler surface — is NOT on the Python shortlist. A Python port of `mcp/` would inherit:
- Worse runtime perf (Python is 5-50× slower than Go on the broker-DTO marshal hot path).
- GIL contention on the per-user concurrent ticker connections (`kc/ticker/`).
- Dependency-management complexity (Python's `uv` / `poetry` ecosystem isn't a strict win over Go modules).

**Realistic effort for a `mcp/` Python port**: similar to TS — 6-9 months. Plus the ecosystem regression on perf-sensitive paths.

**24-month feasibility**: Python's strength is analytics-microservice scope (`a03694a` §2.5: ~3k LOC Go + ~180 LOC IPC shim → ~1.5k LOC Python + 3-4 weeks). That swap is realistic. But the component that gets the Python rewrite is NOT the AOP-needing one. **Decorator +3 stays unblocked.**

**Verdict — Python**: Native AOP exists and is among the best in any mainstream language, but the swap surface that's economically realistic (analytics) doesn't overlap with the AOP-needing surface (`mcp/` tool handlers). **No closer to Decorator +3 than Option 4.**

### 2.3 Java/Kotlin (Spring AOP / AspectJ)

**Native AOP form**:

```java
@Aspect
@Component
public class TradingAspect {
    @Around("@annotation(com.kite.Tool) && args(req,..)")
    public Object aroundTool(ProceedingJoinPoint jp, ToolRequest req) throws Throwable {
        // audit, riskguard, billing all happen here
        return jp.proceed();
    }
}
```

Java's Spring AOP / AspectJ IS the textbook from which the rubric's framing was derived. AspectJ is the gold standard for aspect weaving — pointcut DSL, advice composition, compile-time weaving (`ajc`) AND load-time weaving (`-javaagent`). All three rubric paths (A/B/C) at expert-level maturity.

**Component fit**: **Zero.** Java/Kotlin is not on `a03694a`'s 24-month shortlist. The codebase has no Java / Kotlin / JVM presence; broker SDK (`gokiteconnect`) is Go-only; the Kite official SDKs are Python/Java/JS/PHP/.NET — `pykiteconnect` and `kiteconnect-java` are both first-party.

A Spring Boot port of `mcp/` would deliver native AOP **and** ecosystem parity (Spring's IoC container, Spring Security, Spring Cloud) but the migration cost is ~12-18 months for a single-developer team. JVM operational footprint is also 5-10× ours (heap tuning, GC pause budgets, CRaC for fast restart) — adds ops surface we don't need at current scale.

**24-month feasibility**: **Not feasible.** No engineering team that fits.

**Verdict — Java/Kotlin**: Best native AOP in any mainstream language, but stack-discontinuous. **Not realistic.**

### 2.4 C# / .NET (attributes + Roslyn source generators + interceptors)

**Native AOP form**:

```csharp
[Audit, RiskGuard, Billing(Tier.Pro)]
[McpTool("place_order")]
public async Task<PlaceOrderResp> PlaceOrder(PlaceOrderReq req) {
    return await _broker.PlaceOrderAsync(req);
}
```

C# 12 (.NET 8) introduced **interceptors** (compile-time advice woven via Roslyn source generators) which is the closest mainstream language to AspectJ in 2026. `[Aspect]`-style attributes + Roslyn source-gen close A/B/C with compile-time guarantees and ZERO runtime reflection cost.

**Component fit**: Same as Java — zero presence in our codebase. Kite Connect has a `.NET` SDK; ecosystem alignment with broker is fine. But the migration cost is the same 12-18 months for a `mcp/` port.

**24-month feasibility**: **Not feasible.**

**Verdict — C#**: Excellent native AOP (cleaner than Java for our use case because compile-time-only avoids the JVM operational tax). Stack-discontinuous. **Not realistic.**

### 2.5 Rust (proc-macros + tower middleware)

**Native AOP form**:

```rust
#[tool("place_order")]
#[audit]
#[circuit_breaker]
#[riskguard]
#[billing(Tier::Pro)]
async fn place_order(req: PlaceOrderReq) -> Result<PlaceOrderResp, Error> {
    broker.place_order(req).await
}
```

Rust proc-macros (procedural macros) ARE the textbook for compile-time AOP. `tower::Layer` / `tower::Service` middleware composition is functionally identical to Go's `server.ToolHandlerMiddleware` (rubric path F). Stacking the layers via `ServiceBuilder::new().layer(...).layer(...)` IS the rubric's path B/C. `axum`'s extractor pattern is pure path A (reflective composition over typed args).

Crucially, Rust's proc-macros are **compile-time** — no runtime reflection cost, no startup overhead, error reports point to the original source. AspectJ-class quality with native compile-time guarantees.

**Component fit in our codebase**: Per `a03694a` §2.1 + §2.4, **riskguard hot-path checks** and **ticker WebSocket connection per user** are the two Rust candidates. Riskguard already has the cross-process IPC shape (`kc/riskguard/checkrpc/`) so the swap is incrementally feasible.

**But riskguard doesn't need AOP either.** It's a sequence of pre-trade checks composed in `kc/riskguard/guard.go` via explicit method calls. The around-hook chain that DOES need AOP is in `mcp/registry.go`'s `HookMiddlewareFor` — a different package.

**Could we Rust-rewrite `mcp/`?** Yes mechanically (axum / tower has the exact middleware shape). Cost: ~20k LOC Go → ~14-16k LOC Rust + 8-12 months. Plus the cascade: use cases, plugins, brokers all need Rust counterparts or RPC seams.

**24-month feasibility for Rust riskguard only**: realistic per `a03694a` §2.1 — but doesn't close Decorator. The Rust riskguard executable is consumed via the existing checkrpc subprocess seam; the *Go* `mcp/` middleware chain wraps the result. AOP doesn't move.

**24-month feasibility for Rust mcp/**: not realistic.

**Verdict — Rust**: Best compile-time AOP in any modern systems language. The stack-aligned swap candidate (riskguard) doesn't need AOP; the AOP-needing swap (`mcp/`) is too large to be 24-month feasible. **No closer to Decorator +3 than Option 4.**

### 2.6 Quick survey of others (rejected, brevity)

| Language | Native AOP? | Stack fit | Verdict |
|---|---|---|---|
| Ruby (`Module#prepend`, `aspector` gem) | Yes — class reopening + method aliasing is path A/B | Zero presence; broker SDK absent | Reject — stack-discontinuous |
| Elixir / Erlang (decorators via `__using__` macros) | Partial — macros + GenServer | Zero presence | Reject — stack-discontinuous |
| Scala (compiler plugins, `@aspectj`) | Yes — JVM Spring AOP available | Same as Java | Reject — see Java |
| Common Lisp / Clojure (CLOS / `defmethod` advice) | Native first-class | Stack-discontinuous extreme | Reject |
| F# (computation expressions + attributes) | Partial — needs Roslyn helpers | Same as C# | Reject — see C# |

---

## 3. Aggregate cost comparison: stack-shift vs Go Option 4

| Path | Component swapped | LOC delta | Effort (weeks) | Decorator +3 closure | Side benefits | Ecosystem regression |
|---|---|---|---|---|---|---|
| **Go Option 4** (reflection AOP) | None (in-place) | +2400 | ~2 weeks | YES (A/B/C all closed) | None — purely score-driven | Anti-Go-idiom signal; +100ns/call runtime; stack trace opacity |
| **TypeScript Nest.js port of `mcp/`** | `mcp/` (~20k LOC) → TS | +12-15k LOC (gross), -20k Go | 24-36 weeks | YES | TS ecosystem velocity, decorator-validation, MCP SDK upstream alignment | Use case + plugin RPC seam; perf regression on broker DTO marshal |
| **Python port of `mcp/`** | `mcp/` (~20k LOC) → Py | +14-18k LOC, -20k Go | 24-36 weeks | YES | Analytics ecosystem | GIL on ticker; perf regression; weaker static analysis |
| **Java/Spring port of `mcp/`** | `mcp/` (~20k LOC) → Java | +25-30k LOC (Java verbosity), -20k Go | 48-72 weeks | YES (gold-standard) | Spring IoC | JVM ops tax; engineering-team unfit |
| **C#/.NET port of `mcp/`** | `mcp/` (~20k LOC) → C# | +20-24k LOC, -20k Go | 48-72 weeks | YES (compile-time) | .NET ecosystem | Stack-discontinuous |
| **Rust/axum port of `mcp/`** | `mcp/` (~20k LOC) → Rust | +14-16k LOC, -20k Go | 32-48 weeks | YES | Compile-time guarantees, perf | Rust borrow-checker learning curve; cascade through use cases |
| **TS Widgets only** (per `a03694a`) | `kc/templates/*.html` + `mcp/plugin_widget_*.go` (~1k LOC) → TS | +700 LOC TSX, -1k Go | 8-12 weeks | NO (widgets aren't AOP surface) | Widget UX velocity | Build pipeline ceremony |
| **Rust riskguard only** (per `a03694a`) | `kc/riskguard/` (~9.5k incl tests) → Rust | +6k LOC Rust, -9.5k Go | 16-32 weeks | NO (riskguard isn't AOP surface) | p99 latency 1-3ms reduction | Cascade through risk-check plugin authors |
| **Python analytics** (per `a03694a`) | `mcp/{backtest,analytics,...}_tool.go` (~3k LOC) → Py | +1.5k LOC Py + 180 LOC Go IPC | 12-16 weeks | NO (analytics isn't AOP surface) | numpy/pandas/quantlib ecosystem | Out-of-process boundary cost |

### Critical observation

**The components that have economically realistic 24-month swaps (widgets→TS, riskguard→Rust, analytics→Python) are NOT the components that need AOP.**

The component that DOES need AOP — `mcp/` tool handler surface, where the around-hook chain lives — is the most expensive possible swap target (largest package, deepest coupling to use cases + plugins + broker port). At 24-36 weeks for TS / Python, 32-48 weeks for Rust, 48-72 for Java/C#, every stack-shift path that closes Decorator +3 costs 12-36× more time than Option 4's 2 weeks.

The "Axis C unlocks AOP for free" intuition was tempting. The reality is the inverse: **Axis C and rubric-path closure are genuinely orthogonal in this codebase.** Components that benefit from a swap (per `a03694a`) have nothing to do with cross-cutting concerns; the cross-cutting-concerns surface (`mcp/`) is the wrong-shape candidate for Axis C swaps.

---

## 4. Per-option verdict

| Option | Verdict | Rationale |
|---|---|---|
| Go Option 4 (reflection AOP) | **DEFER** | 2400 LOC, density 0.21, anti-Go-idiom signal. `e84a8f4` already concluded "non-goal". Closes +3. |
| TS port of `mcp/` for native AOP | **REJECT** | 24-36 weeks for the same +3. Doesn't pay against `kite-mrr-reality.md` ₹15-25k MRR trajectory. |
| Python port of `mcp/` for native AOP | **REJECT** | 24-36 weeks; perf regression on hot paths. Component fit poor. |
| Java/Spring port of `mcp/` | **REJECT** | 48-72 weeks; team-fit zero; JVM ops tax. |
| C#/.NET port of `mcp/` | **REJECT** | 48-72 weeks; team-fit zero. |
| Rust port of `mcp/` | **REJECT** | 32-48 weeks; learning curve; cascade through use cases. |
| TS Widgets only | **APPROVE for separate ROI** (per `a03694a`) — but **DOES NOT close Decorator**. |
| Rust riskguard only | **APPROVE for separate ROI** (per `a03694a`, scale-gated) — but **DOES NOT close Decorator**. |
| Python analytics microservice | **APPROVE for separate ROI** (per `a03694a`) — but **DOES NOT close Decorator**. |

### Single-path recommendation

**KEEP-GO-ACCEPT-97-CEILING.**

Document Decorator at 97 as the **honest empirical Go-idiomatic ceiling** (Option 2 generic-decorator factory + consumer adoption shipped). Do NOT pursue Option 4 (Go reflection AOP) — `e84a8f4` already concluded it's a "non-goal" and density 0.21 fails the 0.4 floor. Do NOT pursue stack-shift solely for Decorator — the AOP-needing component (`mcp/`) is the wrong-shape swap target for the codebase's actual swap candidates (widgets / riskguard / analytics).

The +3 residual blocking 100 is a **rubric-shape mismatch**, not a code or architecture gap. The rubric's A/B/C paths describe Java/Spring AOP / TS Nest.js / Python `@decorator` — paradigms that exist natively in those languages. Mapping that rubric onto a Go codebase via reflection is rubric-chasing; mapping it via stack-shift is rubric-chasing at 12-36× cost.

This is the same finding `e84a8f4` §2 reached, restated more explicitly: **the Decorator +3 isn't Go-irreducible; it's economically irreducible in this codebase.** Stack-shift doesn't change that math.

### Aggregate impact on equal-weighted ceiling

Per `01078bf` re-grade:

```
Current 92.85 equal-weighted → with Decorator stuck at 97:
(100 + 99 + 100 + 100 + 95 + 100 + 100 + 97 + 100 + 86 + 86 + 85 + 59) / 13 = 92.85

If Option 4 ships and closes Decorator to 100:
(100 + 99 + 100 + 100 + 95 + 100 + 100 + 100 + 100 + 86 + 86 + 85 + 59) / 13 = 93.08

If TS-port-of-mcp ships and closes Decorator to 100 (24-36 weeks):
Same 93.08 — but loses 24-36 weeks against zero feature output.
```

**+0.23 absolute** is the prize either way. Stack-shift earns the same +0.23 at 12-36× the cost.

---

## 5. What about combining stack-shifts that DO pay off?

The realistic shortlist from `a03694a` is:
- **TS Widgets** (8-12 weeks, high UX-iteration ROI)
- **Rust riskguard** (16-32 weeks, scale-gated to ~1k+ users)
- **Python analytics** (12-16 weeks, ecosystem-velocity ROI)

**Could those swaps incidentally close Decorator?** No — none of them touches the around-hook chain. But they DO advance Axis C portability per `feedback_decoupling_denominator.md` more than any in-Go cleanup.

The honest framing: **Axis C investments and Decorator +3 are decoupled.** Pursue Axis C swaps for their own ROI (UX velocity / latency / ecosystem); accept Decorator at 97 as the Go-idiomatic empirical ceiling.

---

## 6. Honest opacity

1. **Rubric origin not re-investigated.** The original Decorator rubric criterion in `blockers-to-100.md` was single-line and did not name a specific +5 deliverable. `0d92590` enumerated A-F as plausible interpretations. Stack-shift framing in this doc treats A/B/C as the residual block — this matches `0d92590`'s table and `851baa1`'s §3 verdict but the rubric ITSELF was never re-derived. If a different auditor reads "+5" as path D (compile-time codegen) instead of A/B/C, Option 1 (AST codegen) becomes the answer; that's a different swap question and stack-shift wouldn't help there either.

2. **24-36 week TS/Python port estimates are gross.** Real porting of a Go service to a different language at our scale tends to underestimate the cascade through tests + plugins + use cases. The sign of the verdict (reject) is robust to ±50% on these estimates — the comparison to Option 4's ~2 weeks is so stark that even a 10× underestimate keeps stack-shift dominated. But if anyone wants a precise number, this is gross.

3. **`a03694a` shortlist not re-validated against current HEAD.** The component-language-swap-plan was written at HEAD `4b5120b` (Wave D Phase 2 P2.1). Component LOC counts and boundary characteristics may have drifted. The high-level claim ("widgets / riskguard / analytics are the real swap candidates; `mcp/` tool surface is not") is unchanged at `3501a11` because no Wave D work touched the per-component boundaries — Phase 2 / Phase 3a were inside-Go refactors of the same `app/` and `mcp/` packages.

4. **Fx adoption was the pre-cursor expectation that AOP would emerge from.** ADR 0006 (`docs/adr/0006-fx-adoption.md`) says "the provider graph IS the architectural diagram, machine-readable; per-component rewrites in Rust/TypeScript/Python become 'register a new provider' instead of 'find-and-replace across 985 LOC'". This made stack-shift LATER cheaper. It did NOT change the cost asymmetry between widget swap (cheap) and `mcp/` swap (expensive). The Fx graph helps you swap a cleanly-bounded leaf; it doesn't help when the swap target is the LARGEST package in the codebase with the DEEPEST coupling.

5. **Rust + Go in same process via cgo / `c-shared`?** Not investigated. Rust proc-macros for AOP would require Rust BE the language of the tool handler — partial Rust shim wouldn't get us native AOP. Same conclusion applies.

6. **WASM as middle-ground?** Not investigated as primary path. Per `e84a8f4` §1, WASM cold-start is ~100ms in 2026; that's a non-starter for the trading hot path. The riskguard subprocess RPC pattern is the right precedent here, not WASM.

---

## 7. Final answer

**Recommendation order**:

1. **Document Decorator 97 as the Go-idiomatic empirical ceiling.** Same conclusion `decorator-code-gen-evaluation.md` §6 already reached for Option 2.
2. **Do NOT ship Option 4 (Go reflection AOP).** 0.21 density, anti-Go-idiom, no offsetting ergonomic win.
3. **Do NOT swap `mcp/` to TS / Python / Rust solely for Decorator +3.** 12-36× cost ratio for the same +0.23 equal-weighted lift. Negative against user-MRR axis. Component fit poor (no other reason to swap `mcp/`).
4. **Pursue `a03694a` swaps on their own merits** (widgets→TS, riskguard→Rust, analytics→Python) — but treat Decorator +3 as orthogonal to those decisions. None close it.

**Net: Decorator dim ceiling at 97 IS the empirical maximum** under current constraints. The +3 residual is a rubric-shape mismatch (rubric describes Java/Spring AOP), not an architectural gap. Both Go-internal AOP and stack-shift fail the cost-benefit test for closing it.

**Aggregate ceiling stays at 92.85** equal-weighted (Pass 17 ~97.5). Further code-tractable lift requires Axis C swaps for their own ROI, not for Decorator score-chasing.

---

*Generated 2026-04-26 against HEAD `3501a11`. Read-only research deliverable; no source files modified. Supersedes the Item A directive in the prior dispatch — Option 4 (Go reflection AOP) is not the right answer, AND no language swap is a cleaner answer for closing Decorator +3.*
