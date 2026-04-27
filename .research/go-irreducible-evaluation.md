# Go-Irreducible Evaluation — concrete per-component verdicts

**Date**: 2026-04-27
**HEAD audited**: `92eea3a` (Slice 6e c2 — broker.PnL elevated to Money;
the wholesale type change shipped via the `kc/money` leaf-package
extraction).
**Supersedes / extends**: `a03694a` (`.research/component-language-swap-plan.md`).

This doc supersedes the broad swap-plan with item-level verdicts on the
specific "Go-irreducible" / "anti-arch unreachable" claims I have
made or repeated this session. The previous doc framed swaps as
trigger-gated business decisions; this one asks the harder
engineering question: **is the limitation ACTUALLY the Go language,
or our use of it?** That distinction matters because the
former is a swap candidate; the latter is a Go-internal cleanup
that wouldn't move on language change.

## Methodology

For each item, I cite the actual code in the current repo (paths
+ line refs where helpful) before scoring. The rubric per item:

- **TRULY-Go-limited** — Go's type system, runtime, or stdlib
  forces the limitation. A swap to a different language would
  meaningfully change what's possible.
- **Go-ergonomic-issue-but-fixable-in-Go** — Go can express the
  pattern, but the syntactic / build / library cost is enough to
  call it friction. Don't swap; refactor inside Go.
- **False-irreducible-claim** — the limitation isn't real.
  Either we're not using Go's existing facility, OR the framing
  of the limitation was sloppy.

If TRULY-Go-limited, only then does language-swap analysis follow.

---

## 1. Plugin loader (+0.5 Plugin dim)

**Claim**: Go's static-link plugin model caps the Plugin dim.
Cannot load new plugins at runtime without rebuilding the host
binary; therefore the +0.5 dim is "Go-irreducible".

### Repo evidence

The codebase has TWO plugin paths:

1. **Static-link / register-on-import** — `mcp/plugin_registry.go`
   (691 LOC), `mcp/plugin_register_full.go`, callers in
   `app/wire.go:736`. Plugins are Go packages compiled into the
   server; `RegisterPlugin*()` calls run at startup. **No runtime
   `plugin.Open` / `plugin.Lookup` anywhere in the codebase**
   (verified — `grep "plugin\.Open\|plugin\.Lookup"` returns zero
   non-comment hits).
2. **Subprocess RPC plugins** — `kc/riskguard/subprocess_check.go`
   (391 LOC) using `hashicorp/go-plugin` over netRPC stdio.
   `kc/riskguard/checkrpc/types.go` (216 LOC) is the wire proto.
   Already cross-language by construction: any binary that speaks
   netRPC over stdio can be a plugin.

### Verdict

**False-irreducible-claim**, partial. The sentence "Go's static-link
plugin model caps the Plugin dim" conflates two separate things:

- The **register-on-import pattern** in `mcp/plugin_*.go` is a
  design choice, not a Go limitation. Go HAS `plugin.Open` for
  dynamic .so loading on Linux/macOS — we don't use it because
  the Go plugin package is fragile (every plugin must be built
  with the exact same Go version + GOPATH layout as the host).
  That's a real cost, but it's a Go-ergonomic-issue, not language-
  irreducible.
- The **subprocess RPC seam** already exists. A new plugin in any
  language that produces a netRPC-over-stdio binary loads at
  runtime today (the host re-launches on each evaluation; Wave D
  Phase 2 lifecycle hooks would let you start it once at boot).
  This is the unloved capability that makes the +0.5 claim wrong:
  we ALREADY support cross-language runtime-loaded plugins via
  `subprocess_check.go`. The cap is on `mcp/plugin_*.go`, not the
  riskguard subprocess shape.

### Best-fit alternative IF we wanted true cross-process / cross-language plugins

**WASI/WASM runtime** (e.g. `wasmtime-go`, `wazero`). The plugin
binary becomes a `.wasm` file. Pros: cross-platform (Go's
`plugin.Open` is Linux/macOS only — Windows is unsupported);
sandboxed by default; deterministic resource limits; same plugin
binary runs in any host (Go, Rust, Python, JS).

Cons: WASM is CPU-bound only (no syscalls without WASI imports);
subprocess RPC has a richer effect surface (file IO, network) for
a plugin that needs them; WASM toolchain in 2026 still ~100ms
cold-start which adds latency on the order-placement chain.

### Recommendation

**Don't swap. Use what's already there.** The right architectural
move is:

- Promote `kc/riskguard/checkrpc/` to a first-class IPC contract
  (per `a03694a` §4.3 #1). Other subsystems opt in.
- Keep `mcp/plugin_*.go` static-link pattern for first-party
  plugins (audit-event types, telegram commands, widget bodies)
  where rebuild-the-binary is acceptable.
- WASM is **NOT** worth the 100ms cold-start tax on the trading
  hot path. Reconsider when the cold-start drops to <10ms (~2027
  per current wasmtime/wazero trajectories) AND when third-party
  plugin authorship becomes a real product surface.

**24-month feasibility**: WASM swap **deferred**. Current
subprocess-RPC pattern absorbs the actual need.

---

## 2. Decorator promotion (+5 Decorator dim)

**Claim**: Go's interface-based middleware composition is
syntactically heavier than TypeScript's `@decorator` syntax or
Python's `@decorator`. Therefore, the Decorator dim sits at 95
(not 100) because the syntactic noise costs us.

### Repo evidence

`mcp/middleware_chain.go` (84 LOC) is the entire abstraction:

```go
type MiddlewareBuilder func() server.ToolHandlerMiddleware
func BuildMiddlewareChain(entries map[string]MiddlewareBuilder, order []string) ([]server.ToolHandlerMiddleware, error)
```

10-stage chain (timeout → audit → hooks → circuitbreaker → riskguard
→ ratelimit → billing → papertrading → dashboardurl). Each middleware
is a function returning `func(next ToolHandlerFunc) ToolHandlerFunc`.

### Verdict

**Go-ergonomic-issue-but-fixable-in-Go.**

TypeScript's `@decorator` and Python's `@decorator` would syntax-
sugar this:

```typescript
@audit
@circuitBreaker
@riskGuard
async function placeOrder(...) { ... }
```

vs Go's:

```go
handler = AuditMiddleware(CircuitBreakerMiddleware(RiskGuardMiddleware(handler)))
```

But Go's `BuildMiddlewareChain(entries, order)` already inverts the
nesting: ordering is a config slice, not source-code nesting.
Reading order matches execution order. The decorator pattern IS
fully expressed; only the `@`-syntax sugar is missing.

The +5 gap is **cosmetic**, not architectural. A swap to a `@`-
syntax language would gain 1-2 lines per call site in readability
but lose Go's static analysis (gopls / staticcheck / `gofmt`
deterministic formatting). Net: not worth a swap.

### Recommendation

**No swap.** The Decorator dim ceiling at 95 is honest about
syntax cost; closing it is a non-goal.

---

## 3. CQRS Test-Arch +1 (event-flow viz / saga UI)

**Claim**: Domain-event-flow visualization needs an interactive UI
to score Test-Arch +1; the current Mermaid generator (`b12ac6d`,
`cmd/event-graph/main.go`, 142 LOC) is static markdown only.

### Repo evidence

`cmd/event-graph/main.go` walks `app/providers.CanonicalPersister
Subscriptions` and emits Mermaid markdown to `docs/event-flow.md`.
Snapshot test enforces freshness. Output is checked into git;
viewable on GitHub via Mermaid's native rendering.

### Verdict

**Go-ergonomic-issue-but-fixable-in-Go**, leaning towards
**false-irreducible-claim**.

For a STATIC viz, Go is fine — `cmd/event-graph` already does the
job. For an INTERACTIVE viz (zoom, filter by aggregate, time-
travel scrubber), the right move isn't a Go-language swap; it's
a JS frontend that consumes the same JSON data the Mermaid
renderer walks. The Go side stays as-is, exposing
`GET /admin/api/event-flow.json` (~50 LOC). The frontend
(React / Svelte / vanilla JS) is ~400 LOC.

### Best-fit alternative for the FRONTEND

**TypeScript + D3.js** OR **React Flow** for a node-graph UI.
Both render JSON data; both run in any modern browser; neither
requires touching the Go backend.

### Recommendation

**No language swap on the backend.** If interactive viz is
desired, ship a TS frontend in the existing widget toolchain
(see `a03694a` §3 item #1 — widget TSX swap). The viz is a
widget body candidate, not a backend rewrite.

**24-month feasibility**: lift-along with the widget TSX swap
when (if) that triggers.

---

## 4. Logger sweep — was THAT actually Go-irreducible?

**Claim**: Go's logger pattern (long-lived service-scoped + async
goroutines) is fundamentally different from ctx-scoped request
logging. Languages with native async/await (Rust, TS) thread ctx
implicitly via the runtime; Go forces explicit `ctx context.
Context` first parameters.

### Repo evidence

`kc/logger/port.go` (58 LOC) defines the new `logger.Logger`
port:

```go
Info(ctx context.Context, msg string, args ...any)
Error(ctx context.Context, msg string, err error, args ...any)
```

Wave D Phase 3 sweep migrated ~37 prod files so far (in flight
on Packages 5c-8). Long-lived services in `kc/papertrading/
engine.go` and `kc/scheduler/scheduler.go` pass
`context.Background()` because they have no request ctx in
scope:

```go
e.logger.Info(context.Background(), "paper trading enabled", ...)
m.logger.Info(context.Background(), "paper trading monitor started", ...)
```

That's the friction the claim points at — the ctx parameter is
mandatory, but ~half the call sites manufacture a `Background`
placeholder.

### Verdict

**Go-ergonomic-issue-but-fixable-in-Go**, leaning **false-
irreducible-claim**.

Rust `tokio` and TS `async/await` do thread context implicitly via
`tokio::task_local!` and `AsyncLocalStorage`. Go's `context.
Context` is explicit by design — Rob Pike's argument is that
implicit context is more dangerous than verbose-but-visible
context.

But the Wave D port shape is not the only option in Go. Two
in-Go alternatives close the ergonomic gap:

1. **Two-method port**: `Info(msg, args...)` and `InfoCtx(ctx,
   msg, args...)`. Background services use the no-ctx variant;
   request-scoped paths use the ctx variant. Same observable
   outcome — when ctx is meaningful, attach it; when it isn't,
   don't pretend.
2. **Logger.With(ctx)** factory: `logger.WithCtx(ctx).Info(msg, args...)`.
   The ctx attachment is explicit per call but the ergonomic
   cost is paid once at the boundary, not on every call site.

The current Wave D port chose option 1's stricter cousin — ctx
on every method — to force every call site to confront whether
it has a request ctx in scope. That's a deliberate trade-off,
not a Go limitation. A swap to Rust/TS would NOT close the
gap; both languages STILL require an explicit decision about
which ctx travels (Rust's `tracing::Span::current()` is the
exact same pattern, just with implicit lookup).

### Recommendation

**No swap.** If the `context.Background()` noise becomes
intolerable, refactor the port shape WITHIN Go (option 1 or 2
above). Logger sweep does not justify a language change.

**24-month feasibility**: keep the sweep going in Go;
ergonomic refactor is a 1-day in-Go task if the friction
mounts.

---

## 5. Wire/fx ceremony

**Claim**: Go's lack of compile-time DI codegen makes Wire/fx
feel ceremonious. Macro-rich languages (Rust, Scala, Lisp)
generate this for free.

### Repo evidence

`app/wire.go` is 937 LOC, 52 `fx.` references, 6 functions. The
fx adoption is partial (Wave D Phase 2 P2.5b cutover in `5f08481`,
P2.5d ADR amendment in `67972c0`). `fx.Provide` declarations:

```go
fx.Provide(providers.BuildManager),
fx.Provide(providers.InitializeAuditStore),
fx.Provide(providers.ProvideAuditMiddleware),
```

Each provider is a constructor function returning the dependency.
Fx walks the type graph at startup, errors on cycles / missing
nodes.

### Verdict

**Go-ergonomic-issue-but-fixable-in-Go**, with the caveat that
the fix is the macro system Go doesn't have.

Rust `axum` + `tower::Service` builds the dep graph at compile
time via type inference. Scala Akka's `ActorSystem` similarly.
Lisp / Clojure's component framework is reflection-driven but
the LISP reader macros make the syntax disappear entirely.

Go's `wire` (Google's compile-time DI) is the closest in-Go
answer — it generates `wire_gen.go` from a `wire.go` injector
declaration. We chose `fx` over `wire` because fx supports
runtime introspection (lifecycle hooks, fault injection in
tests), which a compile-time tool can't do.

The ceremony cost in `wire.go` (937 LOC) is real, but a swap
to Rust would replace `fx.Provide(...)` with
`#[derive(FromRequest)]` — different ceremony, same conceptual
weight. Scala's implicit resolution would actually be lighter,
but the Scala ecosystem cost (build tooling, JVM, learning
curve) overwhelms the win for our scale.

### Recommendation

**No swap.** The ceremony cost is paid in any DI-managed
ecosystem. Go's expression of it is verbose but explicit;
that's a feature for a multi-agent codebase where DI ordering
is a frequent merge-conflict surface.

**24-month feasibility**: stay Go. If the agent-concurrency
denominator (per `feedback_decoupling_denominator.md`) grows
past 6 sustained agents, fx's lifecycle introspection BECOMES
the load-bearing investment, not the ceremony.

---

## 6. Middleware further-split

**Claim**: Go's interface-based composition is awkward vs
languages with higher-kinded types (Haskell, Scala, OCaml).
Splitting the 10-stage chain further (e.g. into "pre-broker
validation tier" + "post-broker side-effect tier") would
require boilerplate that HKT-rich languages avoid.

### Repo evidence

Same as item 2: `mcp/middleware_chain.go` (84 LOC). The 10
middlewares are independent — they compose by ordering, not
by HKT-style stacking.

### Verdict

**False-irreducible-claim.**

HKT-rich languages let you write `forall m. Monad m => ...`
once and parameterize on the effect monad. That's elegant for
MTL-style transformer stacks. But our middleware chain isn't
a transformer stack — each middleware is a closure over
`(ctx, request) -> response`. There's no monad parameter to
abstract over.

A "further split" would just be more middleware entries in the
ordering slice. Adding `preBrokerTier` and `postBrokerTier` to
`DefaultBuiltInOrder` is a 2-line change. No HKT needed; no
language swap helps.

### Recommendation

**No swap.** The further-split anti-rec'd item is achievable
in Go in ~10 LOC; calling it Go-irreducible is sloppy framing.

---

## 7. Per-component shortlist — extending `a03694a`

`a03694a` shipped 5 candidates (widgets / analytics / riskguard
/ telegram / ticker). Adding new candidates from this evaluation:

| # | Component | Current | Proposed lang | Trigger | Verdict |
|---|---|---|---|---|---|
| 1 | Widgets / Apps SDK | Go HTML/template | **TypeScript + React** | Widget UX iteration takes >1d in Go | Realistic Q3 2026 |
| 2 | Analytics numeric kernels | Go pure-functions | **Python (numpy + scipy)** | 2 consecutive analytics tools land as LLM-coordinator | Realistic Q4 2026 |
| 3 | Riskguard hot-path | Go in-process | **Rust subprocess via existing `checkrpc`** | SEBI Algo-ID throughput trigger | Aspirational; gated on MRR >> projection |
| 4 | Telegram bot | Go | **TypeScript / Bun** | Telegram product line expands beyond trading commands | Aspirational |
| 5 | Ticker WebSocket | Go | **Rust + tokio-tungstenite** | >1k concurrent users | Far-future |
| 6 | **Plugin loader (third-party authorship)** | Go static-link | **WASM via wazero** OR keep subprocess-RPC | Third-party plugin marketplace launch | Stay subprocess-RPC; WASM deferred |
| 7 | **Event-flow interactive UI** | Mermaid markdown | **TypeScript + D3.js (frontend only)** | Operator demand for live event-stream dashboard | Lift with widget TSX (#1) |

**Items 1-5 unchanged from `a03694a`. Items 6-7 are new.**

### Item 6 — plugin loader

The novel framing here: don't pick "WASM vs Go's plugin package"
— the right answer is "use what's already there"
(`kc/riskguard/subprocess_check.go`'s netRPC pattern, which is
language-agnostic by construction). Promoting that pattern to
the canonical IPC contract for cross-language plugins is the
unblocker, NOT a language swap.

### Item 7 — event-flow UI

Clarifies an open question from `a03694a`: "is there a better-
fit language for an interactive UI here?" Answer: yes, TS+D3,
but the swap isn't a backend Go replacement. It's a NEW frontend
that consumes the same JSON the Mermaid renderer walks. Backend
stays Go. Lift-along with the widget toolchain.

---

## 8. Aggregate verdict

| Item | Original claim shape | Honest verdict |
|---|---|---|
| 1. Plugin loader (+0.5 Plugin dim) | Go-irreducible | **False-irreducible-claim**. Subprocess-RPC seam already cross-language. The +0.5 cap is on `mcp/plugin_*.go` static-link, which is a design choice not a Go limitation. |
| 2. Decorator promotion (+5) | Go-irreducible (syntax) | **Go-ergonomic-issue-fixable-in-Go**. Cosmetic gap; not worth a swap. |
| 3. Test-Arch +1 (CQRS UI) | Go-irreducible | **False-irreducible-claim**. Static viz works in Go (`cmd/event-graph`); interactive viz is a frontend concern (TS+D3), not backend Go limitation. |
| 4. Logger sweep ergonomics | Go-irreducible (ctx threading) | **False-irreducible-claim** (mostly). Wave D's strict ctx-on-every-method shape is a deliberate choice; less-strict in-Go alternatives exist. Rust/TS implicit ctx is a different shape, not strictly better. |
| 5. Wire/fx ceremony | Go-irreducible (no compile-time DI) | **Go-ergonomic-issue-fixable-in-Go**. Wire (compile-time) IS available; we chose fx for runtime introspection. Ceremony is paid in any DI ecosystem. |
| 6. Middleware further-split | Go-irreducible (no HKT) | **False-irreducible-claim**. Our middleware shape isn't a transformer stack; HKT doesn't apply. |

### Headline finding

**Of 6 "Go-irreducible" claims I have made or repeated this
session, 5 are false-irreducible-claims (or fixable-in-Go) and 1
is a fair Go-ergonomic-issue (Decorator syntax sugar at +5).**

**Zero items are TRULY-Go-limited at the language level.**

This is honest opacity to the user: the language-swap framing,
applied to these specific dim-cap items, was over-aggressive on
my part. The legitimate swap candidates (widgets to TS,
analytics to Python) come from ECOSYSTEM REACH ARGUMENTS
(library availability, hot-reload tooling), not Go-language
limitations. The ecosystem axis is real and was correctly
called out in `a03694a`; the language axis on these dim caps
was inflated.

### Concrete recommendations

1. **Drop the "Go-irreducible" framing on the +0.5 Plugin / +5
   Decorator / +1 Test-Arch / Logger / Wire-fx / Middleware
   items.** Replace with "design-choice ceiling" or
   "ergonomic-cost ceiling" labels in the architecture audit.
2. **Keep the ecosystem-reach swaps in flight per `a03694a`**
   (widgets → TS Q3 2026; analytics → Python Q4 2026 if triggers
   fire).
3. **Promote `kc/riskguard/checkrpc/`** to the canonical cross-
   language IPC seam (already in `a03694a` §4.3 #1; this
   evaluation reinforces it). Item 6 above is the unblocker, not
   WASM.
4. **WASM swap deferred.** Wait for cold-start <10ms and for a
   third-party plugin product motion. Neither is on the 24-month
   horizon.
5. **Interactive event-flow UI deferred** but lift-along with
   widget TSX swap (item 7). Backend stays Go.

### Net effect on the architecture audit

If the dim-cap labels are corrected per recommendation 1, the
"truly limited by Go at the language level" set goes from "6+
items contributing ~6.5 dim points" to **zero items**. The
caps remain (we don't claim 100/100 falsely), but the framing
shifts from "Go is the bottleneck" to "we have made design
choices that pay caps in exchange for benefits we want to keep".
That's a more accurate story for the user, and it removes
specious pressure for language swaps that wouldn't actually
move the dim numbers.
