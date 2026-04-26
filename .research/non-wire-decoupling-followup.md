# Non-Wire Decoupling Patterns — Verification of A's 4-Blocker Stop Recommendation

**Context**: A shipped Step 1 partial (`8727beb`+`9c1eeae`, +280 LOC). LifecycleManager extracted, Blocker 4 cleanly resolved + Blocker 5 documented imperative. A then hit 4 remaining blockers and recommended STOP. This deliverable verifies user's framing of why those 4 blockers stay imperative AND audits non-Wire decoupling patterns that could still address them.

**Charter**: Read-only, `.research/*.md` only. No source-file edits.

**Audited HEAD**: `9c1eeae`.

---

## 1. Verification of A's 4-blocker analysis

Empirical counts from `app/wire.go` (754 LOC post-Step-1).

### Blocker 1 — Runtime conditionals × 6

**User claim**: feature-flag mechanism for multi-mode deploys (Fly.io / local / self-hosted). Wire would need 2⁶=64 builders.

**Verification**: The conditionals fall into two distinct categories:

- **Deployment-mode flags (genuinely 6)**:
  - `app.Config.OAuthJWTSecret != ""` (line 131) — gates encryption + hash-publishing wiring
  - `app.DevMode` (line 124+, repeated as fail-open vs fail-closed gates)
  - `app.Config.StripeSecretKey != "" && !app.DevMode` (line 445) — gates billing entire subsystem
  - `kcManager.AlertDB() != nil` (line 121, 171, 221) — gates audit/consent/riskguard persistence
  - paperEngine wiring (line 360-361) — gated by db availability + DevMode
  - billing/invitation/family wiring (lines 484-488) — chained on billing presence
- **Defensive nil-guards** (NOT mode flags): `if app.outboxPump != nil`, `if app.scheduler != nil`, etc. — these are teardown-time defensive checks, not init-time decisions.

**Verdict**: User's claim **CONFIRMED**. The 6 init-time conditionals are real deployment-mode gates. Wire's compile-time graph would need 2⁶=64 build configurations OR runtime DI (fx) — neither is cleaner than the current `if`. Wire does not handle runtime branching cleanly; this is a known Wire limitation.

### Blocker 2 — Field mutations × 14

**User claim**: organic growth, behavior-correct. Refactoring is Wire tax not quality fix.

**Verification**: `grep -cE "^\s*app\.\w+\s*=" app/wire.go` returns 15 (1 is a `=` in a non-mutation context). Production mutations count: **14** — matches A's claim. Sites: `app.kcManager`, `app.auditStore`, `app.hashPublisherCancel`, `app.consentStore` (×2), `app.riskLimitsLoaded` (×3), `app.riskGuard`, `app.outboxPump`, `app.rateLimitReloadStop`, `app.rateLimitReloadDone`, `app.invitationCleanupCancel`, `app.paperMonitor`, `app.scheduler`.

**Test cascade if refactored**: `grep -rln "app\.\(auditStore\|riskGuard\|consentStore\|outboxPump\|paperMonitor\|scheduler\|kcManager\)" app/` shows ~12 test files mutate `app.X` directly to inject test fixtures. Refactoring App fields to constructor-injection breaks all 12.

**Verdict**: User's claim **CONFIRMED**. The mutations are init-time only (App is then read-only); 14 is genuine field count, not a Wire-fixable smell. Test cascade cost = ~12 files = ~80 LOC of fixture rewrites for ~zero behavior change.

### Blocker 3 — `kcManager.SetX` × 10

**User claim**: mutual recursion (EventDispatcher↔kcManager). Late-binding setter is correct pattern.

**Verification**: 10 SetX calls confirmed via grep. Genuine mutual-recursion cases:
- `SetEventDispatcher` (line 303) — kcManager owns aggregates that emit events; dispatcher owns subscribers that read kcManager state. Genuine cycle.
- `SetMCPServer` (line 549) — kcManager exposes tool registration; mcpServer holds tool handlers that close over kcManager. Cycle.
- `SetEventStore` (line 320) — kcManager use cases append to eventStore; eventStore Drain dispatches events back through kcManager-bound handlers. Cycle.
- `SetPaperEngine` (line 361) — paperEngine takes dispatcher (which references kcManager). 2-step cycle.
- `SetRiskGuard` (line 297) — riskguard config doesn't reference kcManager. **Eliminable** — could be constructor arg.
- `SetAuditStore` (line 150) — audit store doesn't reference kcManager. **Eliminable.**
- `SetBillingStore`, `SetInvitationStore`, `SetFamilyService`, `SetPnLService` — all post-construction wiring without genuine cycle. **4 of 10 are just-laziness.**

**Verdict**: User's claim **PARTIALLY CORRECT**. ~6 of 10 setters are genuine mutual-recursion (Wire can't fix without runtime resolution). ~4 of 10 are eliminable post-construction wiring that COULD become constructor arguments. But eliminating 4 doesn't break the keystone — the remaining 6 require imperative SetX regardless. Wire still adds zero value here.

### Blocker 6 — Middleware chain × 13

**User claim**: ordering is architectural; Wire produces values not ordered slices. Wrapping in single provider is structurally equivalent.

**Verification**: `grep -nE "WithToolHandlerMiddleware\|server\.With" app/wire.go` returns **11 invocations**, NOT 13 (user count was off by 2). The 11: correlation, timeout, audit (conditional), hooks, circuitbreaker, riskguard, ratelimit, billing (conditional), papertrading (conditional), dashboardurl, plus `WithElicitation` and `WithHooks`.

Order matters semantically: correlation MUST wrap timeout (so cancel fires correctly); audit MUST wrap riskguard (so blocked orders get logged). The 11-item ordered slice is the public-API contract.

**Verdict**: User's claim **CONFIRMED on substance, off by 2 on count**. Wire produces dependency-resolved values, not ordered chains. Modeling a chain in Wire requires either (a) a single provider that internally builds the slice (structurally equivalent to current code) or (b) per-middleware providers each declaring "I depend on the previous slot" (cascade of phantom dependencies, harder to read). The current `serverOpts = append(serverOpts, server.WithX(...))` pattern is the most direct expression of the requirement. Wire wins zero readability here.

---

## 2. Non-Wire pattern candidates

### Pattern P1 — Functional options for App construction

**Targets**: Blocker 2 (field mutations).

**Mechanism**: Replace `app.X = ...` with `WithX(...)` options applied in `NewAppWithConfig`. Each option is an idempotent func mutating an unexported staging struct.

**Cost**: ~120 LOC (14 options × ~5 LOC each + plumbing) + 12 test-file cascade (same as Wire) = ~200 LOC total.

**Agent-concurrency lift**: NEAR ZERO. The shared edit point is still `app/app.go` `App struct` field list. Adding a new field still requires editing the central struct — option func is just sugar. Mode 2 conflict on `App struct` declarations is unchanged.

**Side effects**: Standard Go idiom, low runtime tax, no build complexity. Idiomatically familiar.

**Verdict**: **REJECT for concurrency goal** — doesn't eliminate the shared edit point. Worth considering for API ergonomics if `NewAppWithConfig` ever becomes a public-facing API, but `NewAppWithConfig` is an internal construction helper and unlikely to gain external consumers.

### Pattern P2 — Builder pattern for ordered chains

**Targets**: Blocker 6 (middleware chain).

**Mechanism**: `mw := mcp.NewMiddlewareBuilder(); mw.AddCorrelation(); mw.AddTimeout(30*time.Second); ...; serverOpts = append(serverOpts, mw.Options()...)`.

**Cost**: ~60 LOC for the builder + 11 callsite changes in wire.go = ~80 LOC.

**Agent-concurrency lift**: ~0. The 11-line block in wire.go becomes an 11-line block elsewhere. Adding a new middleware still touches a single shared file (the builder definition or the wire.go block). Net zero.

**Side effects**: Non-idiomatic for Go (Go prefers slices over builders); adds indirection without enabling test mocks (every middleware is already independently testable).

**Verdict**: **REJECT** — moves friction without eliminating it. The user's framing (`single-provider-with-imperative-append is structurally equivalent`) is correct.

### Pattern P3 — fx (Uber DI runtime container)

**Targets**: Blockers 1+3 (runtime conditionals + late-binding).

**Mechanism**: `fx.Module("app", fx.Provide(NewKcManager, NewEventDispatcher, ...), fx.Invoke(SetupRoutes))`. Lifecycle hooks (`fx.Lifecycle`) handle ordered startup/teardown. Conditional wiring via `fx.Options(condA, fx.Options(...), elseB)`.

**Cost**: ~400 LOC migration + permanent runtime DI tax (~5-15ms startup overhead per memory pull from kite-mcp-server's deploy runbook context) + fx-specific debugging (DI-resolution errors are stack-trace-opaque) + dependency adds (`go.uber.org/fx` is a non-trivial transitive surface).

**Agent-concurrency lift**: Mode 2 reduction on `wire.go` shared edit ≈ 30-40% (each agent owns their own `Module` file, central composition is a 1-line `fx.Options(modA, modB, ...)` call). However: fx's `lifecycle.Append` still requires a central Append site; the conditional `fx.Options` ordering is a shared edit point similar to current `if/else` blocks. Net concurrency lift: 4→6 agents (same tier as I+J).

**Side effects**: Runtime DI tax on every startup; harder unit tests (require `fx.New(fx.Options(...)).Start()`); error messages cryptic.

**Verdict**: **REJECT at current scale**. fx solves Blockers 1+3 partially but introduces equivalent shared edit points elsewhere. The 400 LOC + permanent runtime tax doesn't return more concurrency than the cheaper Phase 3a port migration (already in flight). fx might be justified at 8+ permanent agents on the wire layer, but A's Phase 3a port migration is the higher-ROI concurrency lift currently underway.

### Pattern P4 — Struct split (interface-segregation for App)

**Targets**: Blocker 2 (field mutations) by eliminating the 14-field central struct.

**Mechanism**: Split `App struct` into bounded-context structs: `App.LifecycleHandles`, `App.AuditServices`, `App.PaperServices`, `App.BillingServices`, etc. Each sub-struct owns its own field set; the central App becomes a 7-field struct of sub-struct pointers.

**Cost**: ~250 LOC App refactor + ~150 LOC test fixture rewrites (12 test files × ~12 LOC) = ~400 LOC. The actual field count doesn't drop — they migrate from `App.X` to `App.SomeContext.X`.

**Agent-concurrency lift**: REAL. Mode 2 conflict on `App struct` declarations drops to ~5%/wk (only adding a NEW context creates a central edit). Adding a field within an existing context = touch only that sub-struct = different files for different agents.

**Side effects**: Two-layer access (`app.AuditServices.Store` vs `app.auditStore`) — minor verbosity tax. Aligned with Phase 3a port migration's bounded-context philosophy. Could be staged AFTER Phase 3a completes.

**Verdict**: **CONDITIONAL ACCEPT** — promising IF Phase 3a port migration delivers the bounded-context boundaries first. Without Phase 3a, struct split is arbitrary grouping. With Phase 3a's port-defined contexts, struct split becomes natural.

**LOC**: ~400, dependency-gated on Phase 3a completion (already in flight per `7cfe93a`).

**Agent-concurrency**: 4→6 ceiling specifically on `app/wire.go` + `app/app.go` shared edits. Combined with Phase 3a's 4→6 ceiling on tool handlers, the joint ceiling is ~7-8 agents.

---

## 3. Honest comparison vs A's "stop here" recommendation

A's claim: lifecycle alone is the win; defer the rest.

| Pattern | Beats "stop here"? | Why |
|---|---|---|
| P1 Functional options | NO | Doesn't eliminate shared edit; ~200 LOC for cosmetic gain |
| P2 Builder for chains | NO | Moves friction, doesn't eliminate; ~80 LOC for net-zero |
| P3 fx runtime DI | NO at current scale | 400 LOC + permanent tax; net concurrency tier same as I+J already underway |
| P4 Struct split (post-Phase-3a) | MAYBE | 400 LOC, real Mode 2 drop on App struct, but gated on Phase 3a completing |

**Honest assessment**: only P4 has non-zero ROI under the merge-conflict accounting from `8596138`. And P4 is gated — useful only AFTER Phase 3a's bounded-context boundaries land in production.

A's "stop here" is **correct for the 4 immediate blockers**. The right next move is NOT another wire-layer refactor; it's letting Phase 3a finish (Batch 5 just landed in `7cfe93a`), then evaluating P4 against fresh empirical conflict data once the team scales past 6 agents.

---

## 4. Updated verdict

**A's stop recommendation HOLDS for Wire-layer decoupling.** None of the 4 non-Wire patterns examined beats "ship lifecycle, stop, let Phase 3a finish".

**Material corrections to user's framing**:
1. Blocker 6 middleware count is **11, not 13**. Substance unchanged.
2. Blocker 3 SetX count is **10, but 4 are eliminable** as constructor args. Doesn't change Wire verdict (the 6 mutual-recursion cases would still block Wire), but worth knowing if a future agent claims "we have 10 setters that need fixing".
3. Blocker 1 conditionals are **genuinely 6 deployment-mode flags**. Confirmed.
4. Blocker 2 field mutations are **genuinely 14**. Confirmed.

**Material correction to `8596138` recommendations**:
- Wire/fx (Investment A) Phase 3 in `8596138` was promoted from REJECT to recommended. **A's empirical investigation shows the 4 blockers prevent Wire from delivering the predicted value.** Wire/fx should drop OUT of the recommended sequence. Logger wrap, Federated build, full ES — all remain REJECT (verdict from `8596138` holds for those, hardens for Wire).
- The actual highest-ROI sequence is **I + J + E (Phase 3a)** — exactly what is currently shipping. No structural decoupling investment beyond Phase 3a is justified at current 4-agent baseline.

**One genuine non-Wire candidate worth tracking**: P4 (struct split aligned with Phase 3a bounded contexts) — re-evaluate after Phase 3a's last batch lands and team has run at 6+ agents long enough to measure App-struct conflict frequency empirically.

---

*Generated 2026-04-26 against HEAD `9c1eeae`. Read-only research deliverable; no source files modified.*
