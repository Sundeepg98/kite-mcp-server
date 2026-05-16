# `app/` Extraction Roadmap (Research-Only)

_Authored: 2026-05-16 IST_
_Source agent: Research dispatch (app/ extractability)_
_Status: REFERENCE — answers "should `app/` itself ever become external?"_
_Scope: READ-ONLY across `kite-mcp-server` + `algo2go/kite-mcp-bootstrap` + 32 algo2go modules. No tree mutations besides this doc._

---

## §0 — Headline finding

**The task brief assumed `app/` lives at `D:/Sundeep/projects/kite-mcp-server/app/`. Empirically it does NOT — `app/` was relocated to `algo2go/kite-mcp-bootstrap/app/` on 2026-05-16 as part of the Sprint 0 bootstrap-relocation.** The roadmap below answers the equivalent forward-looking question for `app/`'s **current location** in the bootstrap module: should it be further sliced out into a thinner `kite-mcp-app-helpers` module, or stay as the composition root inside bootstrap?

**Recommendation: STAY (do not extract). `app/` is the composition root that wires every other algo2go module — by definition the one place that cannot externalize.** A thin "helpers" extraction is technically possible (~7-12 utility files) but offers no agent-concurrency ROI given Phase 3 (mcp/ extraction) is the gating dependency. **Sequence: finish Phase 3 first; revisit `app/`-helpers only if a clear shared-consumer emerges.**

---

## §INPUTS — load-bearing facts (verified 2026-05-16)

| # | Claim | Probe | Verified |
|---|---|---|---|
| 1 | `kite-mcp-server/app/` directory does NOT exist (relocated 2026-05-16) | `ls D:/Sundeep/projects/kite-mcp-server/` | 2026-05-16 |
| 2 | `app/` now lives at `algo2go/kite-mcp-bootstrap/app/` | `ls D:/Sundeep/projects/algo2go/kite-mcp-bootstrap/app/` | 2026-05-16 |
| 3 | In-tree `kite-mcp-server` is a 35-line thin shell delegating to `bootstrap.Main` | `cat D:/Sundeep/projects/kite-mcp-server/main.go` | 2026-05-16 |
| 4 | `app/` (root, non-test): **29 .go files**, **7,052 LOC** | `find ... | xargs wc -l` | 2026-05-16 |
| 5 | `app/` (root, test): **39 _test.go files**, **18,318 LOC** | `find ...` | 2026-05-16 |
| 6 | `app/providers/` (sub-module, non-test): **22 .go files**, **2,859 LOC** | `find ... | xargs wc -l` | 2026-05-16 |
| 7 | `app/providers/` is already an EXTRACTED sub-module of bootstrap (`github.com/algo2go/kite-mcp-bootstrap/app/providers`) | `cat app/providers/go.mod` | 2026-05-16 |
| 8 | `app/wire.go`: **1,008 LOC** (middleware-chain assembly + fx.New providers + tool registration) | `wc -l app/wire.go` | 2026-05-16 |
| 9 | `app/http.go`: **1,596 LOC** (HTTP server + mux setup + handlers + setupGracefulShutdown) | `wc -l app/http.go` | 2026-05-16 |
| 10 | `app/app.go`: **825 LOC** (App struct + NewApp constructor + lifecycle fields) | `wc -l app/app.go` | 2026-05-16 |
| 11 | `app/` imports **30 algo2go modules** directly + 2 bootstrap sub-modules (mcp, plugins) + app/providers | `grep "algo2go" *.go` over app/ | 2026-05-16 |
| 12 | `algo2go/` org has **32 modules total** (28 domain + bootstrap + kc + metrics + tools-common) | `ls D:/Sundeep/projects/algo2go/` | 2026-05-16 |
| 13 | Production `tools=111` invariant across 66 consecutive deploys | `curl /healthz` per STATE.md §2.1 | 2026-05-16 |
| 14 | Phase 3 (mcp/ extraction) paused per task #355 | task tracker reference in dispatch brief | 2026-05-16 |
| 15 | `kc/manager_*.go` Tier B decomp is in flight (Steps 1-5) | `kc-manager-decomp-roadmap-2026-05-16.md` | 2026-05-16 |

---

## §1 — Survey: what's in `app/`

### §1.1 File inventory (non-test, root of `app/`)

29 files / 7,052 LOC. Per-file LOC + content classification (K/E/M) follow §2.

| # | File | LOC | Primary content |
|---|---|---|---|
| 1 | `adapters_briefing.go` | 42 | briefingTokenAdapter, briefingCredAdapter — kc → alerts port bridges |
| 2 | `adapters_eventsourcing.go` | 353 | makeEventPersister — domain.Event → audit log adapter |
| 3 | `adapters_local_bus.go` | 279 | In-process CommandBus fallback for unit tests (CQRS dispatch path) |
| 4 | `adapters_oauth_client.go` | 84 | OAuth client store adapter |
| 5 | `adapters_oauth_exchanger.go` | 232 | kiteExchangerAdapter — exchanges request_token via CommandBus |
| 6 | `adapters_oauth_registry.go` | 41 | OAuth client registry adapter |
| 7 | `adapters_paper.go` | 36 | Paper-trading adapter (thin) |
| 8 | `adapters_riskguard.go` | 51 | RiskGuard adapter (thin) |
| 9 | `adapters_signer.go` | 25 | SessionSigner adapter (thin) |
| 10 | `adapters_telegram.go` | 73 | Telegram bot adapter |
| 11 | `app.go` | 825 | `App` struct (~30 fields), `NewApp(...)` constructor, helper accessors |
| 12 | `client_metadata.go` | 67 | `withClientMetadata` HTTP middleware (IP + UA → ctx for audit) |
| 13 | `config.go` | 167 | `Config` env-var struct + `ConfigFromEnv` / `ConfigFromMap` parsers |
| 14 | `envcheck.go` | 325 | Startup env-var validation (Fly region, OAuth secret length, etc.) |
| 15 | `graceful_restart.go` | 265 | SIGUSR2 nginx-style hot-reload (socketpair FD passing) |
| 16 | `graceful_restart_unix.go` | 232 | Unix syscall variant |
| 17 | `graceful_restart_windows.go` | 58 | Windows no-op stub |
| 18 | `http.go` | 1,596 | HTTP server creation + setupMux + setupGracefulShutdown + handlers |
| 19 | `legal.go` | 102 | Goldmark renderer for /terms + /privacy markdown |
| 20 | `lifecycle.go` | 138 | `LifecycleManager` — ordered teardown registry |
| 21 | `plugin_routes.go` | 137 | Plugin HTTP route registration + reserved-prefix guard |
| 22 | `ratelimit.go` | 309 | `ipRateLimiter` + `userRateLimiter` (golang.org/x/time/rate wrappers) |
| 23 | `ratelimit_reload.go` | 154 | SIGHUP hot-reload of rate-limit caps |
| 24 | `recovery.go` | 120 | `recoverPanic` middleware (outermost HTTP layer) |
| 25 | `requestid.go` | 127 | `withRequestID` middleware — UUIDv7 generation + ctx threading |
| 26 | `session_resolver.go` | 57 | `clientHintedResolver` — kc → mcp-go SessionIdManager bridge |
| 27 | `tier_rate_multiplier.go` | 18 | Pure func — billing.Tier → rate-limit multiplier |
| 28 | `tls.go` | 131 | Inline ACME (autocert) for off-Fly self-host |
| 29 | `wire.go` | 1,008 | initializeServices — middleware-chain assembly + fx.New providers + tool registration |
| | **TOTAL** | **7,052** | |

### §1.2 What KIND of thing is `app/`?

A faithful summary of the directory's role, per file-header read:

1. **Composition root** — `wire.go` + `app.go` assemble the entire object graph: `kc.Manager` + `*server.MCPServer` + middleware chain + lifecycle. This is the cmd-only layer; consumers are nobody but `main`.

2. **HTTP serving + middleware** — `http.go` (1,596 LOC) owns the HTTP server, mux, OAuth callback handlers, dashboard routes, admin routes, `setupGracefulShutdown`. `requestid.go` + `client_metadata.go` + `recovery.go` are HTTP middleware. `ratelimit.go` + `ratelimit_reload.go` + `plugin_routes.go` complete the HTTP surface.

3. **Cross-package adapters** (the `adapters_*.go` files) — bridge **kc** stores/managers to **alerts**, **audit**, **oauth**, **eventsourcing**, **registry**, **usecases** ports. These exist here SPECIFICALLY to avoid import cycles: `kc` cannot import `usecases` because `usecases` imports `kc`. The adapter pattern lives in the composition root because that's where both ends are visible.

4. **Boot-time concerns** — `envcheck.go`, `config.go`, `legal.go` (templates), `graceful_restart*.go`, `tls.go`. These run ONCE at startup and are tightly coupled to the App struct.

5. **Already-extracted DI providers** — `app/providers/` is already an Fx-provider sub-module (`github.com/algo2go/kite-mcp-bootstrap/app/providers` v0.3.0), wired via go.work + replace directives. 22 files / 2,859 LOC. Provides BuildManager, BuildMCPServer, ProvideAuditMiddleware, etc.

### §1.3 Cross-package types defined in `app/`

The package exports a handful of types that downstream code (tests, plugins, cmd/) depends on:

- `App` struct (~30 fields) — owned by main; not consumed externally
- `Config` struct — read by app/providers and several tests
- `LifecycleManager` — internal teardown registry; not exposed
- `RequestIDFromCtx(ctx) string` + `LoggerPortWithRequestID(...)` — **the only "reusable" surface**. Consumed by audit middleware (and would be by any future module that wants correlation IDs).
- `tierRateMultiplier(billing.Tier) int` — pure function; only consumed inside the package today.

**Only `RequestIDFromCtx` + `LoggerPortWithRequestID` qualify as "general HTTP helpers a different consumer might want."** Everything else is App-scoped.

---

## §2 — Per-file classification (K / E / M)

Legend:
- **K** — Keep in composition root (cmd-only layer)
- **E** — Extract-candidate to a `kite-mcp-app-helpers` (or similar) module
- **M** — Move to existing algo2go module

| # | File | Class | One-line rationale |
|---|---|---|---|
| 1 | `adapters_briefing.go` | M | Could live in **kite-mcp-alerts** as an adapter sub-package; consumer is alerts.TokenChecker. |
| 2 | `adapters_eventsourcing.go` | M | Belongs in **kite-mcp-eventsourcing**; it IS the production event persister, currently here only for the *slog logger seam. |
| 3 | `adapters_local_bus.go` | K | Test-fallback bus construction tied to `kc.Manager` reference shape — cannot leave the composition site without dragging kc + cqrs + usecases together at a thinner seam. |
| 4 | `adapters_oauth_client.go` | M | Belongs in **kite-mcp-oauth** (or its own adapter sub-pkg); it's a port satisfaction. |
| 5 | `adapters_oauth_exchanger.go` | M | Belongs in **kite-mcp-oauth**; dispatches via CommandBus but the production binding for `RequestTokenExchanger` is here. |
| 6 | `adapters_oauth_registry.go` | M | Belongs in **kite-mcp-oauth**. |
| 7 | `adapters_paper.go` | M | Trivial 36-LOC adapter — fold into **kite-mcp-papertrading** as a port. |
| 8 | `adapters_riskguard.go` | M | Fold into **kite-mcp-riskguard** as the production binding. |
| 9 | `adapters_signer.go` | M | Trivial signer adapter — fold into **kite-mcp-oauth** or **kite-mcp-kc**. |
| 10 | `adapters_telegram.go` | M | Fold into **kite-mcp-telegram**. |
| 11 | `app.go` | K | The App struct IS the composition root. By definition the one place that cannot externalize — it holds every wired dependency. |
| 12 | `client_metadata.go` | E | Pure HTTP middleware (IP + UA → ctx). Reusable across any audited HTTP service; only depends on `kite-mcp-audit`. |
| 13 | `config.go` | K | Reads every algo2go module's env contract — by construction can only exist at the composition root. |
| 14 | `envcheck.go` | K | 325-LOC startup validation that knows the union of all algo2go module configs — can only live at the union point. |
| 15 | `graceful_restart.go` | E | nginx-style hot-reload primitive. Reusable in any single-binary Go server; no algo2go module deps. |
| 16 | `graceful_restart_unix.go` | E | Companion to above. |
| 17 | `graceful_restart_windows.go` | E | Companion stub. |
| 18 | `http.go` | K | 1,596 LOC of mux assembly + per-route handlers. Imports kc, audit, billing, i18n, ops, telegram, templates, mcp parent, oauth. This is THE composition site for HTTP — cannot externalize without dragging 10 modules. |
| 19 | `legal.go` | E | Goldmark renderer for /terms + /privacy. Only imports `kite-mcp-legaldocs`. Reusable. |
| 20 | `lifecycle.go` | E | Pure `LifecycleManager` — ordered teardown registry. No algo2go deps. Useful in any Go service. |
| 21 | `plugin_routes.go` | E | Plugin HTTP route registration. Lightly coupled (only `net/http`); could move to a plugins-runtime helper. |
| 22 | `ratelimit.go` | E | Per-IP + per-user rate limiters over `golang.org/x/time/rate`. Only imports `kite-mcp-oauth` for JWT claims. Reusable. |
| 23 | `ratelimit_reload.go` | E | SIGHUP hot-reload companion. |
| 24 | `recovery.go` | E | `recoverPanic` middleware over `logport.Logger`. No algo2go deps beyond logger port. Reusable. |
| 25 | `requestid.go` | E | UUIDv7 X-Request-ID middleware + `RequestIDFromCtx` + `LoggerPortWithRequestID`. **The strongest E candidate** — already designed as a reusable port-friendly helper. |
| 26 | `session_resolver.go` | K | Adapts `*kc.ClientHintResolver` to mcp-go's `SessionIdManagerResolver`. Pure composition glue between two libraries the app already owns. |
| 27 | `tier_rate_multiplier.go` | M | Pure func — fold into **kite-mcp-billing** as `Tier.RateMultiplier()` method; trivial 18-LOC move. |
| 28 | `tls.go` | E | autocert wiring. No algo2go deps. Reusable across any single-binary Go server. |
| 29 | `wire.go` | K | 1,008 LOC of `initializeServices` — wires 16+ algo2go modules through fx.New providers. THE composition root. |

**Tally**:
- **K** (Keep — composition root): **8 files / ~5,653 LOC** = `app.go` + `http.go` + `wire.go` + `adapters_local_bus.go` + `config.go` + `envcheck.go` + `session_resolver.go` (~80% of the package)
- **E** (Extract-candidate to helpers module): **11 files / ~1,360 LOC** = `requestid.go` + `client_metadata.go` + `recovery.go` + `lifecycle.go` + `ratelimit.go` + `ratelimit_reload.go` + `plugin_routes.go` + `graceful_restart{,_unix,_windows}.go` + `legal.go` + `tls.go`
- **M** (Move to existing module): **10 files / ~960 LOC** = the 9 `adapters_*.go` (except `adapters_local_bus.go`) + `tier_rate_multiplier.go`

(7,052 LOC total — small rounding from header/blank-line counting per `wc -l`.)

---

## §3 — Dependency-map: what `app/` imports

### §3.1 algo2go module imports from `app/` (non-test)

Direct imports observed via `grep "algo2go" app/*.go`:

```
algo2go/kite-mcp-alerts          (adapters_briefing, wire, http, app)
algo2go/kite-mcp-audit            (adapters_oauth_exchanger, adapters_eventsourcing, client_metadata, envcheck, wire, http, app)
algo2go/kite-mcp-billing          (tier_rate_multiplier, wire, http)
algo2go/kite-mcp-bootstrap/app    (referenced from test files — self)
algo2go/kite-mcp-bootstrap/app/providers (wire)
algo2go/kite-mcp-bootstrap/mcp    (wire, http, app)
algo2go/kite-mcp-bootstrap/mcp/paper (wire)
algo2go/kite-mcp-bootstrap/plugins/rolegate (wire)
algo2go/kite-mcp-bootstrap/plugins/telegramnotify (wire)
algo2go/kite-mcp-bootstrap/testutil (tests only)
algo2go/kite-mcp-bootstrap/testutil/kcfixture (tests only)
algo2go/kite-mcp-broker            (adapters_oauth_exchanger, app)
algo2go/kite-mcp-broker/zerodha    (app)
algo2go/kite-mcp-clockport         (helpers_test or test infra)
algo2go/kite-mcp-cqrs              (adapters_oauth_exchanger, adapters_local_bus, wire)
algo2go/kite-mcp-domain            (adapters_eventsourcing, wire)
algo2go/kite-mcp-eventsourcing     (adapters_eventsourcing, wire, app)
algo2go/kite-mcp-i18n              (http)
algo2go/kite-mcp-instruments       (tests)
algo2go/kite-mcp-kc                (app, http, wire, session_resolver, adapters_briefing, adapters_local_bus, adapters_oauth_exchanger)
algo2go/kite-mcp-kc/ops            (http, app — LogBuffer)
algo2go/kite-mcp-legaldocs         (legal)
algo2go/kite-mcp-logger            (recovery, requestid, lifecycle, envcheck, adapters_eventsourcing)
algo2go/kite-mcp-metrics           (wire, app)
algo2go/kite-mcp-oauth             (adapters_oauth_client, ratelimit, http, app)
algo2go/kite-mcp-papertrading      (adapters_paper, wire, app)
algo2go/kite-mcp-registry          (adapters_local_bus)
algo2go/kite-mcp-riskguard         (adapters_riskguard, wire, app)
algo2go/kite-mcp-scheduler         (app)
algo2go/kite-mcp-telegram          (adapters_telegram, http, app)
algo2go/kite-mcp-templates         (http)
algo2go/kite-mcp-usecases          (adapters_oauth_exchanger, adapters_local_bus, wire)
algo2go/kite-mcp-users             (wire, app, adapters_local_bus)
```

**Total: 30 algo2go modules** directly imported by `app/` (plus 2 bootstrap sub-modules: mcp, plugins/{rolegate,telegramnotify}, app/providers, testutil).

### §3.2 Implication for extractability

| Question | Answer |
|---|---|
| Does `app/` pull a narrow subset of algo2go modules? | **NO.** `app/` imports **30 of 32** algo2go modules — essentially the entire org. Excluded: `kite-mcp-aop` (orphaned per STATE.md §1.1), `kite-mcp-isttz` (indirect-only). |
| Is `app/` "the only place that pulls in N modules"? | **YES.** Per STATE.md §1.1, this is the union-of-all-imports site. |
| Can the union site externalize? | **NO** (by definition). Whatever the union site is — currently `bootstrap/app/` — is the composition root. Externalizing it means moving the union somewhere else, not removing it. |
| Can a SUBSET externalize? | **YES** — the **11 E-class files** (HTTP middleware + lifecycle + ratelimit + legal + tls + graceful-restart) form a coherent group that imports at most 2 algo2go modules (`kite-mcp-audit`, `kite-mcp-oauth`, `kite-mcp-legaldocs`, `kite-mcp-logger`). |
| Can the 10 M-class files relocate? | **YES** — each adapter (`adapters_*.go`) is a port-satisfaction for one specific algo2go module; the natural home is that module's `adapters/` sub-package. |

---

## §4 — Three roadmap paths

### §4.1 Path A — STAY (do nothing; status quo)

**Description**: `app/` continues to live in `algo2go/kite-mcp-bootstrap/app/` as the composition root. No further extraction. `app/providers/` (already external sub-module) covers the Fx provider seam; `app/` proper stays cohesive.

**Effort**: 0h.

**Risk**: LOW (nothing changes).

**ROI**:
- Agent-concurrency denominator: zero benefit; agents already work across all 32 algo2go modules + bootstrap + kite-mcp-server simultaneously. `app/` is touched by ~3 agents/week per the dispatch map (kc-manager-decomp, Phase 3, occasional middleware tweaks).
- User-MRR denominator: zero benefit (composition-root code never ships customer-visible features).

**When to revisit**: Only if a 4th concurrent agent appears with disjoint `app/` scope (currently no demand observed).

### §4.2 Path B — Extract `kite-mcp-app-helpers` module (E-class only)

**Description**: Move the 11 E-class files (~1,360 LOC) to a new `algo2go/kite-mcp-app-helpers` module:
- `requestid.go` (UUIDv7 + ctx)
- `client_metadata.go` (HTTP middleware)
- `recovery.go` (panic recovery)
- `lifecycle.go` (LifecycleManager)
- `ratelimit.go` + `ratelimit_reload.go` (per-IP/user rate limiters)
- `plugin_routes.go` (plugin HTTP route registry)
- `graceful_restart{,_unix,_windows}.go` (SIGUSR2 hot-reload)
- `legal.go` (markdown→HTML for ToS/Privacy)
- `tls.go` (autocert wiring)

`bootstrap/app/` then imports `kite-mcp-app-helpers` and consumes them as before.

**Effort**:
- Module creation + 11 file moves + import-path updates: **~6-8h**
- Test re-wiring (many `app/*_test.go` files reference these helpers): **~4-6h**
- WSL2 green-light verification + GOPROXY tag (avoid v0.2.0 immutability burn): **~1-2h**
- **Total: 11-16h** (1.5-2 dev-days).

**Risk**: MED.
- LOW for `requestid.go`, `recovery.go`, `lifecycle.go`, `tls.go`, `legal.go` — pure utility, zero coupling to App struct.
- MED for `ratelimit.go` — imports `kite-mcp-oauth` for JWT claim reading; this is a load-bearing coupling.
- MED for `graceful_restart*.go` — `parent` references `app.gracefulShutdownDone` channel and `app.lifecycle`; not pure.
- HIGH for `plugin_routes.go` — coupling to `app.registry` (plugin hook registry); would require extracting registry first.

In practice **~6-8 of the 11 E files** are clean extractions; **3-5 retain coupling** that would need either (a) refactor-before-extract or (b) staying behind.

**ROI**:
- **Agent-concurrency denominator**: marginal. The hypothetical scenario is "an agent touches only HTTP middleware while another touches only domain logic." This already works today because the files are co-located in `app/` but are independently editable. Module boundary adds versioning overhead (GOPROXY tag-cut every time middleware changes).
- **Cognitive load**: slight reduction — `bootstrap/app/` shrinks from 29 → 18 files. But the 18 remaining files are the COMPLEX ones (`http.go` 1,596 LOC, `wire.go` 1,008 LOC, `app.go` 825 LOC). The complexity that matters doesn't shrink.
- **Reuse**: zero external consumers known. `requestid.go` is a candidate for OSS-extraction someday but nobody outside our tree wants `kite-mcp-app-helpers` specifically.

**Verdict**: **Marginally positive but not before Phase 3 closes.** See §6.

### §4.3 Path C — Move M-class files to their natural-home modules

**Description**: Relocate the 10 M-class files to the algo2go module they bridge to:
- 6 `adapters_oauth_*.go` files → `kite-mcp-oauth/adapters/`
- `adapters_eventsourcing.go` → `kite-mcp-eventsourcing/`
- `adapters_briefing.go` → `kite-mcp-alerts/adapters/`
- `adapters_paper.go` → `kite-mcp-papertrading/`
- `adapters_riskguard.go` → `kite-mcp-riskguard/`
- `adapters_signer.go` → `kite-mcp-oauth/` or `kite-mcp-kc/`
- `adapters_telegram.go` → `kite-mcp-telegram/`
- `tier_rate_multiplier.go` → `kite-mcp-billing/`

**Effort**:
- 10 file relocations across 7 target modules: **~12-16h** (more than B because each move is a per-module PR with its own version-bump + cross-ref update + WSL2 verify).
- GOPROXY tag-cuts × 7 modules: **~2h** (must be coordinated to avoid Brief-2.B-style transitive-version drift).
- **Total: 14-18h** (2-2.5 dev-days).

**Risk**: HIGH.
- Each adapter file currently lives in `app/` precisely BECAUSE moving it to its target module would create import cycles. Example: `adapters_oauth_exchanger.go` imports `kite-mcp-cqrs` (for CommandBus dispatch) AND `kite-mcp-usecases` AND `kite-mcp-kc`. Moving it to `kite-mcp-oauth` requires `kite-mcp-oauth` to import all three — and `kite-mcp-kc` ALREADY imports `kite-mcp-oauth`. Cycle.
- Each cycle break needs a port-extraction (the Anchor 5 pattern from Path A — see `god-object-inventory-2026-05-11.md`). That's ~2-3h per file. So real cost is **30-50h** (4-6 dev-days), not 14-18h.

**ROI**: 
- Adapter co-location with its domain module DOES improve cohesion. The cost is the cycle-break work above.
- Currently this is the pattern Path A (the umbrella refactor agent's work, NOT to be confused with this doc's Path A) has been doing incrementally. **Not urgent — let it land naturally as each port is extracted under Anchor 5.**

**Verdict**: **Defer indefinitely. Let it happen organically as Anchor 5 ports get extracted per the kc-manager-decomp roadmap.**

---

## §5 — Risk profile summary

| Path | Effort | Risk | Agent-concurrency ROI | Sequencing |
|---|---|---|---|---|
| **A (Stay)** | 0h | LOW | N/A (zero delta) | — |
| **B (Extract helpers)** | 11-16h | MED | Marginal positive (versioning overhead vs co-location convenience) | After Phase 3 closes |
| **C (Move adapters)** | 30-50h | HIGH | Indirect (improves long-run cohesion) | Organic via Anchor 5 |

---

## §6 — Decision matrix: `app/`-extraction vs Phase 3 (mcp/ extraction)

Per task brief and STATE.md, the open structural questions on the table are:
- **app/-extraction** (this doc)
- **Phase 3** (mcp/ → algo2go/kite-mcp-tools-foo extraction, currently paused per task #355)
- **kc/manager_*.go Tier B decomp** (in flight, separate dispatch)
- **testutil/ extraction** (in flight, parallel dispatch)

### §6.1 Per-axis comparison: app/ Path B vs Phase 3

| Axis | app/ Path B | Phase 3 (mcp/) |
|---|---|---|
| **LOC affected** | ~1,360 LOC (11 E-class files) | ~25,000+ LOC (mcp/ at pre-Sprint-0 baseline; current size in bootstrap unknown without re-survey) |
| **Effort** | 11-16h | 40-80h (multi-sprint per phase-3-dispatch-briefs) |
| **Risk** | MED | MED-HIGH (touches every tool registration) |
| **Agent-concurrency ROI** | Marginal | HIGH — mcp/ is 18× larger; concurrent edits today are the main friction source per phase-3-ops-port-prereq |
| **Tool-surface impact** | Zero | HIGH — Phase 3 has historically been the source of `tools=111` ⇄ `tools=130` count drift; extra-careful |
| **Production-deploy risk** | LOW (composition-root files; not user-facing) | MED-HIGH (changes the registered-tool surface) |
| **Reverse-dependency cost** | Low (11 files, well-scoped) | High (mcp/ is consumed by EVERY other algo2go module's tests via testutil shims) |
| **Memory rule alignment** | Compile-and-run methodology already proven | Same; but invariant verification needed across 111 tools |

### §6.2 Recommended sequence

```
T0  NOW                                          Phase 3 (mcp/) paused per task #355.
T1  +1-2 weeks  → Resume + close Phase 3        (HIGH ROI, gating dependency for app/-anything)
T2  +1-2 days   → app/ Path B IF still wanted   (MED ROI, optional)
T3  organic     → app/ Path C adapter migration (LOW priority, happens naturally)
```

**Why Phase 3 first?**

1. **Phase 3 unblocks more concurrent work.** Per phase-3-dispatch-briefs, mcp/ extraction enables 4 simultaneous tool-domain agents (read-tools, write-tools, admin-tools, observability-tools). app/ extraction enables ~1 additional agent (HTTP-middleware), and that agent's work today is already small.

2. **Phase 3 may MOOT some `app/` files.** Several files in `app/` (the adapters_*.go group) only exist to bridge mcp tool handlers to ports. If Phase 3 reshapes mcp/, the adapters may relocate or disappear.

3. **GOPROXY tag-cut budget**. Each new external module is one more place for the `feedback_goproxy_immutability` rule to bite. Concentrate tag-cut activity on Phase 3 first; only add new modules (app-helpers) once Phase 3's cross-ref-update muscle memory is rehearsed.

4. **No urgent forcing function on app/.** Per STATE.md, `app/` is touched ~3×/week. mcp/ is touched ~10-15×/week. Concurrent-edit conflict probability scales with touch frequency; Phase 3 is where the conflicts ARE.

**If Phase 3 cannot resume** (task #355 stays paused indefinitely): then app/ Path B becomes the highest-ROI structural item available. Estimate: ~2-3 month delay before this conditional triggers.

---

## §7 — Falsifiability triggers

This roadmap should be re-evaluated if any of the following empirical observations land:

1. **A new external consumer wants `app/`-helpers.** Today there is none. If a sibling project (e.g., a separate algo2go-org HTTP service) emerges, `kite-mcp-app-helpers` becomes naturally justified — re-run Path B analysis.

2. **`app/` grows past ~10,000 LOC.** Current 7,052 LOC is within the manageable-by-one-agent zone. If `app/` accretes another 3,000+ LOC of HTTP handler code (e.g., a new dashboard + admin surface), splitting becomes a cohesion fix even without external consumer.

3. **Phase 3 (mcp/) extraction closes successfully.** Re-survey `app/` then — Phase 3 may relocate ~5-10 of the adapters_*.go files automatically, leaving a different E-class composition.

4. **A 4th concurrent agent dispatch domain emerges with HTTP-middleware focus.** Current agent-domain-map shows ~16 agents across kc/bootstrap/algo2go; none own `app/`-helpers specifically. If one emerges, agent-concurrency-decoupling math shifts.

5. **GOPROXY tag-cut process becomes cheaper.** Today every new module incurs the `feedback_goproxy_immutability` rule overhead. If we move to a tag-immutability-safe workflow (e.g., monorepo internal modules without GOPROXY round-trip), Path B's ~1-2h GOPROXY overhead disappears and the math improves.

6. **A regulatory mandate touches HTTP middleware specifically.** Hypothetical: if SEBI mandates a specific X-Request-ID format or audit-trail schema for HTTP requests, isolating that code as a versionable artifact would be load-bearing. Watch SEBI Annexure-I evolution.

7. **`app/wire.go` exceeds 1,500 LOC.** Currently 1,008. If it accretes another ~500 LOC of fx.New providers, the bigger split (extract Fx-graph as a separate module) becomes warranted — and that's a different question from Path B.

---

## §8 — Final recommendation

**Recommended action: Path A (STAY).**

Reasoning chain:

1. `app/` is the union site for 30 of 32 algo2go modules. By definition (composition-root semantics) it CANNOT externalize as a whole.

2. The extractable subset (Path B) is ~1,360 LOC across 11 files. Effort is 11-16h. Agent-concurrency ROI is marginal: only ~3 agents/week currently touch `app/`, and they coordinate fine via the existing file-level isolation.

3. **Phase 3 (mcp/ extraction) is the higher-ROI structural item by ~10× on every axis** (LOC affected, agent-concurrency uplift, tool-surface visibility). Sequence Phase 3 first; only revisit `app/` once it closes.

4. The adapter files (Path C, M-class) will relocate naturally as Anchor 5 port extractions proceed under the kc-manager-decomp roadmap. No standalone sprint needed.

5. The user's standing rule `feedback_decoupling_denominator` says: evaluate decoupling against AGENT-concurrency, not user-MRR. By that rule, the `app/` E-extraction case is still weak — the agent-concurrency wins from a `kite-mcp-app-helpers` module are dwarfed by the wins from finishing Phase 3.

**Sequencing**:
- **Now**: Path A (no action). Close Phase 3 first.
- **After Phase 3 closes (~2-4 weeks if resumed)**: Re-survey `app/` at the new HEAD; if the E-class still cleanly separates AND a concurrent-edit problem has emerged, execute Path B.
- **Indefinite organic background**: Path C adapter migration happens incrementally as ports get extracted.

---

## §9 — Open questions for next research dispatch

1. **Phase 3 status at next resume**: when task #355 unfreezes, the first job is to confirm `app/` at that HEAD still matches this snapshot. The 11 E-class files may have grown or shrunk.

2. **`requestid.go` as standalone OSS**: this one file (127 LOC) is unusually clean and reusable. Is there appetite for publishing it as a standalone Go module under MIT (or similar) once we have launch-credibility? Not blocking but a forward-looking question.

3. **Adapter pattern documentation**: the 10 M-class files all follow the same pattern (composition-root port-binding). Worth codifying as a §12 pattern in `architectural-patterns-record.md` so future adapters land in the right place from the start, not in `app/` by default.

4. **`app/providers/` as the model**: the existing `app/providers/` sub-module (already extracted as a workspace member of bootstrap) is the proof-of-concept for in-tree-workspace-extraction without a GOPROXY tag-cut. If Path B ever proceeds, `app/helpers/` (in-tree workspace) is the lower-risk variant of "publish kite-mcp-app-helpers as standalone module."
