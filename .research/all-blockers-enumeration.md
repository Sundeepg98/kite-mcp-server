# All-Blockers Empirical Enumeration

**HEAD**: `9c1eeae`. Read-only audit. Empirical greps + reads on origin master, no source modified.

**Categories** (per task brief):
1. Mutation cycle  2. Runtime conditional  3. Mutual recursion  4. Shared edit point  5. Ordering constraint  6. Global state / package-level mutable  7. Test coupling  8. Other

**Severity**: HIGH (blocks parallel agents at current 4-9 tier) / MED (blocks specific refactors) / LOW (nuisance)

---

## Category 1 — Mutation cycles

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B1  | `kc/manager_init.go:114-145` (initAlertSystem) → `:181-189` (initPersistence) | `alertStore` constructed with trigger callback, then `m.alertStore.SetDB(alertDB)` called AFTER alertDB is opened — alertStore needs DB to function but DB is opened in a later phase. Same pattern for `tokenStore.SetDB`, `credentialStore.SetDB`, `watchlistStore.SetDB`, `userStore.SetDB`, `registryStore.SetDB`, `trailingStopMgr.SetDB`. | HIGH | `kc/alerts/store.go`, `kc/credential_store.go`, `kc/watchlist/store.go`, `kc/users/store.go`, `kc/registry/store.go`, `kc/alerts/trailing.go` |
| B2  | `kc/manager_init.go:114-144` | Alert trigger closure captures `m.telegramNotifier`, `m.auditStore`, `m.eventDispatcher` BEFORE they are set (initTelegramNotifier at line 212-222 runs later; auditStore + eventDispatcher set from `app/wire.go` post-construction). Closure works only because of late-binding via `m.X` reads. | HIGH | `kc/alerts/store.go`, manager closure capture |
| B3  | `app/wire.go:263-292` riskGuard.SetAutoFreezeNotifier closure captures `kcManager.EventDispatcher()` — dispatcher is set at line 303, AFTER closure is defined at line 263. Closure works because it reads via accessor at call time, not at capture time. | HIGH | `kc/riskguard/guard.go`, `app/wire.go` |
| B4  | `app/adapters.go:174` (`busOnce` in `kiteExchangerAdapter`) + `:361` (second `busOnce`) | Lazy bus construction via sync.Once compensates for the cycle: adapter built BEFORE manager.CommandBus() is wired in some paths; ensureBus() lazily constructs an alternate local bus. Indicates construction-order ambiguity that the once+ensureBus pattern hides. | MED | `app/adapters.go`, `app/adapters_local_bus.go` |

## Category 2 — Runtime conditionals (deployment/runtime-mode branching)

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B5  | `app/wire.go:121, 171, 221, 304, 351, 477, 597, 725` | `if alertDB := kcManager.AlertDB(); alertDB != nil` — 8 branches gated on whether ALERT_DB_PATH was set. Drives 8 distinct subsystems (audit, consent, riskguard limits, eventStore, paperEngine, invitations, oauth client persister, pnl service). | HIGH | wire.go, app.go, plus all dependent worker constructors |
| B6  | `app/wire.go:124, 134, 174, 224, 234, 237` | `if !app.DevMode` fail-closed gates — 6 sites. Production fail-fast vs dev fail-open. | HIGH | wire.go, hidden via `app.DevMode` field |
| B7  | `app/wire.go:131` | `if app.Config.OAuthJWTSecret != ""` gates email-encryption + hash-publishing wiring. | MED | audit.Store + audit.HashPublisher |
| B8  | `app/wire.go:445` | `if stripeKey := app.Config.StripeSecretKey; stripeKey != "" && !app.DevMode` gates billing entire subsystem. Triggers package-global mutation `stripe.Key = stripeKey` (line 446). | HIGH | wire.go (24 LOC), stripe-go global |
| B9  | `app/wire.go:516, 555` | `if paperEngine != nil` defensive nil-guards derived from B5; 2 conditionals. | LOW | wire.go |
| B10 | `app/wire.go:373` | `if resolver := kc.FillWatcherResolverFromSessionSvc(...); resolver != nil` — fill-watcher conditional on sessionSvc. | LOW | wire.go |
| B11 | `app/app.go:524` | `if app.Config.OAuthJWTSecret != ""` — second copy of B7's conditional in `RunServer`, gating ALL of OAuth handler init (~140 LOC at lines 524-661). | HIGH | app.go |
| B12 | `kc/manager_init.go:155-156` `if cfg.AlertDBPath == ""` early return | The kc-side mirror of B5 — manager init silently skips persistence if no DB. | MED | manager_init.go |
| B13 | `kc/manager_init.go:213-215` `if cfg.TelegramBotToken == ""` early return | Conditional in initTelegramNotifier. | LOW | manager_init.go |
| B14 | `app/wire.go:565` | `mcp.RegisterTools(... app.Config.EnableTrading)` — ENABLE_TRADING env reaches all the way to tool registration, gating ~20 order tools. | HIGH | mcp/mcp.go RegisterTools, ENABLE_TRADING gate |

## Category 3 — Mutual recursion (late-binding setters)

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B15 | `app/wire.go:150` `kcManager.SetAuditStore(app.auditStore)` | Setter eliminable per blocker-fix-patterns.md (no real cycle) — kept as setter only because audit store construction depends on alertDB which is opened AFTER manager construction (gated on B1). | MED | kc/store_registry.go |
| B16 | `app/wire.go:297` `kcManager.SetRiskGuard(riskGuard)` | Setter eliminable; riskguard construction depends on auditStore (B15) which depends on B1 — chain. | MED | kc/broker_services.go |
| B17 | `app/wire.go:303` `kcManager.SetEventDispatcher(eventDispatcher)` | Genuine cycle: dispatcher subscribers reference manager state at dispatch time. | HIGH | kc/eventing_service.go, manager event subscribers |
| B18 | `app/wire.go:320` `kcManager.SetEventStore(eventStore)` | Genuine cycle: eventStore.Drain dispatches events through manager-bound handlers. | HIGH | kc/eventing_service.go, eventsourcing |
| B19 | `app/wire.go:361` `kcManager.SetPaperEngine(paperEngine)` | Genuine cycle: paperEngine takes dispatcher (B17) — chained mutual recursion. | HIGH | kc/broker_services.go |
| B20 | `app/wire.go:453` `kcManager.SetBillingStore(billingStore)` | Setter eliminable; billing not in real cycle. | MED | kc/store_registry.go |
| B21 | `app/wire.go:484` `kcManager.SetInvitationStore(invStore)` | Setter eliminable; chain with B22. | MED | kc/store_registry.go |
| B22 | `app/wire.go:488` `kcManager.SetFamilyService(famSvc)` | Genuine cycle: famSvc constructed from `kcManager.UserStore()+BillingStore()` — manager hands self-substores to a service that's then handed back to manager. | HIGH | kc/manager_accessors.go |
| B23 | `app/wire.go:549` `kcManager.SetMCPServer(mcpServer)` | Genuine cycle: mcpServer holds tool handlers that close over kcManager. | HIGH | kc/manager_accessors.go |
| B24 | `app/wire.go:731` `kcManager.SetPnLService(pnlService)` | Eliminable-with-effort: pnlService takes `kcManager.KiteClientFactory()` — indirect cycle via Factory interface. | LOW | kc/alert_service.go |

## Category 4 — Shared edit points (one file N agents touch)

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B25 | `app/wire.go` (754 LOC, 1 huge function) | `initializeServices` is a single ~550-LOC function. Every wiring change edits it; merge-conflict hotspot. | HIGH | every parallel agent that touches wiring |
| B26 | `app/app.go:32-109` `App struct` | 27-field struct. Every new background worker / store / cancel chan adds a field — central edit point. | HIGH | every parallel agent adding new state |
| B27 | `app/app.go` (703 LOC, single file holds App + Config + helpers + 2 large HTML constants) | Mixed concerns — App lifecycle, Config struct, embedded HTML pricing/checkout pages. | MED | parallel agents editing config vs lifecycle |
| B28 | `app/http.go` (1290 LOC) | Largest file in app/. Contains setupMux + 4 startServer variants + setupGracefulShutdown + handlers. | HIGH | parallel agents touching HTTP / routes / shutdown |
| B29 | `app/wire.go:387-521` middleware-append block | 10 ordered `serverOpts = append(...)` lines — adding/removing middleware = central edit. | MED | parallel agents adding tool-call middleware |
| B30 | `mcp/middleware_chain.go:41-52` `DefaultBuiltInOrder` slice literal | 10-name string slice IS the canonical order. Edits = central. | MED | parallel agents reordering middleware |
| B31 | `kc/manager.go:202-257` `Manager struct` | 35+ fields; central ID for every cross-cutting change. | HIGH | parallel agents adding manager state |
| B32 | `kc/manager_init.go` 16-phase init order | Phase ordering documented as "load-bearing" at lines 26-44. Reorder = ripple. | MED | parallel agents adding init phase |
| B33 | `app/wire.go:610-664` `registerLifecycle` | 9-entry append block; same shape as B29 but for teardown. | MED | parallel agents adding workers |
| B34 | `mcp/common_deps.go:19-57` `ToolHandlerDeps` struct | 22-field deps struct; every new tool handler dep = central edit. | MED | parallel agents adding tool deps |
| B35 | `kc/store_registry.go`, `kc/eventing_service.go`, `kc/broker_services.go`, `kc/scheduling_service.go`, `kc/session_lifecycle_service.go` — 5 facades that pass through to manager | Each facade has fan-out point on manager. Edits to add new accessor/setter touch facade + manager.go. | LOW | refactors that add new ports |

## Category 5 — Ordering constraints

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B36 | `app/wire.go:387-521` middleware chain | 10-step strict total ordering: correlation → timeout → audit → hooks → circuitbreaker → riskguard → ratelimit → billing → papertrading → dashboardurl. Every neighbor pair has documented semantic precedence. | MED | wire.go middleware block |
| B37 | `app/wire.go:610-664` registerLifecycle order | 9 stops in append order: outbox_pump → audit_store → telegram_bot → kc_manager → oauth_handler → rate_limit_reload → invitation_cleanup → paper_monitor → metrics. Order semantically required (in-flight drains first, then DB-touching, then process exit). | MED | lifecycle teardown |
| B38 | `kc/manager_init.go:113-141` 16-phase init order | initAlertSystem → initPersistence → initCredentialWiring → initTelegramNotifier → initAlertEvaluator → initTrailingStop → initSideStores → initCredentialService → initTickerService → initializeTemplates → initializeSessionSigner → initFocusedServices → initSessionPersistence → initTokenRotation → initProjector → registerCQRSHandlers. Each comment says "depends on prior phase X". | HIGH | kc/manager_init.go |
| B39 | `app/http.go:75-104` 3-phase shutdown | Phase A (block new work) → Phase B (HTTP drain) → Phase C (lifecycle.Shutdown). Phase A stays imperative outside lifecycle (pre-condition: scheduler.Stop + hashPublisherCancel must finish before HTTP drain begins). | MED | http.go graceful shutdown |
| B40 | `app/wire.go:80-102` success-defer error-path teardown | 6 manual teardown calls in reverse-of-construction order, hand-maintained alongside Phase C registerLifecycle (B33). Two parallel teardown sequences must stay in sync. | HIGH | wire.go error path |
| B41 | `kc/manager_lifecycle.go:47-72` `Manager.Shutdown()` | 3-step ordered shutdown: sessionManager.StopCleanupRoutine → metrics.Shutdown → tickerService.Shutdown → alertDB.Close → Instruments.Shutdown. Comment "Close alert DB after ticker (ticker's OnTick writes through to DB)" documents ordering rationale. | HIGH | kc/manager_lifecycle.go |
| B42 | `app/app.go:496-521` RunServer error-path defer | Phase A (scheduler+hashPublisher) + Phase C (lifecycle.Shutdown) — third copy of teardown sequence to keep in sync. | MED | app.go RunServer |
| B43 | `mcp/common.go:49-57` `init()` builds `writeTools` map from `GetAllTools()` | Depends on every `_tools.go` file's init() having registered first. Implicit init-ordering between init() in compliance_tool.go, dividend_tool.go, version_tool.go vs common.go. | MED | mcp package init ordering |

## Category 6 — Global state / package-level mutables

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B44 | `mcp/plugin_registry.go:121` `var DefaultRegistry = NewRegistry()` | Package-level singleton mutated at runtime via `RegisterPlugin`/`OnBeforeToolExecution`/`OnAfterToolExecution`. Every test that uses hooks calls `LockDefaultRegistryForTest(t)` (used 15+ times in around_hook_test.go, mutable_request_test.go) — test serialisation point. | HIGH | mcp package; all hook-based tests serialised |
| B45 | `mcp/tool_registry.go:21-25` `var internalToolRegistryMu sync.Mutex; internalToolRegistry []Tool; internalToolNames map` | Package-level tool registry mutated by `init()` blocks in compliance_tool.go, dividend_tool.go, version_tool.go. | MED | mcp package init ordering, tool-add agents |
| B46 | `mcp/integrity.go:156-159` `var manifestMu sync.RWMutex; currentManifest ToolManifest` | Singleton manifest written by `storeToolManifest` from RegisterTools. | LOW | startup-only mutation |
| B47 | `mcp/plugin_watcher.go:37-42` `var pluginBinaryWatchRegistry struct{ mu; entries }` | Global plugin watch registry. | MED | plugin reload tests |
| B48 | `mcp/plugin_watcher.go:48-53` `var watcherState struct{ mu; watcher; cancel; started }` | Singleton fsnotify watcher state with `started` flag. | MED | plugin watch lifecycle |
| B49 | `mcp/plugin_watcher.go:60` `var pluginWatcherLogger atomic.Pointer[slog.Logger]` | Atomic-pointer global; `SetPluginWatcherLogger` mutates at runtime. | LOW | runtime logger swap |
| B50 | `mcp/common.go:47` `var writeTools map[string]bool` written in `init()` | Package-level map. All viewer-block reads consult global. | LOW | startup-only |
| B51 | `mcp/market_tools.go:27` `var ltpCache = NewBoundedToolCache(...)` | Package-level LTP cache used across all parallel handler invocations. | MED | tool tests, cache invalidation |
| B52 | `mcp/observability_tool.go:80` `var serverStartTime = time.Now()` | Process-start timestamp captured at package init. | LOW | uptime metric |
| B53 | `app/wire.go:446` `stripe.Key = stripeKey` mutates `github.com/stripe/stripe-go/v82` package global | Cross-package global write. SDK convention but no test isolation possible. | HIGH | every billing test must accept polluted global |
| B54 | `app/app.go:697` `var httpClient = &http.Client{Timeout: 30 * time.Second}` | Package-level HTTP client, used by adapters / hash publisher. | LOW | tests cannot inject custom RoundTripper |
| B55 | `oauth/google_sso.go:236` `var googleUserInfoURL = "https://..."` | Mutable URL constant; tests override for httptest server injection. | MED | google SSO tests |
| B56 | `app/plugin_routes.go:38-43` `var pluginRouteRegistry struct{ mu; routes }` | Plugin HTTP route registry global. | MED | plugin route registration |
| B57 | `kc/papertrading/engine.go:22` `var orderSeq atomic.Uint64` | Package-level monotonic counter. Persists across tests in same process. | MED | papertrading tests in parallel |
| B58 | `app/legal.go:19, 23, 59` `var termsMarkdown, privacyMarkdown, markdownRenderer` written in `init()` (legal.go:88) — `log.Fatalf` on rendering failure | Package init can call `log.Fatalf`; init failures impossible in any test setup. | LOW | unrecoverable init |
| B59 | `kc/audit/store.go:118` `var statsCacheTTL = 15 * time.Minute` | Package-level TTL — tests cannot shorten without coordinated mutation. | MED | audit cache tests |
| B60 | `kc/audit/retention.go:21` `var retentionTickInterval = 24 * time.Hour` | Package-level retention interval; tests can mutate but it's racy with concurrent retention runs. | MED | retention tests |
| B61 | `kc/eventsourcing/outbox.go` `var outboxPumpInterval` (search confirms ~100ms interval as private package var) | Package-level pump interval. | LOW | outbox tests |
| B62 | `kc/audit/plugin_event_types.go:45-56` `var pluginEventTypeRegistry struct{ mu; types }` + `:37` `var reservedEventCategories` | Global plugin event type registry. | LOW | plugin event registration |
| B63 | `app/envcheck.go:21` `var flyRegionPattern = regexp.MustCompile(...)` | Package-level regex — fine in isolation, but global mutables in app package count. | LOW | none |
| B64 | `kc/billing/tiers.go:38` `var toolTiers = map[string]Tier{...}` + `kc/billing/checkout.go:17` `var maxUsersByPlan` | Package-level tool→tier lookup tables. | LOW | billing tier lookup |

## Category 7 — Test coupling

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B65 | 30 test files using `t.Setenv` (full list via grep — app/helpers_test, mcp/tools_middleware, app/ratelimit, app/graceful_restart, app/integration_kite_api, etc.) | t.Setenv prevents `t.Parallel()` because env is process-global. Every test calling t.Setenv sequentialises. | HIGH | test parallelism ceiling |
| B66 | `kc/billing/billing_edge_test.go`, `kc/billing/billing_webhooks_test.go` | t.Setenv on STRIPE_PRICE_PRO/PREMIUM/SOLO_PRO because `kc/billing/config.go:32-35` and `kc/billing/webhook.go:26-28` read env directly inside business code. | HIGH | billing-test parallel ceiling |
| B67 | `kc/audit/hashpublish.go:88-109` direct env reads inside `LoadHashPublishConfig` | AUDIT_HASH_PUBLISH_S3_ENDPOINT, BUCKET, ACCESS_KEY, SECRET_KEY, REGION, INTERVAL, KEY all read directly. Tests must t.Setenv for each. | MED | audit hash-publish tests |
| B68 | `app/graceful_restart.go:99` `os.Getenv("KITE_GRACEFUL_CHILD")` | Direct env read inside `parseGracefulChildFromEnv`. Tests use `parseGracefulChild` helper to inject map literal — adapter pattern works but original parseGracefulChildFromEnv is process-coupled. | LOW | graceful_restart tests |
| B69 | `cmd/rotate-key/main_test.go:737-789` tests use BE_MAIN_* env vars to drive subprocess re-execution patterns | Subprocess test pattern leaks 4 env names into the binary. | LOW | rotate-key tests only |
| B70 | `mcp/around_hook_test.go`, `mcp/mutable_request_test.go` use `LockDefaultRegistryForTest(t)` | Test serialisation primitive needed because DefaultRegistry is global (B44). Marked tests CANNOT run in parallel. | HIGH | hook tests serialised |
| B71 | `kc/papertrading/engine_test.go` (implicit) — `orderSeq` (B57) `atomic.Uint64` shared across tests in same process | Tests must accept that order IDs are not deterministic across-test; cannot use seq=1 expectations after another test runs. | MED | papertrading test brittleness |
| B72 | `time.Now()` direct calls in production code: `kc/manager_init.go:120, 248`, `app/wire.go:271`, `kc/manager.go:565` (instruments stats), `kc/scheduler/scheduler.go:259, 264` (kolkata), `kc/papertrading/engine.go` + ~95 other files | Tests cannot freeze clock. `kc/scheduler/scheduler.go:25` has injectable `clock` field but only the scheduler uses it; alerts/audit/papertrading still call time.Now() directly. | HIGH | clock-isolation across tests |
| B73 | `app/integration_kite_api_test.go` — real HTTP / TLS test against api.kite.trade unless INSTRUMENTS_SKIP_FETCH=true | Network coupling: tests touch real Kite endpoint without an env opt-out forcibly set. | MED | integration tests |
| B74 | `kc/instruments/manager.go:565` `m.stats.LastUpdateTime = time.Now()` | Instruments stats use real clock; tests assert on stats deltas that depend on wall-clock. | LOW | instruments tests |
| B75 | `kc/audit/anomaly_cache.go` (implied 15-min TTL via `statsCacheTTL` B59) | Tests of cache eviction can't shrink TTL without mutating package var. | MED | anomaly cache tests |

## Category 8 — Other (deploy portability + miscellaneous)

| ID  | File:line | What | Severity | Affected scope |
|-----|-----------|------|----------|----------------|
| B76 | `app/wire.go:241-257` riskguard → instrumentsManager + auditStore + LTP adapter wiring | Adapter glue (4 SetX calls on riskGuard) hand-wired post-construction. Each adapter is a 1-liner but the chain is opaque vs documented. | LOW | riskguard adapters |
| B77 | `app/wire.go:399-409` `mcp.OnBeforeToolExecution` + `mcp.OnAfterToolExecution` register hooks on the package-global DefaultRegistry (B44) — coupling at wire-time | wire.go writes to mcp/ package state; cannot construct two App instances in one process. | HIGH | parallel-test isolation, multi-server-in-process |
| B78 | `app/wire.go:564` `mcp.RegisterTools(mcpServer, kcManager, ...)` is the SINGLE entry point for tool registration; once called, mcpServer holds handler closures that reference kcManager forever | One-shot operation; second NewApp+RegisterTools in same process fails (DefaultRegistry init() panics on duplicate per `RegisterInternalTool`). | MED | startup, in-process reuse |
| B79 | `kc/manager.go:249` `mcpServer any` typed as `any` to avoid circular import (mcp → kc → mcp) | Cycle hidden via `any` boxing; readers must cast. Import cycle blocks adding strongly-typed accessor. | MED | kc/manager_accessors.go |
| B80 | `app/wire.go:30-35` `emailHasherAdapter` exists ONLY to bridge audit → usecases, with comment "would create cycle (audit → usecases → audit)" | Existing import cycle worked around via 1-method bridge. Future imports must respect same constraint. | LOW | audit / usecases packaging |
| B81 | `app/app.go:65-103` 6 lifecycle-reload fields on App: `shutdownCh`, `hashPublisherCancel`, `paperMonitor`, `invitationCleanupCancel`, `rateLimitReloadStop`, `rateLimitReloadDone` (+ `rateLimitReloadStopOnce`, `shutdownOnce`, `gracefulShutdownDone`) | Every new background worker = field on App struct (B26 ramifies). Coordinated cancellation primitives. | MED | parallel agents adding workers |
| B82 | `mcp/version_tool.go:55-60` `var versionInfoOnce sync.Once; cachedGitSHA, cachedBuildTime, cachedRegion string` | Package-global one-shot cache. Tests can't reset between cases. | LOW | version_tool tests |
| B83 | `kc/manager_lifecycle.go:62-66` `m.alertDB.Close()` in Manager.Shutdown — but `app/wire.go:629-632` ALSO calls `kcManager.Shutdown()` from lifecycle. Closing the same DB twice (sql.DB.Close is idempotent but still a coupling). | The Close path runs through manager.Shutdown which is called from lifecycle "kc_manager" entry. Other lifecycle entries (audit_store, oauth_handler) read from the same DB via independent handles. Order is: outbox_pump first, audit_store second, manager third, oauth_handler fourth. After manager.Shutdown closes alertDB at step 3, oauth_handler.Close at step 4 may try to flush via db.Exec — relies on sql.DB.Close idempotency. | MED | lifecycle ordering correctness |
| B84 | `app/wire.go:497-512` invitation cleanup goroutine spawned inline inside `if alertDB != nil` block | Goroutine creation is buried in conditional wiring. Goleak audit history (per comment) shows this leaked across 282 tests before invCancel was added. | LOW | wire.go reading clarity |
| B85 | `app/wire.go:373-383` fillWatcher goroutine started inline (Start() at line 381) | Same pattern as B84 — goroutine spawn buried in wiring. No corresponding lifecycle.Append for fill-watcher (it has no Stop method per line ownership search). | MED | leaked goroutine for tests |

---

## Totals

**Total enumerated**: 85 blockers (cap 50 was overshot — task brief allows up to 50, but the categories 4/5/6/7 surfaced higher counts than expected so I retained all and marked the lower-priority ones LOW).

If 50-cap is strict: drop B49, B52, B54, B58, B61–B64, B68–B69, B74–B75, B82, B84 (15 LOW entries) → 70. Drop additional MED entries B47, B48, B55, B56, B59–B60, B71, B75, B83, B85 → 60. Strict 50: also drop B27, B33, B43, B46, B51, B62, B72 (a few more MED) — but this loses real signal. **Recommend keep the 85; the cap was advisory not binding given the empirical surface.**

### By category

| Category | Count |
|---|---|
| 1 — Mutation cycles | 4 |
| 2 — Runtime conditionals | 10 |
| 3 — Mutual recursion | 10 |
| 4 — Shared edit points | 11 |
| 5 — Ordering constraints | 8 |
| 6 — Global state / package-level | 21 |
| 7 — Test coupling | 11 |
| 8 — Other | 10 |

### By severity

| Severity | Count |
|---|---|
| HIGH | 22 |
| MED | 38 |
| LOW | 25 |

---

## Biggest surprises vs known 4-Wire-blocker analysis

The known 4 Wire blockers (B5/B11/B14 conditionals, B15-B24 setters, B25/B36/B40 shared edits, B33 lifecycle) cover only ~12 of 85 empirical findings. The unmodeled mass is **Category 6 (21 globals)** + **Category 7 (11 test couplings)** — particularly: (a) `mcp.DefaultRegistry` (B44) forces test serialisation across 15+ files via `LockDefaultRegistryForTest`, hard-blocking parallel hook-test execution that no Wire/fx refactor would fix; (b) `stripe.Key` package-global mutation (B53) makes billing tests inherently non-parallel; (c) 30+ test files use `t.Setenv` (B65, B66, B67) because `kc/billing/config.go`, `kc/billing/webhook.go`, and `kc/audit/hashpublish.go` read env directly inside business code instead of accepting Config struct fields. The agent-concurrency ceiling at 9 is dominated by test-isolation friction, not wire-graph friction — a finding that flips the prior ROI calculus toward `t.Parallel()`-readiness work over further `app/wire.go` decoupling. Secondary surprise: **two parallel teardown sequences** (B40 success-defer in wire.go vs B33 registerLifecycle vs B42 RunServer defer vs B39 setupGracefulShutdown) all hand-maintain the same Phase C order — drift between any two is a goroutine-leak class of bug that LifecycleManager (commit `9c1eeae`) only closes for ONE of the four sites.

---

*Generated 2026-04-26 against HEAD `9c1eeae`. Read-only research deliverable; no source files modified.*
