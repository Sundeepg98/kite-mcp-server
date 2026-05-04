# Redundancy Audit — kite-mcp-server (master HEAD `61da394`)

**Method:** Empirical grep + code-read. Read-only. Excludes in-flight C-path packages (`broker/ticker/*`, `broker/zerodha/ticker_adapter.go`, `kc/ticker/service.go`, `broker/conformance/*`, `broker.PortContract` callsites) per dispatch scope.

## Summary

- **Total findings: 8**
- **HIGH: 1**
- **MEDIUM: 5**
- **LOW: 2**

The dominant pattern is **Phase-B-or-later migration debt**: `kc/ports/*` was introduced as the bounded-context replacement for `kc/manager_interfaces.go:*Provider` and `kc/interfaces.go:*StoreInterface`, with 11 explicit `// Deprecated:` annotations marking the legacy declarations. Migration is in-flight but unfinished — both old and new contracts coexist on `*kc.Manager`. Net: most "redundancy" is *known* to maintainers, but it is real and creates a wide blast radius for any future broker/store-interface refactor.

## Findings

### F1. `kc/manager_interfaces.go *Provider` shadows `kc/ports/*` (HIGH)

- **Severity:** HIGH — blocks any clean refactor of broker/store ports; consumers split across two seams.
- **Class:** parallel-interface
- **Evidence:**
  - `kc/manager_interfaces.go:103` `AlertStoreProvider` — explicitly `// Deprecated: prefer ports.AlertPort` (and 5 more siblings: AlertDBProvider, TelegramNotifierProvider, TrailingStopManagerProvider, PnLServiceProvider, InstrumentsManagerProvider all marked Deprecated → ports.AlertPort/InstrumentPort)
  - `kc/manager_interfaces.go:18` `SessionProvider` — `// Deprecated: use ports.SessionPort`
  - `kc/manager_interfaces.go:55` `CredentialResolver` — `// Deprecated: use ports.CredentialPort`
  - `kc/ports/alert.go:23` `AlertPort` — comment line 22 confirms *"The five legacy provider types in kc/manager_interfaces.go stay as deprecated aliases until Phase B/D migrates remaining call sites"*
- **Recommendation:** Phase B/D as the maintainers planned — `grep -rE "AlertStoreProvider|AlertDBProvider|TelegramNotifierProvider|TrailingStopManagerProvider|PnLServiceProvider|InstrumentsManagerProvider|SessionProvider|CredentialResolver" --include='*.go'`, migrate each callsite to the corresponding `ports.*Port`, then delete the deprecated types from `kc/manager_interfaces.go`. Net loss: ~80 LOC + the StoreAccessor aggregate.
- **Acceptance:** zero callers of the 8 deprecated types remain; `kc/manager_interfaces.go` keeps only the still-active providers (the non-deprecated half).

### F2. `kc/interfaces.go` duplicates `kc/usecases/*.go` for User/Audit (MEDIUM)

- **Severity:** MEDIUM — same names declared in sibling packages create import-time confusion.
- **Class:** parallel-interface
- **Evidence:**
  - `kc/interfaces.go:193` `UserReader` — `List(), Get(email), Count()` — ALSO `kc/usecases/admin_usecases.go:17` `UserReader` — `List(), Get(email), Count()`. **Identical sigs, different declaration sites.**
  - `kc/interfaces.go:226` `UserWriter` ↔ `kc/usecases/admin_usecases.go:24` `UserWriter` — same shape (`UpdateStatus`, `UpdateRole`, `Create`)
  - `kc/interfaces.go:253` `UserAuthChecker` ↔ `kc/usecases/admin_usecases.go:31` `UserAuthChecker` — same single method `IsAdmin(email) bool`
  - `kc/interfaces.go:109` `AuditReader` ↔ `kc/usecases/observability_usecases.go:20` `AuditReader` — identical 3-method sig
  - `kc/interfaces.go:94` `AuditWriter` ↔ `kc/usecases/observability_usecases.go:28` `AuditWriter` — identical 2-method sig
- **Recommendation:** consolidate. The use-case-package copies exist because `kc/usecases/` cannot import `kc` (would create a cycle — usecases ← used by → kc/manager). Two clean fixes: (a) move the canonical declarations to a leaf package both can import (e.g. `kc/ports/user.go`, `kc/ports/audit.go`); (b) delete from `kc/interfaces.go` once `kc` itself only consumes via its own concrete types. Cost: ~3 hr including callsite update.
- **Acceptance:** `grep -nE "^type (UserReader|UserWriter|UserAuthChecker|AuditReader|AuditWriter) interface" --include='*.go'` returns ≤1 declaration per name.

### F3. `BrokerDataProvider` parallel-interface (already flagged at `61da394`) (MEDIUM)

- **Severity:** MEDIUM — confirmed; chain agent's existing finding.
- **Class:** parallel-interface
- **Evidence:**
  - `kc/alerts/briefing.go:24` `BrokerDataProvider` — 4 methods (GetHoldings/GetPositions/GetUserMargins/GetLTP) returning `kiteconnect.*` types
  - `broker/broker.go:443` `PortfolioReader` — same domain (holdings/positions/margins) but returns broker-port types (`broker.Holding`, `broker.Positions`, `broker.Margins`)
  - `kc/alerts/briefing.go:22-23` comment: *"abstracts broker API calls for testability"*
- **Recommendation:** noted in chain-agent's design doc. Migrate `BriefingService` to consume `broker.PortfolioReader` + add a thin LTP method (or use `broker.MarketDataReader`).
- **Acceptance:** `kc/alerts/briefing.go` no longer declares `BrokerDataProvider`; consumers receive `broker.Client` or composition.

### F4. Three `KiteClientFactory` interfaces with overlapping signatures (MEDIUM)

- **Severity:** MEDIUM — name collision across three packages on the same SDK seam.
- **Class:** parallel-interface
- **Evidence:**
  - `kc/kite_client.go:21` `KiteClientFactory` — 2 methods: `NewClient(apiKey)`, `NewClientWithToken(apiKey, accessToken)`
  - `kc/alerts/briefing.go:44` `KiteClientFactory` — 1 method: `NewClientWithToken(apiKey, accessToken)` (subset)
  - `kc/telegram/bot.go:37` `KiteClientFactory` — 2 methods (matches `kc/kite_client.go`)
  - Comment in `briefing.go:41-43`: *"mirrors kc.KiteClientFactory for briefing use"* — explicit acknowledgement
- **Recommendation:** declare the canonical version in `broker/zerodha/` (or a new `kc/sdkfactory/` leaf package), have all three sites consume it. The 1-method briefing-only variant is a structural-subtype concern — Go interface-satisfies-by-shape lets briefing accept the 2-method version even if it only uses one.
- **Acceptance:** one declaration; the three current callers all import from the canonical site.

### F5. `InstrumentLookup` name collision with divergent contracts (MEDIUM)

- **Severity:** MEDIUM — same name, **different** signatures — actively confusing.
- **Class:** parallel-interface
- **Evidence:**
  - `kc/usecases/place_order.go:35` `InstrumentLookup` — `Get(exchange, tradingsymbol) (lotSize int, tickSize float64, ok bool)` (lot/tick metadata)
  - `kc/telegram/bot.go:66` `InstrumentLookup` — `GetByID(id string) (instruments.Instrument, error)` (full struct lookup by token)
  - Adjacent: `kc/usecases/create_alert.go:24` `InstrumentResolver` — `GetInstrumentToken(exchange, tradingsymbol) (uint32, error)` — third instrument-lookup port with yet another shape
- **Recommendation:** rename for intent: `InstrumentMetaLookup` (for place_order's lot/tick), `InstrumentByIDLookup` (telegram), `SymbolToTokenResolver` (create_alert). Better still, declare all three on a single `kc/ports/instrument.go` if they share an underlying implementer (`instruments.Manager`). Reduces ISP fragmentation if callers actually need the union.
- **Acceptance:** `grep -nE "^type InstrumentLookup interface" --include='*.go'` returns ≤1 declaration.

### F6. OAuth client-store CQRS registration duplicated app↔kc (MEDIUM)

- **Severity:** MEDIUM — same registration shape in two files; intentional for test mode but high LOC.
- **Class:** code-clone
- **Evidence:**
  - `kc/manager_commands_oauth.go:90-125` registers `SaveOAuthClientCommand` + `DeleteOAuthClientCommand` with a `clientStore func() usecases.OAuthClientStore` factory (production)
  - `app/adapters_local_bus.go:145-178` registers the **same two commands** with a parallel factory (`localOAuthClientStore` instead of `oauthClientStoreAdapter`)
  - Comment line 175 in app/adapters_local_bus.go: *"local port adapters: mirror kc/manager_commands_oauth.go's adapters"*
- **Recommendation:** extract a single `RegisterOAuthClientHandlers(bus cqrs.CommandBus, store usecases.OAuthClientStore, logger *slog.Logger)` helper. Both call sites pass their respective store implementation. Cost: ~30 min + tests.
- **Acceptance:** the two call sites become 2-line invocations of the shared registrar.

### F7. `kc/aop/` reflection AOP package — gated by ADR but verify zero unintended callers (LOW)

- **Severity:** LOW — opt-in via ADR-0008 (decorator-option-4-go-reflection-aop).
- **Class:** dead-code (potentially) / multi-impl
- **Evidence:**
  - `kc/aop/aop.go:1-10` package comment: *"WARNING — non-idiomatic Go ... explicit anti-Go-idiom path established in .research/decorator-stack-shift-evaluation.md"*
  - Mentions ~100ns/intercepted-call cost; this is the alternative to the production decorator chain
- **Recommendation:** verify with `grep -rE "kc/aop\b" --include='*.go' | grep -vE "_test\.go"` that production code does NOT actually wire AOP advice (only tests/research probes do). If yes, the package is documentation-only and should be tagged `//go:build research` or explicitly carry "do not import in production" enforcement (a build-tag would let `go build ./...` of the production binary not even include it).
- **Acceptance:** either AOP has zero non-test callers and is tagged research-only, OR it has callers and the package comment is updated to explain when production should reach for it.

### F8. Multiple `newTestStore()` / `newTestManager()` helpers across packages (LOW)

- **Severity:** LOW — common in Go; each package owns its own seed.
- **Class:** test-helper-dup
- **Evidence:**
  - `kc/alerts/helpers_test.go:23` `newTestStore()`
  - `kc/billing/billing_test.go:26` `newTestStore()`
  - `kc/eventsourcing/store_test.go:21` `newTestStore(t)`
  - `kc/helpers_test.go:24` `newTestManagerWithDB(t)`
  - `app/helpers_test.go:159` `newTestManager(t)` + `:166` `newTestManagerWithDB(t)` + `:175` `newTestManagerWithInvitations(t)` + `:185` `newTestAuditStore`
  - `kc/alerts/trailing_test.go:37` `newTestManager(t)` (different return type)
- **Recommendation:** acceptable as-is for package-local helpers. Only if a future refactor shows ≥3 sites copy-pasting the SAME 30+ LOC seed, extract to `testutil/`. Not worth pre-emptive consolidation.
- **Acceptance:** revisit only when grep shows duplicate body content, not just duplicate names.

## Out-of-scope (already excluded per dispatch)

`broker/ticker/*` (commit 1), `broker/zerodha/ticker_adapter.go` (commit 2), `kc/ticker/service.go` swap (commit 3), `broker/conformance/*` (commit 4) — verified via `grep -rnE "type .*Ticker\b"` returning expected in-flight matches; not scored.

## Recommended sequence

1. **F1** (HIGH, ~3 hr) — finishes the existing Phase B/D port migration; clears `kc/manager_interfaces.go` deprecated half.
2. **F2** (~3 hr) — kills the User/Audit-interface name collision between `kc/interfaces.go` and `kc/usecases/`.
3. **F3 + F4** (~2 hr together) — local-broker-provider and KiteClientFactory consolidation.
4. **F5** (~1 hr) — rename for intent.
5. **F6** (~30 min) — extract shared OAuth-CQRS registrar.
6. **F7** (~15 min verify) — confirm AOP is research-only or document its production gate.
7. **F8** — defer; not actionable until a real LOC-duplication shows up.

Total budget: ~10 hr to retire all flagged redundancy. F1 is the highest-leverage and unblocks the cleaner shape that subsequent items inherit.
