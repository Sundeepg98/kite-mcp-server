# Manager decomposition — Round 2

## Goal
Continue the Round 1 decomposition (Task #7: 95 → 55) by pulling more focused
services out of `kc/manager.go`. Target: <45 methods in manager.go itself.

## Trajectory

| Round | File                 | Methods | Δ    |
|-------|----------------------|---------|------|
| 0     | kc/manager.go        | 95      | —    |
| 1     | kc/manager.go        | 55      | −40  | (Task #7: StoreRegistry + EventingService + BrokerServices)
| 2a    | kc/manager.go        | 38      | −17  | (Task #14: SchedulingService + SessionLifecycleService extracted by another teammate)
| 2b    | kc/manager.go        | **34**  | −4   | (this session: callback handler extracted)

Final: **34 methods in kc/manager.go** — comfortably under the <45 target.

## Round 2b: callback handler extraction

### Motivation
Four tightly-coupled methods implemented the `/callback` HTTP handler flow:
- `HandleKiteCallback` — public entry point, returns an `http.HandlerFunc`
- `handleCallbackError` — private: logs + `http.Error`
- `extractCallbackParams` — private: parses + verifies signed session ID
- `renderSuccessTemplate` — private: renders `login_success.html`

Plus one tiny local type (`TemplateData`) used only by `renderSuccessTemplate`.

Together they represent a cohesive HTTP endpoint and were the last remaining
"HTTP handler on the Manager" responsibility. Everything else in manager.go is
either config getters, service accessors, or lifecycle (New/Shutdown).

### What moved
New file: `kc/callback_handler.go` (85 LOC). All 4 methods moved verbatim, plus
the `TemplateData` struct. Signatures unchanged — still methods on `*Manager`,
so all 12+ test callsites and the `app/http.go` wiring continue to work
unchanged.

### What stayed in manager.go
- Package-level constants `indexTemplate`, `missingParamsMessage`,
  `sessionErrorMessage`, `templateNotFoundError` (they live in a `const (...)`
  block with other manager-wide constants — moving them would be churn).
- `setupTemplates()` (package function, loaded once at Manager init, not
  callback-specific enough to justify extraction).

### Import cleanup
After the move, `net/http` became unused in manager.go and was removed. All
other imports (`errors`, `fmt`, `html/template`, `log/slog`, `net/url`,
`os/exec`, `runtime`, `time`, kiteconnect, models, metrics, broker, alerts,
audit, billing, domain, eventsourcing, instruments, papertrading, registry,
riskguard, templates, ticker, users, watchlist) verified still in use.

## Full decomposed-file inventory

| File                         | LOC | Role                                              |
|------------------------------|-----|---------------------------------------------------|
| kc/manager.go                | 800 | Config, New, struct def, Shutdown, core getters   |
| kc/store_registry.go         | 180 | 22 store accessors + setters (Round 1)            |
| kc/broker_services.go        | 133 | KiteClientFactory, Instruments, Ticker, Paper, RiskGuard (Round 1) |
| kc/scheduling_service.go     |  99 | cleanup routines, metrics recording (Round 2 teammate) |
| kc/callback_handler.go       |  85 | HTTP callback flow (this session)                 |
| kc/eventing_service.go       |  49 | EventDispatcher + EventStore (Round 1)            |

Total facade LOC: 546. Manager.go LOC: 800 (was 1199 after Round 1, was 1033+ before any decomposition — the shrinkage tracks method removal almost 1:1).

## Verification

```
$ grep -c "^func (m \*Manager)" kc/manager.go
34   # target was <45, achieved 34

$ go vet ./kc
(clean, exit 0)

$ gofmt -e -l kc/manager.go kc/callback_handler.go
(empty — syntax clean)
```

Full-module build cannot be run to completion right now because of concurrent
in-progress work in `kc/ops/` (task #16 dashboard_templates split) and
`app/` which transitively imports oauth (task #15 just completed, but other
build artifacts may still be settling). The kc root package itself vets clean.

## Method distribution after round 2b (34 methods in kc/manager.go)

Grouped by logical role:

**Service accessors (7)**: CredentialSvc, SessionSvc, PortfolioSvc, OrderSvc,
AlertSvc, FamilyService, SetFamilyService.

**Session accessors (4)**: SessionManager, ManagedSessionSvc, SessionSigner,
UpdateSessionSignerExpiry.

**Config getters (6)**: IsLocalMode, ExternalURL, AdminSecretPath, DevMode,
APIKey, HasPreAuth.

**Credential-state delegators to CredentialService (7)**: HasCachedToken,
HasGlobalCredentials, IsTokenValid, HasUserCredentials, GetAPIKeyForEmail,
GetAPISecretForEmail, GetAccessTokenForEmail.

**Alert delegators (4)**: TelegramNotifier, TrailingStopManager, PnLService,
SetPnLService.

**MCP server ref (2)**: SetMCPServer, MCPServer.

**Utility (2)**: OpenBrowser, Shutdown.

**Initialization (2, unexported)**: initializeTemplates, initializeSessionSigner.

These 34 are almost all either (a) thin accessors to decomposed services or
(b) core lifecycle (New/Shutdown) or (c) config getters. Further extraction
would be aesthetic rather than architectural — the "god object" shape is
gone. Any further pulls should be driven by a specific pain point
(e.g. introducing a `ConfigProvider` only if two services start needing
the same three getters).

## Notes

- This work was done on top of task #14, which was marked in-progress by
  another teammate and then completed during this session (SchedulingService
  and SessionLifecycleService already wired when I picked up the deeper-work
  directive).
- No test files touched. All 12+ tests of `HandleKiteCallback` across
  manager_test.go, manager_edge_test.go, service_test.go, session_edge_test.go
  continue to call `m.HandleKiteCallback()` unchanged because the method is
  still on `*Manager` — just defined in a different file.
- `kc/manager.go` LOC dropped from 991 (post-Round-1) to 800 in this session.
