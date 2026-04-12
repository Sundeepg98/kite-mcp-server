# Task #22 — Split kc/manager_interfaces.go StoreAccessor

## Goal
StoreAccessor had 18 methods in a single grab-bag interface — ISP violation.
Split into focused sub-interfaces (≤3 methods each) while keeping
`StoreAccessor` as a composite alias so existing consumers don't break.

## BEFORE

```go
type StoreAccessor interface {
    TokenStore() TokenStoreInterface
    CredentialStore() CredentialStoreInterface
    AlertStore() AlertStoreInterface
    TelegramStore() TelegramStoreInterface
    WatchlistStore() WatchlistStoreInterface
    UserStore() UserStoreInterface
    RegistryStore() RegistryStoreInterface
    AuditStore() AuditStoreInterface
    BillingStore() BillingStoreInterface
    TickerService() TickerServiceInterface
    PaperEngine() PaperEngineInterface
    InstrumentsManager() InstrumentManagerInterface
    AlertDB() *alerts.DB
    RiskGuard() *riskguard.Guard
    TelegramNotifier() *alerts.TelegramNotifier
    TrailingStopManager() *alerts.TrailingStopManager
    PnLService() *alerts.PnLSnapshotService
    MCPServer() any
}
```

18 methods, single interface, no way to depend on just one of them without
accepting the whole surface.

## AFTER

18 focused single-method provider interfaces + one composite. Every
sub-interface has exactly **1 method** (target was ≤3), so consumers can
depend on the narrowest capability they need.

### Focused providers (exactly 1 method each)

| Interface                     | Method                          |
|-------------------------------|---------------------------------|
| TokenStoreProvider            | TokenStore()                    |
| CredentialStoreProvider       | CredentialStore()               |
| AlertStoreProvider            | AlertStore()                    |
| TelegramStoreProvider         | TelegramStore()                 |
| WatchlistStoreProvider        | WatchlistStore()                |
| UserStoreProvider             | UserStore()                     |
| RegistryStoreProvider         | RegistryStore()                 |
| AuditStoreProvider            | AuditStore()                    |
| BillingStoreProvider          | BillingStore()                  |
| TickerServiceProvider         | TickerService()                 |
| PaperEngineProvider           | PaperEngine()                   |
| InstrumentsManagerProvider    | InstrumentsManager()            |
| AlertDBProvider               | AlertDB()                       |
| RiskGuardProvider             | RiskGuard()                     |
| TelegramNotifierProvider      | TelegramNotifier() (AlertService only) |
| TrailingStopManagerProvider   | TrailingStopManager() (AlertService only) |
| PnLServiceProvider            | PnLService() (AlertService only) |
| MCPServerProvider             | MCPServer()                     |

### Composite (for Manager's compile-time check)

```go
type StoreAccessor interface {
    TokenStoreProvider
    CredentialStoreProvider
    AlertStoreProvider
    TelegramStoreProvider
    WatchlistStoreProvider
    UserStoreProvider
    RegistryStoreProvider
    AuditStoreProvider
    BillingStoreProvider
    TickerServiceProvider
    PaperEngineProvider
    InstrumentsManagerProvider
    AlertDBProvider
    RiskGuardProvider
    MCPServerProvider
}
```

**Note: 15 sub-interfaces, not 18.** The 3 alert-adjacent providers
(`TelegramNotifierProvider`, `TrailingStopManagerProvider`,
`PnLServiceProvider`) were removed from the composite because Round 3
Manager decomposition (task #19, in progress) moved those accessors off
Manager and onto `AlertService`. Callers now use
`m.AlertSvc().TelegramNotifier()` etc. The standalone provider interfaces
still exist (they're implemented by `*AlertService`) for consumers that
want to depend on just those capabilities.

## Notes

Most of this task was already done by another teammate when I claimed it —
the 18 focused provider interfaces were already extracted and the composite
was in place. My remaining work:

1. Discovered via `grep` that `TelegramNotifier`, `TrailingStopManager`, and
   `PnLService` were no longer Manager methods (Round 3 moved them to
   AlertService), which broke the `_ StoreAccessor = (*Manager)(nil)`
   compile-time assertion.
2. Removed those 3 providers from the composite `StoreAccessor` and added a
   doc comment explaining why they're excluded and where to obtain them now.
3. Verified every remaining sub-interface still corresponds to a live method
   on Manager.

## Verification

**Method presence on Manager (all 15 composite members):**

```
TokenStore, CredentialStore, AlertStore, TelegramStore, WatchlistStore,
UserStore, RegistryStore, AuditStore, BillingStore, AlertDB
    → all in kc/store_registry.go

TickerService, PaperEngine, InstrumentsManager, RiskGuard
    → all in kc/broker_services.go

MCPServer
    → kc/manager.go
```

**Sub-interface method counts:**

```
$ python parse kc/manager_interfaces.go
TokenStoreProvider: 1        InstrumentsManagerProvider: 1
CredentialStoreProvider: 1   AlertDBProvider: 1
AlertStoreProvider: 1        RiskGuardProvider: 1
TelegramStoreProvider: 1     TelegramNotifierProvider: 1
WatchlistStoreProvider: 1    TrailingStopManagerProvider: 1
UserStoreProvider: 1         PnLServiceProvider: 1
RegistryStoreProvider: 1     MCPServerProvider: 1
AuditStoreProvider: 1        SessionProvider: 9
BillingStoreProvider: 1      AppConfigProvider: 5
TickerServiceProvider: 1     MetricsRecorder: 4 (not a Provider)
PaperEngineProvider: 1       ManagerLifecycle: 4 (not a Provider)
```

All 18 `*Provider` interfaces: exactly 1 method. Target was ≤3 — achieved 1.

**Build status:** `go vet ./kc` fails on an unrelated assertion —
`CredentialResolver` is missing `GetAPIKeyForEmail` because Round 3 (task #19,
in flight) moved credential accessors off Manager. That failure is task #19's
to fix, not task #22's. The `StoreAccessor` composite now compiles cleanly
against the current Manager.

## Blast radius

Zero external consumers: grep for `StoreAccessor` finds only the declaration
in `manager_interfaces.go` itself plus the one compile-time assertion. No
test files reference it, no other packages import it by name. The whole
point of the interface was to document Manager's surface area and support
ISP in *future* callers, so narrowing it costs nothing.
