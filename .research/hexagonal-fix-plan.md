# Hexagonal Architecture Fix Plan

## Implementation Status

### Completed
- **broker.Client interface extended** with 14 new methods: ConvertPosition, 7 MF operations, 3 margin operations
- **Broker-agnostic types added** to `broker/broker.go`: ConvertPositionParams, MFOrder, MFSIP, MFHolding, MFOrderParams, MFSIPParams, MFOrderResponse, MFSIPResponse, OrderMarginParam, OrderChargesParam, plus Factory/Authenticator interfaces
- **Zerodha adapter** implements all 14 new methods in `broker/zerodha/client.go` with conversions in `broker/zerodha/convert.go`
- **Broker Factory + Authenticator** created at `broker/zerodha/factory.go` (Factory, Auth types with compile-time interface checks)
- **Mock broker** extended with all 14 new methods + error injection fields in `broker/mock/client.go`
- **12 SDK bypass sites migrated** in `mcp/` to use `session.Broker`:
  - `mcp/common.go:111` — token probe: `session.Kite.Client.GetUserProfile()` → `session.Broker.GetProfile()`
  - `mcp/mf_tools.go` — all 7 MF calls (GetMFOrders, GetMFSIPs, GetMFHoldings, PlaceMFOrder, CancelMFOrder, PlaceMFSIP, CancelMFSIP)
  - `mcp/margin_tools.go` — all 3 margin calls (GetOrderMargins, GetBasketMargins, GetOrderCharges)
  - `mcp/post_tools.go` — ConvertPosition (then further routed through CQRS use case by another agent)
- **Test updates**: DEV_MODE tests updated (MF/margin tools now succeed via mock broker instead of erroring on dead stub URL)
- **usecases test mock** updated with all 14 new interface methods
- **`go vet ./...` passes** cleanly

### Not Yet Implemented (scope for future tasks)
- Native alert tools (`mcp/native_alert_tools.go`) still use `session.Kite.Client` — Zerodha-specific AlertParams/Basket types resist clean abstraction. Recommend sub-interface pattern (`broker.NativeAlertCapable`).
- session_service.go still has hardcoded `zerodha.New()` calls — Factory/Auth types are created but not wired into SessionService yet (requires careful migration of auth lifecycle).
- Manager decomposition not started (Phase 2/3 from plan below).
- NotificationService interface not started.

### Files Changed
- `broker/broker.go` — 14 new types, Factory/Authenticator interfaces, Client interface extended
- `broker/zerodha/client.go` — 14 new method implementations
- `broker/zerodha/convert.go` — MF conversion functions (convertMFOrders, convertMFSIPs, convertMFHoldings)
- `broker/zerodha/factory.go` — NEW: Factory + Auth types
- `broker/mock/client.go` — 14 new methods + error injection fields
- `mcp/common.go` — token probe fix
- `mcp/mf_tools.go` — 7 calls migrated, kiteconnect import removed
- `mcp/margin_tools.go` — 3 calls migrated, kiteconnect import removed
- `mcp/post_tools.go` — ConvertPosition migrated
- `mcp/tools_devmode_test.go` — 10 tests updated
- `kc/usecases/usecases_test.go` — mock updated with 14 methods

---

## 1. Direct Kite SDK Calls Bypassing broker.Client

### Summary
Found **18 distinct direct SDK calls** via `session.Kite.Client.XXX` in `mcp/` plus 1 in `mcp/common.go` (token refresh probe). These bypass the `broker.Client` abstraction and couple tool handlers directly to Zerodha's gokiteconnect SDK.

### Group A: Mutual Fund Operations (7 calls)
| # | File:Line | SDK Method | Proposed broker.Client Method |
|---|-----------|------------|-------------------------------|
| 1 | `mcp/mf_tools.go:35` | `GetMFOrders()` | `GetMFOrders() ([]MFOrder, error)` |
| 2 | `mcp/mf_tools.go:70` | `GetMFSIPs()` | `GetMFSIPs() ([]MFSIP, error)` |
| 3 | `mcp/mf_tools.go:105` | `GetMFHoldings()` | `GetMFHoldings() ([]MFHolding, error)` |
| 4 | `mcp/mf_tools.go:195` | `PlaceMFOrder(orderParams)` | `PlaceMFOrder(MFOrderParams) (MFOrderResponse, error)` |
| 5 | `mcp/mf_tools.go:236` | `CancelMFOrder(orderID)` | `CancelMFOrder(orderID string) (MFOrderResponse, error)` |
| 6 | `mcp/mf_tools.go:323` | `PlaceMFSIP(sipParams)` | `PlaceMFSIP(MFSIPParams) (MFSIPResponse, error)` |
| 7 | `mcp/mf_tools.go:364` | `CancelMFSIP(sipID)` | `CancelMFSIP(sipID string) (MFSIPResponse, error)` |

**Broker-agnostic types needed:** `MFOrder`, `MFSIP`, `MFHolding`, `MFOrderParams`, `MFSIPParams`, `MFOrderResponse`, `MFSIPResponse`

### Group B: Native Alert Operations (5 calls)
| # | File:Line | SDK Method | Proposed broker.Client Method |
|---|-----------|------------|-------------------------------|
| 8 | `mcp/native_alert_tools.go:165` | `CreateAlert(params)` | `CreateNativeAlert(NativeAlertParams) (NativeAlert, error)` |
| 9 | `mcp/native_alert_tools.go:211` | `GetAlerts(filters)` | `GetNativeAlerts(filters map[string]string) ([]NativeAlert, error)` |
| 10 | `mcp/native_alert_tools.go:373` | `ModifyAlert(uuid, params)` | `ModifyNativeAlert(uuid string, params NativeAlertParams) (NativeAlert, error)` |
| 11 | `mcp/native_alert_tools.go:427` | `DeleteAlerts(uuids...)` | `DeleteNativeAlerts(uuids ...string) error` |
| 12 | `mcp/native_alert_tools.go:475` | `GetAlertHistory(uuid)` | `GetNativeAlertHistory(uuid string) ([]NativeAlertEvent, error)` |

**Broker-agnostic types needed:** `NativeAlertParams`, `NativeAlert`, `NativeAlertEvent`

**Note:** Native alerts (ATO) are Zerodha-specific. Other brokers may not support server-side alerts. The interface methods should be optional — consider an `OptionalCapabilities` pattern or a separate `NativeAlertBroker` sub-interface.

### Group C: Margin Query Operations (3 calls)
| # | File:Line | SDK Method | Proposed broker.Client Method |
|---|-----------|------------|-------------------------------|
| 13 | `mcp/margin_tools.go:106` | `GetOrderMargins(params)` | `GetOrderMargins(OrderMarginParams) ([]OrderMarginResult, error)` |
| 14 | `mcp/margin_tools.go:178` | `GetBasketMargins(params)` | `GetBasketMargins(BasketMarginParams) (BasketMarginResult, error)` |
| 15 | `mcp/margin_tools.go:238` | `GetOrderCharges(params)` | `GetOrderCharges(OrderChargesParams) ([]OrderChargeResult, error)` |

**Broker-agnostic types needed:** `OrderMarginParam`, `OrderMarginResult`, `BasketMarginParams`, `BasketMarginResult`, `OrderChargesParam`, `OrderChargeResult`

### Group D: Position Conversion (1 call)
| # | File:Line | SDK Method | Proposed broker.Client Method |
|---|-----------|------------|-------------------------------|
| 16 | `mcp/post_tools.go:646` | `ConvertPosition(params)` | `ConvertPosition(ConvertPositionParams) (bool, error)` |

**Broker-agnostic types needed:** `ConvertPositionParams`

### Group E: Token/Auth Operations (2 calls in common.go, session_service.go)
| # | File:Line | SDK Method | Purpose |
|---|-----------|------------|---------|
| 17 | `mcp/common.go:111` | `GetUserProfile()` | Token validity probe (already in broker.Client as `GetProfile`) |
| 18 | `kc/session_service.go:375` | `GenerateSession(requestToken, apiSecret)` | Auth flow — inherently broker-specific |

**Recommendation:**
- Call 17: Replace `session.Kite.Client.GetUserProfile()` with `session.Broker.GetProfile()`. Direct 1:1 replacement.
- Call 18: `GenerateSession` is an authentication lifecycle method, not a trading API. Keep in session_service but route through a `BrokerAuthenticator` interface (see section 2).

### Additional kc/ references (session lifecycle, not tool handlers)
| File:Line | SDK Method | Notes |
|-----------|------------|-------|
| `kc/session_service.go:124` | `SetAccessToken()` | Auth lifecycle — Kite-specific, OK to keep |
| `kc/session_service.go:132` | `SetAccessToken()` | Auth lifecycle |
| `kc/session_service.go:152` | `InvalidateAccessToken()` | Cleanup hook |
| `kc/session_service.go:200` | `SetAccessToken()` | Session restore |
| `kc/session_service.go:204` | `SetAccessToken()` | Pre-auth |
| `kc/session_service.go:347` | `GetLoginURL()` | Login URL generation |
| `kc/session_service.go:382` | `SetAccessToken()` | Post-auth |
| `kc/manager.go:602` | `InvalidateAccessToken()` | Duplicate cleanup hook |

These are auth lifecycle calls, not trading API calls. They should be abstracted via a `BrokerAuthenticator` interface (section 2).

---

## 2. Broker Factory / Registry Design

### Current State
Hardcoded `zerodha.New()` calls in `kc/session_service.go`:
- Line 117: `Broker: zerodha.New(kc.Client)` — session creation
- Line 196: `kiteData.Broker = zerodha.New(kiteData.Kite.Client)` — session restore
- Line 450: `return zerodha.New(kc.Client), nil` — `GetBrokerForEmail`

### Proposed Design: `broker.Factory` + `broker.Authenticator`

```go
// broker/factory.go

// Factory creates broker Client instances from credentials.
type Factory interface {
    // Create returns a new unauthenticated broker client for the given API key.
    Create(apiKey string) (Client, error)

    // CreateWithToken returns an authenticated broker client.
    CreateWithToken(apiKey, accessToken string) (Client, error)

    // BrokerName returns which broker this factory creates.
    BrokerName() Name
}

// Authenticator handles broker-specific auth lifecycle.
type Authenticator interface {
    // GetLoginURL returns the broker's login URL for OAuth/redirect flow.
    GetLoginURL(apiKey string) string

    // ExchangeToken completes auth flow, returns access token + user info.
    ExchangeToken(apiKey, apiSecret, requestToken string) (AuthResult, error)

    // InvalidateToken invalidates a token (best-effort).
    InvalidateToken(apiKey, accessToken string) error
}

// AuthResult returned from ExchangeToken.
type AuthResult struct {
    AccessToken string
    UserID      string
    UserName    string
    UserType    string
}

// Registry maps broker names to their factories and authenticators.
type Registry struct {
    factories      map[Name]Factory
    authenticators map[Name]Authenticator
}

func NewRegistry() *Registry { ... }
func (r *Registry) Register(f Factory, a Authenticator) { ... }
func (r *Registry) GetFactory(name Name) (Factory, error) { ... }
func (r *Registry) GetAuthenticator(name Name) (Authenticator, error) { ... }
```

### Zerodha Implementation

```go
// broker/zerodha/factory.go

type ZerodhaFactory struct{}

func (f *ZerodhaFactory) BrokerName() broker.Name { return broker.Zerodha }

func (f *ZerodhaFactory) Create(apiKey string) (broker.Client, error) {
    kc := kiteconnect.New(apiKey)
    return New(kc), nil
}

func (f *ZerodhaFactory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
    kc := kiteconnect.New(apiKey)
    kc.SetAccessToken(accessToken)
    return New(kc), nil
}

// broker/zerodha/authenticator.go

type ZerodhaAuthenticator struct{}

func (a *ZerodhaAuthenticator) GetLoginURL(apiKey string) string {
    kc := kiteconnect.New(apiKey)
    return kc.GetLoginURL()
}

func (a *ZerodhaAuthenticator) ExchangeToken(apiKey, apiSecret, requestToken string) (broker.AuthResult, error) {
    kc := kiteconnect.New(apiKey)
    sess, err := kc.GenerateSession(requestToken, apiSecret)
    if err != nil { return broker.AuthResult{}, err }
    return broker.AuthResult{
        AccessToken: sess.AccessToken,
        UserID:      sess.UserID,
        UserName:    sess.UserName,
        UserType:    sess.UserType,
    }, nil
}

func (a *ZerodhaAuthenticator) InvalidateToken(apiKey, accessToken string) error {
    kc := kiteconnect.New(apiKey)
    kc.SetAccessToken(accessToken)
    _, err := kc.InvalidateAccessToken()
    return err
}
```

### Migration in session_service.go

```go
// SessionService gets a broker.Factory + broker.Authenticator instead of hardcoded zerodha
type SessionService struct {
    brokerFactory       broker.Factory
    brokerAuthenticator broker.Authenticator
    // ... existing fields
}

// createKiteSessionData becomes:
func (ss *SessionService) createKiteSessionData(sessionID, email string) *KiteSessionData {
    client, _ := ss.brokerFactory.Create(apiKey)
    return &KiteSessionData{
        Broker: client,
        Email:  email,
    }
}
```

**Key change:** `KiteSessionData.Kite *KiteConnect` field becomes unnecessary once all direct SDK calls go through `broker.Client`. The `Kite` field exists solely to give tool handlers direct SDK access. After migration, it can be removed and `KiteSessionData` becomes `SessionData { Broker broker.Client; Email string }`.

---

## 3. Manager Decomposition

### Current State: Manager is a God Object
`kc/manager.go` has **45+ fields** and **70+ methods**. It serves as a service locator for the entire application.

### Every Field on Manager

**Configuration:**
- `apiKey string`, `apiSecret string`, `accessToken string`
- `appMode string`, `externalURL string`, `adminSecretPath string`, `devMode bool`

**Core infrastructure:**
- `Logger *slog.Logger`
- `metrics *metrics.Manager`
- `templates map[string]*template.Template`

**Focused services (already extracted):**
- `credentialSvc *CredentialService`
- `sessionSvc *SessionService`
- `managedSessionSvc *ManagedSessionService`
- `portfolioSvc *PortfolioService`
- `orderSvc *OrderService`
- `alertSvc *AlertService`
- `familyService *FamilyService`

**Data stores:**
- `Instruments *instruments.Manager`
- `sessionManager *SessionRegistry`
- `sessionSigner *SessionSigner`
- `tokenStore *KiteTokenStore`
- `credentialStore *KiteCredentialStore`
- `tickerService *ticker.Service`
- `alertStore *alerts.Store`
- `alertEvaluator *alerts.Evaluator`
- `trailingStopMgr *alerts.TrailingStopManager`
- `pnlService *alerts.PnLSnapshotService`
- `watchlistStore *watchlist.Store`
- `userStore *users.Store`
- `registryStore *registry.Store`
- `telegramNotifier *alerts.TelegramNotifier`
- `alertDB *alerts.DB`
- `auditStore *audit.Store`
- `riskGuard *riskguard.Guard`
- `paperEngine *papertrading.PaperEngine`
- `billingStore *billing.Store`
- `invitationStore *users.InvitationStore`
- `eventDispatcher *domain.EventDispatcher`
- `eventStore *eventsourcing.EventStore`
- `mcpServer any`

### Every Method on Manager (grouped by concern)

**Initialization (constructor):**
- `New(Config) (*Manager, error)` — 380-line constructor that wires everything
- `NewManager(apiKey, apiSecret, logger)` — deprecated alias

**Service accessors (delegate pattern, ~20 methods):**
- `CredentialSvc()`, `SessionSvc()`, `PortfolioSvc()`, `OrderSvc()`, `AlertSvc()`, `FamilyService()`
- `TokenStore()`, `TokenStoreConcrete()`, `CredentialStore()`, `CredentialStoreConcrete()`
- `UserStore()`, `UserStoreConcrete()`, `RegistryStore()`, `RegistryStoreConcrete()`
- `AlertStore()`, `AlertStoreConcrete()`, `WatchlistStore()`, `WatchlistStoreConcrete()`
- `TickerService()`, `TickerServiceConcrete()`, `InstrumentsManager()`, `InstrumentsManagerConcrete()`
- `AuditStore()`, `AuditStoreConcrete()`, `TelegramStore()`, `TelegramNotifier()`
- `RiskGuard()`, `PaperEngine()`, `PaperEngineConcrete()`, `BillingStore()`, `BillingStoreConcrete()`
- `TrailingStopManager()`, `PnLService()`, `EventDispatcher()`, `EventStoreConcrete()`
- `InvitationStore()`, `AlertDB()`, `MCPServer()`, `ManagedSessionSvc()`, `SessionSigner()`
- `SessionManager()`

**Setters (late wiring, ~8 methods):**
- `SetFamilyService()`, `SetAuditStore()`, `SetRiskGuard()`, `SetPaperEngine()`
- `SetBillingStore()`, `SetInvitationStore()`, `SetEventDispatcher()`, `SetEventStore()`
- `SetMCPServer()`, `SetPnLService()`

**Credential delegation (~6 methods):**
- `HasPreAuth()`, `HasCachedToken()`, `HasGlobalCredentials()`, `HasUserCredentials()`
- `GetAPIKeyForEmail()`, `GetAPISecretForEmail()`, `GetAccessTokenForEmail()`
- `IsTokenValid()`

**Session delegation (~8 methods):**
- `GetOrCreateSession()`, `GetOrCreateSessionWithEmail()`, `GetSession()`
- `ClearSession()`, `ClearSessionData()`, `GenerateSession()`
- `SessionLoginURL()`, `CompleteSession()`
- `GetActiveSessionCount()`, `CleanupExpiredSessions()`, `StopCleanupRoutine()`

**Metrics delegation (~4 methods):**
- `HasMetrics()`, `IncrementMetric()`, `TrackDailyUser()`, `IncrementDailyMetric()`

**Instruments delegation (~3 methods):**
- `GetInstrumentsStats()`, `UpdateInstrumentsConfig()`, `ForceInstrumentsUpdate()`

**Config accessors:**
- `IsLocalMode()`, `ExternalURL()`, `AdminSecretPath()`, `APIKey()`, `DevMode()`

**HTTP handling:**
- `HandleKiteCallback()`, `extractCallbackParams()`, `renderSuccessTemplate()`
- `handleCallbackError()`, `OpenBrowser()`

**Lifecycle:**
- `Shutdown()`
- `initializeTemplates()`, `initializeSessionSigner()`, `initializeSessionManager()`
- `kiteSessionCleanupHook()`
- `UpdateSessionSignerExpiry()`

### Proposed Decomposition into Bounded Context Services

The good news: Manager already has 7 focused services extracted (CredentialService, SessionService, PortfolioService, OrderService, AlertService, ManagedSessionService, FamilyService). The problem is that **Manager still holds all the stores and acts as a service locator** — tool handlers receive `*Manager` and call any accessor.

**Phase 1: No new services needed. Remove Manager as the pass-through layer.**

Instead of tool handlers receiving `*Manager` and calling `manager.AlertStore()`, `manager.TickerService()`, etc., they should receive a focused dependency struct:

```go
// Current (every tool gets *Manager which has ~30 stores):
func (*MFOrdersTool) Handler(manager *kc.Manager) server.ToolHandlerFunc { ... }

// Target (each tool gets only what it needs):
type MFDeps struct {
    SessionSvc  *kc.SessionService
    Logger      *slog.Logger
}
func (*MFOrdersTool) Handler(deps MFDeps) server.ToolHandlerFunc { ... }
```

**Phase 2: Extract remaining store ownership from Manager.**

| Current Manager field | Move to | Rationale |
|----------------------|---------|-----------|
| `alertStore`, `alertEvaluator`, `trailingStopMgr`, `telegramNotifier`, `pnlService` | Already in `AlertService` | AlertService already wraps these |
| `watchlistStore` | New `WatchlistService` or keep in Manager | Low priority — single store |
| `userStore`, `invitationStore` | New `UserService` or existing `FamilyService` | User lifecycle + invitations |
| `billingStore` | `FamilyService` (already uses billing) | Billing is part of family context |
| `auditStore` | `AuditService` (new) | Audit is cross-cutting |
| `riskGuard` | `OrderService` (already exists) | RiskGuard is order-placement middleware |
| `paperEngine` | `OrderService` | Paper trading intercepts orders |
| `eventDispatcher`, `eventStore` | New `EventService` or keep in Manager | DDD infrastructure |
| `tickerService` | `AlertService` | Ticker feeds alert evaluation |
| `tokenStore`, `credentialStore`, `registryStore` | Already in `CredentialService` | Credential lifecycle |
| `sessionManager`, `sessionSigner` | Already in `SessionService` | Session lifecycle |
| `Instruments` | Standalone (already is) | No change needed |
| `metrics` | Inject directly into services | Cross-cutting, not a service |
| `templates` | Move to HTTP handler layer | Not domain logic |
| `mcpServer` | Move to `app/` layer | Infrastructure, not domain |

**Phase 3: Manager becomes a thin composition root.**

```go
type Manager struct {
    // Config
    appMode     string
    externalURL string
    devMode     bool

    // Services (own nothing, just hold references for wiring)
    CredentialSvc  *CredentialService
    SessionSvc     *SessionService
    PortfolioSvc   *PortfolioService
    OrderSvc       *OrderService
    AlertSvc       *AlertService
    FamilySvc      *FamilyService
    AuditSvc       *AuditService
    Instruments    *instruments.Manager

    Logger  *slog.Logger
    Metrics *metrics.Manager
}
```

This reduces Manager from ~45 fields to ~12 and from ~70 methods to ~15 (config + lifecycle only).

---

## 4. NotificationServiceInterface Design

### Current State
`alerts.TelegramNotifier` is a concrete type used directly:
- Manager holds `telegramNotifier *alerts.TelegramNotifier`
- AlertService exposes `TelegramNotifier() *alerts.TelegramNotifier`
- Briefing, trading commands, and trailing stop callbacks all use concrete type
- Tool handlers access via `manager.TelegramNotifier()`

### Proposed: `notification.Service` Interface

```go
// notification/notification.go (new package)

// Service defines the contract for sending user notifications.
// Implementations: TelegramNotifier, SlackNotifier, EmailNotifier, NoopNotifier
type Service interface {
    // SendMarkdown sends a MarkdownV2 message to the user identified by email.
    SendMarkdown(email string, text string) error

    // SendHTML sends an HTML-formatted message to the user identified by email.
    SendHTML(email string, text string) error

    // NotifyAlert sends a formatted price alert notification.
    NotifyAlert(alert AlertInfo, currentPrice float64) error

    // IsConfigured returns true if the notification service is ready.
    IsConfigured() bool
}

// AlertInfo is a minimal struct for notification formatting (no dependency on alerts package).
type AlertInfo struct {
    Email         string
    Exchange      string
    Tradingsymbol string
    Direction     string
    TargetPrice   float64
    ReferencePrice float64
}
```

### Migration Path

1. Create `notification/notification.go` with the interface
2. Make `alerts.TelegramNotifier` implement `notification.Service`:
   - `SendMarkdown(email, text)` — lookup chatID internally, then send
   - `SendHTML(email, text)` — same
   - `NotifyAlert(info, price)` — existing `Notify()` logic
3. Create `notification.Noop` for when Telegram is not configured
4. Replace concrete `*alerts.TelegramNotifier` references with `notification.Service`:
   - `AlertService` holds `notification.Service` instead of `*alerts.TelegramNotifier`
   - Briefing/trading commands receive `notification.Service`
5. Telegram-specific features (bot API, trading commands with inline keyboards) remain in `kc/telegram/` but receive `notification.Service` for basic messaging

### Why not just use an interface in kc/interfaces.go?

The `alerts.TelegramNotifier` has Telegram-specific methods (`Bot()`, `Store()`) that shouldn't be in a generic interface. A separate `notification` package keeps the abstraction clean and avoids importing `alerts` package types into the notification contract.

---

## 5. Recommended Interface Extension for broker.Client

### New broker.Client methods (16 additions grouped into sub-interfaces)

```go
// broker/broker.go — extended Client interface

type Client interface {
    // ... existing 22 methods ...

    // --- Mutual Funds ---
    GetMFOrders() ([]MFOrder, error)
    GetMFSIPs() ([]MFSIP, error)
    GetMFHoldings() ([]MFHolding, error)
    PlaceMFOrder(params MFOrderParams) (MFOrderResponse, error)
    CancelMFOrder(orderID string) (MFOrderResponse, error)
    PlaceMFSIP(params MFSIPParams) (MFSIPResponse, error)
    CancelMFSIP(sipID string) (MFSIPResponse, error)

    // --- Margins ---
    GetOrderMargins(params OrderMarginParams) ([]OrderMarginResult, error)
    GetBasketMargins(params BasketMarginParams) (BasketMarginResult, error)
    GetOrderCharges(params OrderChargesParams) ([]OrderChargeResult, error)

    // --- Position Management ---
    ConvertPosition(params ConvertPositionParams) (bool, error)
}
```

### Optional capabilities (sub-interfaces for broker-specific features)

```go
// broker/native_alerts.go — optional sub-interface

// NativeAlertCapable is implemented by brokers that support server-side alerts.
// Use type assertion: if nac, ok := client.(NativeAlertCapable); ok { ... }
type NativeAlertCapable interface {
    CreateNativeAlert(params NativeAlertParams) (NativeAlert, error)
    GetNativeAlerts(filters map[string]string) ([]NativeAlert, error)
    ModifyNativeAlert(uuid string, params NativeAlertParams) (NativeAlert, error)
    DeleteNativeAlerts(uuids ...string) error
    GetNativeAlertHistory(uuid string) ([]NativeAlertEvent, error)
}
```

This way:
- Core `broker.Client` grows by 11 methods (MF + Margins + Position) — these are common across Indian brokers
- Native alerts are optional — only Zerodha implements them currently
- Tool handlers check capability: `if nac, ok := session.Broker.(broker.NativeAlertCapable); ok { ... }`

---

## 6. Risk Assessment & Migration Priority

### Priority Order (by impact × safety)

1. **Token probe fix** (`mcp/common.go:111`) — Trivial 1-line change, high value: `session.Kite.Client.GetUserProfile()` → `session.Broker.GetProfile()`. No new types needed.

2. **Broker Factory** — Unlocks multi-broker support, eliminates hardcoded `zerodha.New()`. Medium effort. Pre-req for everything else.

3. **Margin methods** — 3 tools, well-scoped, read-only. Low risk.

4. **MF methods** — 7 tools, includes writes (PlaceMFOrder, PlaceMFSIP). Medium risk (financial). Good test coverage needed.

5. **Position conversion** — 1 tool, write operation. Low effort.

6. **Native alerts** — 5 tools, Zerodha-specific. Needs sub-interface pattern. Higher design complexity.

7. **NotificationService** — Cross-cutting refactor, touches many files. Can be done independently.

8. **Manager decomposition** — Largest change, highest risk. Do last, after all other changes are stable.
