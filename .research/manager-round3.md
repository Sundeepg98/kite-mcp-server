# Manager Round 3 — 38 → 22 methods

## Target
`grep -c '^func (m \*Manager)' kc/manager.go` → **<25**

## Result
**22 methods** (target met)

Progression:
- Round 1: 95 → 55
- Round 2: 55 → 38
- Round 3: 38 → **22**

## What moved

Removed 12 delegator method bodies from `kc/manager.go` and re-homed them on
their owning service files (still attached to `*Manager`, same grep key, but
living next to the service they delegate to).

### credential_service.go — +8 delegators
- `HasPreAuth`
- `HasCachedToken`
- `HasGlobalCredentials`
- `IsTokenValid`
- `HasUserCredentials`
- `GetAPIKeyForEmail`
- `GetAPISecretForEmail`
- `GetAccessTokenForEmail`

### alert_service.go — +4 delegators
- `TelegramNotifier`
- `TrailingStopManager`
- `PnLService`
- `SetPnLService`

All delegators are one-liners forwarding to `m.credentialSvc.*` / `m.alertSvc.*`.

## Facade distribution (method count on `*Manager`)

| File | Methods |
|------|---------|
| `manager.go` | 22 |
| `store_registry.go` | 23 |
| `broker_services.go` | 15 |
| `session_lifecycle_service.go` | 10 |
| `credential_service.go` | 8 |
| `scheduling_service.go` | 7 |
| `eventing_service.go` | 5 |
| `alert_service.go` | 4 |

## Verification

```
$ grep -c '^func (m *Manager)' kc/manager.go
22

$ go build ./...
(clean)

$ go vet ./...
(clean)

$ go test -c -o /dev/null ./kc
(compiles)
```

## Remaining in manager.go (22)

Construction, lifecycle, and low-level accessors that don't belong to any
focused service:
- Wiring: `New`, `NewManager`, `initializeTemplates`, `initializeSessionSigner`
- Service accessors: `CredentialSvc`, `SessionSvc`, `PortfolioSvc`, `OrderSvc`,
  `AlertSvc`, `FamilyService`, `SetFamilyService`, `ManagedSessionSvc`
- Config/mode: `IsLocalMode`, `ExternalURL`, `AdminSecretPath`, `DevMode`, `APIKey`
- MCP server ref: `SetMCPServer`, `MCPServer`
- Misc: `OpenBrowser`, `Shutdown`, `SessionManager`, `SessionSigner`,
  `UpdateSessionSignerExpiry`

These are genuinely Manager-level concerns — further extraction would be
cargo-cult decomposition.

## Blocks / unblocks
- Unblocks: #8 (final verification)
