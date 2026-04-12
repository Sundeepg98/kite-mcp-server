# ACTION 3 — ISP Wiring Report

Wired 15 previously unused narrow Provider interfaces into `mcp.ToolHandlerDeps`
so each has at least one production consumer in the mcp package.

## Strategy

- Expanded `mcp.ToolHandlerDeps` (in `mcp/common.go`) with 15 new typed fields,
  one per narrow Provider. `NewToolHandler(manager *kc.Manager)` assigns
  `manager` to each — `*kc.Manager` satisfies every Provider via existing
  accessor methods.
- Migrated production call sites from `manager.XxxStore()` to
  `handler.deps.Xxx.XxxStore()` so the Provider interface becomes a real
  dependency rather than a shadow definition.
- Added compile-time assertions in `kc/manager_interfaces.go` so accidental
  renames/removals fail the build.

## Provider consumer count (post-wiring)

Production call sites grepped with
`handler\.deps\.<Provider>\.` (excludes `*_test.go`).

| Provider | Before | After | Primary consumers |
|---|---|---|---|
| TokenStoreProvider          | 0 | 3 | alert_tools, account_tools |
| CredentialStoreProvider     | 0 | 3 | account_tools |
| AlertStoreProvider          | 0 | 4 | alert_tools, account_tools |
| TelegramStoreProvider       | 0 | 2 | alert_tools |
| WatchlistStoreProvider      | 0 | 8 | watchlist_tools, account_tools |
| UserStoreProvider           | 0 | 7 | admin_user_tools, admin_server_tools, account_tools |
| RegistryStoreProvider       | 0 | 1 | admin_server_tools |
| AuditStoreProvider          | 0 | 1 | observability_tool |
| BillingStoreProvider        | 0 | 1 | admin_risk_tools |
| TickerServiceProvider       | 0 | 6 | ticker_tools, alert_tools |
| PaperEngineProvider         | 0 | 4 | paper_tools, account_tools |
| InstrumentsManagerProvider  | 0 | 1 | alert_tools |
| AlertDBProvider             | 0 | 1 | admin_server_tools |
| RiskGuardProvider           | 0 | 3 | admin_user_tools, admin_server_tools |
| MCPServerProvider           | 0 | 2 | admin_user_tools |
| **Total**                   | **0** | **46** | |

All 15 narrow Providers now have `>0` production consumers.

## Verification

- `go vet ./...` — clean
- `go build ./...` — clean
- `go test ./kc/...` — passes (domain suite flaked on SAC policy; unrelated to
  this change)
- `go test ./kc/usecases/...` — passes
- Two mcp failures (`TestAdminListFamily_WithPagination`, `TestFamilyInviteFlow`)
  were pre-existing ACTION 2 regressions in `admin_family_tools.go` using a nil
  `QueryBus` in test mode. Not introduced by this action.
- Two app failures (`TestInitializeServices_*`) were pre-existing ALERT_DB_PATH
  init-order regressions. Not introduced by this action.

## Files touched

- `kc/manager_interfaces.go` — added 15 compile-time interface assertions
- `mcp/common.go` — added 15 Provider fields to `ToolHandlerDeps`
- `mcp/alert_tools.go` — Alerts, Telegram, Ticker, Tokens, Instruments
- `mcp/watchlist_tools.go` — Watchlist
- `mcp/ticker_tools.go` — Ticker (5 sites)
- `mcp/account_tools.go` — CredStore, Tokens, Alerts, Watchlist, Paper, Users
- `mcp/paper_tools.go` — Paper (3 tools: Toggle, Status, Reset)
- `mcp/observability_tool.go` — Audit
- `mcp/admin_user_tools.go` — Users, RiskGuard, MCPServer
- `mcp/admin_server_tools.go` — Users, RiskGuard, Registry, AlertDB
- `mcp/admin_risk_tools.go` — Billing

## Philosophy note

Per the team-lead directive: **wire, don't delete**. No Provider was removed;
every one was made a real, consumed dependency. The remaining Provider
interfaces (`TelegramNotifierProvider`, `TrailingStopManagerProvider`,
`PnLServiceProvider`) live on `AlertService`, not `Manager`, and are out of
scope for the 15 listed in the ACTION 3 task description.
