# ops-push100 Coverage Push Progress

## Status: COMPLETE (go vet clean)

## File Created
- `kc/ops/ops_push100_test.go` — 101 test functions, ~1850 lines

## Coverage Targets Hit

### handler.go
- freezeTradingGlobal success path (line 697-732)
- freezeTradingGlobal empty reason defaulted
- Nil userStore returns 403 (dead code path — isAdmin blocks first)
- OffboardUser admin success with full cleanup
- OffboardUser invalid JSON
- ChangeRole invalid JSON
- ChangeRole user not found
- Credentials POST auto-register new key
- Credentials GET long secret truncation
- truncKey short/exact length

### user_render.go
- ordersToStatsData: no P&L, win rate, negative P&L
- ordersToTableData: sell side, nil optionals, trigger pending, rejected, cancelled, unknown status
- alertsToStatsData: nil nearest, with nearest, empty avg time
- alertsToActiveData: with distance, high distance
- alertsToTriggeredData: with notification, empty notification
- marketIndicesToBarData: negative change
- portfolioToStatsData: ticker running, zero current value
- pnlDisplayClass: zero value
- fmtINR: exact 3 digits, 4 digits, negative small, zero, negative large
- fmtINRShort: exactly lakh, exactly thousand, below thousand, negative lakh
- fmtTimeDDMon, fmtTimeHMS: non-zero
- barClass/distanceClass: all boundaries
- boolClass: true/false
- Fragment templates: orders table, alerts active
- usersToTemplateData: suspended and offboarded users

### admin_render.go
- metricsToTemplateData: nil stats, zero total calls
- formatInt: small, with commas
- formatFloat: decimal
- getCatColor: all known categories
- getCatLabel: all known categories

### dashboard.go / dashboard_templates.go
- serveBillingPage: Pro/Premium/PastDue/Canceled/Free/FamilyMember
- tierDisplayName: all tiers
- serveSafetyPageSSR: with RiskGuard
- servePaperPageSSR: with engine
- serveAlertsPageSSR: with alerts, no email
- serveOrdersPageSSR: with audit data, no audit store
- servePageFallback: valid + non-existent
- paperStatusToBanner: not enabled
- paperStatusToStats: all zero
- paperDataToTables: with orders, cancelled, open
- buildOrderSummary: mixed entries, no P&L
- buildOrderEntries: nil tool call
- parseOrderParamsJSON: all fields
- toFloat: valid string
- toInt: float64
- servePage: with full data

### overview_sse.go
- sendAllAdminEvents: with populated data
- logStream: cancelled during stream

### logbuffer.go
- TeeHandler: WithAttrs, WithGroup, Handle
- LogBuffer: multiple listeners, ring buffer wrap around

### safety render
- safetyToFreezeData: frozen, frozen zero time, disabled with custom message
- safetyToLimitsData: full utilization, low utilization, zero limits
- safetyToSEBIData: mixed bools

### metrics API
- 30d period
- 7d period

## Dead Code Identified
- Nil userStore guards inside suspendUser/activateUser/offboardUser/changeRole (lines ~540, ~570, ~610, ~670 in handler.go) are unreachable because `isAdmin()` returns false when userStore is nil (line 83-84), blocking execution before reaching those guards. Tests verify the 403 Forbidden response instead.

## Helpers
- `newPush100OpsHandler(t)` — minimal handler with nil userStore
- `newPush100OpsHandlerFull(t)` — full handler with userStore, auditStore, alertStore, riskguard, papertrading engine
- `push100AdminReq(method, path, body)` — creates request with admin email in OAuth context
