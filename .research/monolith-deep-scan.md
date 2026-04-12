# Monolith Deep Scan Analysis: kite-mcp-temp Go Codebase

## Executive Summary

This is a HIGH-SEVERITY monolith with classic signs of decomposition problems.

- Total Lines: 52,453 lines
- Total Go files: 171 (non-test)
- Verdict: MONOLITH requiring phase refactoring

## KEY FINDINGS

### 1. GOD OBJECT: kc.Manager (CRITICAL)

File: /d/kite-mcp-temp/kc/manager.go
Lines: 1,194
Methods: 95
Severity: HIGH

Handles 14 different responsibilities:
- Alert management (5 methods)
- Session management (8 methods)
- Token/credential caching (8 methods)
- Kite broker operations (6 methods)
- User/Registry/Audit stores (5 methods)
- Instruments & ticker (4 methods)
- Event sourcing (2 methods)
- Watchlist management (2 methods)
- Settings/Config (8 methods)
- Cleanup/utilities (15+ methods)

Impact: Used as service locator by 35+ code locations
Fix: Split into SessionService, AlertService, AuditService
Effort: 40 hours

### 2. SERVICE LOCATOR ANTI-PATTERN (CRITICAL)

File: /d/kite-mcp-temp/mcp/common.go (lines 66-214)
Severity: HIGH
Usage: 35+ code locations

All MCP tools pass *kc.Manager and call:
  h.manager.GetOrCreateSession()
  h.manager.UserStore()
  h.manager.TokenStore()
  h.manager.AuditStore()

Problem: Implicit dependencies, hard to test tools in isolation
Fix: Inject specific services instead
Effort: 40 hours

### 3. FILES OVER 500 LINES (Top 10)

1. app/app.go: 2,022 lines
2. kc/ops/api_handlers.go: 1,892 lines
3. oauth/handlers.go: 1,255 lines
4. kc/manager.go: 1,194 lines (GOD OBJECT)
5. kc/ops/dashboard_templates.go: 1,176 lines
6. kc/ops/handler.go: 1,115 lines
7. mcp/admin_tools.go: 1,073 lines
8. kc/alerts/db.go: 1,033 lines
9. kc/ops/user_render.go: 986 lines
10. broker/mock/client.go: 971 lines

### 4. STRUCTS WITH >15 METHODS

Manager: 95 methods (CRITICAL)
Client (broker/zerodha): 37 methods
DB (alerts): 40 methods
Guard (riskguard): 30 methods
DashboardHandler: 30 methods
Handler (oauth): 27 methods
Store (users): 26 methods
App: 26 methods

### 5. FAT INTERFACES (>10 methods = ISP violation)

UserStoreInterface: 21 methods (MEDIUM severity)
AuditStoreInterface: 14 methods
RegistryStoreInterface: 12 methods
PaperEngineInterface: 12 methods
InstrumentManagerInterface: 12 methods
WatchlistStoreInterface: 11 methods
AlertStoreInterface: 10 methods

Problem: Clients must depend on all methods to use one feature
Fix: Split interfaces into smaller, focused ones
Effort: 16 hours

### 6. PACKAGE COUPLING (HIGH FAN-OUT)

app/app.go imports 21 internal packages (CRITICAL):
  app/metrics, broker, broker/zerodha,
  kc, kc/alerts, kc/audit, kc/billing, kc/domain,
  kc/eventsourcing, kc/instruments, kc/ops,
  kc/papertrading, kc/registry, kc/riskguard,
  kc/scheduler, kc/templates, kc/ticker, kc/users,
  kc/watchlist, mcp, oauth

kc/manager.go imports 15 internal packages

Problem: Central orchestrator tightly coupled to all subsystems
Fix: Create focused builders, reduce import count
Effort: 24 hours

### 7. MIXED RESPONSIBILITIES

kc/ package handles (doing TOO MUCH):
- Session management
- User store
- Alert system
- Audit trail
- Billing
- Instrument data
- Paper trading
- Risk guards
- Watchlists
- Telegram bot
- Event sourcing
- Order aggregation

Severity: HIGH
Fix: Create domain services
Effort: 80 hours

### 8. DASHBOARD MONOLITH

4 related files = 6,338 lines:
  dashboard.go: 2,284 lines
  api_handlers.go: 1,892 lines
  user_render.go: 986 lines
  dashboard_templates.go: 1,176 lines

Responsibilities: UI + API + streaming + CSV export

Fix: Split into separate handlers, move templates to files
Effort: 24 hours

### 9. MUTABLE PACKAGE STATE

writeTools map (mcp/common.go:47): No synchronization
knownAnnualDividends (mcp/dividend_tool.go): Hard-coded
dividendSeasonality (mcp/dividend_tool.go): Hard-coded

Fix: Add RWMutex, move data to database
Effort: 12 hours

## REFACTORING ROADMAP

Phase 1: Immediate (2-3 weeks, 20 hours)
Phase 2: Short-term (4-6 weeks, 72 hours)
Phase 3: Medium-term (8-12 weeks, 80 hours)
Phase 4: Long-term (16+ weeks, 60+ hours)

Total Estimated Effort: 232+ hours (6 weeks full-time)

## VERDICT

HIGH-SEVERITY MONOLITH with:
✗ God Object (Manager: 95 methods)
✗ Service Locator (manager passed everywhere)
✗ Fat Interfaces (UserStore: 21 methods)
✗ Mixed Responsibilities (kc/ handles 12 domains)
✗ High Fan-Out (app imports 21 packages)

NOT BEYOND REDEMPTION:
✓ Hexagonal architecture skeleton
✓ Interface-based design
✓ No circular imports
✓ Test infrastructure in place

RECOMMENDATION: Start Phase 1-2 (8-12 weeks) to decompose Manager
and eliminate service locator pattern.
