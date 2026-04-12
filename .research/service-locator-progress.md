# Service Locator Reduction — Progress

## Status: Phase 1 Complete

## What Changed

### 1. New interfaces added to `kc/manager_interfaces.go`
- `DevMode()` added to `AppConfigProvider` interface

### 2. `ToolHandlerDeps` struct (`mcp/common.go:60`)
New dependency container holding focused interfaces:
- `Logger` — `*slog.Logger`
- `TokenStore` — `kc.TokenStoreInterface`
- `UserStore` — `kc.UserStoreInterface` (may be nil)
- `Sessions` — `kc.SessionProvider`
- `Credentials` — `kc.CredentialResolver`
- `Metrics` — `kc.MetricsRecorder`
- `Config` — `kc.AppConfigProvider`

### 3. `ToolHandler` struct expanded (`mcp/common.go:70`)
- Added `deps ToolHandlerDeps` field alongside existing `manager *kc.Manager`
- `manager` retained for backward compat — individual tool files still use it
- `NewToolHandler(manager)` populates deps from manager automatically

### 4. All `common.go` methods updated
Replaced 26 `h.manager.*` calls with `h.deps.*`:
- `trackToolCall` → `h.deps.Metrics`
- `trackToolError` → `h.deps.Metrics`
- `WithViewerBlock` → `h.deps.UserStore`
- `WithTokenRefresh` → `h.deps.TokenStore`, `h.deps.Logger`
- `WithSession` → `h.deps.Sessions`, `h.deps.Credentials`, `h.deps.Config`, `h.deps.Logger`, `h.deps.Metrics`, `h.deps.TokenStore`
- `callWithNilKiteGuard` → `h.deps.Logger`
- `MarshalResponse` → `h.deps.Logger`
- `HandleAPICall` → `h.deps.Logger`
- `PaginatedToolHandler` → `h.deps.Logger`
- `PaginatedToolHandlerWithArgs` → `h.deps.Logger`

## What Did NOT Change (Future Work)
- Individual tool `Handler(manager *kc.Manager)` signatures — 80+ tools still take full Manager
- `adminCheck`, `withAdminCheck` in `admin_tools.go` still use `manager` directly
- Tool-level `manager.Logger`, `manager.AlertStore()`, etc. in ~302 call sites

## Verification
- `go build ./...` — clean
- `go vet ./...` — clean
- All common.go-related tests pass (40+ tests)
- Pre-existing ext_apps test failures are unrelated
