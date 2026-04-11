# Kite MCP Server — Development Guidelines

## Testing Policy: TDD for New Features

**All new features MUST follow Test-Driven Development:**

1. Write the test FIRST (what the feature should do)
2. Run the test — it MUST fail (proves the test is real)
3. Write the minimum code to make it pass
4. Refactor (clean up, DRY, extract helpers)
5. Verify all tests still pass

### Test file locations:
- MCP tool tests: `mcp/*_test.go` (use `callToolWithManager` or `callAdminTool` helpers)
- Use case tests: `kc/usecases/usecases_test.go` (use `mockBrokerClient`)
- Store tests: same package (e.g., `kc/billing/billing_test.go`)
- Integration tests: `mcp/admin_tools_test.go` (E2E workflows)

### Test patterns used in this codebase:
- **Table-driven**: `tests := []struct{ name string; ... }{ ... }`
- **ArgParser**: `p := NewArgParser(args)` for tool arg extraction
- **Mock broker**: `broker/mock/client.go` — use `SetQuotes()`, `SetGTTs()` etc.
- **Admin test manager**: `newAdminTestManager(t)` + `seedUsers(t, manager)`
- **httptest**: `httptest.NewRequest()` + `httptest.NewRecorder()` for HTTP handlers

### Coverage targets:
- New code: 80%+ coverage required
- Critical paths (billing, auth, orders): 90%+
- Pure functions: 100%

## Architecture: Clean Architecture with CQRS

**All new tool handlers MUST route through use cases:**

```
Tool Handler → Use Case → CQRS Command/Query → Broker Port → Adapter
```

- Do NOT call `session.Broker.*` directly from tool handlers
- Create a use case in `kc/usecases/` for new operations
- Use `NewArgParser(request.GetArguments())` for arg extraction
- Use error constants from `mcp/common.go` (ErrAuthRequired, etc.)

### Admin tools:
- Use `adminCheck()` or `withAdminCheck()` helper
- All admin tools are `TierFree` (gated by role, not billing)
- Destructive tools need `confirm: bool` parameter + elicitation

## Middleware Chain (order matters):
1. Timeout (30s)
2. Audit (logging)
3. Hooks (plugin before/after)
4. RiskGuard (order safety)
5. Rate Limiter (per-tool per-user)
6. Billing (tier gating)
7. Paper Trading (order interception)
8. Dashboard URL (append widget links)

## Key Patterns:
- **Retry**: All broker adapter methods use `retryOnTransient()` (2 retries, exponential backoff)
- **CSS injection**: Widgets use `/*__INJECTED_CSS__*/` placeholder — dashboard-base.css injected at serve time
- **AppBridge**: Canonical source at `kc/templates/appbridge.js` — widgets copy it inline (MCP protocol constraint)
- **Plugin registry**: `mcp.RegisterPlugin()` for external tools, `OnBeforeToolExecution()` for hooks

## Commands:
```bash
go build ./...              # Build
go test ./... -count=1      # Test (uncached)
go test ./mcp/ -cover       # Coverage for mcp package
just lint                   # Lint
just test-race              # Race condition detection
flyctl deploy -a kite-mcp-server --remote-only  # Deploy
```
