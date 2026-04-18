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

HTTP layer (in `app/http.go` / `app/requestid.go`):
1. X-Request-ID (generates UUIDv7 if absent, threads via ctx)

MCP tool-call middleware (in `app/wire.go`):
2. Timeout (30s)
3. Audit (logging with CallID)
4. Hooks (plugin before/after)
5. CircuitBreaker (freezes on error spike)
6. RiskGuard (9 pre-trade checks: kill switch, cap, count, rate, duplicate, idempotency key, confirmation, anomaly, off-hours)
7. Rate Limiter (per-tool per-user)
8. Billing (tier gating via `ENABLE_TRADING` for order-placement tools)
9. Paper Trading (order interception)
10. Dashboard URL (append widget links)

## Key Patterns:
- **Retry**: All broker adapter methods use `retryOnTransient()` (2 retries, exponential backoff)
- **CSS injection**: Widgets use `/*__INJECTED_CSS__*/` placeholder — dashboard-base.css injected at serve time
- **AppBridge**: Canonical source at `kc/templates/appbridge.js` — widgets copy it inline (MCP protocol constraint)
- **Plugin registry**: `mcp.RegisterPlugin()` for external tools, `OnBeforeToolExecution()` for hooks
- **Idempotency**: Optional `client_order_id` on place_order/modify_order. Dedup via SHA256(email+clientOrderID), 15-min TTL. See `kc/riskguard/dedup.go`.
- **Anomaly detection**: `kc/audit/anomaly.go` provides rolling μ+3σ stats per user; `kc/riskguard/guard.go` consults via `BaselineProvider` interface. Cached 15-min TTL in `kc/audit/anomaly_cache.go`, bounded 10K entries.
- **X-Request-ID**: propagates via `context.WithValue(ctx, requestIDCtxKey, id)`. Read with `app.RequestIDFromCtx(ctx)`. Logger: `app.LoggerWithRequestID(logger, ctx)`.
- **Version introspection**: `server_version` MCP tool returns git SHA (via `runtime/debug.ReadBuildInfo()`), uptime, region, env flags. No ldflags coupling.
- **Tool integrity manifest**: `mcp/integrity.go` hashes each tool's description at startup; logs mismatches (detects tool poisoning / line-jumping).

## 2026-04 tools added:
- `analyze_concall` — frames LLM for earnings-call analysis; returns structured metadata + WebFetch hints
- `get_fii_dii_flow` — FII/DII flow URL pointer + themes to extract
- `peer_compare` — PEG/Piotroski/Altman-Z structured report with external-data hints
- `server_version` — build SHA + uptime + region + env flags (for debugging)

## Path 2 compliance:
- `ENABLE_TRADING` env gates ~20 order-placement tools (place/modify/cancel/GTT/MF/trailing/native-alerts)
- Default: `false` on Fly.io (Path 2 hosted = read-only per NSE/INVG/69255 Annexure I Para 2.8)
- Local: `ENABLE_TRADING=true` preserves full trading (personal-use safe harbor — OpenAlgo precedent)
- See `docs/incident-response.md` Scenario 1-C: env flip is the 5-minute regulator panic button

## Commands:
```bash
go build ./...              # Build
go test ./... -count=1      # Test (uncached)
go test ./mcp/ -cover       # Coverage for mcp package
just lint                   # Lint
just test-race              # Race condition detection
flyctl deploy -a kite-mcp-server --remote-only  # Deploy
```
