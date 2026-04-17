# How to add a new MCP tool

A walkthrough for contributors using the recently-added `test_ip_whitelist` tool (`mcp/setup_tool.go`) as the worked example. Read this end-to-end, then open `mcp/setup_tool.go` in a second pane — the whole file is ~100 lines and every pattern in this guide appears there.

For the deeper architecture story (CQRS, hexagonal ports, use cases), see `ARCHITECTURE.md`. This doc focuses on the 80% case: a typical read-only tool that wraps a broker call and returns structured data.

## 1. What is an MCP tool in this codebase?

An MCP tool is a Go type that implements the `mcp.Tool` interface:

```go
type Tool interface {
    Tool() gomcp.Tool                        // metadata: name, description, schema, annotations
    Handler(*kc.Manager) server.ToolHandlerFunc  // the actual function Claude calls
}
```

Every tool goes through `ToolHandler` (defined in `mcp/common.go`). `NewToolHandler(manager)` wires in the broker resolver, audit tracking, token-expiry detection, and RBAC — none of which you have to write per-tool. The handler's helpers (`WithSession`, `MarshalResponse`, `trackToolCall`) give you a clean call site.

The MCP spec requires three things from each tool: a unique snake_case name, a user-facing description, and annotations (read-only, idempotent, destructive, open-world). Everything else is server-side convention.

## 2. Create the tool file

Conventionally one file per logical tool group. For a new tool `your_tool`, create `mcp/your_tool.go`. Use `setup_tool.go` as the template:

```go
package mcp

import (
    "context"

    "github.com/mark3labs/mcp-go/mcp"
    "github.com/mark3labs/mcp-go/server"
    "github.com/zerodha/kite-mcp-server/kc"
)

type YourTool struct{}

func (*YourTool) Tool() mcp.Tool {
    return mcp.NewTool("your_tool",
        mcp.WithDescription("One short sentence. End with 'Not investment advice.' if advisory."),
        mcp.WithTitleAnnotation("Your Tool"),
        mcp.WithReadOnlyHintAnnotation(true),
        mcp.WithIdempotentHintAnnotation(true),
        mcp.WithOpenWorldHintAnnotation(true),
        // ... mcp.WithString / WithNumber / WithBoolean for each param
    )
}

func (*YourTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
    handler := NewToolHandler(manager)
    return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
        handler.trackToolCall(ctx, "your_tool")
        // body goes here
    }
}
```

The struct itself holds no state — all dependencies flow through `manager` and `handler`.

## 3. Parse arguments

Use `NewArgParser` plus `ValidateRequired`. The parser coerces `interface{}` to the right Go type with fallbacks:

```go
args := request.GetArguments()
if err := ValidateRequired(args, "instrument", "quantity"); err != nil {
    return mcp.NewToolResultError(err.Error()), nil
}

p := NewArgParser(args)
instrument := p.String("instrument", "")
qty := p.Int("quantity", 0)
limitPrice := p.Float("price", 0)
enable := p.Bool("enable", false)
tags := p.StringArray("tags")  // returns []string; handles both JSON array and single string
```

`NewArgParser` lives in `mcp/common.go`. The `Safe*` variants (`SafeAssertInt`, `SafeAssertFloat64`) handle the JSON quirk where numbers arrive as `float64` — use them if you're unwrapping a nested value outside the parser's coverage.

## 4. Call the broker

Two patterns, pick one:

**Pattern A: `handler.WithSession` for per-user Kite broker access**

Used when the tool needs a valid Kite session. `WithSession` handles session lookup, creates a new one if needed, runs the RBAC viewer-block, and enforces token refresh if the cached token expired.

```go
return handler.WithSession(ctx, "your_tool", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
    profile, err := session.Broker.GetProfile()
    if err != nil {
        return mcp.NewToolResultError(err.Error()), nil
    }
    return handler.MarshalResponse(profile, "your_tool")
})
```

**Pattern B: CQRS buses for domain operations**

Per the TDD/architecture rules in `.claude/CLAUDE.md`, new broker-touching tool handlers should route through use cases. For read paths, dispatch a `Query`; for write paths, dispatch a `Command`:

```go
raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetHistoricalDataQuery{
    Email:           session.Email,
    InstrumentToken: token,
    Interval:        "day",
    From:            from,
    To:              now,
})
if err != nil { ... }
candles := raw.([]broker.HistoricalCandle)
```

See `mcp/backtest_tool.go` for the canonical CQRS-within-WithSession pattern, and `mcp/paper_tools.go` for command-bus writes that skip `WithSession` (paper mode doesn't need the Kite broker).

## 5. Marshal the response

Use `handler.MarshalResponse(data, toolName)`. It:

1. JSON-marshals `data` for the text fallback.
2. Wraps the value in `{"items": ...}` if it's a naked array or primitive (MCP spec requires `structuredContent` to be a JSON object, not an array — see `mcp/common_response.go`).
3. Returns a `*mcp.CallToolResult` with both text and structured content populated.

```go
type yourResponse struct {
    Status string `json:"status"`
    Data   any    `json:"data"`
}
resp := &yourResponse{Status: "ok", Data: result}
return handler.MarshalResponse(resp, "your_tool")
```

Arrays get auto-wrapped (the fix that unblocked strict Zod-validated clients like Claude Code): if you return `[]Holding{...}`, the structured content becomes `{"items": [...]}`. Clients that only read the text fallback still see the naked array.

## 6. Register the tool

Open `mcp/mcp.go` and add your tool struct to the `GetAllTools()` built-in slice, in the right category. Example:

```go
// Tools for setting up the client
&LoginTool{},
&OpenDashboardTool{},
&TestIPWhitelistTool{},
&YourTool{},   // <-- add here
```

Categories are comment-delimited — pick the closest one. `GetAllTools()` is consumed by both `RegisterTools` at startup and `init()` (which derives the `writeTools` set from annotations to power the viewer RBAC). Adding to this slice is the single source of truth; no other registration file to edit.

## 7. Bind to a widget (optional)

If your tool's response should render inside a dashboard widget in MCP App hosts (claude.ai, ChatGPT, VS Code):

1. Add your tool name → dashboard page path in `toolDashboardPage` in `mcp/setup_tools.go`.
2. Make sure the page path has a matching `ui://` URI in `pagePathToResourceURI` in `mcp/ext_apps.go`.
3. If you're adding a *new* widget (not reusing an existing one), add an `appResource{}` entry in `appResources` and drop a `*_app.html` template in `kc/templates/`.

`RegisterTools` then auto-injects the `_meta["ui/resourceUri"]` field so supporting clients render the widget inline. The `DashboardURLMiddleware` also appends a dashboard URL hint to the text response for clients that don't support MCP Apps.

## 8. Write tests

Follow the table-driven pattern from `mcp/tool_handler_test.go`. Two helpers cover most cases:

**For tool calls that need a full Manager with session/broker wiring**, use `callToolWithManager` (in `helpers_test.go`):

```go
func TestYourTool_HappyPath(t *testing.T) {
    mgr := newTestManager(t)  // kcfixture.NewTestManager with RiskGuard
    result := callToolWithManager(t, mgr, "your_tool", "user@example.com", map[string]any{
        "instrument": "NSE:INFY",
    })
    require.False(t, result.IsError)
    assertResultContains(t, result, "expected substring")
}
```

**For admin tools**, use `newAdminTestManager` + `seedUsers` + `callAdminTool`:

```go
mgr := newAdminTestManager(t)
seedUsers(t, mgr)
result := callAdminTool(t, mgr, "admin_list_users", "admin@example.com", map[string]any{})
```

**For pure unit tests of helper functions**, use the mock broker at `broker/mock/client.go` (`SetQuotes`, `SetGTTs`, etc.) without constructing a full Manager.

Per the TDD rule in `.claude/CLAUDE.md`: write the test first, run it, watch it fail, then implement. Target 80%+ coverage for new code (90%+ for billing/auth/orders).

## 9. Build, vet, test

```bash
go build ./...
go vet ./...
go test ./mcp/ -count=1
go test ./mcp/ -cover  # optional: verify your coverage target
just lint              # full lint + race check
```

The `-count=1` flag disables the test cache so you actually run your new test. Run the full suite at least once before opening a PR; `just test-race` catches concurrency bugs that occasionally slip past the default test.

## 10. Gotchas

A short list of things that have bitten previous contributors:

- **Disclaimer**: if the tool has any advisory framing (signals, rebalance suggestions, backtest results), end the description with "Not investment advice." — see `backtest_tool.go`, `rebalance_tool.go`, `options_greeks_tool.go` for examples.
- **Annotations**: set `ReadOnlyHint`, `IdempotentHint`, `OpenWorldHint`, `DestructiveHint` accurately. `ReadOnlyHint=true` auto-removes your tool from the viewer-RBAC blocklist; `DestructiveHint=true` signals clients to surface extra-scary confirmation UI.
- **RiskGuard**: order-placing tools go through the RiskGuard middleware (`kc/riskguard/`). It can reject with `global freeze`, `user freeze`, `daily limit`, `duplicate order`, or `rate limit`. Return the error as-is — don't swallow it.
- **Rate limiter + audit**: both are wired via middleware in the chain (`mcp.go` registration). You do **not** add logging/rate-limit code to your handler; `trackToolCall` is just for per-session metric counters.
- **SAC-blocked tests on Windows**: some tests hit the filesystem or spawn processes that Windows Smart App Control flags. Run on Linux/CI, or use `go test -run=^$ ./mcp/...` to compile-only if you're just checking your new file builds.
- **Widget data injection**: if you add a widget template, data is injected into `__INJECTED_DATA__` as a JSON literal. `mcp/ext_apps.go` already escapes `</`, `<!--`, U+2028, and U+2029 — don't duplicate that work, but don't bypass it by constructing your own HTML either.
- **Admin authorisation**: use `withAdminCheck` (`mcp/admin_tools.go`). It extracts the caller's email, checks `UserStore.IsAdmin`, and returns the standard error result on failure. Don't reinvent the check — inconsistent error messages leak role information.

Welcome to the codebase.
