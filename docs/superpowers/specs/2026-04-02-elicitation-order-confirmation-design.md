# Elicitation: Order Confirmation Design

## Problem

Claude AI places real orders on Zerodha Kite with real money. There is no human confirmation gate — if Claude hallucminates a wrong symbol, quantity, or price, the order executes immediately. AI models achieve only ~67% accuracy on financial tool use (arXiv 2510.00332).

## Solution

Use MCP elicitation (server-initiated user input) to pause order execution and show a confirmation dialog. The user sees a summary of what's about to happen and clicks Accept or Decline.

## Governing Principle

**Confirm tools that CREATE financial risk. Skip tools that REMOVE risk.**

| Tool | Confirm | Rationale |
|------|---------|-----------|
| `place_order` | YES | New order, unbounded blast radius |
| `modify_order` | YES | Can change approved params catastrophically (LIMIT→MARKET) |
| `close_position` | YES | MARKET order under the hood |
| `close_all_positions` | YES | Maximum blast radius, bulk action |
| `place_gtt_order` | YES | Time-bomb: triggers later, 6+ params |
| `modify_gtt_order` | YES | Same as place_gtt |
| `place_mf_order` | YES | Real money, wrong ISIN risk |
| `place_mf_sip` | YES | Recurring commitment, compounds if wrong |
| `cancel_order` | NO | Removes risk, zero loss, time-sensitive, easily re-placed |
| `delete_gtt_order` | NO | Removes standing trigger, parallel to cancel |

## Architecture

### Plumbing

Store `*server.MCPServer` in `kc.Manager` so any tool handler can call `RequestElicitation`:

```go
// kc/manager.go
func (m *Manager) SetMCPServer(srv *server.MCPServer) { m.mcpServer = srv }
func (m *Manager) MCPServer() *server.MCPServer       { return m.mcpServer }
```

Wire in `app.go` after creating the MCP server:

```go
serverOpts = append(serverOpts, server.WithElicitation())
mcpServer := server.NewMCPServer("Kite MCP Server", app.Version, serverOpts...)
kcManager.SetMCPServer(mcpServer)
```

### Confirmation Helper

A shared `requestConfirmation()` function in a new file `mcp/elicit.go`:

```go
func requestConfirmation(ctx context.Context, srv *server.MCPServer, message string) error
```

- Builds an `ElicitationRequest` with the message and a single boolean `confirm` field
- Sends via `srv.RequestElicitation(ctx, req)` — blocks until user responds
- Returns `nil` on Accept (proceed), error on Decline/Cancel
- If client doesn't support elicitation (`ErrElicitationNotSupported`): returns nil (fail open)

### Confirmation Message Format

Each tool builds a human-readable summary:

```
place_order:          "Confirm: BUY 10 x NSE:RELIANCE @ MARKET (CNC)"
modify_order:         "Confirm modify order 250402000123: price 2500 → 2800"
close_position:       "Confirm: SELL 50 x NFO:NIFTY24APR24000CE @ MARKET"
close_all_positions:  "Confirm: Close ALL 5 open positions at MARKET"
place_gtt_order:      "Confirm GTT: BUY 10 x NSE:INFY trigger ≤1400, limit 1395"
modify_gtt_order:     "Confirm GTT modify 12345: trigger 1400 → 1350"
place_mf_order:       "Confirm MF: BUY ₹10,000 of INF209K01YN0 (Axis Bluechip)"
place_mf_sip:         "Confirm SIP: ₹5,000/month into INF209K01YN0, 12 instalments"
```

### Graceful Degradation

If `RequestElicitation` returns `ErrElicitationNotSupported`:
- **Fail open** — order proceeds without confirmation
- This ensures backward compatibility with mcp-remote and older MCP clients
- The existing `destructiveHint: true` annotation still tells Claude to ask the user in text

### Flow (place_order example)

```
1. Validate params           (existing)
2. requestConfirmation()     (NEW — blocking, user-paced)
   → User sees: "Confirm: BUY 10 x NSE:RELIANCE @ MARKET (CNC)"
   → User clicks Accept or Decline
3. If declined → return error "Order cancelled by user"
4. Place order via Kite API  (existing)
5. 1.5s fill check           (existing)
```

## Files to Modify

| File | Change |
|------|--------|
| `kc/manager.go` | Add `mcpServer` field, `SetMCPServer()`, `MCPServer()` |
| `app/app.go` | Add `server.WithElicitation()` to serverOpts, call `kcManager.SetMCPServer(mcpServer)` after creation |
| `mcp/elicit.go` | **New** — `requestConfirmation()` helper, `confirmableTools` set, message builders per tool |
| `mcp/post_tools.go` | Add confirmation call in `PlaceOrderTool.Handler` and `ModifyOrderTool.Handler` before `WithSession` |
| `mcp/exit_tools.go` | Add confirmation in `ClosePositionTool.Handler` and `CloseAllPositionsTool.Handler` |
| `mcp/gtt_tools.go` | Add confirmation in `PlaceGTTTool.Handler` and `ModifyGTTTool.Handler` |
| `mcp/mf_tools.go` | Add confirmation in `PlaceMFOrderTool.Handler` and `PlaceMFSIPTool.Handler` |
| `mcp/elicit_test.go` | **New** — test confirmation helper with mock sessions |

## Client UX

| Client | Rendering |
|--------|-----------|
| Claude Code CLI (2.1.76+) | Native form dialog with Accept/Decline buttons |
| Claude Desktop | Same native dialog |
| claude.ai web | Inline form in chat |
| VS Code Copilot | Inline widget |
| Older clients / mcp-remote | Fail open (no dialog, order proceeds) |

## Design Decisions

1. **All orders confirm, not just large ones** — AI hallucination risk is independent of order size. A 1-share order with the wrong symbol is still wrong.

2. **Fail open, not fail closed** — if the client can't show the dialog, the order still goes through. This preserves backward compatibility. The alternative (fail closed) would break existing workflows.

3. **Single boolean field** — the elicitation schema is a single `confirm: boolean` with default `true`. The message itself carries all the information. We don't ask the user to re-enter parameters.

4. **No timeout** — `RequestElicitation` blocks until the user responds. There is no server-side timeout. The user controls the pace.

5. **Cancel and delete skip confirmation** — these are defensive actions that remove risk. Adding friction to defense is counterproductive. If cancelled by mistake, re-placement goes through confirmation.

## Not In Scope

- Per-user opt-out of confirmation (future: add to risk_limits table)
- Threshold-based confirmation (only confirm orders > X value) — all orders confirm for now
- Elicitation for read-only tools — no confirmation needed for queries
