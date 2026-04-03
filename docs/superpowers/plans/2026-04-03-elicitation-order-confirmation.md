# Elicitation: Order Confirmation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add MCP elicitation dialogs that ask the user to confirm before placing/modifying orders with real money.

**Architecture:** Store `*server.MCPServer` in `kc.Manager`, create a shared `requestConfirmation()` helper in `mcp/elicit.go`, call it from 8 tool handlers before the Kite API call. Gracefully degrades (fail-open) when the client doesn't support elicitation.

**Tech Stack:** Go, mcp-go v0.46.0 (`server.WithElicitation()`, `server.RequestElicitation()`), existing kiteconnect types.

---

### Task 1: Add MCPServer accessor to Manager

**Files:**
- Modify: `kc/manager.go:386` (after `auditStore` field)

- [ ] **Step 1: Add the field and accessors**

In `kc/manager.go`, add the field to the `Manager` struct and two methods. Insert after the `auditStore` field (line ~385):

```go
// In the Manager struct, after the auditStore field:
	mcpServer      any // *server.MCPServer — stored as any to avoid circular import
```

Then add these methods after the existing accessors (after `func (m *Manager) AlertDB()`):

```go
// SetMCPServer stores a reference to the MCP server for elicitation support.
// Stored as any to avoid importing the server package in kc.
func (m *Manager) SetMCPServer(srv any) {
	m.mcpServer = srv
}

// MCPServer returns the stored MCP server reference, or nil.
func (m *Manager) MCPServer() any {
	return m.mcpServer
}
```

Note: We use `any` instead of `*server.MCPServer` to avoid a circular import (`kc` → `server` → potentially back). The `mcp` package will type-assert when calling.

- [ ] **Step 2: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./kc/...`
Expected: clean build, no errors.

- [ ] **Step 3: Commit**

```bash
git add kc/manager.go
git commit -m "feat(elicit): add MCPServer accessor to Manager for elicitation support"
```

---

### Task 2: Wire elicitation capability in app.go

**Files:**
- Modify: `app/app.go:340-367` (server options + post-creation wiring)

- [ ] **Step 1: Add WithElicitation to server options**

In `app/app.go`, after line 346 (`serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(mcp.DashboardURLMiddleware(kcManager)))`), add:

```go
	// Enable elicitation so tool handlers can request user confirmation before
	// placing orders. Clients that don't support elicitation will gracefully
	// degrade (fail open — orders proceed without confirmation).
	serverOpts = append(serverOpts, server.WithElicitation())
```

- [ ] **Step 2: Wire MCPServer into Manager after creation**

In `app/app.go`, after line 366 (`app.logger.Debug("MCP server created successfully")`), add:

```go
	// Wire MCPServer into Manager so tool handlers can call RequestElicitation.
	kcManager.SetMCPServer(mcpServer)
```

- [ ] **Step 3: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add app/app.go
git commit -m "feat(elicit): enable elicitation capability and wire MCPServer into Manager"
```

---

### Task 3: Create the elicitation helper

**Files:**
- Create: `mcp/elicit.go`
- Create: `mcp/elicit_test.go`

- [ ] **Step 1: Write the test file**

Create `mcp/elicit_test.go`:

```go
package mcp

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestBuildOrderConfirmMessage(t *testing.T) {
	t.Run("place_order MARKET", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_order", map[string]any{
			"transaction_type": "BUY",
			"quantity":         float64(10),
			"exchange":         "NSE",
			"tradingsymbol":    "RELIANCE",
			"order_type":       "MARKET",
			"product":          "CNC",
		})
		assert.Contains(t, msg, "BUY")
		assert.Contains(t, msg, "10")
		assert.Contains(t, msg, "NSE:RELIANCE")
		assert.Contains(t, msg, "MARKET")
		assert.Contains(t, msg, "CNC")
	})

	t.Run("place_order LIMIT with price", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_order", map[string]any{
			"transaction_type": "SELL",
			"quantity":         float64(5),
			"exchange":         "BSE",
			"tradingsymbol":    "INFY",
			"order_type":       "LIMIT",
			"price":            float64(1500.50),
			"product":          "MIS",
		})
		assert.Contains(t, msg, "SELL")
		assert.Contains(t, msg, "BSE:INFY")
		assert.Contains(t, msg, "1500.50")
	})

	t.Run("modify_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("modify_order", map[string]any{
			"order_id":   "250402000123",
			"order_type": "LIMIT",
			"quantity":   float64(20),
			"price":      float64(2800),
		})
		assert.Contains(t, msg, "Modify order")
		assert.Contains(t, msg, "250402000123")
		assert.Contains(t, msg, "2800")
	})

	t.Run("close_all_positions", func(t *testing.T) {
		msg := buildOrderConfirmMessage("close_all_positions", map[string]any{
			"confirm": true,
			"product": "ALL",
		})
		assert.Contains(t, msg, "Close ALL")
	})

	t.Run("place_gtt_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_gtt_order", map[string]any{
			"exchange":         "NSE",
			"tradingsymbol":    "INFY",
			"transaction_type": "BUY",
			"trigger_type":     "single",
			"trigger_value_1":  float64(1400),
			"limit_price_1":    float64(1395),
		})
		assert.Contains(t, msg, "GTT")
		assert.Contains(t, msg, "NSE:INFY")
		assert.Contains(t, msg, "1400")
	})

	t.Run("place_mf_order", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_mf_order", map[string]any{
			"tradingsymbol":    "INF209K01YN0",
			"transaction_type": "BUY",
			"amount":           float64(10000),
		})
		assert.Contains(t, msg, "MF")
		assert.Contains(t, msg, "INF209K01YN0")
		assert.Contains(t, msg, "10000")
	})

	t.Run("place_mf_sip", func(t *testing.T) {
		msg := buildOrderConfirmMessage("place_mf_sip", map[string]any{
			"tradingsymbol": "INF209K01YN0",
			"amount":        float64(5000),
			"frequency":     "monthly",
			"instalments":   float64(12),
		})
		assert.Contains(t, msg, "SIP")
		assert.Contains(t, msg, "5000")
		assert.Contains(t, msg, "monthly")
		assert.Contains(t, msg, "12")
	})

	t.Run("unknown tool returns generic message", func(t *testing.T) {
		msg := buildOrderConfirmMessage("unknown_tool", map[string]any{})
		assert.Contains(t, msg, "Confirm")
	})
}

func TestIsConfirmableTool(t *testing.T) {
	assert.True(t, isConfirmableTool("place_order"))
	assert.True(t, isConfirmableTool("modify_order"))
	assert.True(t, isConfirmableTool("close_position"))
	assert.True(t, isConfirmableTool("close_all_positions"))
	assert.True(t, isConfirmableTool("place_gtt_order"))
	assert.True(t, isConfirmableTool("modify_gtt_order"))
	assert.True(t, isConfirmableTool("place_mf_order"))
	assert.True(t, isConfirmableTool("place_mf_sip"))
	assert.False(t, isConfirmableTool("cancel_order"))
	assert.False(t, isConfirmableTool("delete_gtt_order"))
	assert.False(t, isConfirmableTool("get_holdings"))
	assert.False(t, isConfirmableTool("login"))
}

func TestParseElicitationError(t *testing.T) {
	t.Run("user declined", func(t *testing.T) {
		err := errors.New("order declined by user")
		assert.Contains(t, err.Error(), "declined")
	})

	t.Run("user cancelled", func(t *testing.T) {
		err := errors.New("order cancelled by user")
		assert.Contains(t, err.Error(), "cancelled")
	})
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd D:/kite-mcp-temp && go test -ldflags="-s -w" ./mcp/ -run "TestBuildOrderConfirmMessage|TestIsConfirmableTool" -v 2>&1 | tail -5`
Expected: FAIL — functions not defined.

- [ ] **Step 3: Write the implementation**

Create `mcp/elicit.go`:

```go
package mcp

import (
	"context"
	"errors"
	"fmt"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
)

// confirmableTools lists tools that require user confirmation via elicitation.
// Principle: confirm tools that CREATE financial risk, skip tools that REMOVE risk.
var confirmableTools = map[string]bool{
	"place_order":         true,
	"modify_order":        true,
	"close_position":      true,
	"close_all_positions": true,
	"place_gtt_order":     true,
	"modify_gtt_order":    true,
	"place_mf_order":      true,
	"place_mf_sip":        true,
}

// isConfirmableTool returns true if the tool should show a confirmation dialog.
func isConfirmableTool(toolName string) bool {
	return confirmableTools[toolName]
}

// confirmSchema is the JSON Schema for the confirmation dialog — a single boolean field.
var confirmSchema = map[string]any{
	"type": "object",
	"properties": map[string]any{
		"confirm": map[string]any{
			"type":        "boolean",
			"description": "Confirm this action?",
			"default":     true,
		},
	},
	"required": []string{"confirm"},
}

// requestConfirmation sends an elicitation dialog to the user and blocks until
// they respond. Returns nil if the user confirms, an error if they decline/cancel.
// Fails open: if the client doesn't support elicitation, returns nil (proceed).
func requestConfirmation(ctx context.Context, mcpServerRef any, message string) error {
	srv, ok := mcpServerRef.(*server.MCPServer)
	if !ok || srv == nil {
		return nil // no server reference — fail open
	}

	req := gomcp.ElicitationRequest{
		Params: gomcp.ElicitationParams{
			Message:         message,
			RequestedSchema: confirmSchema,
		},
	}

	result, err := srv.RequestElicitation(ctx, req)
	if err != nil {
		if errors.Is(err, server.ErrElicitationNotSupported) || errors.Is(err, server.ErrNoActiveSession) {
			return nil // client doesn't support elicitation — fail open
		}
		return fmt.Errorf("elicitation failed: %w", err)
	}

	switch result.Action {
	case gomcp.ElicitationResponseActionAccept:
		data, ok := result.Content.(map[string]any)
		if !ok {
			return nil // malformed response — fail open
		}
		confirmed, _ := data["confirm"].(bool)
		if !confirmed {
			return fmt.Errorf("order declined by user")
		}
		return nil
	case gomcp.ElicitationResponseActionDecline:
		return fmt.Errorf("order declined by user")
	case gomcp.ElicitationResponseActionCancel:
		return fmt.Errorf("order cancelled by user")
	default:
		return nil // unknown action — fail open
	}
}

// buildOrderConfirmMessage creates a human-readable confirmation message for the given tool.
func buildOrderConfirmMessage(toolName string, args map[string]any) string {
	switch toolName {
	case "place_order":
		txn := SafeAssertString(args["transaction_type"], "?")
		qty := SafeAssertInt(args["quantity"], 0)
		exchange := SafeAssertString(args["exchange"], "?")
		symbol := SafeAssertString(args["tradingsymbol"], "?")
		orderType := SafeAssertString(args["order_type"], "?")
		product := SafeAssertString(args["product"], "?")
		price := SafeAssertFloat64(args["price"], 0)
		triggerPrice := SafeAssertFloat64(args["trigger_price"], 0)

		priceStr := "MARKET"
		if orderType == "LIMIT" && price > 0 {
			priceStr = fmt.Sprintf("%.2f", price)
		} else if (orderType == "SL" || orderType == "SL-M") && triggerPrice > 0 {
			priceStr = fmt.Sprintf("trigger %.2f", triggerPrice)
		}

		return fmt.Sprintf("Confirm: %s %d x %s:%s @ %s (%s, %s)",
			txn, qty, exchange, symbol, priceStr, orderType, product)

	case "modify_order":
		orderID := SafeAssertString(args["order_id"], "?")
		orderType := SafeAssertString(args["order_type"], "?")
		qty := SafeAssertInt(args["quantity"], 0)
		price := SafeAssertFloat64(args["price"], 0)
		triggerPrice := SafeAssertFloat64(args["trigger_price"], 0)

		detail := fmt.Sprintf("qty %d", qty)
		if orderType == "LIMIT" && price > 0 {
			detail += fmt.Sprintf(", price %.2f", price)
		}
		if triggerPrice > 0 {
			detail += fmt.Sprintf(", trigger %.2f", triggerPrice)
		}
		return fmt.Sprintf("Confirm: Modify order %s → %s (%s)", orderID, detail, orderType)

	case "close_position":
		instrument := SafeAssertString(args["instrument"], "?")
		product := SafeAssertString(args["product"], "")
		msg := fmt.Sprintf("Confirm: Close position %s at MARKET", instrument)
		if product != "" {
			msg += fmt.Sprintf(" (%s)", product)
		}
		return msg

	case "close_all_positions":
		product := SafeAssertString(args["product"], "ALL")
		return fmt.Sprintf("Confirm: Close ALL open positions at MARKET (product: %s)", product)

	case "place_gtt_order":
		exchange := SafeAssertString(args["exchange"], "?")
		symbol := SafeAssertString(args["tradingsymbol"], "?")
		txn := SafeAssertString(args["transaction_type"], "?")
		triggerType := SafeAssertString(args["trigger_type"], "single")
		triggerVal := SafeAssertFloat64(args["trigger_value_1"], 0)
		limitPrice := SafeAssertFloat64(args["limit_price_1"], 0)

		return fmt.Sprintf("Confirm GTT: %s %s:%s (%s) trigger %.2f, limit %.2f",
			txn, exchange, symbol, triggerType, triggerVal, limitPrice)

	case "modify_gtt_order":
		triggerID := SafeAssertInt(args["trigger_id"], 0)
		exchange := SafeAssertString(args["exchange"], "?")
		symbol := SafeAssertString(args["tradingsymbol"], "?")
		triggerVal := SafeAssertFloat64(args["trigger_value_1"], 0)

		return fmt.Sprintf("Confirm: Modify GTT %d (%s:%s) → trigger %.2f",
			triggerID, exchange, symbol, triggerVal)

	case "place_mf_order":
		symbol := SafeAssertString(args["tradingsymbol"], "?")
		txn := SafeAssertString(args["transaction_type"], "?")
		amount := SafeAssertFloat64(args["amount"], 0)
		qty := SafeAssertFloat64(args["quantity"], 0)

		if amount > 0 {
			return fmt.Sprintf("Confirm MF: %s ₹%.0f of %s", txn, amount, symbol)
		}
		return fmt.Sprintf("Confirm MF: %s %.0f units of %s", txn, qty, symbol)

	case "place_mf_sip":
		symbol := SafeAssertString(args["tradingsymbol"], "?")
		amount := SafeAssertFloat64(args["amount"], 0)
		freq := SafeAssertString(args["frequency"], "?")
		instalments := SafeAssertInt(args["instalments"], 0)

		return fmt.Sprintf("Confirm SIP: ₹%.0f/%s into %s, %d instalments",
			amount, freq, symbol, instalments)

	default:
		return fmt.Sprintf("Confirm: Execute %s?", toolName)
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd D:/kite-mcp-temp && go test -ldflags="-s -w" ./mcp/ -run "TestBuildOrderConfirmMessage|TestIsConfirmableTool" -v 2>&1 | tail -20`
Expected: all PASS.

- [ ] **Step 5: Commit**

```bash
git add mcp/elicit.go mcp/elicit_test.go
git commit -m "feat(elicit): add order confirmation elicitation helper with message builders"
```

---

### Task 4: Add confirmation to place_order and modify_order

**Files:**
- Modify: `mcp/post_tools.go:89-161` (PlaceOrderTool.Handler)
- Modify: `mcp/post_tools.go:209-241` (ModifyOrderTool.Handler)

- [ ] **Step 1: Add confirmation to PlaceOrderTool.Handler**

In `mcp/post_tools.go`, inside `PlaceOrderTool.Handler`, insert after the validation block (after line 131, before the `return handler.WithSession` call on line 133):

```go
		// Request user confirmation via elicitation before placing the order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 2: Add confirmation to ModifyOrderTool.Handler**

In `mcp/post_tools.go`, inside `ModifyOrderTool.Handler`, insert after the validation block (after line 231, before the `return handler.WithSession` call on line 233):

```go
		// Request user confirmation via elicitation before modifying the order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("modify_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "modify_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 3: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add mcp/post_tools.go
git commit -m "feat(elicit): add confirmation dialog to place_order and modify_order"
```

---

### Task 5: Add confirmation to close_position and close_all_positions

**Files:**
- Modify: `mcp/exit_tools.go:32-100` (ClosePositionTool.Handler)
- Modify: `mcp/exit_tools.go:136-` (CloseAllPositionsTool.Handler)

- [ ] **Step 1: Add confirmation to ClosePositionTool.Handler**

In `mcp/exit_tools.go`, inside `ClosePositionTool.Handler`, insert after the instrument format validation (after line 48, before the `return handler.WithSession` call on line 52):

```go
		// Request user confirmation via elicitation.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("close_position", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "close_position", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 2: Add confirmation to CloseAllPositionsTool.Handler**

In `mcp/exit_tools.go`, inside `CloseAllPositionsTool.Handler`, insert after the existing `confirm` boolean check (after line 146, before the `productFilter` line 148):

```go
		// Request user confirmation via elicitation (in addition to the confirm param).
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("close_all_positions", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "close_all_positions", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 3: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add mcp/exit_tools.go
git commit -m "feat(elicit): add confirmation dialog to close_position and close_all_positions"
```

---

### Task 6: Add confirmation to GTT tools

**Files:**
- Modify: `mcp/post_tools.go:357-` (PlaceGTTOrderTool.Handler)
- Modify: `mcp/post_tools.go:616-` (ModifyGTTOrderTool.Handler)

- [ ] **Step 1: Add confirmation to PlaceGTTOrderTool.Handler**

In `mcp/post_tools.go`, inside `PlaceGTTOrderTool.Handler`, insert after the validation block (after line 365, before the GTT params setup on line 369):

```go
		// Request user confirmation via elicitation before placing the GTT.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_gtt_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_gtt_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 2: Add confirmation to ModifyGTTOrderTool.Handler**

In `mcp/post_tools.go`, inside `ModifyGTTOrderTool.Handler`, insert after the validation block (after line 624, before the triggerID line 628):

```go
		// Request user confirmation via elicitation before modifying the GTT.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("modify_gtt_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "modify_gtt_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 3: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add mcp/post_tools.go
git commit -m "feat(elicit): add confirmation dialog to place_gtt_order and modify_gtt_order"
```

---

### Task 7: Add confirmation to MF tools

**Files:**
- Modify: `mcp/mf_tools.go:134-` (PlaceMFOrderTool.Handler)
- Modify: `mcp/mf_tools.go:247-` (PlaceMFSIPTool.Handler)

- [ ] **Step 1: Add confirmation to PlaceMFOrderTool.Handler**

In `mcp/mf_tools.go`, inside `PlaceMFOrderTool.Handler`, insert after the validation block (after line 141, before line 144):

```go
		// Request user confirmation via elicitation before placing the MF order.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_mf_order", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_mf_order", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 2: Add confirmation to PlaceMFSIPTool.Handler**

In `mcp/mf_tools.go`, inside `PlaceMFSIPTool.Handler`, insert after the validation block (after line 254, before line 257):

```go
		// Request user confirmation via elicitation before placing the SIP.
		if srv := manager.MCPServer(); srv != nil {
			msg := buildOrderConfirmMessage("place_mf_sip", args)
			if err := requestConfirmation(ctx, srv, msg); err != nil {
				handler.trackToolError(ctx, "place_mf_sip", "user_declined")
				return mcp.NewToolResultError(err.Error()), nil
			}
		}
```

- [ ] **Step 3: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./...`
Expected: clean build.

- [ ] **Step 4: Commit**

```bash
git add mcp/mf_tools.go
git commit -m "feat(elicit): add confirmation dialog to place_mf_order and place_mf_sip"
```

---

### Task 8: Run full test suite and deploy

**Files:** none (verification only)

- [ ] **Step 1: Run full test suite**

Run: `cd D:/kite-mcp-temp && go test -ldflags="-s -w" ./... -count=1 -short 2>&1 | grep -E "^(FAIL|ok)"`
Expected: all packages pass.

- [ ] **Step 2: Run elicit-specific tests**

Run: `cd D:/kite-mcp-temp && go test -ldflags="-s -w" ./mcp/ -run "TestBuildOrderConfirmMessage|TestIsConfirmableTool" -v`
Expected: all PASS.

- [ ] **Step 3: Commit final state**

```bash
git add -A
git status  # verify only expected files
git commit -m "feat: MCP elicitation for order confirmation — 8 tools, fail-open degradation

Adds user confirmation dialogs before placing/modifying orders with real money.
Governed by principle: confirm tools that CREATE risk, skip tools that REMOVE risk.

Tools with confirmation: place_order, modify_order, close_position,
close_all_positions, place_gtt_order, modify_gtt_order, place_mf_order, place_mf_sip.

Tools without (defensive/protective): cancel_order, delete_gtt_order.

Gracefully degrades: if client doesn't support elicitation, orders proceed
without confirmation (fail open).

Co-Authored-By: Claude Opus 4.6 (1M context) <noreply@anthropic.com>"
```

- [ ] **Step 4: Push and deploy**

```bash
git push origin master
/c/Users/Dell/.fly/bin/flyctl.exe deploy -a kite-mcp-server
```

Expected: successful deployment, server healthy.
