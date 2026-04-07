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
	"place_native_alert":  true, // ATO alerts auto-place orders
	"modify_native_alert": true, // ATO alert modifications
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
	p := NewArgParser(args)
	switch toolName {
	case "place_order":
		txn := p.String("transaction_type", "?")
		qty := p.Int("quantity", 0)
		exchange := p.String("exchange", "?")
		symbol := p.String("tradingsymbol", "?")
		orderType := p.String("order_type", "?")
		product := p.String("product", "?")
		price := p.Float("price", 0)
		triggerPrice := p.Float("trigger_price", 0)

		priceStr := "MARKET"
		if orderType == "LIMIT" && price > 0 {
			priceStr = fmt.Sprintf("%.2f", price)
		} else if (orderType == "SL" || orderType == "SL-M") && triggerPrice > 0 {
			priceStr = fmt.Sprintf("trigger %.2f", triggerPrice)
		}

		return fmt.Sprintf("Confirm: %s %d x %s:%s @ %s (%s, %s)",
			txn, qty, exchange, symbol, priceStr, orderType, product)

	case "modify_order":
		orderID := p.String("order_id", "?")
		orderType := p.String("order_type", "?")
		qty := p.Int("quantity", 0)
		price := p.Float("price", 0)
		triggerPrice := p.Float("trigger_price", 0)

		detail := fmt.Sprintf("qty %d", qty)
		if orderType == "LIMIT" && price > 0 {
			detail += fmt.Sprintf(", price %.2f", price)
		}
		if triggerPrice > 0 {
			detail += fmt.Sprintf(", trigger %.2f", triggerPrice)
		}
		return fmt.Sprintf("Confirm: Modify order %s → %s (%s)", orderID, detail, orderType)

	case "close_position":
		instrument := p.String("instrument", "?")
		product := p.String("product", "")
		msg := fmt.Sprintf("Confirm: Close position %s at MARKET", instrument)
		if product != "" {
			msg += fmt.Sprintf(" (%s)", product)
		}
		return msg

	case "close_all_positions":
		product := p.String("product", "ALL")
		return fmt.Sprintf("Confirm: Close ALL open positions at MARKET (product: %s)", product)

	case "place_gtt_order":
		exchange := p.String("exchange", "?")
		symbol := p.String("tradingsymbol", "?")
		txn := p.String("transaction_type", "?")
		triggerType := p.String("trigger_type", "single")
		triggerVal := p.Float("trigger_value", 0)
		limitPrice := p.Float("limit_price", 0)

		return fmt.Sprintf("Confirm GTT: %s %s:%s (%s) trigger %.2f, limit %.2f",
			txn, exchange, symbol, triggerType, triggerVal, limitPrice)

	case "modify_gtt_order":
		triggerID := p.Int("trigger_id", 0)
		exchange := p.String("exchange", "?")
		symbol := p.String("tradingsymbol", "?")
		triggerVal := p.Float("trigger_value", 0)

		return fmt.Sprintf("Confirm: Modify GTT %d (%s:%s) → trigger %.2f",
			triggerID, exchange, symbol, triggerVal)

	case "place_mf_order":
		symbol := p.String("tradingsymbol", "?")
		txn := p.String("transaction_type", "?")
		amount := p.Float("amount", 0)
		qty := p.Float("quantity", 0)

		if amount > 0 {
			return fmt.Sprintf("Confirm MF: %s ₹%.0f of %s", txn, amount, symbol)
		}
		return fmt.Sprintf("Confirm MF: %s %.0f units of %s", txn, qty, symbol)

	case "place_mf_sip":
		symbol := p.String("tradingsymbol", "?")
		amount := p.Float("amount", 0)
		freq := p.String("frequency", "?")
		instalments := p.Int("instalments", 0)

		return fmt.Sprintf("Confirm SIP: ₹%.0f/%s into %s, %d instalments",
			amount, freq, symbol, instalments)

	case "place_native_alert":
		name := p.String("name", "?")
		alertType := p.String("type", "simple")
		exchange := p.String("exchange", "?")
		symbol := p.String("tradingsymbol", "?")
		operator := p.String("operator", "?")
		rhsType := p.String("rhs_type", "constant")
		rhs := fmt.Sprintf("%.2f", p.Float("rhs_constant", 0))
		if rhsType == "instrument" {
			rhs = fmt.Sprintf("%s:%s", p.String("rhs_exchange", "?"), p.String("rhs_tradingsymbol", "?"))
		}
		return fmt.Sprintf("Confirm: Create %s alert '%s' — %s:%s %s %s",
			alertType, name, exchange, symbol, operator, rhs)

	case "modify_native_alert":
		uuid := p.String("uuid", "?")
		name := p.String("name", "?")
		alertType := p.String("type", "simple")
		exchange := p.String("exchange", "?")
		symbol := p.String("tradingsymbol", "?")
		operator := p.String("operator", "?")

		return fmt.Sprintf("Confirm: Modify %s alert %s ('%s') — %s:%s %s",
			alertType, uuid, name, exchange, symbol, operator)

	default:
		return fmt.Sprintf("Confirm: Execute %s?", toolName)
	}
}
