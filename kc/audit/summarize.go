package audit

import (
	"fmt"
	"sort"
	"strings"

	gomcp "github.com/mark3labs/mcp-go/mcp"
)

// SummarizeInput returns a human-readable one-line summary of tool input parameters.
// It has specific formatters for known tools and a generic fallback for unknown ones.
func SummarizeInput(toolName string, args map[string]any) string {
	if len(args) == 0 {
		return "(no params)"
	}

	switch toolName {
	case "place_order", "modify_order":
		return summarizePlaceOrder(args)
	case "cancel_order":
		return summarizeCancelOrder(args)
	case "place_gtt_order", "modify_gtt_order":
		return summarizeGTTOrder(args)
	case "delete_gtt_order":
		return summarizeDeleteGTT(args)
	case "get_ltp", "get_ohlc", "get_quotes":
		return strVal(args, "instruments")
	case "search_instruments":
		return fmt.Sprintf("search %q", strVal(args, "query"))
	case "get_historical_data":
		return summarizeHistoricalData(args)
	case "set_alert":
		return summarizeSetAlert(args)
	case "delete_alert":
		return fmt.Sprintf("Delete alert %s", strVal(args, "alert_id"))
	case "start_ticker", "stop_ticker":
		return strVal(args, "email")
	case "subscribe_instruments", "unsubscribe_instruments":
		return strVal(args, "instruments")
	case "setup_telegram":
		return fmt.Sprintf("chat_id=%s", strVal(args, "chat_id"))
	case "get_order_history", "get_order_trades":
		return fmt.Sprintf("order %s", strVal(args, "order_id"))
	default:
		return summarizeDefault(args)
	}
}

// SummarizeOutput returns a human-readable summary of tool output.
func SummarizeOutput(toolName string, result *gomcp.CallToolResult) string {
	if result == nil {
		return "(no result)"
	}

	if result.IsError {
		text := extractText(result)
		if text == "" {
			return "ERROR: (empty)"
		}
		return truncate("ERROR: "+text, 200)
	}

	text := extractText(result)
	if text == "" {
		return "(empty response)"
	}
	return truncate(text, 200)
}

// extractText gets text from the first TextContent in result.Content.
func extractText(result *gomcp.CallToolResult) string {
	if result == nil {
		return ""
	}
	for _, c := range result.Content {
		if tc, ok := gomcp.AsTextContent(c); ok {
			return tc.Text
		}
	}
	return ""
}

// summarizePlaceOrder formats: "BUY 10 RELIANCE NSE MARKET CNC"
func summarizePlaceOrder(args map[string]any) string {
	parts := []string{
		strings.ToUpper(strVal(args, "transaction_type")),
		strVal(args, "quantity"),
		strings.ToUpper(strVal(args, "tradingsymbol")),
		strings.ToUpper(strVal(args, "exchange")),
		strings.ToUpper(strVal(args, "order_type")),
		strings.ToUpper(strVal(args, "product")),
	}
	return strings.Join(nonEmpty(parts), " ")
}

// summarizeCancelOrder formats: "Cancel regular 220101000012345"
func summarizeCancelOrder(args map[string]any) string {
	variety := strVal(args, "variety")
	if variety == "" {
		variety = "regular"
	}
	return fmt.Sprintf("Cancel %s %s", variety, strVal(args, "order_id"))
}

// summarizeGTTOrder formats: "GTT BUY RELIANCE 10 @ 2800"
func summarizeGTTOrder(args map[string]any) string {
	txnType := strings.ToUpper(strVal(args, "transaction_type"))
	symbol := strings.ToUpper(strVal(args, "tradingsymbol"))
	qty := strVal(args, "quantity")
	triggerPrice := strVal(args, "trigger_price")
	return fmt.Sprintf("GTT %s %s %s @ %s", txnType, symbol, qty, triggerPrice)
}

// summarizeDeleteGTT formats: "Delete GTT 123456"
func summarizeDeleteGTT(args map[string]any) string {
	return fmt.Sprintf("Delete GTT %s", strVal(args, "trigger_id"))
}

// summarizeHistoricalData formats: "NSE:RELIANCE 5minute 2026-03-01->2026-03-26"
func summarizeHistoricalData(args map[string]any) string {
	instrID := strVal(args, "instrument_id")
	interval := strVal(args, "interval")
	from := strVal(args, "from")
	to := strVal(args, "to")
	return fmt.Sprintf("%s %s %s\u2192%s", instrID, interval, from, to)
}

// summarizeSetAlert formats: "RELIANCE above 2800"
// Extracts symbol from instrument_id which is "exchange:symbol".
func summarizeSetAlert(args map[string]any) string {
	instrID := strVal(args, "instrument_id")
	symbol := instrID
	if idx := strings.Index(instrID, ":"); idx >= 0 {
		symbol = instrID[idx+1:]
	}
	direction := strVal(args, "direction")
	targetPrice := strVal(args, "target_price")
	return fmt.Sprintf("%s %s %s", symbol, direction, targetPrice)
}

// summarizeDefault lists first 3 param keys for unknown tools.
func summarizeDefault(args map[string]any) string {
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	n := len(keys)
	if n <= 3 {
		return fmt.Sprintf("%d params: %s", n, strings.Join(keys, ", "))
	}
	return fmt.Sprintf("%d params: %s...", n, strings.Join(keys[:3], ", "))
}

// strVal safely extracts a string value from the args map.
// Returns "" if the key is missing or the value is not a string-like type.
func strVal(args map[string]any, key string) string {
	v, ok := args[key]
	if !ok || v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// nonEmpty filters out empty strings from a slice.
func nonEmpty(parts []string) []string {
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// truncate shortens s to maxLen characters, appending "..." if truncated.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	if maxLen <= 3 {
		return s[:maxLen]
	}
	return s[:maxLen-3] + "..."
}
