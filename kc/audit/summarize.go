package audit

import (
	"encoding/json"
	"fmt"
	"math"
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
	case "convert_position":
		return fmt.Sprintf("Convert %s %s %s→%s qty=%v",
			strVal(args, "tradingsymbol"),
			strVal(args, "exchange"),
			strVal(args, "old_product"),
			strVal(args, "new_product"),
			args["quantity"])
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
// It has per-tool formatters that produce concise summaries instead of raw JSON.
func SummarizeOutput(toolName string, result *gomcp.CallToolResult) string {
	if result == nil {
		return "(no result)"
	}

	text := extractText(result)

	if result.IsError {
		if text == "" {
			return "ERROR: (empty)"
		}
		return truncate("ERROR: "+text, 200)
	}

	if text == "" {
		return "(empty response)"
	}

	// Per-tool smart summaries.
	switch toolName {
	case "get_holdings":
		return summarizeHoldings(text)
	case "get_positions":
		return summarizePositions(text)
	case "get_orders":
		return summarizeOrders(text)
	case "get_profile":
		return summarizeProfile()
	case "place_order", "modify_order":
		return summarizeOrderResult(text)
	case "get_ltp":
		return summarizeLTP(text)
	case "get_margins":
		return summarizeMargins(text)
	case "search_instruments":
		return summarizeSearch(text)
	}

	// Default: truncate.
	return truncate(text, 200)
}

// --- Per-tool output summarizers ---

// summarizeHoldings parses holdings JSON and produces a compact summary.
// Expected format: {"data": [...], "pagination": {...}} or a raw array.
func summarizeHoldings(text string) string {
	items := extractDataArray(text)
	if items == nil {
		return truncate(text, 200)
	}
	n := len(items)
	if n == 0 {
		return "No holdings"
	}

	var totalInvested, totalCurrent float64
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		avgPrice := jsonFloat(m, "average_price")
		qty := jsonFloat(m, "quantity")
		lastPrice := jsonFloat(m, "last_price")
		totalInvested += avgPrice * qty
		totalCurrent += lastPrice * qty
	}
	return fmt.Sprintf("%d holdings, invested %s, current %s", n, formatRupee(totalInvested), formatRupee(totalCurrent))
}

// summarizePositions parses positions JSON and produces a compact summary.
func summarizePositions(text string) string {
	items := extractDataArray(text)
	if items == nil {
		return truncate(text, 200)
	}
	n := len(items)
	if n == 0 {
		return "No positions"
	}
	var dayPnL float64
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		dayPnL += jsonFloat(m, "pnl")
	}
	return fmt.Sprintf("%d positions, day P&L %s", n, formatRupee(dayPnL))
}

// summarizeOrders parses orders JSON and counts by status.
func summarizeOrders(text string) string {
	items := extractDataArray(text)
	if items == nil {
		return truncate(text, 200)
	}
	n := len(items)
	if n == 0 {
		return "No orders"
	}
	statusCounts := make(map[string]int)
	for _, item := range items {
		m, ok := item.(map[string]any)
		if !ok {
			continue
		}
		status := strings.ToLower(jsonString(m, "status"))
		if status == "" {
			status = "unknown"
		}
		statusCounts[status]++
	}
	parts := make([]string, 0, len(statusCounts))
	for status, count := range statusCounts {
		parts = append(parts, fmt.Sprintf("%d %s", count, status))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d orders (%s)", n, strings.Join(parts, ", "))
}

// summarizeProfile returns a fixed string to avoid PII leakage (name, email, PAN).
func summarizeProfile() string {
	return "Profile retrieved"
}

// summarizeOrderResult extracts the order_id from the response.
func summarizeOrderResult(text string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return truncate(text, 200)
	}
	// Check for data.order_id or order_id
	if data, ok := obj["data"].(map[string]any); ok {
		if oid := jsonString(data, "order_id"); oid != "" {
			return "Order ID: " + oid
		}
	}
	if oid := jsonString(obj, "order_id"); oid != "" {
		return "Order ID: " + oid
	}
	return truncate(text, 200)
}

// summarizeLTP extracts instrument prices.
func summarizeLTP(text string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return truncate(text, 200)
	}
	// Try "data" key first, then top-level
	data, ok := obj["data"].(map[string]any)
	if !ok {
		data = obj
	}
	if len(data) == 0 {
		return truncate(text, 200)
	}
	parts := make([]string, 0, len(data))
	for key, val := range data {
		m, ok := val.(map[string]any)
		if !ok {
			continue
		}
		ltp := jsonFloat(m, "last_price")
		// Extract symbol from "EXCHANGE:SYMBOL" key
		symbol := key
		if idx := strings.LastIndex(key, ":"); idx >= 0 {
			symbol = key[idx+1:]
		}
		parts = append(parts, fmt.Sprintf("%s %s", symbol, formatRupee(ltp)))
	}
	sort.Strings(parts)
	return fmt.Sprintf("%d instruments: %s", len(parts), strings.Join(parts, ", "))
}

// summarizeMargins extracts available margin info.
func summarizeMargins(text string) string {
	var obj map[string]any
	if err := json.Unmarshal([]byte(text), &obj); err != nil {
		return truncate(text, 200)
	}
	data, ok := obj["data"].(map[string]any)
	if !ok {
		data = obj
	}
	parts := make([]string, 0, 2)
	for _, segment := range []string{"equity", "commodity"} {
		seg, ok := data[segment].(map[string]any)
		if !ok {
			continue
		}
		avail := jsonFloat(seg, "available")
		if avail == 0 {
			// Try nested available.live_balance
			if a, ok := seg["available"].(map[string]any); ok {
				avail = jsonFloat(a, "live_balance")
			}
		}
		if avail > 0 {
			parts = append(parts, fmt.Sprintf("%s (%s)", formatRupee(avail), segment))
		}
	}
	if len(parts) == 0 {
		return truncate(text, 200)
	}
	return "Available " + strings.Join(parts, " ")
}

// summarizeSearch counts search results.
func summarizeSearch(text string) string {
	items := extractDataArray(text)
	if items == nil {
		return truncate(text, 200)
	}
	return fmt.Sprintf("Found %d instruments", len(items))
}

// --- JSON helper utilities ---

// extractDataArray tries to extract []any from paginated or raw JSON.
func extractDataArray(text string) []any {
	// Try paginated format: {"data": [...], "pagination": {...}}
	var paginated struct {
		Data []any `json:"data"`
	}
	if err := json.Unmarshal([]byte(text), &paginated); err == nil && paginated.Data != nil {
		return paginated.Data
	}
	// Try raw array
	var arr []any
	if err := json.Unmarshal([]byte(text), &arr); err == nil {
		return arr
	}
	return nil
}

// jsonFloat extracts a float64 from a JSON object map, returning 0 on failure.
func jsonFloat(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case json.Number:
		f, _ := n.Float64()
		return f
	default:
		return 0
	}
}

// jsonString extracts a string from a JSON object map.
func jsonString(m map[string]any, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if !ok {
		return fmt.Sprintf("%v", v)
	}
	return s
}

// formatRupee formats a float as a compact rupee string (e.g. "5.2L", "50K", "1,250").
func formatRupee(amount float64) string {
	abs := math.Abs(amount)
	sign := ""
	if amount < 0 {
		sign = "-"
	}
	switch {
	case abs >= 1_00_00_000: // 1 crore
		return fmt.Sprintf("%s\u20b9%.1fCr", sign, abs/1_00_00_000)
	case abs >= 1_00_000: // 1 lakh
		return fmt.Sprintf("%s\u20b9%.1fL", sign, abs/1_00_000)
	case abs >= 1_000:
		return fmt.Sprintf("%s\u20b9%.0fK", sign, abs/1_000)
	default:
		return fmt.Sprintf("%s\u20b9%.0f", sign, abs)
	}
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
