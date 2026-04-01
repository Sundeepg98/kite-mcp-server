package audit

import "strings"

// sensitiveKeys lists parameter names whose values must be redacted in audit logs.
// Comparison is case-insensitive.
var sensitiveKeys = map[string]struct{}{
	"access_token": {},
	"api_key":      {},
	"api_secret":   {},
	"password":     {},
	"secret":       {},
	"token":        {},
}

// SanitizeParams returns a shallow copy of params with sensitive keys redacted
// to "<redacted>". Key matching is case-insensitive. Returns nil for nil input.
func SanitizeParams(params map[string]any) map[string]any {
	if params == nil {
		return nil
	}

	out := make(map[string]any, len(params))
	for k, v := range params {
		if _, ok := sensitiveKeys[strings.ToLower(k)]; ok {
			out[k] = "<redacted>"
		} else {
			out[k] = v
		}
	}
	return out
}

// toolCategories maps each known tool name to its category.
var toolCategories = map[string]string{
	// order
	"place_order":      "order",
	"modify_order":     "order",
	"cancel_order":     "order",
	"place_gtt_order":  "order",
	"modify_gtt_order": "order",
	"delete_gtt_order": "order",

	// query
	"get_profile":       "query",
	"get_margins":       "query",
	"get_holdings":      "query",
	"get_positions":     "query",
	"get_trades":        "query",
	"get_orders":        "query",
	"get_order_history": "query",
	"get_order_trades":  "query",
	"get_gtts":          "query",
	"get_mf_holdings":   "query",

	// market_data
	"get_quotes":          "market_data",
	"search_instruments":  "market_data",
	"get_historical_data": "market_data",
	"get_ltp":             "market_data",
	"get_ohlc":            "market_data",

	// ticker
	"start_ticker":           "ticker",
	"stop_ticker":            "ticker",
	"ticker_status":          "ticker",
	"subscribe_instruments":  "ticker",
	"unsubscribe_instruments": "ticker",

	// alert
	"setup_telegram": "alert",
	"set_alert":      "alert",
	"list_alerts":    "alert",
	"delete_alert":   "alert",

	// setup
	"login":          "setup",
	"open_dashboard": "setup",
}

// ToolCategory returns the category for a given tool name.
// Unknown tools return "other".
func ToolCategory(toolName string) string {
	if cat, ok := toolCategories[toolName]; ok {
		return cat
	}
	return "other"
}
