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
	"delete_gtt_order":  "order",
	"convert_position":     "order",
	"close_all_positions": "order",

	// mf_order
	"place_mf_order":  "mf_order",
	"cancel_mf_order": "mf_order",
	"place_mf_sip":    "mf_order",
	"cancel_mf_sip":   "mf_order",

	// query
	"trading_context":   "query",
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
	"get_mf_orders":     "query",
	"get_mf_sips":       "query",

	// analytics
	"portfolio_summary":       "query",
	"portfolio_concentration": "query",
	"position_analysis":       "query",
	"pre_trade_check":         "query",

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

	// trailing_stop
	"set_trailing_stop":    "trailing_stop",
	"list_trailing_stops":  "trailing_stop",
	"cancel_trailing_stop": "trailing_stop",

	// watchlist
	"create_watchlist":       "watchlist",
	"delete_watchlist":       "watchlist",
	"add_to_watchlist":       "watchlist",
	"remove_from_watchlist":  "watchlist",
	"get_watchlist":          "watchlist",
	"list_watchlists":        "watchlist",

	// pnl
	"get_pnl_journal": "query",

	// analytics
	"historical_price_analyzer": "analytics",
	"technical_indicators":      "analytics",
	"options_greeks":            "analytics",
	"options_payoff_builder":    "analytics",
	"portfolio_analysis":        "analytics",
	"tax_harvest_analysis":   "analytics",
	"sector_exposure":        "analytics",
	"dividend_calendar":      "analytics",
	"sebi_compliance_status": "analytics",

	// setup
	"login":          "setup",
	"open_dashboard": "setup",
	"server_metrics": "setup",

	// notification (synthetic events from alert triggers / trailing stop modifications)
	"alert_triggered":        "notification",
	"trailing_stop_modified": "notification",
}

// ToolCategory returns the category for a given tool name.
// Unknown tools return "other".
func ToolCategory(toolName string) string {
	if cat, ok := toolCategories[toolName]; ok {
		return cat
	}
	return "other"
}
