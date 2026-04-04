package billing

// Tier represents a billing subscription level.
type Tier int

const (
	TierFree    Tier = 0
	TierPro     Tier = 1
	TierPremium Tier = 2
)

// String returns the human-readable name of the tier.
func (t Tier) String() string {
	switch t {
	case TierPro:
		return "pro"
	case TierPremium:
		return "premium"
	default:
		return "free"
	}
}

// toolTiers maps each MCP tool name to its minimum required billing tier.
var toolTiers = map[string]Tier{
	// Free — read-only data, paper trading, watchlists, dashboard
	"login": TierFree, "get_profile": TierFree, "get_margins": TierFree,
	"get_holdings": TierFree, "get_positions": TierFree, "get_orders": TierFree,
	"get_order_history": TierFree, "get_order_trades": TierFree, "get_trades": TierFree,
	"search_instruments": TierFree, "get_ltp": TierFree, "get_ohlc": TierFree,
	"get_quotes": TierFree, "get_historical_data": TierFree,
	"paper_trading_toggle": TierFree, "paper_trading_status": TierFree, "paper_trading_reset": TierFree,
	"trading_context": TierFree, "portfolio_summary": TierFree,
	"create_watchlist": TierFree, "delete_watchlist": TierFree,
	"add_to_watchlist": TierFree, "remove_from_watchlist": TierFree,
	"get_watchlist": TierFree, "list_watchlists": TierFree,
	"open_dashboard": TierFree, "get_option_chain": TierFree,

	// Pro — order placement, GTT, alerts, Telegram, trailing stops, analytics
	"place_order": TierPro, "modify_order": TierPro, "cancel_order": TierPro,
	"close_position": TierPro, "close_all_positions": TierPro,
	"place_gtt_order": TierPro, "modify_gtt_order": TierPro, "delete_gtt_order": TierPro,
	"set_alert": TierPro, "list_alerts": TierPro, "delete_alert": TierPro,
	"setup_telegram": TierPro, "set_trailing_stop": TierPro,
	"list_trailing_stops": TierPro, "cancel_trailing_stop": TierPro,
	"pre_trade_check": TierPro, "get_pnl_journal": TierPro,
	"portfolio_concentration": TierPro, "position_analysis": TierPro,
	"sector_exposure": TierPro,

	// Premium — advanced analytics, backtesting, compliance
	"backtest_strategy": TierPremium, "options_greeks": TierPremium,
	"options_strategy": TierPremium, "technical_indicators": TierPremium,
	"portfolio_rebalance": TierPremium, "dividend_calendar": TierPremium,
	"tax_harvest_analysis": TierPremium, "sebi_compliance_status": TierPremium,
	"server_metrics": TierPremium,
}

// RequiredTier returns the minimum billing tier needed to invoke the named tool.
// Unknown tools default to TierFree (fail open).
func RequiredTier(toolName string) Tier {
	if t, ok := toolTiers[toolName]; ok {
		return t
	}
	return TierFree
}
