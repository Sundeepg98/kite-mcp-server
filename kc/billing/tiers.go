package billing

// Tier represents a billing subscription level.
type Tier int

const (
	TierFree    Tier = 0
	TierPro     Tier = 1
	TierPremium Tier = 2
	TierSoloPro Tier = 3 // Solo Pro: same tool access as Pro, max_users=1
)

// String returns the human-readable name of the tier.
func (t Tier) String() string {
	switch t {
	case TierSoloPro:
		return "solo_pro"
	case TierPro:
		return "pro"
	case TierPremium:
		return "premium"
	default:
		return "free"
	}
}

// EffectiveTier returns the tier used for tool-access comparisons.
// TierSoloPro grants the same tool access as TierPro (the difference is
// max_users, not feature gates), so it maps down to TierPro here.
func (t Tier) EffectiveTier() Tier {
	if t == TierSoloPro {
		return TierPro
	}
	return t
}

// toolTiers maps each MCP tool name to its minimum required billing tier.
var toolTiers = map[string]Tier{
	// Free — read-only data, paper trading, watchlists, dashboard, account, observability
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
	"get_gtts": TierFree,
	"get_mf_holdings": TierFree, "get_mf_orders": TierFree, "get_mf_sips": TierFree,
	"start_ticker": TierFree, "stop_ticker": TierFree, "ticker_status": TierFree,
	"subscribe_instruments": TierFree, "unsubscribe_instruments": TierFree,
	"get_order_margins": TierFree, "get_basket_margins": TierFree, "get_order_charges": TierFree,
	"delete_my_account": TierFree, "update_my_credentials": TierFree,
	"server_metrics": TierFree,
	"server_time":    TierFree,
	"get_order_projection": TierFree,
	"get_order_history_reconstituted": TierFree,
	"get_alert_history_reconstituted": TierFree,
	"get_position_history_reconstituted": TierFree,

	// Admin tools (gated by admin role check, not billing tier)
	"admin_list_users": TierFree, "admin_get_user": TierFree,
	"admin_server_status": TierFree, "admin_get_risk_status": TierFree,
	"admin_suspend_user": TierFree, "admin_activate_user": TierFree,
	"admin_change_role": TierFree, "admin_freeze_user": TierFree,
	"admin_unfreeze_user": TierFree, "admin_freeze_global": TierFree,
	"admin_unfreeze_global": TierFree,
	"admin_invite_family_member": TierFree, "admin_list_family": TierFree,
	"admin_remove_family_member": TierFree,

	// Pro — order placement, GTT, alerts, Telegram, trailing stops, analytics, MF orders, native alerts
	"place_order": TierPro, "modify_order": TierPro, "cancel_order": TierPro,
	"close_position": TierPro, "close_all_positions": TierPro, "convert_position": TierPro,
	"place_gtt_order": TierPro, "modify_gtt_order": TierPro, "delete_gtt_order": TierPro,
	"set_alert": TierPro, "list_alerts": TierPro, "delete_alert": TierPro,
	"place_native_alert": TierPro, "list_native_alerts": TierPro,
	"modify_native_alert": TierPro, "delete_native_alert": TierPro, "get_native_alert_history": TierPro,
	"setup_telegram": TierPro, "set_trailing_stop": TierPro,
	"list_trailing_stops": TierPro, "cancel_trailing_stop": TierPro,
	"pre_trade_check": TierPro, "get_pnl_journal": TierPro,
	"portfolio_concentration": TierPro, "position_analysis": TierPro,
	"sector_exposure": TierPro,
	"place_mf_order": TierPro, "cancel_mf_order": TierPro,
	"place_mf_sip": TierPro, "cancel_mf_sip": TierPro,

	// Premium — advanced analytics, backtesting, compliance
	"historical_price_analyzer": TierPremium, "options_greeks": TierPremium,
	"options_payoff_builder": TierPremium, "technical_indicators": TierPremium,
	"portfolio_analysis": TierPremium, "dividend_calendar": TierPremium,
	"tax_harvest_analysis": TierPremium, "sebi_compliance_status": TierPremium,
}

// RequiredTier returns the minimum billing tier needed to invoke the named tool.
// Unknown tools default to TierFree (fail open).
func RequiredTier(toolName string) Tier {
	if t, ok := toolTiers[toolName]; ok {
		return t
	}
	return TierFree
}

// HasExplicitTier reports whether the given tool name has an explicit entry
// in the billing tier map. This is exported for cross-package tests that
// need to verify all tools are mapped without accessing the unexported map.
func HasExplicitTier(toolName string) bool {
	_, ok := toolTiers[toolName]
	return ok
}
