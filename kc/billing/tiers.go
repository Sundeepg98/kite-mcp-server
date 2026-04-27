package billing

import "github.com/zerodha/kite-mcp-server/kc/domain"

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

// tierMonthlyINRAmounts is the canonical per-tier monthly rupee amount
// in float64 form. Kept as a private map so we always go through
// TierMonthlyINR (which returns Money) at every read site, eliminating
// the chance that a downstream caller picks up a bare float64. This is
// the in-process mirror of Stripe's price list, used for two purposes:
//   - stamping Subscription.MonthlyAmount when SetSubscription is called
//     without an explicit amount (the common path — webhook + admin
//     tool both leave it unset);
//   - annotating TierChangedEvent.Amount so audit consumers can compute
//     MRR delta without a join into the billing table.
//
// Stripe remains the source of truth for what the user is actually
// charged; this table is only consulted on the in-process side.
var tierMonthlyINRAmounts = map[Tier]float64{
	TierFree:    0,
	TierSoloPro: 500,
	TierPro:     999,
	TierPremium: 2999,
}

// TierMonthlyINR returns the canonical monthly INR amount for the
// given tier as a domain.Money. TierFree is the zero Money — callers
// that want to detect "no paid plan" should use the IsZero() sentinel
// rather than comparing against a magic float, mirroring Slice 1's
// UserLimits zero-Money convention.
//
// Unknown tiers fall through to zero Money rather than panicking — a
// future tier added without a price entry behaves like Free until the
// table is updated, which is the safer failure mode for audit-event
// annotation (downstream MRR consumers see "no contribution" rather
// than a corrupt figure).
func TierMonthlyINR(t Tier) domain.Money {
	return domain.NewINR(tierMonthlyINRAmounts[t])
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
	"list_mcp_sessions": TierFree, "revoke_mcp_session": TierFree,
	"server_metrics":  TierFree,
	"server_time":     TierFree,
	"server_version":  TierFree,
	"get_order_projection": TierFree,
	"get_order_history_reconstituted": TierFree,
	"get_alert_history_reconstituted": TierFree,
	"get_position_history_reconstituted": TierFree,

	// Analytics — ungated under SEBI Path 1 (stay free forever). Previously
	// Pro/Premium, but the billing system is dormant infrastructure and there
	// is no regulatory or commercial reason to withhold read-only analytics.
	"list_alerts": TierFree, "list_trailing_stops": TierFree,
	"portfolio_concentration": TierFree, "order_risk_report": TierFree,
	"get_pnl_journal": TierFree, "sector_exposure": TierFree,
	"sebi_compliance_status": TierFree,
	"dividend_calendar": TierFree, "tax_loss_analysis": TierFree,
	"technical_indicators": TierFree,
	"historical_price_analyzer": TierFree,
	"portfolio_analysis": TierFree,
	"options_payoff_builder": TierFree,
	"volume_spike_detector":  TierFree,
	"analyze_concall":        TierFree,
	"get_fii_dii_flow":       TierFree,
	"peer_compare":           TierFree,

	// Admin tools (gated by admin role check, not billing tier)
	"admin_list_users": TierFree, "admin_get_user": TierFree,
	"admin_get_user_baseline":   TierFree,
	"admin_stats_cache_info":    TierFree,
	"admin_list_anomaly_flags":  TierFree,
	"admin_server_status":       TierFree, "admin_get_risk_status": TierFree,
	"admin_suspend_user": TierFree, "admin_activate_user": TierFree,
	"admin_change_role": TierFree, "admin_freeze_user": TierFree,
	"admin_unfreeze_user": TierFree, "admin_freeze_global": TierFree,
	"admin_unfreeze_global": TierFree,
	"admin_invite_family_member": TierFree, "admin_list_family": TierFree,
	"admin_remove_family_member": TierFree,
	"admin_set_billing_tier":     TierFree,

	// Setup / onboarding diagnostics — always free, used before any paid
	// feature is even usable.
	"test_ip_whitelist": TierFree,

	// Pro — state-changing/broker-write tools: order placement, GTT, alerts,
	// Telegram, trailing stops, MF orders, native alerts. These remain gated
	// because they carry real financial risk and are the natural dividing line
	// if/when the billing infrastructure is reactivated. Read-only analytics
	// that used to live here have been moved to TierFree (Path 1: stay free
	// forever under SEBI MCP framework). The billing system stays as dormant
	// infrastructure but every shipped analytics tool is free.
	"place_order": TierPro, "modify_order": TierPro, "cancel_order": TierPro,
	"close_position": TierPro, "close_all_positions": TierPro, "convert_position": TierPro,
	"place_gtt_order": TierPro, "modify_gtt_order": TierPro, "delete_gtt_order": TierPro,
	"set_alert": TierPro, "delete_alert": TierPro, "composite_alert": TierPro,
	"place_native_alert": TierPro, "list_native_alerts": TierPro,
	"modify_native_alert": TierPro, "delete_native_alert": TierPro, "get_native_alert_history": TierPro,
	"setup_telegram": TierPro, "set_trailing_stop": TierPro,
	"cancel_trailing_stop": TierPro,
	"position_analysis": TierPro,
	"place_mf_order": TierPro, "cancel_mf_order": TierPro,
	"place_mf_sip": TierPro, "cancel_mf_sip": TierPro,

	// Premium — advanced derivatives analytics. Only options_greeks remains
	// gated here: Black-Scholes pricing is genuinely speculative/advanced and
	// a plausible upsell target if billing is ever switched on. All other
	// analytics (historical backtest, technical indicators, tax, dividends,
	// compliance, portfolio rebalance, options payoff) were moved to Free.
	"options_greeks": TierPremium,
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
