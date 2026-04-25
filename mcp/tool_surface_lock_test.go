package mcp

import (
	"crypto/sha256"
	"encoding/hex"
	"sort"
	"strings"
	"testing"
)

// TestToolSurfaceLock_Names locks the canonical sorted list of tool names
// from GetAllTools() against a SHA256. Failures here are backward-compat
// regressions (gap G120) — external MCP clients bind to tool names.
//
// HOW TO UPDATE: copy the actual hash from the failure log into
// expectedSurfaceHash and update lockedSurfaceTools. Reviewers must treat
// the diff as a wire-protocol change.
func TestToolSurfaceLock_Names(t *testing.T) {
	t.Parallel()

	tools := GetAllTools()
	got := make([]string, 0, len(tools))
	for _, tl := range tools {
		got = append(got, tl.Tool().Name)
	}
	sort.Strings(got)

	sum := sha256.Sum256([]byte(strings.Join(got, "\n")))
	gotHash := hex.EncodeToString(sum[:])
	if gotHash == expectedSurfaceHash {
		return
	}

	lockSet := make(map[string]bool, len(lockedSurfaceTools))
	for _, n := range lockedSurfaceTools {
		lockSet[n] = true
	}
	gotSet := make(map[string]bool, len(got))
	var added, removed []string
	for _, n := range got {
		gotSet[n] = true
		if !lockSet[n] {
			added = append(added, n)
		}
	}
	for _, n := range lockedSurfaceTools {
		if !gotSet[n] {
			removed = append(removed, n)
		}
	}
	sort.Strings(added)
	sort.Strings(removed)
	t.Errorf("tool surface drift detected.\n  expected: %s\n  actual:   %s\n  added:    %s\n  removed:  %s\nUpdate expectedSurfaceHash + lockedSurfaceTools.",
		expectedSurfaceHash, gotHash, strings.Join(added, ", "), strings.Join(removed, ", "))
}

// expectedSurfaceHash is SHA256 over strings.Join(sortedToolNames, "\n").
const expectedSurfaceHash = "fb5e9d0362f28cc1ada295ae5ad2325a33a93cfa465423bd272cd9787b7ea898"

// lockedSurfaceTools is the sorted golden list — used only for diff-on-mismatch.
var lockedSurfaceTools = strings.Fields(`
add_to_watchlist admin_activate_user admin_change_role admin_freeze_global admin_freeze_user
admin_get_risk_status admin_get_user admin_get_user_baseline admin_invite_family_member
admin_list_anomaly_flags admin_list_family admin_list_users admin_remove_family_member
admin_server_status admin_set_billing_tier admin_stats_cache_info admin_suspend_user
admin_unfreeze_global admin_unfreeze_user analyze_concall cancel_mf_order cancel_mf_sip
cancel_order cancel_trailing_stop close_all_positions close_position composite_alert
convert_position create_watchlist delete_alert delete_gtt_order delete_my_account
delete_native_alert delete_watchlist dividend_calendar get_alert_history_reconstituted
get_basket_margins get_fii_dii_flow get_gtts get_historical_data get_holdings get_ltp
get_margins get_mf_holdings get_mf_orders get_mf_sips get_native_alert_history get_ohlc
get_option_chain get_order_charges get_order_history get_order_history_reconstituted
get_order_margins get_order_projection get_order_trades get_orders get_pnl_journal
get_position_history_reconstituted get_positions get_profile get_quotes get_trades
get_watchlist historical_price_analyzer list_alerts list_mcp_sessions list_native_alerts
list_trailing_stops list_watchlists login modify_gtt_order modify_native_alert modify_order
open_dashboard options_greeks options_payoff_builder order_risk_report paper_trading_reset
paper_trading_status paper_trading_toggle peer_compare place_gtt_order place_mf_order
place_mf_sip place_native_alert place_order portfolio_analysis portfolio_concentration
portfolio_summary position_analysis remove_from_watchlist revoke_mcp_session
search_instruments sebi_compliance_status sector_exposure server_metrics server_version
set_alert set_trailing_stop setup_telegram start_ticker stop_ticker subscribe_instruments
tax_loss_analysis technical_indicators test_ip_whitelist ticker_status trading_context
unsubscribe_instruments update_my_credentials volume_spike_detector
`)
