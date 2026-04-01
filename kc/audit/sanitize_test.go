package audit

import "testing"

func TestSanitizeParams(t *testing.T) {
	t.Parallel()

	t.Run("nil input returns nil", func(t *testing.T) {
		t.Parallel()
		if got := SanitizeParams(nil); got != nil {
			t.Fatalf("expected nil, got %v", got)
		}
	})

	t.Run("sensitive keys redacted", func(t *testing.T) {
		t.Parallel()
		params := map[string]any{
			"access_token": "secret-tok-123",
			"api_key":      "my-api-key",
			"api_secret":   "my-api-secret",
			"password":     "hunter2",
			"secret":       "shh",
			"token":        "tok-abc",
			"exchange":     "NSE",
			"tradingsymbol": "INFY",
		}

		got := SanitizeParams(params)

		// Sensitive keys must be redacted.
		for _, k := range []string{"access_token", "api_key", "api_secret", "password", "secret", "token"} {
			if got[k] != "<redacted>" {
				t.Errorf("expected %q to be redacted, got %v", k, got[k])
			}
		}

		// Normal keys must be preserved.
		if got["exchange"] != "NSE" {
			t.Errorf("expected exchange=NSE, got %v", got["exchange"])
		}
		if got["tradingsymbol"] != "INFY" {
			t.Errorf("expected tradingsymbol=INFY, got %v", got["tradingsymbol"])
		}
	})

	t.Run("original map not mutated", func(t *testing.T) {
		t.Parallel()
		params := map[string]any{
			"token":    "original-value",
			"exchange": "NSE",
		}
		_ = SanitizeParams(params)

		if params["token"] != "original-value" {
			t.Error("original map was mutated")
		}
	})
}

func TestSanitizeParams_CaseInsensitive(t *testing.T) {
	t.Parallel()

	cases := []struct {
		key string
	}{
		{"Access_Token"},
		{"ACCESS_TOKEN"},
		{"Api_Key"},
		{"API_KEY"},
		{"Api_Secret"},
		{"API_SECRET"},
		{"Password"},
		{"PASSWORD"},
		{"Secret"},
		{"SECRET"},
		{"Token"},
		{"TOKEN"},
	}

	for _, tc := range cases {
		t.Run(tc.key, func(t *testing.T) {
			t.Parallel()
			params := map[string]any{tc.key: "sensitive-value"}
			got := SanitizeParams(params)
			if got[tc.key] != "<redacted>" {
				t.Errorf("expected %q to be redacted (case-insensitive), got %v", tc.key, got[tc.key])
			}
		})
	}
}

func TestToolCategory(t *testing.T) {
	t.Parallel()

	tests := []struct {
		tool     string
		expected string
	}{
		// order
		{"place_order", "order"},
		{"modify_order", "order"},
		{"cancel_order", "order"},
		{"place_gtt_order", "order"},
		{"modify_gtt_order", "order"},
		{"delete_gtt_order", "order"},

		// query
		{"get_profile", "query"},
		{"get_margins", "query"},
		{"get_holdings", "query"},
		{"get_positions", "query"},
		{"get_orders", "query"},
		{"get_gtts", "query"},
		{"get_mf_holdings", "query"},

		// market_data
		{"get_quotes", "market_data"},
		{"search_instruments", "market_data"},
		{"get_historical_data", "market_data"},
		{"get_ltp", "market_data"},
		{"get_ohlc", "market_data"},

		// ticker
		{"start_ticker", "ticker"},
		{"stop_ticker", "ticker"},
		{"ticker_status", "ticker"},
		{"subscribe_instruments", "ticker"},
		{"unsubscribe_instruments", "ticker"},

		// alert
		{"setup_telegram", "alert"},
		{"set_alert", "alert"},
		{"list_alerts", "alert"},
		{"delete_alert", "alert"},

		// setup
		{"login", "setup"},
		{"open_dashboard", "setup"},

		// unknown
		{"nonexistent_tool", "other"},
		{"", "other"},
	}

	for _, tc := range tests {
		t.Run(tc.tool, func(t *testing.T) {
			t.Parallel()
			got := ToolCategory(tc.tool)
			if got != tc.expected {
				t.Errorf("ToolCategory(%q) = %q, want %q", tc.tool, got, tc.expected)
			}
		})
	}
}
