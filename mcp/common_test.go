package mcp

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/billing"
)

// TestSafeAssertFunctions tests all SafeAssert utility functions
func TestSafeAssertFunctions(t *testing.T) {
	t.Parallel()
	t.Run("SafeAssertString", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "test", SafeAssertString("test", "default"))
		assert.Equal(t, "default", SafeAssertString(nil, "default"))
		assert.Equal(t, "42", SafeAssertString(42, "default"))
	})

	t.Run("SafeAssertInt", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 42, SafeAssertInt(42, 0))
		assert.Equal(t, 42, SafeAssertInt(42.0, 0))
		assert.Equal(t, 0, SafeAssertInt(nil, 0))
		assert.Equal(t, 0, SafeAssertInt("invalid", 0))
	})

	t.Run("SafeAssertFloat64", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 3.14, SafeAssertFloat64(3.14, 0.0))
		assert.Equal(t, 42.0, SafeAssertFloat64(42, 0.0))
		assert.Equal(t, 0.0, SafeAssertFloat64(nil, 0.0))
	})

	t.Run("SafeAssertBool", func(t *testing.T) {
		t.Parallel()
		// Test boolean values
		assert.True(t, SafeAssertBool(true, false))
		assert.False(t, SafeAssertBool(false, true))

		// Test truthy strings
		for _, truthy := range []string{"true", "True", "TRUE", "1", "yes", "Yes", "YES", "on", "On", "ON"} {
			assert.True(t, SafeAssertBool(truthy, false), "Expected %s to be truthy", truthy)
		}

		// Test falsy strings
		for _, falsy := range []string{"false", "False", "FALSE", "0", "no", "No", "NO", "off", "Off", "OFF"} {
			assert.False(t, SafeAssertBool(falsy, true), "Expected %s to be falsy", falsy)
		}

		// Test fallback cases
		assert.True(t, SafeAssertBool("unknown", true))
		assert.False(t, SafeAssertBool("unknown", false))
		assert.True(t, SafeAssertBool(nil, true))
	})

	t.Run("SafeAssertStringArray", func(t *testing.T) {
		t.Parallel()
		// Valid array with mixed types
		result := SafeAssertStringArray([]interface{}{"hello", "world", 42, nil, ""})
		assert.Equal(t, []string{"hello", "world", "42"}, result)

		// Empty array
		result = SafeAssertStringArray([]interface{}{})
		assert.Empty(t, result)

		// Nil input
		result = SafeAssertStringArray(nil)
		assert.Nil(t, result)

		// Single string input — wraps into slice
		result = SafeAssertStringArray("NSE:INFY")
		assert.Equal(t, []string{"NSE:INFY"}, result)

		// Empty string input
		result = SafeAssertStringArray("")
		assert.Nil(t, result)
	})
}

// TestArgParser tests the declarative argument parser
func TestArgParser(t *testing.T) {
	t.Parallel()
	args := map[string]interface{}{
		"name":    "test",
		"count":   42,
		"price":   3.14,
		"active":  true,
		"tags":    []interface{}{"a", "b"},
	}
	p := NewArgParser(args)

	t.Run("String", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, "test", p.String("name", ""))
		assert.Equal(t, "default", p.String("missing", "default"))
	})

	t.Run("Int", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 42, p.Int("count", 0))
		assert.Equal(t, 99, p.Int("missing", 99))
	})

	t.Run("Float", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, 3.14, p.Float("price", 0.0))
		assert.Equal(t, 1.0, p.Float("missing", 1.0))
	})

	t.Run("Bool", func(t *testing.T) {
		t.Parallel()
		assert.True(t, p.Bool("active", false))
		assert.False(t, p.Bool("missing", false))
	})

	t.Run("StringArray", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, []string{"a", "b"}, p.StringArray("tags"))
		assert.Nil(t, p.StringArray("missing"))
	})

	t.Run("Required", func(t *testing.T) {
		t.Parallel()
		assert.NoError(t, p.Required("name", "count"))
		assert.Error(t, p.Required("name", "missing_key"))
	})

	t.Run("Raw", func(t *testing.T) {
		t.Parallel()
		assert.Equal(t, args, p.Raw())
	})
}

// TestValidateRequired tests parameter validation
func TestValidateRequired(t *testing.T) {
	t.Parallel()
	t.Run("valid parameters", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{
			"param1": "value1",
			"param2": []string{"item1", "item2"},
			"param3": []int{1, 2, 3},
		}
		assert.NoError(t, ValidateRequired(args, "param1", "param2", "param3"))
	})

	t.Run("missing parameters", func(t *testing.T) {
		t.Parallel()
		args := map[string]interface{}{"param1": "value1"}
		err := ValidateRequired(args, "param1", "missing")
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "missing")
	})

	t.Run("empty parameters", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			name  string
			value interface{}
		}{
			{"empty string", ""},
			{"nil value", nil},
			{"empty []interface{}", []interface{}{}},
			{"empty []string", []string{}},
			{"empty []int", []int{}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				args := map[string]interface{}{"param": tc.value}
				err := ValidateRequired(args, "param")
				assert.Error(t, err)
			})
		}
	})
}

// TestPagination tests pagination functionality
func TestPagination(t *testing.T) {
	t.Parallel()
	data := []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

	t.Run("ApplyPagination", func(t *testing.T) {
		testCases := []struct {
			name     string
			params   PaginationParams
			expected []int
		}{
			{"no pagination", PaginationParams{From: 0, Limit: 0}, []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}},
			{"from start with limit", PaginationParams{From: 0, Limit: 3}, []int{0, 1, 2}},
			{"from middle with limit", PaginationParams{From: 3, Limit: 4}, []int{3, 4, 5, 6}},
			{"from only no limit", PaginationParams{From: 5, Limit: 0}, []int{5, 6, 7, 8, 9}},
			{"beyond bounds", PaginationParams{From: 15, Limit: 5}, []int{}},
			{"negative from", PaginationParams{From: -5, Limit: 3}, []int{0, 1, 2}},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				result := ApplyPagination(data, tc.params)
				assert.Equal(t, tc.expected, result)
			})
		}
	})

	t.Run("ParsePaginationParams", func(t *testing.T) {
		args := map[string]interface{}{"from": 10, "limit": 50}
		params := ParsePaginationParams(args)
		assert.Equal(t, 10, params.From)
		assert.Equal(t, 50, params.Limit)
	})

	t.Run("CreatePaginatedResponse", func(t *testing.T) {
		originalData := []string{"a", "b", "c", "d", "e"}
		paginatedData := []string{"b", "c"}
		params := PaginationParams{From: 1, Limit: 2}

		response := CreatePaginatedResponse(originalData, paginatedData, params, len(originalData))

		assert.Equal(t, paginatedData, response.Data)
		assert.Equal(t, 1, response.Pagination.From)
		assert.Equal(t, 2, response.Pagination.Limit)
		assert.Equal(t, 5, response.Pagination.Total)
		assert.Equal(t, 2, response.Pagination.Returned)
		assert.True(t, response.Pagination.HasMore)
	})
}

// TestToolExclusion tests tool exclusion logic
func TestToolExclusion(t *testing.T) {
	t.Parallel()
	t.Run("parseExcludedTools", func(t *testing.T) {
		t.Parallel()
		testCases := []struct {
			input    string
			expected map[string]bool
		}{
			{"", map[string]bool{}},
			{"place_order", map[string]bool{"place_order": true}},
			{"place_order,modify_order", map[string]bool{"place_order": true, "modify_order": true}},
			{" place_order , modify_order ", map[string]bool{"place_order": true, "modify_order": true}},
			{"place_order,,modify_order", map[string]bool{"place_order": true, "modify_order": true}},
		}

		for _, tc := range testCases {
			result := parseExcludedTools(tc.input)
			assert.Equal(t, tc.expected, result)
		}
	})

	t.Run("filterTools", func(t *testing.T) {
		t.Parallel()
		allTools := GetAllTools()

		// No exclusions
		filtered, registered, excluded := filterTools(allTools, map[string]bool{})
		assert.Equal(t, len(allTools), registered)
		assert.Equal(t, 0, excluded)
		assert.Len(t, filtered, len(allTools))

		// Exclude some tools
		excludedSet := map[string]bool{"place_order": true, "modify_order": true}
		filtered, registered, excluded = filterTools(allTools, excludedSet)
		assert.Equal(t, len(allTools)-2, registered)
		assert.Equal(t, 2, excluded)
		assert.Len(t, filtered, len(allTools)-2)

		// Verify excluded tools not in filtered list
		filteredNames := make(map[string]bool)
		for _, tool := range filtered {
			filteredNames[tool.Tool().Name] = true
		}
		assert.False(t, filteredNames["place_order"])
		assert.False(t, filteredNames["modify_order"])
	})

	t.Run("GetAllTools integrity", func(t *testing.T) {
		t.Parallel()
		allTools := GetAllTools()
		assert.Greater(t, len(allTools), 20)

		// Check for duplicates and essential tools
		toolNames := make(map[string]bool)
		for _, tool := range allTools {
			assert.NotNil(t, tool)
			name := tool.Tool().Name
			assert.NotEmpty(t, name)
			assert.False(t, toolNames[name], "Duplicate tool: %s", name)
			toolNames[name] = true
		}

		// Verify essential tools exist
		essential := []string{"login", "get_profile", "place_order", "get_quotes"}
		for _, toolName := range essential {
			assert.True(t, toolNames[toolName], "Essential tool missing: %s", toolName)
		}
	})
}

// TestToolDashboardPage verifies the tool-to-dashboard-page mapping
func TestToolDashboardPage(t *testing.T) {
	t.Parallel()
	t.Run("portfolio tools map to /dashboard", func(t *testing.T) {
		t.Parallel()
		portfolioTools := []string{
			"get_holdings", "get_positions", "get_margins", "get_profile",
			"portfolio_summary", "portfolio_concentration", "position_analysis",
			"trading_context", "pre_trade_check", "get_pnl_journal", "get_mf_holdings",
			"tax_harvest_analysis",
		}
		for _, tool := range portfolioTools {
			path, ok := toolDashboardPage[tool]
			assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
			assert.Equal(t, "/dashboard", path, "tool %s should map to /dashboard", tool)
		}
	})

	t.Run("order tools map to /dashboard/orders", func(t *testing.T) {
		t.Parallel()
		orderTools := []string{
			"get_orders", "get_order_history", "get_order_trades", "get_trades",
			"place_order", "modify_order", "cancel_order",
			"close_position", "close_all_positions",
			"get_gtts", "place_gtt_order", "modify_gtt_order", "delete_gtt_order",
		}
		for _, tool := range orderTools {
			path, ok := toolDashboardPage[tool]
			assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
			assert.Equal(t, "/dashboard/orders", path, "tool %s should map to /dashboard/orders", tool)
		}
	})

	t.Run("alert tools map to /dashboard/alerts", func(t *testing.T) {
		t.Parallel()
		alertTools := []string{
			"list_alerts", "set_alert", "delete_alert",
			"set_trailing_stop", "list_trailing_stops", "cancel_trailing_stop",
		}
		for _, tool := range alertTools {
			path, ok := toolDashboardPage[tool]
			assert.True(t, ok, "tool %s should be in toolDashboardPage", tool)
			assert.Equal(t, "/dashboard/alerts", path, "tool %s should map to /dashboard/alerts", tool)
		}
	})

	t.Run("unmapped tools return empty", func(t *testing.T) {
		t.Parallel()
		unmappedTools := []string{
			"login", "open_dashboard", "stop_ticker", "unsubscribe_instruments",
			"delete_my_account", "update_my_credentials", "server_metrics",
			"admin_list_users", "admin_get_user", "admin_server_status",
			"admin_get_risk_status", "admin_suspend_user", "admin_activate_user",
			"admin_change_role", "admin_freeze_user", "admin_unfreeze_user",
			"admin_freeze_global",
			"admin_unfreeze_global",
			"admin_invite_family_member",
			"admin_list_family",
			"admin_remove_family_member",
		}
		for _, tool := range unmappedTools {
			_, ok := toolDashboardPage[tool]
			assert.False(t, ok, "tool %s should NOT be in toolDashboardPage", tool)
		}
	})

	t.Run("all mapped tools exist in GetAllTools", func(t *testing.T) {
		t.Parallel()
		allTools := GetAllTools()
		registeredNames := make(map[string]bool)
		for _, tool := range allTools {
			registeredNames[tool.Tool().Name] = true
		}
		for toolName := range toolDashboardPage {
			assert.True(t, registeredNames[toolName],
				"toolDashboardPage has %s but it is not in GetAllTools()", toolName)
		}
	})
}

// TestRaceConditions tests thread safety
func TestRaceConditions(t *testing.T) {
	t.Parallel()
	t.Run("SafeAssert functions", func(t *testing.T) {
		t.Parallel()
		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = SafeAssertString("test", "default")
				_ = SafeAssertInt(42, 0)
				_ = SafeAssertBool(true, false)
			}()
		}
		wg.Wait()
	})

	t.Run("pagination functions", func(t *testing.T) {
		t.Parallel()
		data := []int{1, 2, 3, 4, 5}
		params := PaginationParams{From: 1, Limit: 2}

		var wg sync.WaitGroup
		for i := 0; i < 100; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = ApplyPagination(data, params)
				_ = ParsePaginationParams(map[string]interface{}{"from": 1, "limit": 2})
			}()
		}
		wg.Wait()
	})
}

// TestAllToolsHaveBillingTier verifies that every tool returned by GetAllTools
// has an explicit entry in the billing toolTiers map. This lives here (not in
// kc/billing) to avoid an import cycle.
func TestAllToolsHaveBillingTier(t *testing.T) {
	t.Parallel()
	allTools := GetAllTools()
	for _, tool := range allTools {
		name := tool.Tool().Name
		assert.Truef(t, billing.HasExplicitTier(name),
			"tool %q is in GetAllTools but has no explicit billing tier mapping", name)
	}
}
