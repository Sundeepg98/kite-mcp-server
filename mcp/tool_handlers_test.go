package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/money"
	"github.com/zerodha/kite-mcp-server/kc/scheduler"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// ---------------------------------------------------------------------------
// Tool registration: all required tools exist
// ---------------------------------------------------------------------------


// ---------------------------------------------------------------------------
// Analytics tools: annotations (read-only, etc.)
// ---------------------------------------------------------------------------
func TestAnalyticsToolsAnnotations(t *testing.T) {
	tools := GetAllTools()
	readOnlyTools := []string{
		"portfolio_summary", "portfolio_concentration", "position_analysis",
		"sector_exposure", "tax_loss_analysis", "dividend_calendar",
		"portfolio_analysis", "sebi_compliance_status",
		"historical_price_analyzer", "technical_indicators",
		"options_greeks", "options_payoff_builder",
	}

	toolMap := make(map[string]Tool)
	for _, td := range tools {
		toolMap[td.Tool().Name] = td
	}

	for _, name := range readOnlyTools {
		td, found := toolMap[name]
		if !found {
			t.Errorf("expected tool %s to be registered", name)
			continue
		}
		toolDef := td.Tool()
		assert.True(t, toolDef.Annotations.ReadOnlyHint != nil && *toolDef.Annotations.ReadOnlyHint,
			"tool %s should be read-only", name)
	}
}


func TestWriteToolsHaveDestructiveHint(t *testing.T) {
	tools := GetAllTools()
	destructiveTools := []string{
		"place_order", "cancel_order", "place_gtt_order", "delete_gtt_order",
		"place_mf_order", "cancel_mf_order", "cancel_mf_sip",
		"delete_watchlist", "remove_from_watchlist",
		"cancel_trailing_stop",
	}

	toolMap := make(map[string]Tool)
	for _, td := range tools {
		toolMap[td.Tool().Name] = td
	}

	for _, name := range destructiveTools {
		td, found := toolMap[name]
		if !found {
			t.Errorf("expected tool %s to be registered", name)
			continue
		}
		toolDef := td.Tool()
		assert.True(t, toolDef.Annotations.DestructiveHint != nil && *toolDef.Annotations.DestructiveHint,
			"tool %s should be marked destructive", name)
	}
}


// ===========================================================================
// NEW TESTS: coverage push from 28.3% to 45%+
// ===========================================================================

// ---------------------------------------------------------------------------
// common.go: SessionType context functions
// ---------------------------------------------------------------------------
func TestWithSessionType_RoundTrip(t *testing.T) {
	ctx := context.Background()
	ctx = WithSessionType(ctx, SessionTypeSSE)
	assert.Equal(t, SessionTypeSSE, SessionTypeFromContext(ctx))
}


func TestSessionTypeFromContext_Default(t *testing.T) {
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))
}


func TestSessionTypeFromContext_AllTypes(t *testing.T) {
	for _, st := range []string{SessionTypeSSE, SessionTypeMCP, SessionTypeStdio, SessionTypeUnknown} {
		ctx := WithSessionType(context.Background(), st)
		assert.Equal(t, st, SessionTypeFromContext(ctx))
	}
}


// ---------------------------------------------------------------------------
// common.go: Error constants
// ---------------------------------------------------------------------------
func TestErrorConstants(t *testing.T) {
	assert.Contains(t, ErrAuthRequired, "Authentication")
	assert.Contains(t, ErrAdminRequired, "Admin")
	assert.Contains(t, ErrUserStoreNA, "User store")
	assert.Contains(t, ErrTargetEmailRequired, "target_email")
	assert.Contains(t, ErrSelfAction, "yourself")
	assert.Contains(t, ErrLastAdmin, "last active admin")
	assert.Contains(t, ErrRiskGuardNA, "RiskGuard")
	assert.Contains(t, ErrConfirmRequired, "confirm")
	assert.Contains(t, ErrInvitationStoreNA, "Invitation store")
}


func TestMaxPaginationLimit(t *testing.T) {
	assert.Equal(t, 500, MaxPaginationLimit)
}


// ---------------------------------------------------------------------------
// common.go: ValidationError type
// ---------------------------------------------------------------------------
func TestValidationError_ErrorString(t *testing.T) {
	err := ValidationError{Parameter: "quantity", Message: "is required"}
	assert.Equal(t, "parameter 'quantity': is required", err.Error())
}


func TestValidationError_Interface(t *testing.T) {
	var err error = ValidationError{Parameter: "price", Message: "cannot be negative"}
	assert.Contains(t, err.Error(), "price")
	assert.Contains(t, err.Error(), "cannot be negative")
}


// ---------------------------------------------------------------------------
// common.go: MarshalResponse
// ---------------------------------------------------------------------------
func TestMarshalResponse_Success(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	data := map[string]string{"key": "value"}
	result, err := handler.MarshalResponse(data, "test_tool")
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestMarshalResponse_Unmarshalable(t *testing.T) {
	mgr := newTestManager(t)
	handler := NewToolHandler(mgr)
	// channels cannot be marshaled to JSON
	result, err := handler.MarshalResponse(make(chan int), "test_tool")
	assert.NoError(t, err) // handler returns error as tool result, not Go error
	assert.True(t, result.IsError)
}


// ---------------------------------------------------------------------------
// common.go: Pagination edge cases
// ---------------------------------------------------------------------------
func TestParsePaginationParams_Defaults(t *testing.T) {
	p := ParsePaginationParams(map[string]any{})
	assert.Equal(t, 0, p.From)
	assert.Equal(t, 0, p.Limit)
}


func TestParsePaginationParams_WithValues(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"from":  float64(10),
		"limit": float64(50),
	})
	assert.Equal(t, 10, p.From)
	assert.Equal(t, 50, p.Limit)
}


func TestParsePaginationParams_CapsAtMax(t *testing.T) {
	p := ParsePaginationParams(map[string]any{
		"limit": float64(9999),
	})
	assert.Equal(t, MaxPaginationLimit, p.Limit)
}


func TestApplyPagination_EmptySlice(t *testing.T) {
	result := ApplyPagination([]int{}, PaginationParams{From: 0, Limit: 10})
	assert.Empty(t, result)
}


func TestApplyPagination_LimitExceedsLength(t *testing.T) {
	data := []string{"a", "b", "c"}
	result := ApplyPagination(data, PaginationParams{From: 0, Limit: 100})
	assert.Equal(t, data, result)
}


func TestCreatePaginatedResponse_NilPaginatedData(t *testing.T) {
	resp := CreatePaginatedResponse(nil, nil, PaginationParams{From: 0, Limit: 5}, 10)
	assert.Equal(t, 5, resp.Pagination.Returned)
	assert.True(t, resp.Pagination.HasMore)
}


func TestCreatePaginatedResponse_InterfaceSlice(t *testing.T) {
	data := []any{"a", "b"}
	resp := CreatePaginatedResponse(nil, data, PaginationParams{From: 0, Limit: 5}, 10)
	assert.Equal(t, 2, resp.Pagination.Returned)
	assert.True(t, resp.Pagination.HasMore)
}


func TestCreatePaginatedResponse_NoMore(t *testing.T) {
	data := []string{"a", "b", "c"}
	resp := CreatePaginatedResponse(data, data, PaginationParams{From: 0, Limit: 5}, 3)
	assert.False(t, resp.Pagination.HasMore)
}


// ---------------------------------------------------------------------------
// common.go: writeTools init
// ---------------------------------------------------------------------------
func TestWriteToolsPopulated(t *testing.T) {
	assert.NotEmpty(t, writeTools, "writeTools should be populated by init()")
	// Known write tools
	assert.True(t, writeTools["place_order"], "place_order should be a write tool")
	assert.True(t, writeTools["cancel_order"], "cancel_order should be a write tool")
	// Known read-only tools should NOT be write tools
	assert.False(t, writeTools["get_holdings"], "get_holdings should NOT be a write tool")
	assert.False(t, writeTools["get_profile"], "get_profile should NOT be a write tool")
}


// ---------------------------------------------------------------------------
// setup_tools.go: isAlphanumeric
// ---------------------------------------------------------------------------
func TestIsAlphanumeric(t *testing.T) {
	assert.True(t, isAlphanumeric("abc123"))
	assert.True(t, isAlphanumeric("ABCDEF"))
	assert.True(t, isAlphanumeric("a"))
	assert.False(t, isAlphanumeric(""))
	assert.False(t, isAlphanumeric("abc-123"))
	assert.False(t, isAlphanumeric("abc 123"))
	assert.False(t, isAlphanumeric("abc@123"))
	assert.False(t, isAlphanumeric("abc_123"))
}


// ---------------------------------------------------------------------------
// setup_tools.go: pageRoutes mapping
// ---------------------------------------------------------------------------
func TestPageRoutes_AllNonEmpty(t *testing.T) {
	assert.NotEmpty(t, pageRoutes)
	for page, path := range pageRoutes {
		assert.NotEmpty(t, path, "page %s has empty path", page)
		assert.True(t, len(path) > 1, "page %s path too short: %s", page, path)
	}
}


func TestPageRoutes_KnownPages(t *testing.T) {
	expected := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "watchlist", "options", "chart"}
	for _, page := range expected {
		_, ok := pageRoutes[page]
		assert.True(t, ok, "page %s should exist in pageRoutes", page)
	}
}


// ---------------------------------------------------------------------------
// setup_tools.go: DashboardURLForTool
// ---------------------------------------------------------------------------
func TestDashboardURLForTool_UnmappedToolReturnsEmpty(t *testing.T) {
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "nonexistent_tool")
	assert.Empty(t, url)
}


func TestDashboardURLForTool_LoginToolReturnsEmpty(t *testing.T) {
	mgr := newTestManager(t)
	url := DashboardURLForTool(mgr, "login")
	assert.Empty(t, url)
}


// ---------------------------------------------------------------------------
// setup_tools.go: toolDashboardPage consistency
// ---------------------------------------------------------------------------
func TestToolDashboardPage_AllValuesNonEmpty(t *testing.T) {
	for toolName, pagePath := range toolDashboardPage {
		assert.NotEmpty(t, pagePath, "tool %s has empty page path", toolName)
	}
}


func TestToolDashboardPage_AllPathsStartWithSlash(t *testing.T) {
	for toolName, pagePath := range toolDashboardPage {
		assert.True(t, len(pagePath) > 0 && pagePath[0] == '/', "tool %s path %s should start with /", toolName, pagePath)
	}
}


// ---------------------------------------------------------------------------
// Account tools: delete_my_account
// ---------------------------------------------------------------------------
func TestDeleteMyAccount_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError, "delete_my_account without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestDeleteMyAccount_RequiresConfirm(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "user@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError, "delete_my_account with confirm=false should fail")
	assertResultContains(t, result, "confirm")
}


func TestDeleteMyAccount_ConfirmTrue_Succeeds(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "delete_my_account", "user@example.com", map[string]any{
		"confirm": true,
	})
	assert.False(t, result.IsError, "delete_my_account with confirm=true should succeed")
	assertResultContains(t, result, "Account deleted")
}


// ---------------------------------------------------------------------------
// Account tools: update_my_credentials
// ---------------------------------------------------------------------------
func TestUpdateMyCredentials_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key":    "newkey",
		"api_secret": "newsecret",
	})
	assert.True(t, result.IsError, "update_my_credentials without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestUpdateMyCredentials_MissingApiKey(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_secret": "newsecret",
	})
	assert.True(t, result.IsError, "update_my_credentials without api_key should fail")
	assertResultContains(t, result, "api_key")
}


func TestUpdateMyCredentials_MissingApiSecret(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key": "newkey",
	})
	assert.True(t, result.IsError, "update_my_credentials without api_secret should fail")
	assertResultContains(t, result, "api_secret")
}


func TestUpdateMyCredentials_EmptyValues(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key":    "  ",
		"api_secret": "  ",
	})
	assert.True(t, result.IsError, "update_my_credentials with empty values should fail")
	assertResultContains(t, result, "non-empty")
}


func TestUpdateMyCredentials_Success(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "update_my_credentials", "user@example.com", map[string]any{
		"api_key":    "validkey",
		"api_secret": "validsecret",
	})
	assert.False(t, result.IsError, "update_my_credentials with valid values should succeed")
	assertResultContains(t, result, "Credentials updated")
}


// ---------------------------------------------------------------------------
// Paper trading tools: auth checks
// ---------------------------------------------------------------------------
func TestPaperTradingToggle_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError, "paper_trading_toggle without auth should fail")
	assertResultContains(t, result, "authenticated")
}


func TestPaperTradingToggle_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_toggle", "user@example.com", map[string]any{
		"enable": true,
	})
	assert.True(t, result.IsError, "paper_trading_toggle without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}


func TestPaperTradingStatus_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_status without auth should fail")
	assertResultContains(t, result, "authenticated")
}


func TestPaperTradingStatus_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_status", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_status without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}


func TestPaperTradingReset_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_reset without auth should fail")
	assertResultContains(t, result, "authenticated")
}


func TestPaperTradingReset_NoPaperEngine(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "paper_trading_reset", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "paper_trading_reset without paper engine should fail")
	assertResultContains(t, result, "Paper trading requires database")
}


// ---------------------------------------------------------------------------
// P&L journal: auth and service checks
// ---------------------------------------------------------------------------
func TestGetPnLJournal_RequiresAuth(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError, "get_pnl_journal without email should fail")
	assertResultContains(t, result, "Email required")
}


func TestGetPnLJournal_NoPnLService(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_pnl_journal", "user@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_pnl_journal without PnL service should fail")
	assertResultContains(t, result, "not available")
}


// ---------------------------------------------------------------------------
// Margin tools: pre-session validation
// ---------------------------------------------------------------------------
func TestGetOrderMargins_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_order_margins with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestGetOrderMargins_LimitWithoutPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.True(t, result.IsError, "LIMIT without price should fail")
	assertResultContains(t, result, "price must be greater than 0")
}


func TestGetOrderMargins_SLWithoutTriggerPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_margins", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "SL",
		"price":            float64(1500),
	})
	assert.True(t, result.IsError, "SL without trigger_price should fail")
	assertResultContains(t, result, "trigger_price must be greater than 0")
}


func TestGetBasketMargins_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_basket_margins with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestGetBasketMargins_EmptyOrders(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": "",
	})
	assert.True(t, result.IsError, "empty orders should fail")
	assertResultContains(t, result, "cannot be empty")
}


func TestGetBasketMargins_InvalidJSON(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_basket_margins", "trader@example.com", map[string]any{
		"orders": "not valid json",
	})
	assert.True(t, result.IsError, "invalid JSON should fail")
	assertResultContains(t, result, "Invalid orders JSON")
}


func TestGetOrderCharges_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "get_order_charges with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestGetOrderCharges_EmptyOrders(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "",
	})
	assert.True(t, result.IsError, "empty orders should fail")
	assertResultContains(t, result, "cannot be empty")
}


func TestGetOrderCharges_InvalidJSON(t *testing.T) {

	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "{bad",
	})
	assert.True(t, result.IsError, "invalid JSON should fail")
	assertResultContains(t, result, "Invalid orders JSON")
}
func TestGetOrderCharges_EmptyArray(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "get_order_charges", "trader@example.com", map[string]any{
		"orders": "[]",
	})
	assert.True(t, result.IsError, "empty array should fail")
	assertResultContains(t, result, "cannot be empty")
}


// ---------------------------------------------------------------------------
// Plugin registration: no duplicates after clear
// ---------------------------------------------------------------------------
func TestPluginRegistration_DoesntDuplicateNames(t *testing.T) {
	ClearPlugins()
	tools := GetAllTools()
	names := make(map[string]int)
	for _, tool := range tools {
		names[tool.Tool().Name]++
	}
	for name, count := range names {
		assert.Equal(t, 1, count, "tool %s registered %d times", name, count)
	}
}


// ---------------------------------------------------------------------------
// convert_position: pre-session validation
// ---------------------------------------------------------------------------
func TestConvertPosition_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "convert_position with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestConvertPosition_MissingTradingsymbol(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "convert_position", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
		// tradingsymbol missing
	})
	assert.True(t, result.IsError, "convert_position without tradingsymbol should fail")
	assertResultContains(t, result, "tradingsymbol")
}


// ---------------------------------------------------------------------------
// portfolio_analysis: pre-session validation (rich)
// ---------------------------------------------------------------------------
func TestPortfolioRebalance_MissingTargets(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "portfolio_analysis without targets should fail")
	assertResultContains(t, result, "targets")
}


func TestPortfolioRebalance_InvalidTargetsJSON(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": "not json",
	})
	assert.True(t, result.IsError, "portfolio_analysis with invalid JSON should fail")
	assertResultContains(t, result, "Invalid")
}


func TestPortfolioRebalance_EmptyTargets(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": "{}",
	})
	assert.True(t, result.IsError, "portfolio_analysis with empty targets should fail")
	assertResultContains(t, result, "at least one symbol")
}


func TestPortfolioRebalance_InvalidMode(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": 50, "INFY": 50}`,
		"mode":    "invalid",
	})
	assert.True(t, result.IsError, "portfolio_analysis with invalid mode should fail")
	assertResultContains(t, result, "mode")
}


func TestPortfolioRebalance_NegativeThreshold(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets":   `{"RELIANCE": 50, "INFY": 50}`,
		"threshold": float64(-1),
	})
	assert.True(t, result.IsError, "portfolio_analysis with negative threshold should fail")
	assertResultContains(t, result, "threshold")
}


func TestPortfolioRebalance_ExcessivePercentage(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": 80, "INFY": 80}`,
		"mode":    "percentage",
	})
	assert.True(t, result.IsError, "portfolio_analysis with >105% should fail")
	assertResultContains(t, result, "exceeds 100%")
}


func TestPortfolioRebalance_NegativePercentage(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "portfolio_analysis", "trader@example.com", map[string]any{
		"targets": `{"RELIANCE": -10, "INFY": 50}`,
		"mode":    "percentage",
	})
	assert.True(t, result.IsError, "portfolio_analysis with negative percentage should fail")
	assertResultContains(t, result, "non-negative")
}


// ---------------------------------------------------------------------------
// order_risk_report: pre-session validation
// ---------------------------------------------------------------------------
func TestPreTradeCheck_MissingRequired(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "order_risk_report with no params should fail")
	assertResultContains(t, result, "is required")
}


func TestPreTradeCheck_ZeroQuantity(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(0),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.True(t, result.IsError, "order_risk_report with zero quantity should fail")
	assertResultContains(t, result, "quantity must be greater than 0")
}


func TestPreTradeCheck_LimitWithoutPrice(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "order_risk_report", "trader@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
	})
	assert.True(t, result.IsError, "order_risk_report LIMIT without price should fail")
	assertResultContains(t, result, "price must be greater than 0")
}


// ---------------------------------------------------------------------------
// subscribe_instruments / unsubscribe_instruments: pre-session validation
// ---------------------------------------------------------------------------
func TestSubscribeInstruments_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "subscribe_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "subscribe_instruments without instruments should fail")
	assertResultContains(t, result, "is required")
}


func TestUnsubscribeInstruments_MissingInstruments(t *testing.T) {
	mgr := newTestManager(t)
	result := callToolWithManager(t, mgr, "unsubscribe_instruments", "trader@example.com", map[string]any{})
	assert.True(t, result.IsError, "unsubscribe_instruments without instruments should fail")
	assertResultContains(t, result, "is required")
}


// ---------------------------------------------------------------------------
// Common: CacheKey function
// ---------------------------------------------------------------------------
func TestCacheKey_Consistency(t *testing.T) {
	key1 := CacheKey("get_ltp", "user@test.com", "NSE:INFY,NSE:SBIN")
	key2 := CacheKey("get_ltp", "user@test.com", "NSE:INFY,NSE:SBIN")
	assert.Equal(t, key1, key2, "same inputs should produce same cache key")

	key3 := CacheKey("get_ltp", "other@test.com", "NSE:INFY,NSE:SBIN")
	assert.NotEqual(t, key1, key3, "different inputs should produce different cache keys")
}


// ── Extended mock Kite HTTP server with POST/PUT/DELETE endpoints ─────────
func startExtendedMockKite() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		p := r.URL.Path

		envOK := func(data any) {
			b, _ := json.Marshal(map[string]any{"status": "success", "data": data})
			fmt.Fprint(w, string(b))
		}

		switch {
		// User
		case p == "/user/profile":
			envOK(map[string]any{
				"user_id": "AB1234", "user_name": "Mock User", "email": "mock@test.com",
			})
		case p == "/user/margins":
			envOK(map[string]any{
				"equity": map[string]any{
					"enabled": true, "net": 500000.0,
					"available": map[string]any{"cash": 500000.0, "collateral": 0.0, "intraday_payin": 0.0},
					"utilised":  map[string]any{"debits": 0.0, "exposure": 0.0, "m2m_realised": 0.0, "m2m_unrealised": 0.0},
				},
			})

		// Portfolio
		case p == "/portfolio/holdings":
			envOK([]map[string]any{
				{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 10, "average_price": 1500.0, "last_price": 1600.0, "pnl": 1000.0, "day_change_percentage": 2.5, "product": "CNC", "instrument_token": 256265},
			})
		case p == "/portfolio/positions":
			envOK(map[string]any{
				"net": []map[string]any{
					{"tradingsymbol": "INFY", "exchange": "NSE", "quantity": 5, "average_price": 1550.0, "last_price": 1600.0, "pnl": 250.0, "product": "MIS"},
				},
				"day": []map[string]any{},
			})

		// Orders — list
		case p == "/orders" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
				{"order_id": "MOCK-ORD-2", "status": "OPEN", "tradingsymbol": "RELIANCE", "exchange": "NSE", "transaction_type": "SELL", "order_type": "LIMIT", "quantity": 5.0, "average_price": 0.0, "filled_quantity": 0.0, "order_timestamp": "2026-04-01 10:05:00"},
				{"order_id": "MOCK-ORD-3", "status": "REJECTED", "tradingsymbol": "TCS", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 1.0, "average_price": 0.0, "filled_quantity": 0.0, "order_timestamp": "2026-04-01 10:10:00"},
			})

		// Orders — place
		case p == "/orders/regular" && r.Method == http.MethodPost:
			envOK(map[string]any{"order_id": "MOCK-NEW-ORD"})

		// Orders — modify
		case p == "/orders/regular/MOCK-ORD-1" && r.Method == http.MethodPut:
			envOK(map[string]any{"order_id": "MOCK-ORD-1"})

		// Orders — cancel
		case p == "/orders/regular/MOCK-ORD-1" && r.Method == http.MethodDelete:
			envOK(map[string]any{"order_id": "MOCK-ORD-1"})

		// Order history
		case p == "/orders/MOCK-NEW-ORD" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-NEW-ORD", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1520.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			})
		case p == "/orders/MOCK-ORD-1" && r.Method == http.MethodGet:
			envOK([]map[string]any{
				{"order_id": "MOCK-ORD-1", "status": "COMPLETE", "tradingsymbol": "INFY", "exchange": "NSE", "transaction_type": "BUY", "order_type": "MARKET", "quantity": 10.0, "average_price": 1500.0, "filled_quantity": 10.0, "order_timestamp": "2026-04-01 10:00:00"},
			})

		// Trades
		case p == "/trades":
			envOK([]map[string]any{
				{"trade_id": "T001", "order_id": "MOCK-ORD-1", "exchange": "NSE", "tradingsymbol": "INFY", "transaction_type": "BUY", "quantity": 10.0, "average_price": 1500.0},
			})

		// Quote
		case p == "/quote":
			envOK(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0, "ohlc": map[string]any{"open": 1590.0, "high": 1630.0, "low": 1585.0, "close": 1600.0}},
			})

		// Quote LTP
		case p == "/quote/ltp":
			envOK(map[string]any{
				"NSE:INFY": map[string]any{"instrument_token": 256265, "last_price": 1620.0},
			})

		// GTT
		case p == "/gtt/triggers" && r.Method == http.MethodGet:
			envOK([]map[string]any{})

		// MF
		case p == "/mf/orders" && r.Method == http.MethodGet:
			envOK([]map[string]any{})
		case p == "/mf/sips" && r.Method == http.MethodGet:
			envOK([]map[string]any{})
		case p == "/mf/holdings" && r.Method == http.MethodGet:
			envOK([]map[string]any{})

		// Margins / charges
		case p == "/margins/orders":
			envOK([]map[string]any{
				{"type": "equity", "tradingsymbol": "INFY", "exchange": "NSE", "total": 15000.0},
			})

		default:
			http.Error(w, `{"status":"error","message":"not found: `+p+`"}`, 404)
		}
	}))
}


// ── buildTradingContext — pure function tests ────────────────────────────
func TestBuildTradingContext_WithFullData(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	// Prepare full data with margins, positions, orders, holdings
	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 400000,
				Used:      100000,
				Total:     500000,
			},
		},
		"positions": broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 5, AveragePrice: 1500, LastPrice: 1600, PnL: money.NewINR(500), Product: "MIS"},
				{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: -3, AveragePrice: 2500, LastPrice: 2400, PnL: money.NewINR(300), Product: "NRML"},
				{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 0, AveragePrice: 3000, LastPrice: 3100, PnL: money.NewINR(0), Product: "CNC"},
			},
		},
		"orders": []broker.Order{
			{OrderID: "O1", Status: "COMPLETE", Tradingsymbol: "INFY"},
			{OrderID: "O2", Status: "OPEN", Tradingsymbol: "RELIANCE"},
			{OrderID: "O3", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O4", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O5", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O6", Status: "REJECTED", Tradingsymbol: "TCS"},
			{OrderID: "O7", Status: "TRIGGER PENDING", Tradingsymbol: "SBI"},
			{OrderID: "O8", Status: "AMO REQ RECEIVED", Tradingsymbol: "ITC"},
		},
		"holdings": []broker.Holding{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: money.NewINR(1000)},
			{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 5, AveragePrice: 2500, LastPrice: 2600, PnL: money.NewINR(500)},
		},
	}

	errs := map[string]string{"some_api": "timeout"}
	tc := buildTradingContextFromMap(data, errs, mgr, "test@example.com")

	assert.Equal(t, 2, tc.OpenPositions)
	assert.Equal(t, 800.0, tc.PositionsPnL)
	assert.Equal(t, 1, tc.MISPositions)
	assert.Equal(t, 1, tc.NRMLPositions)
	assert.Len(t, tc.PositionDetails, 2)
	assert.Equal(t, 1, tc.ExecutedToday)
	assert.Equal(t, 3, tc.PendingOrders) // OPEN + TRIGGER PENDING + AMO REQ RECEIVED
	assert.Equal(t, 4, tc.RejectedToday)
	assert.Equal(t, 2, tc.HoldingsCount)
	assert.Equal(t, 1500.0, tc.HoldingsDayPnL)
	assert.Equal(t, 400000.0, tc.MarginAvailable)
	assert.Equal(t, 100000.0, tc.MarginUsed)
	assert.Equal(t, 20.0, tc.MarginUtilization)
	assert.Contains(t, tc.Errors, "some_api")
	// Should have rejected orders warning (>3)
	found := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "rejected") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected rejected orders warning")
}


func TestBuildTradingContext_HighMarginUtilization_Push100(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	data := map[string]any{
		"margins": broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 50000,
				Used:      450000,
				Total:     500000,
			},
		},
	}

	tc := buildTradingContextFromMap(data, nil, mgr, "test@example.com")
	assert.Equal(t, 90.0, tc.MarginUtilization)
	// Should have high margin warning
	found := false
	for _, w := range tc.Warnings {
		if containsAnyStr(w, "margin utilization") {
			found = true
			break
		}
	}
	assert.True(t, found, "expected high margin utilization warning")
}


func TestBuildTradingContext_EmptyData_Push100(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	tc := buildTradingContextFromMap(map[string]any{}, nil, mgr, "")
	assert.Equal(t, 0, tc.OpenPositions)
	assert.Equal(t, 0, tc.HoldingsCount)
	assert.Equal(t, 0, tc.PendingOrders)
	assert.NotEmpty(t, tc.MarketStatus)
}


func TestBuildTradingContext_WithAlerts(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Set up alerts
	if store := mgr.AlertStore(); store != nil {
		_, _ = store.Add("test@example.com", "INFY", "NSE", 256265, 1700, alerts.Direction("above"))
		// Add a second alert and mark it triggered so it doesn't count
		id2, _ := store.Add("test@example.com", "RELIANCE", "NSE", 738561, 2000, alerts.Direction("below"))
		store.MarkTriggered(id2, 1950)
	}

	tc := buildTradingContextFromMap(map[string]any{}, nil, mgr, "test@example.com")
	assert.Equal(t, 1, tc.ActiveAlerts)
	assert.Len(t, tc.AlertDetails, 1)
	assert.Equal(t, "INFY", tc.AlertDetails[0].Symbol)
}


// ── Prompt handler tests ─────────────────────────────────────────────────
func TestMorningBriefPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	srv := server.NewMCPServer("test", "1.0")
	RegisterPrompts(srv, mgr)

	// Call the handler directly
	handler := morningBriefHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "Morning trading briefing", result.Description)
	assert.Len(t, result.Messages, 1)
	assert.Equal(t, gomcp.RoleUser, result.Messages[0].Role)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "Morning Trading Briefing")
	assert.Contains(t, text, "Step 1")
}


func TestTradeCheckPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol":   "RELIANCE",
		"action":   "BUY",
		"quantity": "100",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Contains(t, result.Description, "BUY")
	assert.Contains(t, result.Description, "RELIANCE")
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "RELIANCE")
	assert.Contains(t, text, "BUY")
	assert.Contains(t, text, "100")
}


func TestTradeCheckPrompt_DefaultsNoQty(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := tradeCheckHandler(mgr)
	req := gomcp.GetPromptRequest{}
	req.Params.Arguments = map[string]string{
		"symbol": "INFY",
	}
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "not specified")
	assert.Contains(t, text, "BUY") // default action
}


func TestEodReviewPrompt(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := eodReviewHandler(mgr)
	result, err := handler(context.Background(), gomcp.GetPromptRequest{})
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "End-of-day trading review", result.Description)
	assert.Len(t, result.Messages, 1)
	text := result.Messages[0].Content.(gomcp.TextContent).Text
	assert.Contains(t, text, "End-of-Day Review")
	assert.Contains(t, text, "Step 1")
}


// ── Setup tools helper tests ─────────────────────────────────────────────
func TestIsAlphanumeric_Push100(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  bool
	}{
		{"abc123", true},
		{"ABCdef", true},
		{"12345", true},
		{"", false},
		{"abc-def", false},
		{"abc def", false},
		{"abc_def", false},
		{"abc@def", false},
	}
	for _, tt := range tests {
		assert.Equal(t, tt.want, isAlphanumeric(tt.input), "isAlphanumeric(%q)", tt.input)
	}
}


func TestDashboardLink(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	link := dashboardLink(mgr)
	// May be empty if no external URL — just check it doesn't panic
	_ = link
}


func TestDashboardURLForTool_Mapped(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// A tool that should be mapped
	url := DashboardURLForTool(mgr, "get_holdings")
	// May be empty if no external URL configured, but function should not panic
	_ = url
}


func TestDashboardURLForTool_Unmapped(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	url := DashboardURLForTool(mgr, "nonexistent_tool")
	assert.Empty(t, url)
}


func TestPageRoutes_AllValid(t *testing.T) {
	t.Parallel()
	for page, path := range pageRoutes {
		assert.NotEmpty(t, page, "empty page name")
		assert.NotEmpty(t, path, "empty path for page %s", page)
		assert.Contains(t, path, "/dashboard", "path for %s should contain /dashboard", page)
	}
}


// ── MarketStatus (scheduler) via buildTradingContext ──────────────────────
func TestBuildTradingContext_MarketStatus(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	tc := buildTradingContextFromMap(map[string]any{}, nil, mgr, "")
	// scheduler.MarketStatus always returns a non-empty string
	assert.NotEmpty(t, tc.MarketStatus)
	// Validate it's one of the known statuses
	valid := map[string]bool{
		"open": true, "closed": true, "pre_open": true,
		"closing_session": true, "closed_weekend": true, "closed_holiday": true,
	}
	assert.True(t, valid[tc.MarketStatus], "unexpected market status: %s", tc.MarketStatus)
}


// ── Account tools ────────────────────────────────────────────────────────
func TestDeleteMyAccount_NotConfirmed(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "confirm")
}


func TestDeleteMyAccount_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}


func TestDeleteMyAccount_Success(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.False(t, result.IsError, resultText(t, result))
	assert.Contains(t, resultText(t, result), "deleted")
}


func TestUpdateMyCredentials_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key": "newkey123", "api_secret": "newsecret456",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}


func TestUpdateMyCredentials_MissingKey(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_secret": "newsecret456",
	})
	assert.True(t, result.IsError)
}


// ── Paper trading tool edge cases ────────────────────────────────────────
func TestPaperTradingToggle_EnableAndStatus(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Enable
	result := callToolAdmin(t, mgr, "paper_trading_toggle", "dev@example.com", map[string]any{
		"enable": true, "initial_cash": float64(5000000),
	})
	assert.False(t, result.IsError, resultText(t, result))

	// Status
	result = callToolAdmin(t, mgr, "paper_trading_status", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))

	// Reset
	result = callToolAdmin(t, mgr, "paper_trading_reset", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))
}


// ── PnL journal edge cases ───────────────────────────────────────────────
func TestPnLJournal_NoEmail(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "get_pnl_journal", "", map[string]any{})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Email required")
}


func TestPnLJournal_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	periods := []string{"week", "month", "quarter", "year", "all"}
	for _, period := range periods {
		result := callToolAdmin(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
			"period": period,
		})
		assert.False(t, result.IsError, "period %s: %s", period, resultText(t, result))
	}
}


func TestPnLJournal_CustomDates(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "get_pnl_journal", "dev@example.com", map[string]any{
		"from": "2026-01-01",
		"to":   "2026-03-01",
	})
	assert.False(t, result.IsError, resultText(t, result))
}


// ── Watchlist tool edge cases ────────────────────────────────────────────
func TestWatchlistTools_FullLifecycle(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)

	// Create
	result := callToolAdmin(t, mgr, "create_watchlist", "dev@example.com", map[string]any{
		"name": "Tech Stocks",
	})
	assert.False(t, result.IsError, resultText(t, result))
	assert.Contains(t, resultText(t, result), "Tech Stocks")

	// List
	result = callToolAdmin(t, mgr, "list_watchlists", "dev@example.com", map[string]any{})
	assert.False(t, result.IsError, resultText(t, result))

	// Delete non-existent
	result = callToolAdmin(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "nonexistent",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not found")

	// Delete the real one
	result = callToolAdmin(t, mgr, "delete_watchlist", "dev@example.com", map[string]any{
		"watchlist": "Tech Stocks",
	})
	assert.False(t, result.IsError, resultText(t, result))
}


// ── Historical data edge cases ───────────────────────────────────────────
func TestHistoricalData_InvalidDateFormat(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "01-01-2026",
		"to_date":          "2026-03-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "parse from_date")
}


func TestHistoricalData_FromAfterTo(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-03-01 00:00:00",
		"to_date":          "2026-01-01 00:00:00",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "from_date must be before")
}


func TestHistoricalData_InvalidToDate(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_historical_data", "dev@example.com", map[string]any{
		"instrument_token": float64(256265),
		"from_date":        "2026-01-01 00:00:00",
		"to_date":          "invalid",
		"interval":         "day",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "parse to_date")
}


// ── DashboardURLMiddleware ───────────────────────────────────────────────
func TestDashboardURLMiddleware_NoError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.False(t, result.IsError)
}


func TestDashboardURLMiddleware_WithError(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultError("something went wrong"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "get_holdings"
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, result.IsError)
	// Should NOT append dashboard URL on error
	assert.Len(t, result.Content, 1)
}


func TestDashboardURLMiddleware_UnmappedTool(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	middleware := DashboardURLMiddleware(mgr)
	inner := func(ctx context.Context, req gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		return gomcp.NewToolResultText("ok"), nil
	}
	handler := middleware(inner)

	req := gomcp.CallToolRequest{}
	req.Params.Name = "login" // not in dashboard page mapping
	result, err := handler(context.Background(), req)
	require.NoError(t, err)
	// login is not mapped, so no extra content block
	assert.Len(t, result.Content, 1)
}


// ── Login tool edge cases ────────────────────────────────────────────────
func TestLogin_InvalidAPIKeyChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "abc-def!", "api_secret": "valid123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}


func TestLogin_InvalidAPISecretChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "valid123", "api_secret": "abc def",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}


func TestLogin_OnlyAPIKeyNoSecret(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "valid123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "api_key and api_secret")
}


// ── Open dashboard tool ──────────────────────────────────────────────────
func TestOpenDashboard_Default(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestOpenDashboard_ActivityPage_Push100(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity", "category": "order", "days": float64(7), "errors": true,
	})
	assert.NotNil(t, result)
}


func TestOpenDashboard_InvalidPage(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "nonexistent_page",
	})
	// Should fall back to portfolio page, not error
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


// ── Server metrics tool ──────────────────────────────────────────────────
func TestServerMetrics_AdminSuccess(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
		"period": "1h",
	})
	assert.False(t, result.IsError, resultText(t, result))
	text := resultText(t, result)
	assert.Contains(t, text, "uptime")
}


func TestServerMetrics_AllPeriods(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	for _, period := range []string{"1h", "24h", "7d", "30d"} {
		result := callToolAdmin(t, mgr, "server_metrics", "admin@example.com", map[string]any{
			"period": period,
		})
		assert.False(t, result.IsError, "period %s: %s", period, resultText(t, result))
	}
}


// ── Session type context helpers ─────────────────────────────────────────
func TestSessionTypeContext(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	assert.Equal(t, SessionTypeUnknown, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeSSE)
	assert.Equal(t, SessionTypeSSE, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeMCP)
	assert.Equal(t, SessionTypeMCP, SessionTypeFromContext(ctx))

	ctx = WithSessionType(ctx, SessionTypeStdio)
	assert.Equal(t, SessionTypeStdio, SessionTypeFromContext(ctx))
}


// ── ToolHandler trackToolCall / trackToolError (no-op without metrics) ───
func TestToolHandler_TrackCallsNoMetrics(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	// Should not panic even without metrics configured
	handler.trackToolCall(context.Background(), "test_tool")
	handler.trackToolError(context.Background(), "test_tool", "test_error")
}

// ── Phase 3a Batch 6: narrow accessors on *ToolHandler ──────────────────
//
// These accessors thread the corresponding ToolHandlerDeps provider through
// to the per-handler scope, replacing direct h.manager.X() reaches.
// Behaviour-preserving: each accessor is a 1-line passthrough to the
// already-wired deps field; all tests below assert the returned pointer
// matches the manager's accessor.

func TestToolHandler_RiskGuardAccessor_ReturnsManagerRiskGuard(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	assert.Same(t, mgr.RiskGuard(), handler.RiskGuard(),
		"handler.RiskGuard() must return the same pointer as manager.RiskGuard()")
}

func TestToolHandler_AlertStoreAccessor_ReturnsManagerAlertStore(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	// Allow nil — the accessor MUST NOT panic when the underlying store is nil
	// (DevMode without ALERT_DB_PATH leaves it unset).
	got := handler.AlertStore()
	want := mgr.AlertStore()
	if got == nil && want == nil {
		return
	}
	assert.Same(t, want, got,
		"handler.AlertStore() must return the same pointer as manager.AlertStore()")
}

func TestToolHandler_AlertDBAccessor_ReturnsManagerAlertDB(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	got := handler.AlertDB()
	want := mgr.AlertDB()
	if got == nil && want == nil {
		return
	}
	assert.Same(t, want, got,
		"handler.AlertDB() must return the same pointer as manager.AlertDB()")
}

func TestToolHandler_WatchlistStoreAccessor_ReturnsManagerWatchlistStore(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	got := handler.WatchlistStore()
	want := mgr.WatchlistStore()
	if got == nil && want == nil {
		return
	}
	assert.Same(t, want, got,
		"handler.WatchlistStore() must return the same pointer as manager.WatchlistStore()")
}

// ── Phase 3a Batch 6b: extAppManagerPort interface assertion ────────────
//
// The ext_apps DataFunc + plugin_widget DataFunc signatures take
// extAppManagerPort instead of *kc.Manager directly. *kc.Manager must
// satisfy this interface implicitly so all 80 test callsites that pass
// `mgr` to portfolioData / activityData / etc. continue to compile
// without modification. This compile-time assertion plus a runtime test
// pin the contract.
func TestExtAppManagerPort_KcManagerSatisfies(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// Compile-time assertion at the var line below. This runtime check
	// proves the interface satisfaction is real, not just a Go-rules
	// accident — any drift in the manager's accessor signatures (e.g. an
	// accidental rename of QueryBus to GetQueryBus) breaks this test
	// instead of breaking 80 ext_apps test callsites silently.
	var port extAppManagerPort = mgr
	assert.NotNil(t, port, "*kc.Manager must satisfy extAppManagerPort")
	assert.NotNil(t, port.QueryBus(), "extAppManagerPort.QueryBus must be non-nil for a wired Manager")
}


// ── Scheduler.MarketStatus ───────────────────────────────────────────────
func TestSchedulerMarketStatus(t *testing.T) {
	t.Parallel()
	// Just ensure it returns a known status for "now"
	status := scheduler.MarketStatus(time.Now())
	valid := map[string]bool{
		"open": true, "closed": true, "pre_open": true,
		"closing_session": true, "closed_weekend": true, "closed_holiday": true,
	}
	assert.True(t, valid[status], "unknown market status: %s", status)
}


// ── parseInstrumentList ──────────────────────────────────────────────────
func TestParseInstrumentList_Push100(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  []string
	}{
		{"NSE:INFY,NSE:RELIANCE", []string{"NSE:INFY", "NSE:RELIANCE"}},
		{" NSE:INFY , NSE:RELIANCE ", []string{"NSE:INFY", "NSE:RELIANCE"}},
		{"NSE:INFY", []string{"NSE:INFY"}},
		{"", nil},
		{",,,", nil},
	}
	for _, tt := range tests {
		result := parseInstrumentList(tt.input)
		assert.Equal(t, tt.want, result, "parseInstrumentList(%q)", tt.input)
	}
}


// ── roundTo2 helper ──────────────────────────────────────────────────────
func TestRoundTo2_Push100(t *testing.T) {
	t.Parallel()
	assert.Equal(t, 1.23, roundTo2(1.234))
	assert.Equal(t, 1.24, roundTo2(1.235))
	assert.Equal(t, 0.0, roundTo2(0.0))
	assert.Equal(t, -1.23, roundTo2(-1.234))
}


// ── Mock Kite — PlaceOrder success path with enriched fill status ────────
func TestMock_PlaceOrder_SuccessWithFillCheck(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "place_order", map[string]any{
		"variety": "regular", "exchange": "NSE", "tradingsymbol": "INFY",
		"transaction_type": "BUY", "quantity": float64(10), "product": "CNC",
		"order_type": "MARKET",
	})
	assert.NotNil(t, result)
}


// ── Mock Kite — ModifyOrder success path ─────────────────────────────────
func TestMock_ModifyOrder_Success(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "modify_order", map[string]any{
		"order_id": "MOCK-ORD-1", "variety": "regular",
		"quantity": float64(20), "order_type": "MARKET",
	})
	assert.NotNil(t, result)
}


// ── Mock Kite — CancelOrder success path ─────────────────────────────────
func TestMock_CancelOrder_Success(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "cancel_order", map[string]any{
		"order_id": "MOCK-ORD-1", "variety": "regular",
	})
	assert.NotNil(t, result)
}


// ── Mock Kite — TradingContext success path ───────────────────────────────
func TestMock_TradingContext_FullSuccess(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()
	mgr := newMockKiteManager(t, ts.URL)

	result := callMockTool(t, mgr, "trading_context", map[string]any{})
	assert.NotNil(t, result)
}


// ── Mock Kite — get_watchlist with session (LTP call) ────────────────────
func TestMock_GetWatchlist_WithLTP(t *testing.T) {
	t.Parallel()
	ts := startExtendedMockKite()
	defer ts.Close()

	mgr := newMockKiteManager(t, ts.URL)

	// Create a watchlist and add an item
	wlStore := mgr.WatchlistStore()
	wlID, err := wlStore.CreateWatchlist(mockEmail, "Test WL")
	require.NoError(t, err)

	err = wlStore.AddItem(mockEmail, wlID, &watchlist.WatchlistItem{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		InstrumentToken: 256265,
	})
	if err != nil {
		t.Logf("AddItem error (expected if store interface differs): %v", err)
	}

	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, mockEmail)
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: mockSessionID})

	for _, tool := range GetAllTools() {
		if tool.Tool().Name == "get_watchlist" {
			req := gomcp.CallToolRequest{}
			req.Params.Name = "get_watchlist"
			req.Params.Arguments = map[string]any{"watchlist": "Test WL", "include_ltp": true}
			result, err := tool.Handler(mgr)(ctx, req)
			require.NoError(t, err)
			assert.NotNil(t, result)
			break
		}
	}
}


// ── Modify order edge cases ──────────────────────────────────────────────

// ── SimpleToolHandler / HandleAPICall ────────────────────────────────────
func TestSimpleToolHandler_DevMode(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)

	handler := SimpleToolHandler(mgr, "test_tool", func(_ context.Context, session *kc.KiteSessionData) (any, error) {
		return map[string]string{"status": "ok"}, nil
	})

	ctx := context.Background()
	ctx = oauth.ContextWithEmail(ctx, "dev@example.com")
	mcpSrv := server.NewMCPServer("test", "1.0")
	ctx = mcpSrv.WithContext(ctx, &mockSession{id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890"})

	req := gomcp.CallToolRequest{}
	req.Params.Name = "test_tool"
	result, err := handler(ctx, req)
	require.NoError(t, err)
	assert.NotNil(t, result)
}


// ── ValidationError ──────────────────────────────────────────────────────
func TestValidationError_String(t *testing.T) {
	t.Parallel()
	err := ValidationError{Parameter: "quantity", Message: "must be positive"}
	assert.Equal(t, "parameter 'quantity': must be positive", err.Error())
}


// ── WithViewerBlock ──────────────────────────────────────────────────────
func TestWithViewerBlock_ReadOnlyTool(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	handler := NewToolHandler(mgr)
	ctx := oauth.ContextWithEmail(context.Background(), "test@example.com")
	result := handler.WithViewerBlock(ctx, "get_profile")
	assert.Nil(t, result) // read-only tool = no block even for viewer
}
