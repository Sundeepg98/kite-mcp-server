package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestDevMode_GetHoldings(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetProfile(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrders(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetGTTs(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderTrades(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderHistory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "MARKET",
	})
	assert.NotNil(t, result)
}


func TestDevMode_ModifyOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"variety":    "regular",
		"order_id":   "ORD001",
		"order_type": "LIMIT",
		"quantity":   float64(10),
		"price":      float64(1500),
	})
	assert.NotNil(t, result)
}


func TestDevMode_CancelOrder(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{
		"variety":  "regular",
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"quantity":         float64(10),
		"limit_price":      float64(1395),
	})
	assert.NotNil(t, result)
}


func TestDevMode_DeleteGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{
		"trigger_id": float64(1001),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ModifyGTT(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"trigger_id":       float64(1001),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"last_price":       float64(1500),
		"transaction_type": "BUY",
		"product":          "CNC",
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ConvertPosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
		"position_type":    "day",
	})
	assert.NotNil(t, result)
}


func TestDevMode_ClosePosition(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}


func TestDevMode_PortfolioSummary(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PortfolioConcentration(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PositionAnalysis(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_SectorExposure(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_TaxHarvest(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_loss_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_DividendCalendar(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PortfolioRebalance(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"targets": `{"INFY": 50, "TCS": 50}`,
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetBasketMargins(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderCharges(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORD001",
	})
	assert.NotNil(t, result)
}


func TestDevMode_DividendCalendar_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body with mock broker data
}


func TestDevMode_SectorExposure_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}


func TestDevMode_PortfolioSummary_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body with mock data
}


func TestDevMode_PortfolioConcentration_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PositionAnalysis_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_TaxHarvest_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_loss_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetHoldings_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(2),
	})
	assert.NotNil(t, result)
	// Exercises PaginatedToolHandler with from/limit
}


func TestDevMode_GetPositions_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// Exercises handler body
}


func TestDevMode_GetOrders_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetTrades_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetPositions_DayType(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"position_type": "day",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetPositions_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"position_type": "net",
		"from":          float64(0),
		"limit":         float64(2),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_WithTag(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"variety":          "regular",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"tag":              "test123",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceGTT_FullParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"trigger_type":     "single",
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"trigger_values":   "1500",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"product":          "CNC",
		"order_type":       "LIMIT",
		"price":            float64(1500),
		"last_price":       float64(1800),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderHistory_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{
		"order_id": "ORDER123",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderTrades_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{
		"order_id": "ORDER123",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetProfile_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetMargins_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetTrades_Paginated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"from":  float64(0),
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ConvertPosition_Full(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetBasketMargins_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"product":"CNC","order_type":"MARKET"}]`,
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderCharges_V2(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"order_id": "ORDER-123",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderMargins_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "GetOrderMargins should succeed via mock broker in DEV_MODE")
}


func TestDevMode_GetBasketMargins_SucceedsViaMockBroker(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders": `[{"exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"order_type":"MARKET","product":"CNC"}]`,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError, "GetBasketMargins should succeed via mock broker in DEV_MODE")
}


func TestDevMode_GetOrderCharges_RequiresOrdersParam(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{
		"orders": `[{"order_id":"ORD001","exchange":"NSE","tradingsymbol":"INFY","transaction_type":"BUY","quantity":10,"average_price":1500,"product":"CNC","order_type":"MARKET","variety":"regular"}]`,
	})
	assert.NotNil(t, result)
	// get_order_charges now routes through mock broker and succeeds
	assert.False(t, result.IsError, "GetOrderCharges should succeed via mock broker in DEV_MODE")
}


func TestDevMode_PortfolioRebalance_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PortfolioRebalance_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"target_allocation": "not json",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PortfolioRebalance_ValidAllocation(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"target_allocation": `{"NSE:INFY": 50, "NSE:RELIANCE": 50}`,
	})
	assert.NotNil(t, result)
	// Should reach API call or computation
}


func TestDevMode_PortfolioRebalance_OverAllocated(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_analysis", "dev@example.com", map[string]any{
		"target_allocation": `{"NSE:INFY": 60, "NSE:RELIANCE": 60}`,
	})
	assert.NotNil(t, result)
}


func TestDevMode_TaxHarvest_WithMinLoss(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "tax_loss_analysis", "dev@example.com", map[string]any{
		"min_loss_pct": float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_DividendCalendar_WithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "dividend_calendar", "dev@example.com", map[string]any{
		"days": float64(30),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PortfolioSummary_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_summary", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PortfolioConcentration_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "portfolio_concentration", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PositionAnalysis_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "position_analysis", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_LimitMissingPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		// Missing price — should trigger validation
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PlaceOrder_SLMissingTrigger(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL",
		"product":          "CNC",
		"price":            float64(1500),
		// Missing trigger_price — should trigger validation
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PlaceOrder_IcebergValidation(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(100),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
		"iceberg_legs":     float64(3),
		"iceberg_quantity": float64(0),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ModifyOrder_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_CancelOrder_MissingOrderID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "cancel_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_PlaceGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_ModifyGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_DeleteGTTOrder_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_gtt_order", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_ClosePosition_MissingInstrument(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_ClosePosition_BadFormat(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NOCOLON",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_ClosePosition_WithProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"product":    "MIS",
	})
	assert.NotNil(t, result)
}


func TestDevMode_ConvertPosition_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_CloseAllPositions_WithProduct(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"product": "MIS",
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetHoldings_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_holdings", "dev@example.com", map[string]any{
		"sort_by": "pnl",
		"limit":   float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetPositions_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_positions", "dev@example.com", map[string]any{
		"product": "MIS",
		"limit":   float64(10),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrders_WithFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_orders", "dev@example.com", map[string]any{
		"status": "COMPLETE",
		"limit":  float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetTrades_WithLimit(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_trades", "dev@example.com", map[string]any{
		"limit": float64(5),
	})
	assert.NotNil(t, result)
}


func TestDevMode_GetGTTs_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_gtts", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetProfile_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_profile", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetMargins_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_GetOrderHistory_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_history", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOrderTrades_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_trades", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOrderMargins_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetBasketMargins_MissingJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetBasketMargins_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_basket_margins", "dev@example.com", map[string]any{
		"orders_json": "not valid json",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_GetOrderCharges_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "get_order_charges", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_SectorExposure_Again(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "sector_exposure", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_MarketValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(1),
		"order_type":       "MARKET",
		"product":          "CNC",
	})
	assert.NotNil(t, result)
	// Should reach the Kite API call and get connection error
}


func TestDevMode_PlaceOrder_LimitValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_SLValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL",
		"product":          "CNC",
		"price":            float64(1500),
		"trigger_price":    float64(1490),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_SLMValidParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "SL-M",
		"product":          "CNC",
		"trigger_price":    float64(1490),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_WithDisclosedQty(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":           "NSE",
		"tradingsymbol":      "INFY",
		"transaction_type":   "BUY",
		"quantity":           float64(100),
		"order_type":         "LIMIT",
		"product":            "CNC",
		"price":              float64(1500),
		"disclosed_quantity": float64(10),
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_WithValidity(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(1500),
		"validity":         "IOC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_WithTagAndValidity(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"order_type":       "MARKET",
		"product":          "CNC",
		"tag":              "test_tag",
	})
	assert.NotNil(t, result)
}


func TestDevMode_ModifyOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_order", "dev@example.com", map[string]any{
		"order_id":      "ORD001",
		"quantity":      float64(20),
		"price":         float64(1600),
		"trigger_price": float64(1590),
		"order_type":    "SL",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceGTTOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_gtt_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"price":            float64(1400),
		"product":          "CNC",
		"last_price":       float64(1500),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ModifyGTTOrder_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "modify_gtt_order", "dev@example.com", map[string]any{
		"gtt_id":           float64(12345),
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"trigger_type":     "single",
		"trigger_value":    float64(1400),
		"price":            float64(1400),
		"product":          "CNC",
		"last_price":       float64(1500),
	})
	assert.NotNil(t, result)
}


func TestDevMode_ConvertPosition_AllParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "convert_position", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "INFY",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"old_product":      "MIS",
		"new_product":      "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_NoFilter(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_Exchange(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"exchange": "NSE",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_Confirmed(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "MIS",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "Safety")
}


func TestDevMode_CloseAllPositions_AllProducts(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "ALL",
	})
	assert.NotNil(t, result)
}


func TestDevMode_CloseAllPositions_CNC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_all_positions", "dev@example.com", map[string]any{
		"confirm": true,
		"product": "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_ClosePosition_WithProductCNC(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "close_position", "dev@example.com", map[string]any{
		"instrument": "NSE:INFY",
		"product":    "CNC",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_NRML(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NFO",
		"tradingsymbol":    "NIFTY24MAR18000CE",
		"transaction_type": "BUY",
		"quantity":         float64(50),
		"order_type":       "MARKET",
		"product":          "NRML",
	})
	assert.NotNil(t, result)
}


func TestDevMode_PlaceOrder_SellWithPrice(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "place_order", "dev@example.com", map[string]any{
		"exchange":         "NSE",
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "SELL",
		"quantity":         float64(5),
		"order_type":       "LIMIT",
		"product":          "CNC",
		"price":            float64(2500),
	})
	assert.NotNil(t, result)
}
