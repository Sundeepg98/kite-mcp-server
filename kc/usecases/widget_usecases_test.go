package usecases

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/money"
)

// --- Mock implementations for widget tests ---

// mockWidgetAuditStore implements WidgetAuditStore for testing.
type mockWidgetAuditStore struct {
	entries    []*audit.ToolCall
	total      int
	listErr    error
	stats      *audit.Stats
	statsErr   error
	toolCounts map[string]int
	countsErr  error
	orders     []*audit.ToolCall
	ordersErr  error
}

func (m *mockWidgetAuditStore) List(email string, opts audit.ListOptions) ([]*audit.ToolCall, int, error) {
	return m.entries, m.total, m.listErr
}

func (m *mockWidgetAuditStore) GetStats(email string, since time.Time, category string, errorsOnly bool) (*audit.Stats, error) {
	return m.stats, m.statsErr
}

func (m *mockWidgetAuditStore) GetToolCounts(email string, since time.Time, category string, errorsOnly bool) (map[string]int, error) {
	return m.toolCounts, m.countsErr
}

func (m *mockWidgetAuditStore) ListOrders(email string, since time.Time) ([]*audit.ToolCall, error) {
	return m.orders, m.ordersErr
}

// mockWidgetAlertStore implements WidgetAlertStore for testing.
type mockWidgetAlertStore struct {
	alerts []*alerts.Alert
}

func (m *mockWidgetAlertStore) List(email string) []*alerts.Alert {
	return m.alerts
}

// positionsErrClient embeds mockBrokerClient and overrides GetPositions to return an error.
type positionsErrClient struct {
	mockBrokerClient
}

func (c *positionsErrClient) GetPositions() (broker.Positions, error) {
	return broker.Positions{}, fmt.Errorf("positions API error")
}

// --- GetPortfolioForWidgetUseCase tests ---

func TestGetPortfolioForWidget_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetPortfolioForWidgetUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetPortfolioForWidget_ResolverError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "resolve broker")
}

func TestGetPortfolioForWidget_HoldingsError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{client: &holdingsErrClient{}}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get holdings")
}

func TestGetPortfolioForWidget_PositionsError(t *testing.T) {
	t.Parallel()
	resolver := &mockBrokerResolver{client: &positionsErrClient{
		mockBrokerClient: mockBrokerClient{
			holdings: []broker.Holding{{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: money.NewINR(1000)}},
		},
	}}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "get positions")
}

func TestGetPortfolioForWidget_Success(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{
		holdings: []broker.Holding{
			{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 10, AveragePrice: 1500, LastPrice: 1600, PnL: money.NewINR(1000), DayChangePct: 2.5},
			{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 5, AveragePrice: 3000, LastPrice: 3200, PnL: money.NewINR(1000), DayChangePct: 1.0},
		},
		positions: broker.Positions{
			Net: []broker.Position{
				{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 2, AveragePrice: 2500, LastPrice: 2600, PnL: money.NewINR(200), Product: "CNC"},
			},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: "test@test.com"})
	require.NoError(t, err)

	assert.Len(t, result.Holdings, 2)
	assert.Equal(t, "INFY", result.Holdings[0].Symbol)
	assert.Equal(t, 10, result.Holdings[0].Quantity)
	assert.Equal(t, 1500.0, result.Holdings[0].AvgPrice)
	assert.Equal(t, 1600.0, result.Holdings[0].LastPrice)
	assert.Equal(t, 1000.0, result.Holdings[0].PnL)
	assert.Equal(t, 2.5, result.Holdings[0].DayChgPct)

	assert.Len(t, result.Positions, 1)
	assert.Equal(t, "RELIANCE", result.Positions[0].Symbol)
	assert.Equal(t, "CNC", result.Positions[0].Product)
	assert.Equal(t, 200.0, result.Positions[0].PnL)

	// Verify summary calculations.
	assert.Equal(t, 2, result.Summary["holdings_count"])
	assert.Equal(t, 1, result.Summary["positions_count"])
	// total_invested = 10*1500 + 5*3000 = 30000
	assert.Equal(t, 30000.0, result.Summary["total_invested"])
	// total_current = 10*1600 + 5*3200 = 32000
	assert.Equal(t, 32000.0, result.Summary["total_current"])
	// total_pnl = 1000 + 1000 = 2000
	assert.Equal(t, 2000.0, result.Summary["total_pnl"])
	// positions_pnl = 200
	assert.Equal(t, 200.0, result.Summary["positions_pnl"])
}

func TestGetPortfolioForWidget_EmptyPortfolio(t *testing.T) {
	t.Parallel()
	client := &mockBrokerClient{}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetPortfolioForWidgetUseCase(resolver, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetPortfolioQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Empty(t, result.Holdings)
	assert.Empty(t, result.Positions)
	assert.Equal(t, 0, result.Summary["holdings_count"])
	assert.Equal(t, 0, result.Summary["positions_count"])
	assert.Equal(t, 0.0, result.Summary["total_pnl"])
}

// --- GetOrdersForWidgetUseCase tests ---

func TestGetOrdersForWidget_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetOrdersForWidgetUseCase(&mockBrokerResolver{}, &mockWidgetAuditStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetOrdersForWidget_ListOrdersError(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{ordersErr: fmt.Errorf("db error")}
	uc := NewGetOrdersForWidgetUseCase(&mockBrokerResolver{}, store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list orders")
}

func TestGetOrdersForWidget_Success_WithBrokerEnrichment(t *testing.T) {
	t.Parallel()
	params, _ := json.Marshal(map[string]any{
		"tradingsymbol":    "INFY",
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"order_type":       "LIMIT",
		"quantity":         float64(10),
		"price":            float64(1500),
	})
	store := &mockWidgetAuditStore{
		orders: []*audit.ToolCall{
			{OrderID: "ORD-1", InputParams: string(params), StartedAt: time.Now()},
			{OrderID: "ORD-2", InputParams: "{}", StartedAt: time.Now()},
		},
	}
	client := &mockBrokerClient{
		orders: []broker.Order{
			{OrderID: "ORD-1", Status: "COMPLETE", FilledQuantity: 10, AveragePrice: 1495, Tradingsymbol: "INFY", Exchange: "NSE", TransactionType: "BUY", Quantity: 10, Price: 1500},
			{OrderID: "ORD-2", Status: "REJECTED", Tradingsymbol: "TCS", Exchange: "NSE", TransactionType: "SELL", Quantity: 5, Price: 3000},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrdersForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Len(t, result.Orders, 2)

	// First order: params from audit + enriched from broker.
	assert.Equal(t, "ORD-1", result.Orders[0].OrderID)
	assert.Equal(t, "INFY", result.Orders[0].Symbol)
	assert.Equal(t, "COMPLETE", result.Orders[0].Status)
	assert.Equal(t, 10.0, result.Orders[0].FilledQuantity)
	assert.Equal(t, 1495.0, result.Orders[0].AveragePrice)

	// Second order: no params in audit, enriched from broker.
	assert.Equal(t, "ORD-2", result.Orders[1].OrderID)
	assert.Equal(t, "TCS", result.Orders[1].Symbol)
	assert.Equal(t, "REJECTED", result.Orders[1].Status)

	// Summary.
	assert.Equal(t, 2, result.Summary["total"])
	assert.Equal(t, 1, result.Summary["completed"])
	assert.Equal(t, 1, result.Summary["rejected"])
	assert.Equal(t, 0, result.Summary["pending"])
	// total_buy_value = 1495 * 10 = 14950
	assert.Equal(t, 14950.0, result.Summary["total_buy_value"])
	assert.Equal(t, 0.0, result.Summary["total_sell_value"])
}

func TestGetOrdersForWidget_NoBroker_FallsBack(t *testing.T) {
	t.Parallel()
	params, _ := json.Marshal(map[string]any{
		"tradingsymbol":    "INFY",
		"exchange":         "NSE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
	})
	store := &mockWidgetAuditStore{
		orders: []*audit.ToolCall{
			{OrderID: "ORD-1", InputParams: string(params), StartedAt: time.Now()},
		},
	}
	// Broker resolver error — should still return orders from audit data.
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetOrdersForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Len(t, result.Orders, 1)
	assert.Equal(t, "INFY", result.Orders[0].Symbol)
	assert.Equal(t, "BUY", result.Orders[0].Side)
	// No broker enrichment, so status is empty.
	assert.Equal(t, "", result.Orders[0].Status)
}

func TestGetOrdersForWidget_EmptyOrders(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{orders: []*audit.ToolCall{}}
	uc := NewGetOrdersForWidgetUseCase(&mockBrokerResolver{}, store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Empty(t, result.Orders)
	assert.Equal(t, 0, result.Summary["total"])
}

func TestGetOrdersForWidget_PendingOrders(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{
		orders: []*audit.ToolCall{
			{OrderID: "ORD-1", StartedAt: time.Now()},
			{OrderID: "ORD-2", StartedAt: time.Now()},
		},
	}
	client := &mockBrokerClient{
		orders: []broker.Order{
			{OrderID: "ORD-1", Status: "OPEN", TransactionType: "BUY"},
			{OrderID: "ORD-2", Status: "TRIGGER PENDING", TransactionType: "SELL"},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetOrdersForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetOrdersQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Equal(t, 2, result.Summary["pending"])
	assert.Equal(t, 0, result.Summary["completed"])
}

// --- GetAlertsForWidgetUseCase tests ---

func TestGetAlertsForWidget_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetAlertsForWidgetUseCase(&mockBrokerResolver{}, &mockWidgetAlertStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetAlertsForWidget_Success_ActiveAndTriggered(t *testing.T) {
	t.Parallel()
	now := time.Now()
	store := &mockWidgetAlertStore{
		alerts: []*alerts.Alert{
			{ID: "a1", Tradingsymbol: "INFY", Exchange: "NSE", Direction: alerts.DirectionAbove, TargetPrice: 1700, Triggered: false, CreatedAt: now},
			{ID: "a2", Tradingsymbol: "TCS", Exchange: "NSE", Direction: alerts.DirectionBelow, TargetPrice: 2800, Triggered: true, CreatedAt: now.Add(-time.Hour), TriggeredAt: now, TriggeredPrice: 2795},
		},
	}
	client := &mockBrokerClient{
		ltpMap: map[string]broker.LTP{
			"NSE:INFY": {LastPrice: 1650},
		},
	}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetAlertsForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: "test@test.com"})
	require.NoError(t, err)

	assert.Equal(t, 1, result.ActiveCount)
	assert.Equal(t, 1, result.TriggeredCount)

	// Active alert enriched with LTP.
	assert.Equal(t, "a1", result.Active[0].ID)
	assert.Equal(t, "INFY", result.Active[0].Symbol)
	assert.Equal(t, 1650.0, result.Active[0].CurrentPrice)
	// DistancePct = (1700 - 1650) / 1650 * 100 ≈ 3.03
	assert.InDelta(t, 3.03, result.Active[0].DistancePct, 0.1)

	// Triggered alert.
	assert.Equal(t, "a2", result.Triggered[0].ID)
	assert.Equal(t, 2795.0, result.Triggered[0].TriggeredPrice)
}

func TestGetAlertsForWidget_NoBroker_NoLTPEnrichment(t *testing.T) {
	t.Parallel()
	now := time.Now()
	store := &mockWidgetAlertStore{
		alerts: []*alerts.Alert{
			{ID: "a1", Tradingsymbol: "INFY", Exchange: "NSE", Direction: alerts.DirectionAbove, TargetPrice: 1700, Triggered: false, CreatedAt: now},
		},
	}
	resolver := &mockBrokerResolver{resolveErr: fmt.Errorf("no session")}
	uc := NewGetAlertsForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Equal(t, 1, result.ActiveCount)
	// No LTP enrichment.
	assert.Equal(t, 0.0, result.Active[0].CurrentPrice)
	assert.Equal(t, 0.0, result.Active[0].DistancePct)
}

func TestGetAlertsForWidget_EmptyAlerts(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAlertStore{alerts: []*alerts.Alert{}}
	uc := NewGetAlertsForWidgetUseCase(&mockBrokerResolver{}, store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ActiveCount)
	assert.Equal(t, 0, result.TriggeredCount)
	assert.Empty(t, result.Active)
	assert.Empty(t, result.Triggered)
}

func TestGetAlertsForWidget_AllTriggered(t *testing.T) {
	t.Parallel()
	now := time.Now()
	store := &mockWidgetAlertStore{
		alerts: []*alerts.Alert{
			{ID: "a1", Tradingsymbol: "INFY", Exchange: "NSE", Direction: alerts.DirectionAbove, TargetPrice: 1700, Triggered: true, CreatedAt: now, TriggeredAt: now, TriggeredPrice: 1710},
			{ID: "a2", Tradingsymbol: "TCS", Exchange: "NSE", Direction: alerts.DirectionBelow, TargetPrice: 2800, Triggered: true, CreatedAt: now, TriggeredAt: now, TriggeredPrice: 2790},
		},
	}
	// No LTP call should be made since all alerts are triggered.
	client := &mockBrokerClient{ltpErr: fmt.Errorf("should not be called")}
	resolver := &mockBrokerResolver{client: client}
	uc := NewGetAlertsForWidgetUseCase(resolver, store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetAlertsQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Equal(t, 0, result.ActiveCount)
	assert.Equal(t, 2, result.TriggeredCount)
}

// --- GetActivityForWidgetUseCase tests ---

func TestGetActivityForWidget_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetActivityForWidgetUseCase(&mockWidgetAuditStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestGetActivityForWidget_ListError(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{listErr: fmt.Errorf("db error")}
	uc := NewGetActivityForWidgetUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: "test@test.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "list activity")
}

func TestGetActivityForWidget_Success(t *testing.T) {
	t.Parallel()
	now := time.Now()
	store := &mockWidgetAuditStore{
		entries: []*audit.ToolCall{
			{ID: 1, ToolName: "get_holdings", StartedAt: now, DurationMs: 150},
			{ID: 2, ToolName: "place_order", StartedAt: now.Add(-time.Minute), DurationMs: 200},
		},
		total: 2,
		stats: &audit.Stats{
			TotalCalls:   50,
			ErrorCount:   3,
			AvgLatencyMs: 120.5,
			TopTool:      "get_holdings",
			TopToolCount: 20,
		},
		toolCounts: map[string]int{
			"get_holdings": 20,
			"place_order":  15,
			"get_ltp":      15,
		},
	}
	uc := NewGetActivityForWidgetUseCase(store, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: "test@test.com"})
	require.NoError(t, err)

	assert.Len(t, result.Entries, 2)
	assert.Equal(t, "get_holdings", result.Entries[0].ToolName)
	assert.Equal(t, "place_order", result.Entries[1].ToolName)

	require.NotNil(t, result.Stats)
	assert.Equal(t, 50, result.Stats.TotalCalls)
	assert.Equal(t, 3, result.Stats.ErrorCount)
	assert.Equal(t, "get_holdings", result.Stats.TopTool)

	assert.Len(t, result.ToolCounts, 3)
	assert.Equal(t, 20, result.ToolCounts["get_holdings"])
}

func TestGetActivityForWidget_EmptyActivity(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{
		entries:    []*audit.ToolCall{},
		stats:      nil,
		toolCounts: nil,
	}
	uc := NewGetActivityForWidgetUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: "test@test.com"})
	require.NoError(t, err)
	assert.Empty(t, result.Entries)
	assert.Nil(t, result.Stats)
	assert.Nil(t, result.ToolCounts)
}

func TestGetActivityForWidget_StatsError_StillReturns(t *testing.T) {
	t.Parallel()
	store := &mockWidgetAuditStore{
		entries: []*audit.ToolCall{
			{ID: 1, ToolName: "get_ltp", StartedAt: time.Now()},
		},
		total:     1,
		statsErr:  fmt.Errorf("stats error"),
		countsErr: fmt.Errorf("counts error"),
	}
	uc := NewGetActivityForWidgetUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetWidgetActivityQuery{Email: "test@test.com"})
	// The use case ignores stats/counts errors (uses _ for error).
	require.NoError(t, err)
	assert.Len(t, result.Entries, 1)
	assert.Nil(t, result.Stats)
	assert.Nil(t, result.ToolCounts)
}
