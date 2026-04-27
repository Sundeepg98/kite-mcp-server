package usecases

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// --- Interfaces ---

// WidgetAuditStore abstracts the audit store methods needed by widget use cases.
type WidgetAuditStore interface {
	List(email string, opts audit.ListOptions) ([]*audit.ToolCall, int, error)
	GetStats(email string, since time.Time, category string, errorsOnly bool) (*audit.Stats, error)
	GetToolCounts(email string, since time.Time, category string, errorsOnly bool) (map[string]int, error)
	ListOrders(email string, since time.Time) ([]*audit.ToolCall, error)
}

// WidgetAlertStore abstracts alert read operations for widget use cases.
type WidgetAlertStore interface {
	List(email string) []*alerts.Alert
}

// WidgetBrokerClient abstracts the broker methods needed by widget use cases.
type WidgetBrokerClient interface {
	GetHoldings() ([]broker.Holding, error)
	GetPositions() (broker.Positions, error)
	GetOrders() ([]broker.Order, error)
	GetLTP(instruments ...string) (map[string]broker.LTP, error)
}

// --- Result types ---

// WidgetHoldingItem is a holding formatted for widget display.
type WidgetHoldingItem struct {
	Symbol    string  `json:"tradingsymbol"`
	Exchange  string  `json:"exchange"`
	Quantity  int     `json:"quantity"`
	AvgPrice  float64 `json:"average_price"`
	LastPrice float64 `json:"last_price"`
	PnL       float64 `json:"pnl"`
	DayChgPct float64 `json:"day_change_percentage"`
}

// WidgetPositionItem is a position formatted for widget display.
type WidgetPositionItem struct {
	Symbol    string  `json:"tradingsymbol"`
	Exchange  string  `json:"exchange"`
	Quantity  int     `json:"quantity"`
	AvgPrice  float64 `json:"average_price"`
	LastPrice float64 `json:"last_price"`
	PnL       float64 `json:"pnl"`
	Product   string  `json:"product"`
}

// WidgetPortfolioResult is the portfolio widget data.
type WidgetPortfolioResult struct {
	Holdings  []WidgetHoldingItem  `json:"holdings"`
	Positions []WidgetPositionItem `json:"positions"`
	Summary   map[string]any       `json:"summary"`
}

// WidgetOrderEntry is an order formatted for the orders widget.
type WidgetOrderEntry struct {
	OrderID        string  `json:"order_id"`
	Symbol         string  `json:"tradingsymbol"`
	Exchange       string  `json:"exchange"`
	Side           string  `json:"transaction_type"`
	OrderType      string  `json:"order_type"`
	Quantity       float64 `json:"quantity"`
	FilledQuantity float64 `json:"filled_quantity"`
	Price          float64 `json:"price"`
	AveragePrice   float64 `json:"average_price"`
	Status         string  `json:"status"`
	PlacedAt       string  `json:"placed_at"`
}

// WidgetOrdersResult is the orders widget data.
type WidgetOrdersResult struct {
	Orders  []WidgetOrderEntry `json:"orders"`
	Summary map[string]any     `json:"summary"`
}

// WidgetAlertItem is an alert formatted for the alerts widget.
type WidgetAlertItem struct {
	ID             string  `json:"id"`
	Symbol         string  `json:"tradingsymbol"`
	Exchange       string  `json:"exchange"`
	Direction      string  `json:"direction"`
	TargetPrice    float64 `json:"target_price"`
	CurrentPrice   float64 `json:"current_price,omitempty"`
	DistancePct    float64 `json:"distance_pct,omitempty"`
	CreatedAt      string  `json:"created_at"`
	TriggeredAt    string  `json:"triggered_at,omitempty"`
	TriggeredPrice float64 `json:"triggered_price,omitempty"`
}

// WidgetAlertsResult is the alerts widget data.
type WidgetAlertsResult struct {
	Active         []WidgetAlertItem `json:"active"`
	Triggered      []WidgetAlertItem `json:"triggered"`
	ActiveCount    int               `json:"active_count"`
	TriggeredCount int               `json:"triggered_count"`
}

// WidgetActivityResult is the activity widget data.
type WidgetActivityResult struct {
	Entries    []*audit.ToolCall `json:"entries"`
	Stats      *audit.Stats     `json:"stats"`
	ToolCounts map[string]int   `json:"tool_counts"`
}

// --- GetPortfolioForWidgetUseCase ---

// GetPortfolioForWidgetUseCase fetches holdings + positions in parallel
// and formats them for the portfolio widget.
type GetPortfolioForWidgetUseCase struct {
	brokerResolver BrokerResolver
	logger         *slog.Logger
}

// NewGetPortfolioForWidgetUseCase creates a GetPortfolioForWidgetUseCase.
func NewGetPortfolioForWidgetUseCase(resolver BrokerResolver, logger *slog.Logger) *GetPortfolioForWidgetUseCase {
	return &GetPortfolioForWidgetUseCase{brokerResolver: resolver, logger: logger}
}

// Execute fetches and formats portfolio data for the widget.
func (uc *GetPortfolioForWidgetUseCase) Execute(ctx context.Context, query cqrs.GetWidgetPortfolioQuery) (*WidgetPortfolioResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	client, err := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}

	var holdings []broker.Holding
	var positions broker.Positions
	var holdingsErr, positionsErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() { defer wg.Done(); holdings, holdingsErr = client.GetHoldings() }()
	go func() { defer wg.Done(); positions, positionsErr = client.GetPositions() }()
	wg.Wait()

	if holdingsErr != nil {
		return nil, fmt.Errorf("usecases: get holdings: %w", holdingsErr)
	}
	if positionsErr != nil {
		return nil, fmt.Errorf("usecases: get positions: %w", positionsErr)
	}

	hItems := make([]WidgetHoldingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		// Slice 6b: lift the broker.Holding to domain.Holding so
		// the per-row PnL JSON-emit on WidgetHoldingItem is
		// currency-aware at the boundary; .Float64() drops back
		// to the wire-compatible float. The aggregation
		// accumulators (totalInvested, totalCurrent, totalPnL)
		// deliberately stay bare-float — Slice 3's "sum primitive
		// then wrap once" hot-path discipline keeps inner-loop
		// math allocation-free.
		hd := domain.NewHoldingFromBroker(h)
		hItems = append(hItems, WidgetHoldingItem{
			Symbol: h.Tradingsymbol, Exchange: h.Exchange, Quantity: h.Quantity,
			AvgPrice: h.AveragePrice, LastPrice: h.LastPrice, PnL: hd.PnL().Float64(),
			DayChgPct: h.DayChangePct,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		// Slice 6e c2: h.PnL is now Money; drop to float64 at the
		// aggregation boundary (Slice 3 "sum primitive then wrap once"
		// pattern preserves inner-loop allocation-free math).
		totalPnL += h.PnL.Float64()
	}

	pItems := make([]WidgetPositionItem, 0, len(positions.Net))
	var posPnL float64
	for _, p := range positions.Net {
		// Slice 6: lift the broker.Position to domain.Position so
		// the per-position PnL JSON-emit on WidgetPositionItem is
		// currency-aware at the boundary; .Float64() drops back
		// to the wire-compatible float. The aggregation accumulator
		// (posPnL) deliberately stays bare-float — Slice 3's "sum
		// primitive then wrap once" pattern keeps inner-loop math
		// allocation-free.
		pos := domain.NewPositionFromBroker(p)
		pItems = append(pItems, WidgetPositionItem{
			Symbol: p.Tradingsymbol, Exchange: p.Exchange, Quantity: p.Quantity,
			AvgPrice: p.AveragePrice, LastPrice: p.LastPrice, PnL: pos.PnL().Float64(),
			Product: p.Product,
		})
		// Slice 6e c2: p.PnL is now Money; drop to float64 at the
		// aggregation boundary.
		posPnL += p.PnL.Float64()
	}

	return &WidgetPortfolioResult{
		Holdings:  hItems,
		Positions: pItems,
		Summary: map[string]any{
			"holdings_count":  len(holdings),
			"total_invested":  totalInvested,
			"total_current":   totalCurrent,
			"total_pnl":       totalPnL,
			"positions_count": len(positions.Net),
			"positions_pnl":   posPnL,
		},
	}, nil
}

// --- GetOrdersForWidgetUseCase ---

// GetOrdersForWidgetUseCase fetches audit-tracked orders enriched with broker
// status for the orders widget.
type GetOrdersForWidgetUseCase struct {
	brokerResolver BrokerResolver
	auditStore     WidgetAuditStore
	logger         *slog.Logger
}

// NewGetOrdersForWidgetUseCase creates a GetOrdersForWidgetUseCase.
func NewGetOrdersForWidgetUseCase(resolver BrokerResolver, store WidgetAuditStore, logger *slog.Logger) *GetOrdersForWidgetUseCase {
	return &GetOrdersForWidgetUseCase{brokerResolver: resolver, auditStore: store, logger: logger}
}

// Execute fetches and formats order data for the widget.
func (uc *GetOrdersForWidgetUseCase) Execute(ctx context.Context, query cqrs.GetWidgetOrdersQuery) (*WidgetOrdersResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	since := time.Now().AddDate(0, 0, -1)
	toolCalls, err := uc.auditStore.ListOrders(query.Email, since)
	if err != nil {
		return nil, fmt.Errorf("usecases: list orders: %w", err)
	}

	// Fetch all orders in a single API call for status enrichment.
	orderStatusMap := make(map[string]broker.Order)
	client, brokerErr := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if brokerErr == nil && client != nil {
		if allOrders, oErr := client.GetOrders(); oErr == nil {
			for _, o := range allOrders {
				orderStatusMap[o.OrderID] = o
			}
		}
	}

	orders := make([]WidgetOrderEntry, 0, len(toolCalls))
	for _, tc := range toolCalls {
		oe := WidgetOrderEntry{OrderID: tc.OrderID, PlacedAt: tc.StartedAt.Format(time.RFC3339)}
		if tc.InputParams != "" {
			var params map[string]any
			if json.Unmarshal([]byte(tc.InputParams), &params) == nil {
				if v, ok := params["tradingsymbol"].(string); ok {
					oe.Symbol = v
				}
				if v, ok := params["exchange"].(string); ok {
					oe.Exchange = v
				}
				if v, ok := params["transaction_type"].(string); ok {
					oe.Side = v
				}
				if v, ok := params["order_type"].(string); ok {
					oe.OrderType = v
				}
				if v, ok := params["quantity"].(float64); ok {
					oe.Quantity = v
				}
				if v, ok := params["price"].(float64); ok {
					oe.Price = v
				}
			}
		}
		if o, ok := orderStatusMap[oe.OrderID]; ok {
			oe.Status = o.Status
			oe.FilledQuantity = float64(o.FilledQuantity)
			oe.AveragePrice = o.AveragePrice
			if oe.Symbol == "" {
				oe.Symbol = o.Tradingsymbol
			}
			if oe.Exchange == "" {
				oe.Exchange = o.Exchange
			}
			if oe.Side == "" {
				oe.Side = o.TransactionType
			}
			if oe.Quantity == 0 {
				oe.Quantity = float64(o.Quantity)
			}
			if oe.Price == 0 {
				oe.Price = o.Price
			}
		}
		orders = append(orders, oe)
	}

	var completed, pending, rejected int
	var totalBuyVal, totalSellVal float64
	for _, o := range orders {
		// Reuse the Order entity's lifecycle checks by constructing a minimal
		// broker.Order shim — only Status is needed for bucketing.
		ord := domain.NewOrderFromBroker(broker.Order{Status: o.Status})
		switch {
		case ord.IsComplete():
			completed++
			val := o.AveragePrice * o.FilledQuantity
			if o.Side == domain.TransactionBuy {
				totalBuyVal += val
			} else {
				totalSellVal += val
			}
		case ord.IsPending():
			pending++
		case ord.IsRejected() || ord.IsCancelled():
			rejected++
		}
	}

	return &WidgetOrdersResult{
		Orders: orders,
		Summary: map[string]any{
			"total": len(orders), "completed": completed,
			"pending": pending, "rejected": rejected,
			"total_buy_value": totalBuyVal, "total_sell_value": totalSellVal,
		},
	}, nil
}

// --- GetAlertsForWidgetUseCase ---

// GetAlertsForWidgetUseCase fetches alerts enriched with current LTP for the
// alerts widget.
type GetAlertsForWidgetUseCase struct {
	brokerResolver BrokerResolver
	alertStore     WidgetAlertStore
	logger         *slog.Logger
}

// NewGetAlertsForWidgetUseCase creates a GetAlertsForWidgetUseCase.
func NewGetAlertsForWidgetUseCase(resolver BrokerResolver, store WidgetAlertStore, logger *slog.Logger) *GetAlertsForWidgetUseCase {
	return &GetAlertsForWidgetUseCase{brokerResolver: resolver, alertStore: store, logger: logger}
}

// Execute fetches and formats alert data for the widget.
func (uc *GetAlertsForWidgetUseCase) Execute(ctx context.Context, query cqrs.GetWidgetAlertsQuery) (*WidgetAlertsResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	allAlerts := uc.alertStore.List(query.Email)

	// Batch LTP lookup for active alerts.
	ltpMap := make(map[string]float64)
	client, brokerErr := uc.brokerResolver.GetBrokerForEmail(query.Email)
	if brokerErr == nil && client != nil {
		instruments := make([]string, 0)
		for _, a := range allAlerts {
			if !a.Triggered {
				instruments = append(instruments, a.Exchange+":"+a.Tradingsymbol)
			}
		}
		if len(instruments) > 0 {
			if ltps, err := client.GetLTP(instruments...); err == nil {
				for k, v := range ltps {
					ltpMap[k] = v.LastPrice
				}
			}
		}
	}

	active := make([]WidgetAlertItem, 0)
	triggered := make([]WidgetAlertItem, 0)

	for _, a := range allAlerts {
		item := WidgetAlertItem{
			ID: a.ID, Symbol: a.Tradingsymbol, Exchange: a.Exchange,
			Direction: string(a.Direction), TargetPrice: a.TargetPrice,
			CreatedAt: a.CreatedAt.Format(time.RFC3339),
		}
		if a.Triggered {
			item.TriggeredAt = a.TriggeredAt.Format(time.RFC3339)
			item.TriggeredPrice = a.TriggeredPrice
			triggered = append(triggered, item)
		} else {
			inst := a.Exchange + ":" + a.Tradingsymbol
			if ltp, ok := ltpMap[inst]; ok {
				item.CurrentPrice = ltp
				if ltp > 0 {
					item.DistancePct = (a.TargetPrice - ltp) / ltp * 100
				}
			}
			active = append(active, item)
		}
	}

	return &WidgetAlertsResult{
		Active:         active,
		Triggered:      triggered,
		ActiveCount:    len(active),
		TriggeredCount: len(triggered),
	}, nil
}

// --- GetActivityForWidgetUseCase ---

// GetActivityForWidgetUseCase fetches recent audit entries with stats for the
// activity widget.
type GetActivityForWidgetUseCase struct {
	auditStore WidgetAuditStore
	logger     *slog.Logger
}

// NewGetActivityForWidgetUseCase creates a GetActivityForWidgetUseCase.
func NewGetActivityForWidgetUseCase(store WidgetAuditStore, logger *slog.Logger) *GetActivityForWidgetUseCase {
	return &GetActivityForWidgetUseCase{auditStore: store, logger: logger}
}

// Execute fetches and formats activity data for the widget.
func (uc *GetActivityForWidgetUseCase) Execute(ctx context.Context, query cqrs.GetWidgetActivityQuery) (*WidgetActivityResult, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	since := time.Now().AddDate(0, 0, -7)
	entries, _, err := uc.auditStore.List(query.Email, audit.ListOptions{
		Limit: 20,
		Since: since,
	})
	if err != nil {
		return nil, fmt.Errorf("usecases: list activity: %w", err)
	}

	stats, _ := uc.auditStore.GetStats(query.Email, since, "", false)
	toolCounts, _ := uc.auditStore.GetToolCounts(query.Email, since, "", false)

	return &WidgetActivityResult{
		Entries:    entries,
		Stats:      stats,
		ToolCounts: toolCounts,
	}, nil
}
