// Package mock provides an in-memory implementation of broker.Client for testing.
// All state is stored in memory and can be configured via setter methods.
// Thread-safe: all access is guarded by a sync.RWMutex.
package mock

import (
	"fmt"
	"math"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
)

// compile-time proof that *Client satisfies broker.Client.
var _ broker.Client = (*Client)(nil)

// Client is an in-memory mock implementation of broker.Client.
// Use New() to create one, then configure it with Set* methods
// and inject errors via the exported Err fields.
type Client struct {
	mu sync.RWMutex

	// Configurable data returned by getters.
	profile   broker.Profile
	margins   broker.Margins
	holdings  []broker.Holding
	positions broker.Positions
	orders    []broker.Order
	trades    []broker.Trade
	prices    map[string]float64 // "EXCHANGE:SYMBOL" → last price
	ohlc      map[string]broker.OHLC

	// Auto-incrementing order/trade IDs.
	nextOrderID atomic.Int64
	nextTradeID atomic.Int64

	// Error injection: set any of these to force the corresponding method
	// to return the error without performing any work.
	BrokerNameVal     broker.Name // defaults to "mock"
	GetProfileErr     error
	GetMarginsErr     error
	GetHoldingsErr    error
	GetPositionsErr   error
	GetOrdersErr      error
	GetOrderHistoryErr error
	GetTradesErr      error
	PlaceOrderErr     error
	ModifyOrderErr    error
	CancelOrderErr    error
	GetLTPErr         error
	GetOHLCErr        error
	GetHistoricalErr  error
}

// New creates a ready-to-use mock Client with sensible defaults.
func New() *Client {
	c := &Client{
		prices:    make(map[string]float64),
		ohlc:      make(map[string]broker.OHLC),
		profile: broker.Profile{
			UserID:    "MOCK01",
			UserName:  "Mock User",
			Email:     "mock@example.com",
			Broker:    "mock",
			Exchanges: []string{"NSE", "BSE"},
			Products:  []string{"CNC", "MIS", "NRML"},
		},
		margins: broker.Margins{
			Equity: broker.SegmentMargin{
				Available: 1_00_00_000, // ₹1 crore
				Used:      0,
				Total:     1_00_00_000,
			},
		},
	}
	c.nextOrderID.Store(100000)
	c.nextTradeID.Store(200000)
	return c
}

// ---------------------------------------------------------------------------
// Setters — configure what the mock returns
// ---------------------------------------------------------------------------

// SetProfile sets the profile returned by GetProfile.
func (c *Client) SetProfile(p broker.Profile) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.profile = p
}

// SetMargins sets the margins returned by GetMargins.
func (c *Client) SetMargins(m broker.Margins) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.margins = m
}

// SetHoldings sets the holdings returned by GetHoldings.
func (c *Client) SetHoldings(h []broker.Holding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.holdings = h
}

// SetPositions sets the positions returned by GetPositions.
func (c *Client) SetPositions(p broker.Positions) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.positions = p
}

// SetOrders replaces all orders in the mock.
func (c *Client) SetOrders(o []broker.Order) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.orders = o
}

// SetTrades replaces all trades in the mock.
func (c *Client) SetTrades(t []broker.Trade) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.trades = t
}

// SetPrices sets LTP data. Keys are "EXCHANGE:SYMBOL" (e.g., "NSE:RELIANCE").
func (c *Client) SetPrices(prices map[string]float64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.prices = prices
}

// SetOHLC sets OHLC data. Keys are "EXCHANGE:SYMBOL".
func (c *Client) SetOHLC(data map[string]broker.OHLC) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.ohlc = data
}

// Orders returns a copy of the current orders slice (for test assertions).
func (c *Client) Orders() []broker.Order {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.Order, len(c.orders))
	copy(out, c.orders)
	return out
}

// Trades returns a copy of the current trades slice (for test assertions).
func (c *Client) Trades() []broker.Trade {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.Trade, len(c.trades))
	copy(out, c.trades)
	return out
}

// ---------------------------------------------------------------------------
// broker.Client implementation
// ---------------------------------------------------------------------------

// BrokerName returns the broker identifier (defaults to "mock").
func (c *Client) BrokerName() broker.Name {
	if c.BrokerNameVal != "" {
		return c.BrokerNameVal
	}
	return "mock"
}

// GetProfile returns the configured mock profile.
func (c *Client) GetProfile() (broker.Profile, error) {
	if c.GetProfileErr != nil {
		return broker.Profile{}, c.GetProfileErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.profile, nil
}

// GetMargins returns the configured mock margins.
func (c *Client) GetMargins() (broker.Margins, error) {
	if c.GetMarginsErr != nil {
		return broker.Margins{}, c.GetMarginsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.margins, nil
}

// GetHoldings returns the configured mock holdings.
func (c *Client) GetHoldings() ([]broker.Holding, error) {
	if c.GetHoldingsErr != nil {
		return nil, c.GetHoldingsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.Holding, len(c.holdings))
	copy(out, c.holdings)
	return out, nil
}

// GetPositions returns the configured mock positions.
func (c *Client) GetPositions() (broker.Positions, error) {
	if c.GetPositionsErr != nil {
		return broker.Positions{}, c.GetPositionsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	return broker.Positions{
		Day: append([]broker.Position(nil), c.positions.Day...),
		Net: append([]broker.Position(nil), c.positions.Net...),
	}, nil
}

// GetOrders returns all orders in the mock.
func (c *Client) GetOrders() ([]broker.Order, error) {
	if c.GetOrdersErr != nil {
		return nil, c.GetOrdersErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.Order, len(c.orders))
	copy(out, c.orders)
	return out, nil
}

// GetOrderHistory returns all states for a given order ID.
// In the mock this returns a single-element slice if the order exists.
func (c *Client) GetOrderHistory(orderID string) ([]broker.Order, error) {
	if c.GetOrderHistoryErr != nil {
		return nil, c.GetOrderHistoryErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	for _, o := range c.orders {
		if o.OrderID == orderID {
			return []broker.Order{o}, nil
		}
	}
	return nil, fmt.Errorf("order %s not found", orderID)
}

// GetTrades returns all trades in the mock.
func (c *Client) GetTrades() ([]broker.Trade, error) {
	if c.GetTradesErr != nil {
		return nil, c.GetTradesErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.Trade, len(c.trades))
	copy(out, c.trades)
	return out, nil
}

// PlaceOrder creates an order in memory and returns a generated order ID.
// If the order type is MARKET, it is immediately filled at the configured LTP.
func (c *Client) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	if c.PlaceOrderErr != nil {
		return broker.OrderResponse{}, c.PlaceOrderErr
	}

	id := strconv.FormatInt(c.nextOrderID.Add(1), 10)

	c.mu.Lock()
	defer c.mu.Unlock()

	status := "OPEN"
	filledQty := 0
	avgPrice := 0.0

	// Simulate immediate fill for MARKET orders.
	if params.OrderType == "MARKET" {
		status = "COMPLETE"
		filledQty = params.Quantity
		key := params.Exchange + ":" + params.Tradingsymbol
		if ltp, ok := c.prices[key]; ok {
			avgPrice = ltp
		} else {
			avgPrice = params.Price
		}
	}

	order := broker.Order{
		OrderID:         id,
		Exchange:        params.Exchange,
		Tradingsymbol:   params.Tradingsymbol,
		TransactionType: params.TransactionType,
		OrderType:       params.OrderType,
		Product:         params.Product,
		Quantity:        params.Quantity,
		Price:           params.Price,
		TriggerPrice:    params.TriggerPrice,
		Status:          status,
		FilledQuantity:  filledQty,
		AveragePrice:    avgPrice,
		OrderTimestamp:  time.Now(),
		Tag:             params.Tag,
	}
	c.orders = append(c.orders, order)

	// For MARKET fills, also create a trade record.
	if status == "COMPLETE" {
		tradeID := strconv.FormatInt(c.nextTradeID.Add(1), 10)
		c.trades = append(c.trades, broker.Trade{
			TradeID:         tradeID,
			OrderID:         id,
			Exchange:        params.Exchange,
			Tradingsymbol:   params.Tradingsymbol,
			TransactionType: params.TransactionType,
			Quantity:        params.Quantity,
			Price:           avgPrice,
			Product:         params.Product,
		})
	}

	return broker.OrderResponse{OrderID: id}, nil
}

// ModifyOrder updates a pending order's mutable fields.
func (c *Client) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	if c.ModifyOrderErr != nil {
		return broker.OrderResponse{}, c.ModifyOrderErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.orders {
		if c.orders[i].OrderID == orderID {
			if c.orders[i].Status != "OPEN" {
				return broker.OrderResponse{}, fmt.Errorf("order %s is %s, cannot modify", orderID, c.orders[i].Status)
			}
			if params.Quantity > 0 {
				c.orders[i].Quantity = params.Quantity
			}
			if params.Price > 0 {
				c.orders[i].Price = params.Price
			}
			if params.TriggerPrice > 0 {
				c.orders[i].TriggerPrice = params.TriggerPrice
			}
			if params.OrderType != "" {
				c.orders[i].OrderType = params.OrderType
			}
			return broker.OrderResponse{OrderID: orderID}, nil
		}
	}
	return broker.OrderResponse{}, fmt.Errorf("order %s not found", orderID)
}

// CancelOrder marks a pending order as CANCELLED.
func (c *Client) CancelOrder(orderID string) (broker.OrderResponse, error) {
	if c.CancelOrderErr != nil {
		return broker.OrderResponse{}, c.CancelOrderErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.orders {
		if c.orders[i].OrderID == orderID {
			if c.orders[i].Status != "OPEN" {
				return broker.OrderResponse{}, fmt.Errorf("order %s is %s, cannot cancel", orderID, c.orders[i].Status)
			}
			c.orders[i].Status = "CANCELLED"
			c.orders[i].StatusMessage = "Cancelled by user"
			return broker.OrderResponse{OrderID: orderID}, nil
		}
	}
	return broker.OrderResponse{}, fmt.Errorf("order %s not found", orderID)
}

// GetLTP returns last traded prices for the requested instruments.
func (c *Client) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	if c.GetLTPErr != nil {
		return nil, c.GetLTPErr
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]broker.LTP, len(instruments))
	for _, inst := range instruments {
		if price, ok := c.prices[inst]; ok {
			out[inst] = broker.LTP{LastPrice: price}
		}
	}
	return out, nil
}

// GetOHLC returns OHLC data for the requested instruments.
func (c *Client) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	if c.GetOHLCErr != nil {
		return nil, c.GetOHLCErr
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]broker.OHLC, len(instruments))
	for _, inst := range instruments {
		if data, ok := c.ohlc[inst]; ok {
			out[inst] = data
		}
	}
	return out, nil
}

// GetHistoricalData returns synthetic OHLCV candles between from and to.
// It generates one candle per day (for "day" interval) or one per 5 minutes
// using a deterministic sine-wave pattern around 100.0.
func (c *Client) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	if c.GetHistoricalErr != nil {
		return nil, c.GetHistoricalErr
	}

	var step time.Duration
	switch interval {
	case "5minute":
		step = 5 * time.Minute
	case "15minute":
		step = 15 * time.Minute
	case "60minute":
		step = time.Hour
	default: // "day"
		step = 24 * time.Hour
	}

	var candles []broker.HistoricalCandle
	basePrice := 100.0 + float64(instrumentToken%100)

	for t := from; !t.After(to); t = t.Add(step) {
		// Deterministic wave based on time.
		phase := float64(t.Unix()) / 86400.0 * 2 * math.Pi
		price := basePrice + 10*math.Sin(phase)
		high := price + 2
		low := price - 2

		candles = append(candles, broker.HistoricalCandle{
			Date:   t,
			Open:   price - 0.5,
			High:   high,
			Low:    low,
			Close:  price + 0.5,
			Volume: 100000 + instrumentToken*100,
		})
	}
	return candles, nil
}
