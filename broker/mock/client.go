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

// compile-time proof that *Client satisfies broker.Client and broker.NativeAlertCapable.
var _ broker.Client = (*Client)(nil)
var _ broker.NativeAlertCapable = (*Client)(nil)

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
	quotes    map[string]broker.Quote
	gtts      []broker.GTTOrder

	// Auto-incrementing order/trade IDs.
	nextOrderID   atomic.Int64
	nextTradeID   atomic.Int64
	nextTriggerID atomic.Int64

	// MF data
	mfOrders   []broker.MFOrder
	mfSIPs     []broker.MFSIP
	mfHoldings []broker.MFHolding

	// Auto-incrementing MF IDs
	nextMFOrderID atomic.Int64
	nextMFSIPID   atomic.Int64

	// Error injection: set any of these to force the corresponding method
	// to return the error without performing any work.
	BrokerNameVal       broker.Name // defaults to "mock"
	GetProfileErr       error
	GetMarginsErr       error
	GetHoldingsErr      error
	GetPositionsErr     error
	GetOrdersErr        error
	GetOrderHistoryErr  error
	GetTradesErr        error
	PlaceOrderErr       error
	ModifyOrderErr      error
	CancelOrderErr      error
	GetLTPErr           error
	GetOHLCErr          error
	GetHistoricalErr    error
	GetQuotesErr        error
	GetOrderTradesErr   error
	GetGTTsErr          error
	PlaceGTTErr         error
	ModifyGTTErr        error
	DeleteGTTErr        error
	ConvertPositionErr  error
	GetMFOrdersErr      error
	GetMFSIPsErr        error
	GetMFHoldingsErr    error
	PlaceMFOrderErr     error
	CancelMFOrderErr    error
	PlaceMFSIPErr       error
	CancelMFSIPErr      error
	GetOrderMarginsErr       error
	GetBasketMarginsErr      error
	GetOrderChargesErr       error
	CreateNativeAlertErr     error
	GetNativeAlertsErr       error
	ModifyNativeAlertErr     error
	DeleteNativeAlertsErr    error
	GetNativeAlertHistoryErr error

	// Native alert state
	nativeAlerts      []broker.NativeAlert
	nextNativeAlertID atomic.Int64
}

// New creates a ready-to-use mock Client with sensible defaults.
func New() *Client {
	c := &Client{
		prices:    make(map[string]float64),
		ohlc:      make(map[string]broker.OHLC),
		quotes:    make(map[string]broker.Quote),
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
	c.nextTriggerID.Store(300000)
	c.nextMFOrderID.Store(400000)
	c.nextMFSIPID.Store(500000)
	c.nextNativeAlertID.Store(600000)
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
func (c *Client) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
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

// SetQuotes sets full quote data. Keys are "EXCHANGE:SYMBOL".
func (c *Client) SetQuotes(data map[string]broker.Quote) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.quotes = data
}

// GetQuotes returns full market quotes for the requested instruments.
func (c *Client) GetQuotes(instruments ...string) (map[string]broker.Quote, error) {
	if c.GetQuotesErr != nil {
		return nil, c.GetQuotesErr
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	out := make(map[string]broker.Quote, len(instruments))
	for _, inst := range instruments {
		if data, ok := c.quotes[inst]; ok {
			out[inst] = data
		}
	}
	return out, nil
}

// GetOrderTrades returns trades for a specific order.
// In the mock, this filters the trades list by order ID.
func (c *Client) GetOrderTrades(orderID string) ([]broker.Trade, error) {
	if c.GetOrderTradesErr != nil {
		return nil, c.GetOrderTradesErr
	}

	c.mu.RLock()
	defer c.mu.RUnlock()

	var out []broker.Trade
	for _, t := range c.trades {
		if t.OrderID == orderID {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no trades found for order %s", orderID)
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// GTT operations
// ---------------------------------------------------------------------------

// SetGTTs replaces all GTT orders in the mock.
func (c *Client) SetGTTs(g []broker.GTTOrder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.gtts = g
}

// GTTs returns a copy of the current GTT orders (for test assertions).
func (c *Client) GTTs() []broker.GTTOrder {
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.GTTOrder, len(c.gtts))
	copy(out, c.gtts)
	return out
}

// GetGTTs returns all GTT orders in the mock.
func (c *Client) GetGTTs() ([]broker.GTTOrder, error) {
	if c.GetGTTsErr != nil {
		return nil, c.GetGTTsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.GTTOrder, len(c.gtts))
	copy(out, c.gtts)
	return out, nil
}

// PlaceGTT creates a GTT order in memory and returns a generated trigger ID.
func (c *Client) PlaceGTT(params broker.GTTParams) (broker.GTTResponse, error) {
	if c.PlaceGTTErr != nil {
		return broker.GTTResponse{}, c.PlaceGTTErr
	}

	id := int(c.nextTriggerID.Add(1))

	c.mu.Lock()
	defer c.mu.Unlock()

	gtt := broker.GTTOrder{
		ID:   id,
		Type: params.Type,
		Condition: broker.GTTCondition{
			Exchange:      params.Exchange,
			Tradingsymbol: params.Tradingsymbol,
			LastPrice:     params.LastPrice,
		},
		Status: "active",
	}

	// Build trigger values and order legs based on type.
	switch params.Type {
	case "single":
		gtt.Condition.TriggerValues = []float64{params.TriggerValue}
		gtt.Orders = []broker.GTTOrderLeg{{
			Exchange:        params.Exchange,
			Tradingsymbol:   params.Tradingsymbol,
			TransactionType: params.TransactionType,
			Quantity:        int(params.Quantity),
			OrderType:       "LIMIT",
			Price:           params.LimitPrice,
			Product:         params.Product,
		}}
	case "two-leg":
		gtt.Condition.TriggerValues = []float64{params.LowerTriggerValue, params.UpperTriggerValue}
		gtt.Orders = []broker.GTTOrderLeg{
			{
				Exchange:        params.Exchange,
				Tradingsymbol:   params.Tradingsymbol,
				TransactionType: params.TransactionType,
				Quantity:        int(params.LowerQuantity),
				OrderType:       "LIMIT",
				Price:           params.LowerLimitPrice,
				Product:         params.Product,
			},
			{
				Exchange:        params.Exchange,
				Tradingsymbol:   params.Tradingsymbol,
				TransactionType: params.TransactionType,
				Quantity:        int(params.UpperQuantity),
				OrderType:       "LIMIT",
				Price:           params.UpperLimitPrice,
				Product:         params.Product,
			},
		}
	}

	c.gtts = append(c.gtts, gtt)
	return broker.GTTResponse{TriggerID: id}, nil
}

// ModifyGTT modifies a GTT order in memory.
func (c *Client) ModifyGTT(triggerID int, params broker.GTTParams) (broker.GTTResponse, error) {
	if c.ModifyGTTErr != nil {
		return broker.GTTResponse{}, c.ModifyGTTErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.gtts {
		if c.gtts[i].ID == triggerID {
			c.gtts[i].Type = params.Type
			c.gtts[i].Condition.LastPrice = params.LastPrice
			return broker.GTTResponse{TriggerID: triggerID}, nil
		}
	}
	return broker.GTTResponse{}, fmt.Errorf("GTT trigger %d not found", triggerID)
}

// DeleteGTT removes a GTT order from memory.
func (c *Client) DeleteGTT(triggerID int) (broker.GTTResponse, error) {
	if c.DeleteGTTErr != nil {
		return broker.GTTResponse{}, c.DeleteGTTErr
	}

	c.mu.Lock()
	defer c.mu.Unlock()

	for i := range c.gtts {
		if c.gtts[i].ID == triggerID {
			c.gtts = append(c.gtts[:i], c.gtts[i+1:]...)
			return broker.GTTResponse{TriggerID: triggerID}, nil
		}
	}
	return broker.GTTResponse{}, fmt.Errorf("GTT trigger %d not found", triggerID)
}

// ---------------------------------------------------------------------------
// Position conversion
// ---------------------------------------------------------------------------

// ConvertPosition simulates converting a position between products.
func (c *Client) ConvertPosition(_ broker.ConvertPositionParams) (bool, error) {
	if c.ConvertPositionErr != nil {
		return false, c.ConvertPositionErr
	}
	return true, nil
}

// ---------------------------------------------------------------------------
// Mutual Fund operations
// ---------------------------------------------------------------------------

// SetMFOrders sets the MF orders returned by GetMFOrders.
func (c *Client) SetMFOrders(orders []broker.MFOrder) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mfOrders = orders
}

// SetMFSIPs sets the MF SIPs returned by GetMFSIPs.
func (c *Client) SetMFSIPs(sips []broker.MFSIP) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mfSIPs = sips
}

// SetMFHoldings sets the MF holdings returned by GetMFHoldings.
func (c *Client) SetMFHoldings(holdings []broker.MFHolding) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mfHoldings = holdings
}

// GetMFOrders returns mock mutual fund orders.
func (c *Client) GetMFOrders() ([]broker.MFOrder, error) {
	if c.GetMFOrdersErr != nil {
		return nil, c.GetMFOrdersErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.MFOrder, len(c.mfOrders))
	copy(out, c.mfOrders)
	return out, nil
}

// GetMFSIPs returns mock mutual fund SIPs.
func (c *Client) GetMFSIPs() ([]broker.MFSIP, error) {
	if c.GetMFSIPsErr != nil {
		return nil, c.GetMFSIPsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.MFSIP, len(c.mfSIPs))
	copy(out, c.mfSIPs)
	return out, nil
}

// GetMFHoldings returns mock mutual fund holdings.
func (c *Client) GetMFHoldings() ([]broker.MFHolding, error) {
	if c.GetMFHoldingsErr != nil {
		return nil, c.GetMFHoldingsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()
	out := make([]broker.MFHolding, len(c.mfHoldings))
	copy(out, c.mfHoldings)
	return out, nil
}

// PlaceMFOrder creates a mock MF order and returns a generated order ID.
func (c *Client) PlaceMFOrder(params broker.MFOrderParams) (broker.MFOrderResponse, error) {
	if c.PlaceMFOrderErr != nil {
		return broker.MFOrderResponse{}, c.PlaceMFOrderErr
	}
	id := strconv.FormatInt(c.nextMFOrderID.Add(1), 10)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mfOrders = append(c.mfOrders, broker.MFOrder{
		OrderID:         id,
		Tradingsymbol:   params.Tradingsymbol,
		TransactionType: params.TransactionType,
		Status:          "OPEN",
		Amount:          params.Amount,
		Quantity:        params.Quantity,
		Tag:             params.Tag,
	})
	return broker.MFOrderResponse{OrderID: id}, nil
}

// CancelMFOrder removes a mock MF order.
func (c *Client) CancelMFOrder(orderID string) (broker.MFOrderResponse, error) {
	if c.CancelMFOrderErr != nil {
		return broker.MFOrderResponse{}, c.CancelMFOrderErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.mfOrders {
		if c.mfOrders[i].OrderID == orderID {
			c.mfOrders[i].Status = "CANCELLED"
			return broker.MFOrderResponse{OrderID: orderID}, nil
		}
	}
	return broker.MFOrderResponse{}, fmt.Errorf("MF order %s not found", orderID)
}

// PlaceMFSIP creates a mock MF SIP and returns a generated SIP ID.
func (c *Client) PlaceMFSIP(params broker.MFSIPParams) (broker.MFSIPResponse, error) {
	if c.PlaceMFSIPErr != nil {
		return broker.MFSIPResponse{}, c.PlaceMFSIPErr
	}
	id := strconv.FormatInt(c.nextMFSIPID.Add(1), 10)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.mfSIPs = append(c.mfSIPs, broker.MFSIP{
		SIPID:         id,
		Tradingsymbol: params.Tradingsymbol,
		Frequency:     params.Frequency,
		Amount:        params.Amount,
		Instalments:   params.Instalments,
		InstalmentDay: params.InstalmentDay,
		Status:        "ACTIVE",
		Tag:           params.Tag,
	})
	return broker.MFSIPResponse{SIPID: id}, nil
}

// CancelMFSIP cancels a mock MF SIP.
func (c *Client) CancelMFSIP(sipID string) (broker.MFSIPResponse, error) {
	if c.CancelMFSIPErr != nil {
		return broker.MFSIPResponse{}, c.CancelMFSIPErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.mfSIPs {
		if c.mfSIPs[i].SIPID == sipID {
			c.mfSIPs[i].Status = "CANCELLED"
			return broker.MFSIPResponse{SIPID: sipID}, nil
		}
	}
	return broker.MFSIPResponse{}, fmt.Errorf("MF SIP %s not found", sipID)
}

// ---------------------------------------------------------------------------
// Margin calculation operations
// ---------------------------------------------------------------------------

// GetOrderMargins returns mock margin data.
func (c *Client) GetOrderMargins(_ []broker.OrderMarginParam) (any, error) {
	if c.GetOrderMarginsErr != nil {
		return nil, c.GetOrderMarginsErr
	}
	return map[string]any{
		"total":  5000.0,
		"type":   "equity",
		"source": "mock",
	}, nil
}

// GetBasketMargins returns mock basket margin data.
func (c *Client) GetBasketMargins(_ []broker.OrderMarginParam, _ bool) (any, error) {
	if c.GetBasketMarginsErr != nil {
		return nil, c.GetBasketMarginsErr
	}
	return map[string]any{
		"total":  10000.0,
		"type":   "basket",
		"source": "mock",
	}, nil
}

// GetOrderCharges returns mock order charges data.
func (c *Client) GetOrderCharges(_ []broker.OrderChargesParam) (any, error) {
	if c.GetOrderChargesErr != nil {
		return nil, c.GetOrderChargesErr
	}
	return map[string]any{
		"total_charges": 50.0,
		"source":        "mock",
	}, nil
}

// ---------------------------------------------------------------------------
// NativeAlertCapable implementation
// ---------------------------------------------------------------------------

// SetNativeAlerts replaces all native alerts in the mock.
func (c *Client) SetNativeAlerts(alerts []broker.NativeAlert) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nativeAlerts = alerts
}

// CreateNativeAlert creates a mock native alert and returns it.
func (c *Client) CreateNativeAlert(params broker.NativeAlertParams) (broker.NativeAlert, error) {
	if c.CreateNativeAlertErr != nil {
		return broker.NativeAlert{}, c.CreateNativeAlertErr
	}
	id := c.nextNativeAlertID.Add(1)
	alert := broker.NativeAlert{
		UUID:             fmt.Sprintf("mock-alert-%d", id),
		Name:             params.Name,
		Type:             params.Type,
		Status:           "enabled",
		LHSExchange:      params.LHSExchange,
		LHSTradingSymbol: params.LHSTradingSymbol,
		LHSAttribute:     params.LHSAttribute,
		Operator:         params.Operator,
		RHSType:          params.RHSType,
		RHSConstant:      params.RHSConstant,
		RHSExchange:      params.RHSExchange,
		RHSTradingSymbol: params.RHSTradingSymbol,
		RHSAttribute:     params.RHSAttribute,
	}
	c.mu.Lock()
	c.nativeAlerts = append(c.nativeAlerts, alert)
	c.mu.Unlock()
	return alert, nil
}

// GetNativeAlerts returns mock native alerts, optionally filtered.
func (c *Client) GetNativeAlerts(filters map[string]string) ([]broker.NativeAlert, error) {
	if c.GetNativeAlertsErr != nil {
		return nil, c.GetNativeAlertsErr
	}
	c.mu.RLock()
	defer c.mu.RUnlock()

	if status, ok := filters["status"]; ok {
		var filtered []broker.NativeAlert
		for _, a := range c.nativeAlerts {
			if a.Status == status {
				filtered = append(filtered, a)
			}
		}
		return filtered, nil
	}

	out := make([]broker.NativeAlert, len(c.nativeAlerts))
	copy(out, c.nativeAlerts)
	return out, nil
}

// ModifyNativeAlert modifies a mock native alert by UUID.
func (c *Client) ModifyNativeAlert(uuid string, params broker.NativeAlertParams) (broker.NativeAlert, error) {
	if c.ModifyNativeAlertErr != nil {
		return broker.NativeAlert{}, c.ModifyNativeAlertErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.nativeAlerts {
		if c.nativeAlerts[i].UUID == uuid {
			c.nativeAlerts[i].Name = params.Name
			c.nativeAlerts[i].Type = params.Type
			c.nativeAlerts[i].Operator = params.Operator
			return c.nativeAlerts[i], nil
		}
	}
	return broker.NativeAlert{}, fmt.Errorf("native alert %s not found", uuid)
}

// DeleteNativeAlerts removes native alerts by UUID.
func (c *Client) DeleteNativeAlerts(uuids ...string) error {
	if c.DeleteNativeAlertsErr != nil {
		return c.DeleteNativeAlertsErr
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	uuidSet := make(map[string]bool, len(uuids))
	for _, u := range uuids {
		uuidSet[u] = true
	}
	var remaining []broker.NativeAlert
	for _, a := range c.nativeAlerts {
		if !uuidSet[a.UUID] {
			remaining = append(remaining, a)
		}
	}
	c.nativeAlerts = remaining
	return nil
}

// GetNativeAlertHistory returns mock alert history entries.
func (c *Client) GetNativeAlertHistory(uuid string) ([]broker.NativeAlertHistoryEntry, error) {
	if c.GetNativeAlertHistoryErr != nil {
		return nil, c.GetNativeAlertHistoryErr
	}
	return []broker.NativeAlertHistoryEntry{
		{UUID: uuid, Type: "simple", Condition: "triggered", CreatedAt: "2026-01-01 10:00:00"},
	}, nil
}
