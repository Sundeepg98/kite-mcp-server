// Package zerodha implements the broker.Client interface for Zerodha's Kite Connect API.
// It wraps gokiteconnect/v4 and translates between Kite-specific types and the
// broker-agnostic types defined in the broker package.
package zerodha

import (
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// Client wraps a gokiteconnect Client and satisfies broker.Client.
// All methods delegate to the underlying Kite client and convert the
// response types. Error values are passed through unchanged.
type Client struct {
	kite *kiteconnect.Client
}

// compile-time proof that *Client satisfies broker.Client.
var _ broker.Client = (*Client)(nil)

// New wraps an existing *kiteconnect.Client.
func New(kite *kiteconnect.Client) *Client {
	return &Client{kite: kite}
}

// Kite returns the underlying *kiteconnect.Client for callers that still
// need direct access during the migration period.
func (c *Client) Kite() *kiteconnect.Client {
	return c.kite
}

// BrokerName returns the broker identifier.
func (c *Client) BrokerName() broker.Name {
	return broker.Zerodha
}

// GetProfile returns the authenticated user's profile.
func (c *Client) GetProfile() (broker.Profile, error) {
	p, err := c.kite.GetUserProfile()
	if err != nil {
		return broker.Profile{}, err
	}
	return convertProfile(p), nil
}

// GetMargins returns margin/funds information.
func (c *Client) GetMargins() (broker.Margins, error) {
	m, err := c.kite.GetUserMargins()
	if err != nil {
		return broker.Margins{}, err
	}
	return convertMargins(m), nil
}

// GetHoldings returns the user's portfolio holdings.
func (c *Client) GetHoldings() ([]broker.Holding, error) {
	h, err := c.kite.GetHoldings()
	if err != nil {
		return nil, err
	}
	return convertHoldings(h), nil
}

// GetPositions returns current day and net positions.
func (c *Client) GetPositions() (broker.Positions, error) {
	p, err := c.kite.GetPositions()
	if err != nil {
		return broker.Positions{}, err
	}
	return convertPositions(p), nil
}

// GetOrders returns all orders for the current trading day.
func (c *Client) GetOrders() ([]broker.Order, error) {
	o, err := c.kite.GetOrders()
	if err != nil {
		return nil, err
	}
	return convertOrders(o), nil
}

// GetOrderHistory returns the state history of a specific order.
func (c *Client) GetOrderHistory(orderID string) ([]broker.Order, error) {
	o, err := c.kite.GetOrderHistory(orderID)
	if err != nil {
		return nil, err
	}
	return convertOrders(kiteconnect.Orders(o)), nil
}

// GetTrades returns all executed trades for the day.
func (c *Client) GetTrades() ([]broker.Trade, error) {
	t, err := c.kite.GetTrades()
	if err != nil {
		return nil, err
	}
	return convertTrades(t), nil
}

// PlaceOrder places a new order and returns the order ID.
func (c *Client) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	variety, kp := convertOrderParamsToKite(params)
	resp, err := c.kite.PlaceOrder(variety, kp)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	return broker.OrderResponse{OrderID: resp.OrderID}, nil
}

// ModifyOrder modifies an existing pending order.
func (c *Client) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	variety, kp := convertOrderParamsToKite(params)
	resp, err := c.kite.ModifyOrder(variety, orderID, kp)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	return broker.OrderResponse{OrderID: resp.OrderID}, nil
}

// CancelOrder cancels an existing pending order.
func (c *Client) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
	if variety == "" {
		variety = kiteconnect.VarietyRegular
	}
	resp, err := c.kite.CancelOrder(variety, orderID, nil)
	if err != nil {
		return broker.OrderResponse{}, err
	}
	return broker.OrderResponse{OrderID: resp.OrderID}, nil
}

// GetLTP returns the last traded price for the given instruments.
func (c *Client) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	q, err := c.kite.GetLTP(instruments...)
	if err != nil {
		return nil, err
	}
	return convertLTP(q), nil
}

// GetOHLC returns OHLC data for the given instruments.
func (c *Client) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	q, err := c.kite.GetOHLC(instruments...)
	if err != nil {
		return nil, err
	}
	return convertOHLC(q), nil
}

// GetHistoricalData returns historical candle data for an instrument.
func (c *Client) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	data, err := c.kite.GetHistoricalData(instrumentToken, interval, from, to, false, false)
	if err != nil {
		return nil, err
	}
	return convertHistoricalData(data), nil
}

// GetQuotes returns full market quotes for the given instruments.
func (c *Client) GetQuotes(instruments ...string) (map[string]broker.Quote, error) {
	q, err := c.kite.GetQuote(instruments...)
	if err != nil {
		return nil, err
	}
	return convertQuotes(q), nil
}

// GetOrderTrades returns executed trades for a specific order.
func (c *Client) GetOrderTrades(orderID string) ([]broker.Trade, error) {
	t, err := c.kite.GetOrderTrades(orderID)
	if err != nil {
		return nil, err
	}
	return convertTrades(kiteconnect.Trades(t)), nil
}

// GetGTTs returns all GTT orders.
func (c *Client) GetGTTs() ([]broker.GTTOrder, error) {
	gtts, err := c.kite.GetGTTs()
	if err != nil {
		return nil, err
	}
	return convertGTTs(gtts), nil
}

// PlaceGTT places a new GTT order.
func (c *Client) PlaceGTT(params broker.GTTParams) (broker.GTTResponse, error) {
	kp, err := convertGTTParamsToKite(params)
	if err != nil {
		return broker.GTTResponse{}, err
	}
	resp, err := c.kite.PlaceGTT(kp)
	if err != nil {
		return broker.GTTResponse{}, err
	}
	return broker.GTTResponse{TriggerID: resp.TriggerID}, nil
}

// ModifyGTT modifies an existing GTT order.
func (c *Client) ModifyGTT(triggerID int, params broker.GTTParams) (broker.GTTResponse, error) {
	kp, err := convertGTTParamsToKite(params)
	if err != nil {
		return broker.GTTResponse{}, err
	}
	resp, err := c.kite.ModifyGTT(triggerID, kp)
	if err != nil {
		return broker.GTTResponse{}, err
	}
	return broker.GTTResponse{TriggerID: resp.TriggerID}, nil
}

// DeleteGTT deletes an existing GTT order.
func (c *Client) DeleteGTT(triggerID int) (broker.GTTResponse, error) {
	resp, err := c.kite.DeleteGTT(triggerID)
	if err != nil {
		return broker.GTTResponse{}, err
	}
	return broker.GTTResponse{TriggerID: resp.TriggerID}, nil
}
