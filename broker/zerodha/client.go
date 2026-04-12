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
// Retries up to 2 times on transient network errors.
func (c *Client) GetProfile() (broker.Profile, error) {
	return retryOnTransient(func() (broker.Profile, error) {
		p, err := c.kite.GetUserProfile()
		if err != nil {
			return broker.Profile{}, err
		}
		return convertProfile(p), nil
	}, 2)
}

// GetMargins returns margin/funds information.
// Retries up to 2 times on transient network errors.
func (c *Client) GetMargins() (broker.Margins, error) {
	return retryOnTransient(func() (broker.Margins, error) {
		m, err := c.kite.GetUserMargins()
		if err != nil {
			return broker.Margins{}, err
		}
		return convertMargins(m), nil
	}, 2)
}

// GetHoldings returns the user's portfolio holdings.
// Retries up to 2 times on transient network errors.
func (c *Client) GetHoldings() ([]broker.Holding, error) {
	return retryOnTransient(func() ([]broker.Holding, error) {
		h, err := c.kite.GetHoldings()
		if err != nil {
			return nil, err
		}
		return convertHoldings(h), nil
	}, 2)
}

// GetPositions returns current day and net positions.
// Retries up to 2 times on transient network errors.
func (c *Client) GetPositions() (broker.Positions, error) {
	return retryOnTransient(func() (broker.Positions, error) {
		p, err := c.kite.GetPositions()
		if err != nil {
			return broker.Positions{}, err
		}
		return convertPositions(p), nil
	}, 2)
}

// GetOrders returns all orders for the current trading day.
// Retries up to 2 times on transient network errors.
func (c *Client) GetOrders() ([]broker.Order, error) {
	return retryOnTransient(func() ([]broker.Order, error) {
		o, err := c.kite.GetOrders()
		if err != nil {
			return nil, err
		}
		return convertOrders(o), nil
	}, 2)
}

// GetOrderHistory returns the state history of a specific order.
// Retries up to 2 times on transient network errors.
func (c *Client) GetOrderHistory(orderID string) ([]broker.Order, error) {
	return retryOnTransient(func() ([]broker.Order, error) {
		o, err := c.kite.GetOrderHistory(orderID)
		if err != nil {
			return nil, err
		}
		return convertOrders(kiteconnect.Orders(o)), nil
	}, 2)
}

// GetTrades returns all executed trades for the day.
// Retries up to 2 times on transient network errors.
func (c *Client) GetTrades() ([]broker.Trade, error) {
	return retryOnTransient(func() ([]broker.Trade, error) {
		t, err := c.kite.GetTrades()
		if err != nil {
			return nil, err
		}
		return convertTrades(t), nil
	}, 2)
}

// PlaceOrder places a new order and returns the order ID.
// Retries up to 2 times on transient network errors.
func (c *Client) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	variety, kp := convertOrderParamsToKite(params)
	return retryOnTransient(func() (broker.OrderResponse, error) {
		resp, err := c.kite.PlaceOrder(variety, kp)
		if err != nil {
			return broker.OrderResponse{}, err
		}
		return broker.OrderResponse{OrderID: resp.OrderID}, nil
	}, 2)
}

// ModifyOrder modifies an existing pending order.
// Retries up to 2 times on transient network errors.
func (c *Client) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	variety, kp := convertOrderParamsToKite(params)
	return retryOnTransient(func() (broker.OrderResponse, error) {
		resp, err := c.kite.ModifyOrder(variety, orderID, kp)
		if err != nil {
			return broker.OrderResponse{}, err
		}
		return broker.OrderResponse{OrderID: resp.OrderID}, nil
	}, 2)
}

// CancelOrder cancels an existing pending order.
// Retries up to 2 times on transient network errors.
func (c *Client) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
	if variety == "" {
		variety = kiteconnect.VarietyRegular
	}
	return retryOnTransient(func() (broker.OrderResponse, error) {
		resp, err := c.kite.CancelOrder(variety, orderID, nil)
		if err != nil {
			return broker.OrderResponse{}, err
		}
		return broker.OrderResponse{OrderID: resp.OrderID}, nil
	}, 2)
}

// GetLTP returns the last traded price for the given instruments.
// Retries up to 2 times on transient network errors.
func (c *Client) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	return retryOnTransient(func() (map[string]broker.LTP, error) {
		q, err := c.kite.GetLTP(instruments...)
		if err != nil {
			return nil, err
		}
		return convertLTP(q), nil
	}, 2)
}

// GetOHLC returns OHLC data for the given instruments.
// Retries up to 2 times on transient network errors.
func (c *Client) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	return retryOnTransient(func() (map[string]broker.OHLC, error) {
		q, err := c.kite.GetOHLC(instruments...)
		if err != nil {
			return nil, err
		}
		return convertOHLC(q), nil
	}, 2)
}

// GetHistoricalData returns historical candle data for an instrument.
// Retries up to 2 times on transient network errors.
func (c *Client) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	return retryOnTransient(func() ([]broker.HistoricalCandle, error) {
		data, err := c.kite.GetHistoricalData(instrumentToken, interval, from, to, false, false)
		if err != nil {
			return nil, err
		}
		return convertHistoricalData(data), nil
	}, 2)
}

// GetQuotes returns full market quotes for the given instruments.
// Retries up to 2 times on transient network errors.
func (c *Client) GetQuotes(instruments ...string) (map[string]broker.Quote, error) {
	return retryOnTransient(func() (map[string]broker.Quote, error) {
		q, err := c.kite.GetQuote(instruments...)
		if err != nil {
			return nil, err
		}
		return convertQuotes(q), nil
	}, 2)
}

// GetOrderTrades returns executed trades for a specific order.
// Retries up to 2 times on transient network errors.
func (c *Client) GetOrderTrades(orderID string) ([]broker.Trade, error) {
	return retryOnTransient(func() ([]broker.Trade, error) {
		t, err := c.kite.GetOrderTrades(orderID)
		if err != nil {
			return nil, err
		}
		return convertTrades(kiteconnect.Trades(t)), nil
	}, 2)
}

// GetGTTs returns all GTT orders.
// Retries up to 2 times on transient network errors.
func (c *Client) GetGTTs() ([]broker.GTTOrder, error) {
	return retryOnTransient(func() ([]broker.GTTOrder, error) {
		gtts, err := c.kite.GetGTTs()
		if err != nil {
			return nil, err
		}
		return convertGTTs(gtts), nil
	}, 2)
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

// ConvertPosition converts a position from one product type to another.
func (c *Client) ConvertPosition(params broker.ConvertPositionParams) (bool, error) {
	return c.kite.ConvertPosition(kiteconnect.ConvertPositionParams{
		Exchange:        params.Exchange,
		TradingSymbol:   params.Tradingsymbol,
		TransactionType: params.TransactionType,
		Quantity:        params.Quantity,
		OldProduct:      params.OldProduct,
		NewProduct:      params.NewProduct,
		PositionType:    params.PositionType,
	})
}

// --- Mutual Fund operations ---

// GetMFOrders returns all mutual fund orders.
func (c *Client) GetMFOrders() ([]broker.MFOrder, error) {
	return retryOnTransient(func() ([]broker.MFOrder, error) {
		orders, err := c.kite.GetMFOrders()
		if err != nil {
			return nil, err
		}
		return convertMFOrders(orders), nil
	}, 2)
}

// GetMFSIPs returns all mutual fund SIPs.
func (c *Client) GetMFSIPs() ([]broker.MFSIP, error) {
	return retryOnTransient(func() ([]broker.MFSIP, error) {
		sips, err := c.kite.GetMFSIPs()
		if err != nil {
			return nil, err
		}
		return convertMFSIPs(sips), nil
	}, 2)
}

// GetMFHoldings returns all mutual fund holdings.
func (c *Client) GetMFHoldings() ([]broker.MFHolding, error) {
	return retryOnTransient(func() ([]broker.MFHolding, error) {
		holdings, err := c.kite.GetMFHoldings()
		if err != nil {
			return nil, err
		}
		return convertMFHoldings(holdings), nil
	}, 2)
}

// PlaceMFOrder places a mutual fund order.
func (c *Client) PlaceMFOrder(params broker.MFOrderParams) (broker.MFOrderResponse, error) {
	resp, err := c.kite.PlaceMFOrder(kiteconnect.MFOrderParams{
		Tradingsymbol:   params.Tradingsymbol,
		TransactionType: params.TransactionType,
		Amount:          params.Amount,
		Quantity:        params.Quantity,
		Tag:             params.Tag,
	})
	if err != nil {
		return broker.MFOrderResponse{}, err
	}
	return broker.MFOrderResponse{OrderID: resp.OrderID}, nil
}

// CancelMFOrder cancels a pending mutual fund order.
func (c *Client) CancelMFOrder(orderID string) (broker.MFOrderResponse, error) {
	resp, err := c.kite.CancelMFOrder(orderID)
	if err != nil {
		return broker.MFOrderResponse{}, err
	}
	return broker.MFOrderResponse{OrderID: resp.OrderID}, nil
}

// PlaceMFSIP starts a new mutual fund SIP.
func (c *Client) PlaceMFSIP(params broker.MFSIPParams) (broker.MFSIPResponse, error) {
	resp, err := c.kite.PlaceMFSIP(kiteconnect.MFSIPParams{
		Tradingsymbol: params.Tradingsymbol,
		Amount:        params.Amount,
		Frequency:     params.Frequency,
		Instalments:   params.Instalments,
		InitialAmount: params.InitialAmount,
		InstalmentDay: params.InstalmentDay,
		Tag:           params.Tag,
	})
	if err != nil {
		return broker.MFSIPResponse{}, err
	}
	return broker.MFSIPResponse{SIPID: resp.SIPID}, nil
}

// CancelMFSIP cancels an existing mutual fund SIP.
func (c *Client) CancelMFSIP(sipID string) (broker.MFSIPResponse, error) {
	resp, err := c.kite.CancelMFSIP(sipID)
	if err != nil {
		return broker.MFSIPResponse{}, err
	}
	return broker.MFSIPResponse{SIPID: resp.SIPID}, nil
}

// --- Margin calculation operations ---

// GetOrderMargins calculates margin required for orders.
// Returns the raw Kite API response as any for pass-through.
func (c *Client) GetOrderMargins(orders []broker.OrderMarginParam) (any, error) {
	kiteParams := make([]kiteconnect.OrderMarginParam, len(orders))
	for i, o := range orders {
		kiteParams[i] = kiteconnect.OrderMarginParam{
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Variety:         o.Variety,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Quantity:        o.Quantity,
			Price:           o.Price,
			TriggerPrice:    o.TriggerPrice,
		}
	}
	return c.kite.GetOrderMargins(kiteconnect.GetMarginParams{
		OrderParams: kiteParams,
	})
}

// GetBasketMargins calculates combined margin for a basket of orders.
// Returns the raw Kite API response as any for pass-through.
func (c *Client) GetBasketMargins(orders []broker.OrderMarginParam, considerPositions bool) (any, error) {
	kiteParams := make([]kiteconnect.OrderMarginParam, len(orders))
	for i, o := range orders {
		kiteParams[i] = kiteconnect.OrderMarginParam{
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Variety:         o.Variety,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Quantity:        o.Quantity,
			Price:           o.Price,
			TriggerPrice:    o.TriggerPrice,
		}
	}
	return c.kite.GetBasketMargins(kiteconnect.GetBasketParams{
		OrderParams:       kiteParams,
		ConsiderPositions: considerPositions,
	})
}

// GetOrderCharges calculates brokerage, taxes, and charges for orders.
// Returns the raw Kite API response as any for pass-through.
func (c *Client) GetOrderCharges(orders []broker.OrderChargesParam) (any, error) {
	kiteParams := make([]kiteconnect.OrderChargesParam, len(orders))
	for i, o := range orders {
		kiteParams[i] = kiteconnect.OrderChargesParam{
			OrderID:         o.OrderID,
			Exchange:        o.Exchange,
			Tradingsymbol:   o.Tradingsymbol,
			TransactionType: o.TransactionType,
			Quantity:        o.Quantity,
			AveragePrice:    o.AveragePrice,
			Product:         o.Product,
			OrderType:       o.OrderType,
			Variety:         o.Variety,
		}
	}
	return c.kite.GetOrderCharges(kiteconnect.GetChargesParams{
		OrderParams: kiteParams,
	})
}

// ---------------------------------------------------------------------------
// NativeAlertCapable implementation — server-side Zerodha alerts
// ---------------------------------------------------------------------------

// compile-time proof that *Client satisfies broker.NativeAlertCapable.
var _ broker.NativeAlertCapable = (*Client)(nil)

// CreateNativeAlert creates a server-side alert at Zerodha.
func (c *Client) CreateNativeAlert(params broker.NativeAlertParams) (broker.NativeAlert, error) {
	kp := convertNativeAlertParamsToKite(params)
	alert, err := c.kite.CreateAlert(kp)
	if err != nil {
		return broker.NativeAlert{}, err
	}
	return convertNativeAlert(alert), nil
}

// GetNativeAlerts retrieves all native alerts, optionally filtered.
func (c *Client) GetNativeAlerts(filters map[string]string) ([]broker.NativeAlert, error) {
	return retryOnTransient(func() ([]broker.NativeAlert, error) {
		alerts, err := c.kite.GetAlerts(filters)
		if err != nil {
			return nil, err
		}
		return convertNativeAlerts(alerts), nil
	}, 2)
}

// ModifyNativeAlert modifies an existing native alert by UUID.
func (c *Client) ModifyNativeAlert(uuid string, params broker.NativeAlertParams) (broker.NativeAlert, error) {
	kp := convertNativeAlertParamsToKite(params)
	alert, err := c.kite.ModifyAlert(uuid, kp)
	if err != nil {
		return broker.NativeAlert{}, err
	}
	return convertNativeAlert(alert), nil
}

// DeleteNativeAlerts deletes one or more native alerts by UUID.
func (c *Client) DeleteNativeAlerts(uuids ...string) error {
	return c.kite.DeleteAlerts(uuids...)
}

// GetNativeAlertHistory retrieves the trigger history for an alert.
func (c *Client) GetNativeAlertHistory(uuid string) ([]broker.NativeAlertHistoryEntry, error) {
	return retryOnTransient(func() ([]broker.NativeAlertHistoryEntry, error) {
		history, err := c.kite.GetAlertHistory(uuid)
		if err != nil {
			return nil, err
		}
		return convertNativeAlertHistory(history), nil
	}, 2)
}
