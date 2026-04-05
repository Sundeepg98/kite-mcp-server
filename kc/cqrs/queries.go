package cqrs

import "time"

// --- Portfolio queries ---

// GetPortfolioQuery requests the user's full portfolio (holdings + positions).
type GetPortfolioQuery struct {
	Email string `json:"email"`
}

// GetHoldingsQuery requests only the user's holdings.
type GetHoldingsQuery struct {
	Email string `json:"email"`
}

// GetPositionsQuery requests only the user's open positions.
type GetPositionsQuery struct {
	Email string `json:"email"`
}

// --- Order queries ---

// GetOrdersQuery requests all orders for the current trading day.
type GetOrdersQuery struct {
	Email string `json:"email"`
}

// GetOrderHistoryQuery requests the state history of a specific order.
type GetOrderHistoryQuery struct {
	Email   string `json:"email"`
	OrderID string `json:"order_id"`
}

// GetTradesQuery requests all executed trades for the current trading day.
type GetTradesQuery struct {
	Email string `json:"email"`
}

// --- Alert queries ---

// GetAlertsQuery requests all alerts for a user.
type GetAlertsQuery struct {
	Email string `json:"email"`
}

// --- Market data queries ---

// GetLTPQuery requests the last traded price for instruments.
type GetLTPQuery struct {
	Instruments []string `json:"instruments"` // "EXCHANGE:SYMBOL" format
}

// GetOHLCQuery requests OHLC data for instruments.
type GetOHLCQuery struct {
	Instruments []string `json:"instruments"`
}

// GetHistoricalDataQuery requests historical candle data.
type GetHistoricalDataQuery struct {
	InstrumentToken int       `json:"instrument_token"`
	Interval        string    `json:"interval"` // minute, 5minute, day, etc.
	From            time.Time `json:"from"`
	To              time.Time `json:"to"`
}

// --- Account queries ---

// GetMarginsQuery requests margin/funds information.
type GetMarginsQuery struct {
	Email string `json:"email"`
}

// GetProfileQuery requests the user's broker profile.
type GetProfileQuery struct {
	Email string `json:"email"`
}

// --- Audit queries ---

// GetAuditTrailQuery requests the tool call audit trail.
type GetAuditTrailQuery struct {
	Email      string    `json:"email"`
	Limit      int       `json:"limit,omitempty"`
	Offset     int       `json:"offset,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	OnlyErrors bool      `json:"only_errors,omitempty"`
}
