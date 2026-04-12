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

// GetQuotesQuery requests full market quotes for instruments.
type GetQuotesQuery struct {
	Instruments []string `json:"instruments"` // "EXCHANGE:SYMBOL" format
}

// GetOrderTradesQuery requests executed trades for a specific order.
type GetOrderTradesQuery struct {
	Email   string `json:"email"`
	OrderID string `json:"order_id"`
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

// --- GTT queries ---

// GetGTTsQuery requests all GTT orders for a user.
type GetGTTsQuery struct {
	Email string `json:"email"`
}

// --- Mutual Fund queries ---

// GetMFOrdersQuery requests all mutual fund orders.
type GetMFOrdersQuery struct {
	Email string `json:"email"`
}

// GetMFSIPsQuery requests all mutual fund SIPs.
type GetMFSIPsQuery struct {
	Email string `json:"email"`
}

// GetMFHoldingsQuery requests all mutual fund holdings.
type GetMFHoldingsQuery struct {
	Email string `json:"email"`
}

// --- Margin queries ---

// GetOrderMarginsQuery requests margin calculation for orders.
type GetOrderMarginsQuery struct {
	Email  string `json:"email"`
	Orders []OrderMarginQueryParam `json:"orders"`
}

// OrderMarginQueryParam holds parameters for a single order margin calculation.
type OrderMarginQueryParam struct {
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Variety         string  `json:"variety"`
	Product         string  `json:"product"`
	OrderType       string  `json:"order_type"`
	Quantity        float64 `json:"quantity"`
	Price           float64 `json:"price,omitempty"`
	TriggerPrice    float64 `json:"trigger_price,omitempty"`
}

// GetBasketMarginsQuery requests combined margin for a basket of orders.
type GetBasketMarginsQuery struct {
	Email             string `json:"email"`
	Orders            []OrderMarginQueryParam `json:"orders"`
	ConsiderPositions bool `json:"consider_positions"`
}

// GetOrderChargesQuery requests brokerage and charges calculation for orders.
type GetOrderChargesQuery struct {
	Email  string `json:"email"`
	Orders []OrderChargesQueryParam `json:"orders"`
}

// OrderChargesQueryParam holds parameters for a single order charges calculation.
type OrderChargesQueryParam struct {
	OrderID         string  `json:"order_id"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Quantity        float64 `json:"quantity"`
	AveragePrice    float64 `json:"average_price"`
	Product         string  `json:"product"`
	OrderType       string  `json:"order_type"`
	Variety         string  `json:"variety"`
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

// --- Watchlist queries ---

// ListWatchlistsQuery requests all watchlists for a user.
type ListWatchlistsQuery struct {
	Email string `json:"email"`
}

// GetWatchlistQuery requests items in a specific watchlist.
type GetWatchlistQuery struct {
	Email       string `json:"email"`
	WatchlistID string `json:"watchlist_id"`
}

// --- Paper trading queries ---

// PaperTradingStatusQuery requests the paper trading status.
type PaperTradingStatusQuery struct {
	Email string `json:"email"`
}

// --- Trailing stop queries ---

// ListTrailingStopsQuery requests all trailing stops for a user.
type ListTrailingStopsQuery struct {
	Email string `json:"email"`
}

// --- PnL queries ---

// GetPnLJournalQuery requests P&L journal data.
type GetPnLJournalQuery struct {
	Email    string `json:"email"`
	FromDate string `json:"from_date"`
	ToDate   string `json:"to_date"`
}

// --- Native alert queries ---

// ListNativeAlertsQuery requests native alerts from Zerodha.
type ListNativeAlertsQuery struct {
	Email   string            `json:"email"`
	Filters map[string]string `json:"filters,omitempty"`
}

// GetNativeAlertHistoryQuery requests trigger history for a native alert.
type GetNativeAlertHistoryQuery struct {
	Email string `json:"email"`
	UUID  string `json:"uuid"`
}

// --- Ticker queries ---

// TickerStatusQuery requests the ticker connection status.
type TickerStatusQuery struct {
	Email string `json:"email"`
}

// --- Admin queries ---

// AdminListUsersQuery requests a paginated list of users.
type AdminListUsersQuery struct {
	AdminEmail string `json:"admin_email"`
	From       int    `json:"from"`
	Limit      int    `json:"limit"`
}

// AdminGetUserQuery requests detailed user information.
type AdminGetUserQuery struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
}

// AdminServerStatusQuery requests server health overview.
type AdminServerStatusQuery struct {
	AdminEmail string `json:"admin_email"`
}

// AdminGetRiskStatusQuery requests a user's risk status.
type AdminGetRiskStatusQuery struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
}

// --- Widget queries ---

// GetWidgetPortfolioQuery requests portfolio data formatted for the widget.
type GetWidgetPortfolioQuery struct {
	Email string `json:"email"`
}

// GetWidgetOrdersQuery requests order data formatted for the orders widget.
type GetWidgetOrdersQuery struct {
	Email string `json:"email"`
}

// GetWidgetAlertsQuery requests alert data formatted for the alerts widget.
type GetWidgetAlertsQuery struct {
	Email string `json:"email"`
}

// GetWidgetActivityQuery requests activity data formatted for the activity widget.
type GetWidgetActivityQuery struct {
	Email string `json:"email"`
}
