package broker

import "time"

// Name identifies a broker implementation.
type Name string

const (
	Zerodha  Name = "zerodha"
	AngelOne Name = "angelone"
	Dhan     Name = "dhan"
	Upstox   Name = "upstox"
)

// MarketProtectionAuto is the default value for MarketProtection in OrderParams,
// meaning the broker applies its own default protection percentage.
const MarketProtectionAuto float64 = -1

// Profile contains the authenticated user's broker profile.
type Profile struct {
	UserID    string   `json:"user_id"`
	UserName  string   `json:"user_name"`
	Email     string   `json:"email"`
	Broker    Name     `json:"broker"`
	Exchanges []string `json:"exchanges"`
	Products  []string `json:"products"`
}

// Margins contains margin information across segments.
type Margins struct {
	Equity    SegmentMargin `json:"equity"`
	Commodity SegmentMargin `json:"commodity,omitempty"`
}

// SegmentMargin contains margin details for a single segment.
type SegmentMargin struct {
	Available float64 `json:"available"`
	Used      float64 `json:"used"`
	Total     float64 `json:"total"`
}

// Holding represents a single holding in the portfolio.
type Holding struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	ISIN          string  `json:"isin,omitempty"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
	DayChangePct  float64 `json:"day_change_percentage"`
	Product       string  `json:"product,omitempty"`
}

// Position represents a single trading position.
type Position struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Product       string  `json:"product"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
}

// Positions contains day and net position lists.
type Positions struct {
	Day []Position `json:"day"`
	Net []Position `json:"net"`
}

// Order represents a placed order and its current state.
type Order struct {
	OrderID         string    `json:"order_id"`
	Exchange        string    `json:"exchange"`
	Tradingsymbol   string    `json:"tradingsymbol"`
	TransactionType string    `json:"transaction_type"`
	OrderType       string    `json:"order_type"`
	Product         string    `json:"product"`
	Quantity        int       `json:"quantity"`
	Price           float64   `json:"price"`
	TriggerPrice    float64   `json:"trigger_price"`
	Status          string    `json:"status"`
	FilledQuantity  int       `json:"filled_quantity"`
	AveragePrice    float64   `json:"average_price"`
	OrderTimestamp  time.Time `json:"order_timestamp"`
	StatusMessage   string    `json:"status_message,omitempty"`
	Tag             string    `json:"tag,omitempty"`
}

// Trade represents an executed trade.
type Trade struct {
	TradeID         string `json:"trade_id"`
	OrderID         string `json:"order_id"`
	Exchange        string `json:"exchange"`
	Tradingsymbol   string `json:"tradingsymbol"`
	TransactionType string `json:"transaction_type"`
	Quantity        int    `json:"quantity"`
	Price           float64 `json:"price"`
	Product         string `json:"product"`
}

// OrderParams contains parameters for placing or modifying an order.
type OrderParams struct {
	Exchange         string  `json:"exchange"`
	Tradingsymbol    string  `json:"tradingsymbol"`
	TransactionType  string  `json:"transaction_type"`
	OrderType        string  `json:"order_type"`
	Product          string  `json:"product"`
	Quantity         int     `json:"quantity"`
	Price            float64 `json:"price,omitempty"`
	TriggerPrice     float64 `json:"trigger_price,omitempty"`
	Validity         string  `json:"validity,omitempty"`
	Tag              string  `json:"tag,omitempty"`
	Variety          string  `json:"variety,omitempty"`
	DisclosedQty     int     `json:"disclosed_quantity,omitempty"`
	MarketProtection float64 `json:"market_protection,omitempty"`
}

// OrderResponse is returned after placing, modifying, or cancelling an order.
type OrderResponse struct {
	OrderID string `json:"order_id"`
}

// LTP contains the last traded price for an instrument.
type LTP struct {
	LastPrice float64 `json:"last_price"`
}

// OHLC contains open-high-low-close and last price for an instrument.
type OHLC struct {
	Open      float64 `json:"open"`
	High      float64 `json:"high"`
	Low       float64 `json:"low"`
	Close     float64 `json:"close"`
	LastPrice float64 `json:"last_price"`
}

// DepthItem represents a single entry in the market depth (bid/ask).
type DepthItem struct {
	Price    float64 `json:"price"`
	Quantity int     `json:"quantity"`
	Orders   int     `json:"orders"`
}

// Depth represents market depth with buy and sell sides.
type Depth struct {
	Buy  [5]DepthItem `json:"buy"`
	Sell [5]DepthItem `json:"sell"`
}

// Quote contains the full market quote for a single instrument.
type Quote struct {
	InstrumentToken   int     `json:"instrument_token"`
	LastPrice         float64 `json:"last_price"`
	LastQuantity      int     `json:"last_quantity"`
	AveragePrice      float64 `json:"average_price"`
	Volume            int     `json:"volume"`
	BuyQuantity       int     `json:"buy_quantity"`
	SellQuantity      int     `json:"sell_quantity"`
	OHLC              OHLC    `json:"ohlc"`
	NetChange         float64 `json:"net_change"`
	OI                float64 `json:"oi"`
	OIDayHigh         float64 `json:"oi_day_high"`
	OIDayLow          float64 `json:"oi_day_low"`
	LowerCircuitLimit float64 `json:"lower_circuit_limit"`
	UpperCircuitLimit float64 `json:"upper_circuit_limit"`
	Depth             Depth   `json:"depth"`
}

// HistoricalCandle represents a single OHLCV candle.
type HistoricalCandle struct {
	Date   time.Time `json:"date"`
	Open   float64   `json:"open"`
	High   float64   `json:"high"`
	Low    float64   `json:"low"`
	Close  float64   `json:"close"`
	Volume int       `json:"volume"`
}

// GTTCondition represents the trigger condition for a GTT order.
type GTTCondition struct {
	Exchange      string    `json:"exchange"`
	Tradingsymbol string    `json:"tradingsymbol"`
	TriggerValues []float64 `json:"trigger_values"`
	LastPrice     float64   `json:"last_price"`
}

// GTTOrderLeg represents a single order leg within a GTT.
type GTTOrderLeg struct {
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Quantity        int     `json:"quantity"`
	OrderType       string  `json:"order_type"`
	Price           float64 `json:"price"`
	Product         string  `json:"product"`
}

// GTTOrder represents a GTT (Good Till Triggered) order.
type GTTOrder struct {
	ID        int          `json:"id"`
	Type      string       `json:"type"` // "single" or "two-leg"
	Condition GTTCondition `json:"condition"`
	Orders    []GTTOrderLeg `json:"orders"`
	Status    string       `json:"status"`
	CreatedAt string       `json:"created_at"`
	UpdatedAt string       `json:"updated_at"`
	ExpiresAt string       `json:"expires_at"`
}

// GTTParams contains parameters for placing or modifying a GTT order.
type GTTParams struct {
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	LastPrice       float64 `json:"last_price"`
	TransactionType string  `json:"transaction_type"`
	Product         string  `json:"product"`
	Type            string  `json:"type"` // "single" or "two-leg"
	// For single-leg triggers:
	TriggerValue float64 `json:"trigger_value,omitempty"`
	Quantity     float64 `json:"quantity,omitempty"`
	LimitPrice   float64 `json:"limit_price,omitempty"`
	// For two-leg (OCO) triggers:
	UpperTriggerValue float64 `json:"upper_trigger_value,omitempty"`
	UpperQuantity     float64 `json:"upper_quantity,omitempty"`
	UpperLimitPrice   float64 `json:"upper_limit_price,omitempty"`
	LowerTriggerValue float64 `json:"lower_trigger_value,omitempty"`
	LowerQuantity     float64 `json:"lower_quantity,omitempty"`
	LowerLimitPrice   float64 `json:"lower_limit_price,omitempty"`
}

// GTTResponse is returned after placing or modifying a GTT order.
type GTTResponse struct {
	TriggerID int `json:"trigger_id"`
}

// ConvertPositionParams contains parameters for converting a position from one product to another.
type ConvertPositionParams struct {
	Exchange        string `json:"exchange"`
	Tradingsymbol   string `json:"tradingsymbol"`
	TransactionType string `json:"transaction_type"`
	Quantity        int    `json:"quantity"`
	OldProduct      string `json:"old_product"`
	NewProduct      string `json:"new_product"`
	PositionType    string `json:"position_type"` // "day" or "overnight"
}

// MFOrder represents a mutual fund order.
type MFOrder struct {
	OrderID           string  `json:"order_id"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	TransactionType   string  `json:"transaction_type"`
	Status            string  `json:"status"`
	Amount            float64 `json:"amount"`
	Quantity          float64 `json:"quantity"`
	Folio             string  `json:"folio,omitempty"`
	Fund              string  `json:"fund,omitempty"`
	Tag               string  `json:"tag,omitempty"`
	StatusMessage     string  `json:"status_message,omitempty"`
	PurchaseType      string  `json:"purchase_type,omitempty"`
	OrderTimestamp    string  `json:"order_timestamp,omitempty"`
	ExchangeTimestamp string  `json:"exchange_timestamp,omitempty"`
}

// MFSIP represents a mutual fund SIP (Systematic Investment Plan).
type MFSIP struct {
	SIPID         string  `json:"sip_id"`
	Tradingsymbol string  `json:"tradingsymbol"`
	Fund          string  `json:"fund,omitempty"`
	Frequency     string  `json:"frequency"`
	Amount        float64 `json:"amount"`
	Instalments   int     `json:"instalments"`
	Status        string  `json:"status"`
	InstalmentDay int     `json:"instalment_day,omitempty"`
	Tag           string  `json:"tag,omitempty"`
	Created       string  `json:"created,omitempty"`
}

// MFHolding represents a mutual fund holding.
type MFHolding struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Folio         string  `json:"folio,omitempty"`
	Fund          string  `json:"fund,omitempty"`
	Quantity      float64 `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
}

// MFOrderParams contains parameters for placing a mutual fund order.
type MFOrderParams struct {
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Amount          float64 `json:"amount,omitempty"`
	Quantity        float64 `json:"quantity,omitempty"`
	Tag             string  `json:"tag,omitempty"`
}

// MFOrderResponse is returned after placing or cancelling a mutual fund order.
type MFOrderResponse struct {
	OrderID string `json:"order_id"`
}

// MFSIPParams contains parameters for placing a mutual fund SIP.
type MFSIPParams struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Amount        float64 `json:"amount"`
	Frequency     string  `json:"frequency"`
	Instalments   int     `json:"instalments"`
	InitialAmount float64 `json:"initial_amount,omitempty"`
	InstalmentDay int     `json:"instalment_day,omitempty"`
	Tag           string  `json:"tag,omitempty"`
}

// MFSIPResponse is returned after placing or cancelling a mutual fund SIP.
type MFSIPResponse struct {
	SIPID string `json:"sip_id"`
}

// OrderMarginParam represents a single order for margin calculation.
type OrderMarginParam struct {
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

// OrderMarginResult represents the margin result for one order.
type OrderMarginResult struct {
	Type     string  `json:"type"`
	Exchange string  `json:"exchange"`
	Total    float64 `json:"total"`
	// Raw holds the full margin response from the broker for pass-through.
	Raw any `json:"raw,omitempty"`
}

// BasketMarginResult represents the combined margin for a basket of orders.
type BasketMarginResult struct {
	// Raw holds the full basket margin response from the broker for pass-through.
	Raw any `json:"raw"`
}

// OrderChargesParam represents a single order for charges calculation.
type OrderChargesParam struct {
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

// OrderChargesResult represents the charges for one order.
type OrderChargesResult struct {
	// Raw holds the full charges response from the broker for pass-through.
	Raw any `json:"raw"`
}

// Factory creates broker Client instances from credentials.
type Factory interface {
	// Create returns a new unauthenticated broker client for the given API key.
	Create(apiKey string) (Client, error)

	// CreateWithToken returns an authenticated broker client.
	CreateWithToken(apiKey, accessToken string) (Client, error)

	// BrokerName returns which broker this factory creates.
	BrokerName() Name
}

// Authenticator handles broker-specific auth lifecycle.
type Authenticator interface {
	// GetLoginURL returns the broker's login URL for OAuth/redirect flow.
	GetLoginURL(apiKey string) string

	// ExchangeToken completes auth flow, returns access token + user info.
	ExchangeToken(apiKey, apiSecret, requestToken string) (AuthResult, error)

	// InvalidateToken invalidates a token (best-effort).
	InvalidateToken(apiKey, accessToken string) error
}

// AuthResult returned from ExchangeToken.
type AuthResult struct {
	AccessToken string `json:"access_token"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	UserType    string `json:"user_type"`
}

// Client is the core broker interface. Each broker implementation
// (Zerodha, Angel One, Dhan, Upstox) must satisfy this contract.
type Client interface {
	// BrokerName returns the identifier for this broker implementation.
	BrokerName() Name

	// GetProfile returns the authenticated user's profile.
	GetProfile() (Profile, error)

	// GetMargins returns margin/funds information.
	GetMargins() (Margins, error)

	// GetHoldings returns the user's portfolio holdings.
	GetHoldings() ([]Holding, error)

	// GetPositions returns current day and net positions.
	GetPositions() (Positions, error)

	// GetOrders returns all orders for the current trading day.
	GetOrders() ([]Order, error)

	// GetOrderHistory returns the state history of a specific order.
	GetOrderHistory(orderID string) ([]Order, error)

	// GetTrades returns all executed trades for the day.
	GetTrades() ([]Trade, error)

	// PlaceOrder places a new order and returns the order ID.
	PlaceOrder(params OrderParams) (OrderResponse, error)

	// ModifyOrder modifies an existing pending order.
	ModifyOrder(orderID string, params OrderParams) (OrderResponse, error)

	// CancelOrder cancels an existing pending order.
	// variety specifies the order variety (e.g., "regular", "co", "amo", "iceberg", "auction").
	CancelOrder(orderID string, variety string) (OrderResponse, error)

	// GetLTP returns the last traded price for the given instruments.
	// Instrument format is "EXCHANGE:TRADINGSYMBOL" (e.g., "NSE:RELIANCE").
	GetLTP(instruments ...string) (map[string]LTP, error)

	// GetOHLC returns OHLC data for the given instruments.
	GetOHLC(instruments ...string) (map[string]OHLC, error)

	// GetHistoricalData returns historical candle data for an instrument.
	GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]HistoricalCandle, error)

	// GetQuotes returns full market quotes for the given instruments.
	// Instrument format is "EXCHANGE:TRADINGSYMBOL" (e.g., "NSE:RELIANCE").
	GetQuotes(instruments ...string) (map[string]Quote, error)

	// GetOrderTrades returns executed trades for a specific order.
	GetOrderTrades(orderID string) ([]Trade, error)

	// GetGTTs returns all GTT (Good Till Triggered) orders.
	GetGTTs() ([]GTTOrder, error)

	// PlaceGTT places a new GTT order and returns the trigger ID.
	PlaceGTT(params GTTParams) (GTTResponse, error)

	// ModifyGTT modifies an existing GTT order.
	ModifyGTT(triggerID int, params GTTParams) (GTTResponse, error)

	// DeleteGTT deletes an existing GTT order.
	DeleteGTT(triggerID int) (GTTResponse, error)

	// ConvertPosition converts a position from one product type to another.
	ConvertPosition(params ConvertPositionParams) (bool, error)

	// --- Mutual Fund operations ---

	// GetMFOrders returns all mutual fund orders.
	GetMFOrders() ([]MFOrder, error)

	// GetMFSIPs returns all mutual fund SIPs.
	GetMFSIPs() ([]MFSIP, error)

	// GetMFHoldings returns all mutual fund holdings.
	GetMFHoldings() ([]MFHolding, error)

	// PlaceMFOrder places a mutual fund order.
	PlaceMFOrder(params MFOrderParams) (MFOrderResponse, error)

	// CancelMFOrder cancels a pending mutual fund order.
	CancelMFOrder(orderID string) (MFOrderResponse, error)

	// PlaceMFSIP starts a new mutual fund SIP.
	PlaceMFSIP(params MFSIPParams) (MFSIPResponse, error)

	// CancelMFSIP cancels an existing mutual fund SIP.
	CancelMFSIP(sipID string) (MFSIPResponse, error)

	// --- Margin calculation operations ---

	// GetOrderMargins calculates margin required for orders.
	GetOrderMargins(orders []OrderMarginParam) (any, error)

	// GetBasketMargins calculates combined margin for a basket of orders.
	GetBasketMargins(orders []OrderMarginParam, considerPositions bool) (any, error)

	// GetOrderCharges calculates brokerage, taxes, and charges for orders.
	GetOrderCharges(orders []OrderChargesParam) (any, error)
}

// ---------------------------------------------------------------------------
// Native alert types — broker-agnostic representations of server-side alerts.
// Only Zerodha implements these currently; other brokers may not support them.
// ---------------------------------------------------------------------------

// NativeAlertParams contains parameters for creating or modifying a server-side alert.
type NativeAlertParams struct {
	Name             string          `json:"name"`
	Type             string          `json:"type"` // "simple" or "ato"
	LHSExchange      string          `json:"lhs_exchange"`
	LHSTradingSymbol string          `json:"lhs_tradingsymbol"`
	LHSAttribute     string          `json:"lhs_attribute"`
	Operator         string          `json:"operator"` // "<=", ">=", "<", ">", "=="
	RHSType          string          `json:"rhs_type"` // "constant" or "instrument"
	RHSConstant      float64         `json:"rhs_constant,omitempty"`
	RHSExchange      string          `json:"rhs_exchange,omitempty"`
	RHSTradingSymbol string          `json:"rhs_tradingsymbol,omitempty"`
	RHSAttribute     string          `json:"rhs_attribute,omitempty"`
	BasketJSON       string          `json:"basket_json,omitempty"` // raw JSON for ATO basket
}

// NativeAlert represents a server-side alert returned by the broker.
type NativeAlert struct {
	UUID             string  `json:"uuid"`
	Name             string  `json:"name"`
	Type             string  `json:"type"`
	Status           string  `json:"status"`
	LHSExchange      string  `json:"lhs_exchange"`
	LHSTradingSymbol string  `json:"lhs_tradingsymbol"`
	LHSAttribute     string  `json:"lhs_attribute"`
	Operator         string  `json:"operator"`
	RHSType          string  `json:"rhs_type"`
	RHSConstant      float64 `json:"rhs_constant,omitempty"`
	RHSExchange      string  `json:"rhs_exchange,omitempty"`
	RHSTradingSymbol string  `json:"rhs_tradingsymbol,omitempty"`
	RHSAttribute     string  `json:"rhs_attribute,omitempty"`
	AlertCount       int     `json:"alert_count"`
	CreatedAt        string  `json:"created_at,omitempty"`
	UpdatedAt        string  `json:"updated_at,omitempty"`
}

// NativeAlertHistoryEntry represents a single trigger event in an alert's history.
type NativeAlertHistoryEntry struct {
	UUID      string `json:"uuid"`
	Type      string `json:"type"`
	Condition string `json:"condition"`
	CreatedAt string `json:"created_at,omitempty"`
	Meta      any    `json:"meta,omitempty"`
	OrderMeta any    `json:"order_meta,omitempty"`
}

// NativeAlertCapable is an optional sub-interface implemented by brokers
// that support server-side alerts (e.g., Zerodha). Use a type assertion
// to check: if nac, ok := client.(broker.NativeAlertCapable); ok { ... }
type NativeAlertCapable interface {
	// CreateNativeAlert creates a server-side alert.
	CreateNativeAlert(params NativeAlertParams) (NativeAlert, error)

	// GetNativeAlerts retrieves all native alerts, optionally filtered.
	GetNativeAlerts(filters map[string]string) ([]NativeAlert, error)

	// ModifyNativeAlert modifies an existing native alert by UUID.
	ModifyNativeAlert(uuid string, params NativeAlertParams) (NativeAlert, error)

	// DeleteNativeAlerts deletes one or more native alerts by UUID.
	DeleteNativeAlerts(uuids ...string) error

	// GetNativeAlertHistory retrieves the trigger history for an alert.
	GetNativeAlertHistory(uuid string) ([]NativeAlertHistoryEntry, error)
}
