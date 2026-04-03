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

// HistoricalCandle represents a single OHLCV candle.
type HistoricalCandle struct {
	Date   time.Time `json:"date"`
	Open   float64   `json:"open"`
	High   float64   `json:"high"`
	Low    float64   `json:"low"`
	Close  float64   `json:"close"`
	Volume int       `json:"volume"`
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
	CancelOrder(orderID string) (OrderResponse, error)

	// GetLTP returns the last traded price for the given instruments.
	// Instrument format is "EXCHANGE:TRADINGSYMBOL" (e.g., "NSE:RELIANCE").
	GetLTP(instruments ...string) (map[string]LTP, error)

	// GetOHLC returns OHLC data for the given instruments.
	GetOHLC(instruments ...string) (map[string]OHLC, error)

	// GetHistoricalData returns historical candle data for an instrument.
	GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]HistoricalCandle, error)
}
