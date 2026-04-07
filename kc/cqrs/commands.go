// Package cqrs provides command and query types for a pragmatic CQRS split.
//
// Commands represent write intentions — they describe what the user wants to
// change. Queries represent read requests. Both are plain data objects with
// no behavior. Handler interfaces provide the generic contract for processing
// commands and queries, enabling testable, composable use-case pipelines.
package cqrs

// --- Order commands ---

// PlaceOrderCommand requests placing a new trading order.
type PlaceOrderCommand struct {
	Email           string  `json:"email"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"` // BUY or SELL
	Quantity        int     `json:"quantity"`
	Price           float64 `json:"price,omitempty"`
	OrderType       string  `json:"order_type"`       // MARKET, LIMIT, SL, SL-M
	Product         string  `json:"product"`           // CNC, MIS, NRML
	TriggerPrice    float64 `json:"trigger_price,omitempty"`
	Validity        string  `json:"validity,omitempty"`
	Variety         string  `json:"variety,omitempty"`
	Tag             string  `json:"tag,omitempty"`
}

// CancelOrderCommand requests cancelling an existing order.
type CancelOrderCommand struct {
	Email   string `json:"email"`
	OrderID string `json:"order_id"`
	Variety string `json:"variety,omitempty"`
}

// ModifyOrderCommand requests modifying an existing pending order.
type ModifyOrderCommand struct {
	Email            string  `json:"email"`
	OrderID          string  `json:"order_id"`
	Variety          string  `json:"variety,omitempty"`
	Quantity         int     `json:"quantity,omitempty"`
	Price            float64 `json:"price,omitempty"`
	TriggerPrice     float64 `json:"trigger_price,omitempty"`
	OrderType        string  `json:"order_type,omitempty"`
	Validity         string  `json:"validity,omitempty"`
	DisclosedQty     int     `json:"disclosed_quantity,omitempty"`
	MarketProtection float64 `json:"market_protection,omitempty"`
}

// --- GTT commands ---

// PlaceGTTCommand requests placing a new GTT order.
type PlaceGTTCommand struct {
	Email             string  `json:"email"`
	Exchange          string  `json:"exchange"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	LastPrice         float64 `json:"last_price"`
	TransactionType   string  `json:"transaction_type"`
	Product           string  `json:"product"`
	Type              string  `json:"type"` // "single" or "two-leg"
	TriggerValue      float64 `json:"trigger_value,omitempty"`
	Quantity          float64 `json:"quantity,omitempty"`
	LimitPrice        float64 `json:"limit_price,omitempty"`
	UpperTriggerValue float64 `json:"upper_trigger_value,omitempty"`
	UpperQuantity     float64 `json:"upper_quantity,omitempty"`
	UpperLimitPrice   float64 `json:"upper_limit_price,omitempty"`
	LowerTriggerValue float64 `json:"lower_trigger_value,omitempty"`
	LowerQuantity     float64 `json:"lower_quantity,omitempty"`
	LowerLimitPrice   float64 `json:"lower_limit_price,omitempty"`
}

// ModifyGTTCommand requests modifying an existing GTT order.
type ModifyGTTCommand struct {
	Email             string  `json:"email"`
	TriggerID         int     `json:"trigger_id"`
	Exchange          string  `json:"exchange"`
	Tradingsymbol     string  `json:"tradingsymbol"`
	LastPrice         float64 `json:"last_price"`
	TransactionType   string  `json:"transaction_type"`
	Product           string  `json:"product"`
	Type              string  `json:"type"` // "single" or "two-leg"
	TriggerValue      float64 `json:"trigger_value,omitempty"`
	Quantity          float64 `json:"quantity,omitempty"`
	LimitPrice        float64 `json:"limit_price,omitempty"`
	UpperTriggerValue float64 `json:"upper_trigger_value,omitempty"`
	UpperQuantity     float64 `json:"upper_quantity,omitempty"`
	UpperLimitPrice   float64 `json:"upper_limit_price,omitempty"`
	LowerTriggerValue float64 `json:"lower_trigger_value,omitempty"`
	LowerQuantity     float64 `json:"lower_quantity,omitempty"`
	LowerLimitPrice   float64 `json:"lower_limit_price,omitempty"`
}

// DeleteGTTCommand requests deleting an existing GTT order.
type DeleteGTTCommand struct {
	Email     string `json:"email"`
	TriggerID int    `json:"trigger_id"`
}

// --- Alert commands ---

// CreateAlertCommand requests creating a new price alert.
type CreateAlertCommand struct {
	Email          string  `json:"email"`
	Tradingsymbol  string  `json:"tradingsymbol"`
	Exchange       string  `json:"exchange"`
	TargetPrice    float64 `json:"target_price"`
	Direction      string  `json:"direction"` // above, below, drop_pct, rise_pct
	ReferencePrice float64 `json:"reference_price,omitempty"`
}

// DeleteAlertCommand requests deleting an existing alert.
type DeleteAlertCommand struct {
	Email   string `json:"email"`
	AlertID string `json:"alert_id"`
}

// --- Session commands ---

// FreezeUserCommand requests freezing a user's trading.
type FreezeUserCommand struct {
	Email    string `json:"email"`
	FrozenBy string `json:"frozen_by"` // "admin", "riskguard:circuit-breaker"
	Reason   string `json:"reason"`
}

// UnfreezeUserCommand requests unfreezing a user's trading.
type UnfreezeUserCommand struct {
	Email string `json:"email"`
}

// --- Watchlist commands ---

// CreateWatchlistCommand requests creating a new named watchlist.
type CreateWatchlistCommand struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// AddToWatchlistCommand requests adding an instrument to a watchlist.
type AddToWatchlistCommand struct {
	Email         string `json:"email"`
	WatchlistID   string `json:"watchlist_id"`
	Exchange      string `json:"exchange"`
	Tradingsymbol string `json:"tradingsymbol"`
}
