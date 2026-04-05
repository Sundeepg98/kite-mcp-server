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
}

// ModifyOrderCommand requests modifying an existing pending order.
type ModifyOrderCommand struct {
	Email        string  `json:"email"`
	OrderID      string  `json:"order_id"`
	Quantity     int     `json:"quantity,omitempty"`
	Price        float64 `json:"price,omitempty"`
	TriggerPrice float64 `json:"trigger_price,omitempty"`
	OrderType    string  `json:"order_type,omitempty"`
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
