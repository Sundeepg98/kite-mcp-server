// Package cqrs provides command and query types for a pragmatic CQRS split.
//
// Commands represent write intentions — they describe what the user wants to
// change. Queries represent read requests. Both are plain data objects with
// no behavior. Handler interfaces provide the generic contract for processing
// commands and queries, enabling testable, composable use-case pipelines.
package cqrs

import "github.com/zerodha/kite-mcp-server/kc/domain"

// --- Order commands ---

// PlaceOrderCommand requests placing a new trading order.
// Uses domain value objects for validated fields: Instrument (exchange+symbol),
// Qty (positive integer), and Price (Money in INR).
type PlaceOrderCommand struct {
	Email           string              `json:"email"`
	Instrument      domain.InstrumentKey `json:"instrument"`
	TransactionType string              `json:"transaction_type"` // BUY or SELL
	Qty             domain.Quantity      `json:"qty"`
	Price           domain.Money         `json:"price"`
	OrderType       string              `json:"order_type"` // MARKET, LIMIT, SL, SL-M
	Product         string              `json:"product"`    // CNC, MIS, NRML
	TriggerPrice    float64             `json:"trigger_price,omitempty"`
	Validity        string              `json:"validity,omitempty"`
	Variety         string              `json:"variety,omitempty"`
	Tag             string              `json:"tag,omitempty"`
}

// CancelOrderCommand requests cancelling an existing order.
type CancelOrderCommand struct {
	Email   string `json:"email"`
	OrderID string `json:"order_id"`
	Variety string `json:"variety,omitempty"`
}

// ModifyOrderCommand requests modifying an existing pending order.
// Price uses domain.Money; Quantity stays int (0 = "don't modify").
type ModifyOrderCommand struct {
	Email            string       `json:"email"`
	OrderID          string       `json:"order_id"`
	Variety          string       `json:"variety,omitempty"`
	Quantity         int          `json:"quantity,omitempty"`
	Price            domain.Money `json:"price,omitempty"`
	TriggerPrice     float64      `json:"trigger_price,omitempty"`
	OrderType        string       `json:"order_type,omitempty"`
	Validity         string       `json:"validity,omitempty"`
	DisclosedQty     int          `json:"disclosed_quantity,omitempty"`
	MarketProtection float64      `json:"market_protection,omitempty"`
}

// --- GTT commands ---

// PlaceGTTCommand requests placing a new GTT order.
// Uses domain.InstrumentKey for the instrument and domain.Money for price fields.
// Quantities remain float64 as the GTT API accepts fractional quantities.
type PlaceGTTCommand struct {
	Email             string               `json:"email"`
	Instrument        domain.InstrumentKey  `json:"instrument"`
	LastPrice         domain.Money          `json:"last_price"`
	TransactionType   string               `json:"transaction_type"`
	Product           string               `json:"product"`
	Type              string               `json:"type"` // "single" or "two-leg"
	TriggerValue      float64              `json:"trigger_value,omitempty"`
	Quantity          float64              `json:"quantity,omitempty"`
	LimitPrice        domain.Money          `json:"limit_price,omitempty"`
	UpperTriggerValue float64              `json:"upper_trigger_value,omitempty"`
	UpperQuantity     float64              `json:"upper_quantity,omitempty"`
	UpperLimitPrice   domain.Money          `json:"upper_limit_price,omitempty"`
	LowerTriggerValue float64              `json:"lower_trigger_value,omitempty"`
	LowerQuantity     float64              `json:"lower_quantity,omitempty"`
	LowerLimitPrice   domain.Money          `json:"lower_limit_price,omitempty"`
}

// ModifyGTTCommand requests modifying an existing GTT order.
type ModifyGTTCommand struct {
	Email             string               `json:"email"`
	TriggerID         int                  `json:"trigger_id"`
	Instrument        domain.InstrumentKey  `json:"instrument"`
	LastPrice         domain.Money          `json:"last_price"`
	TransactionType   string               `json:"transaction_type"`
	Product           string               `json:"product"`
	Type              string               `json:"type"` // "single" or "two-leg"
	TriggerValue      float64              `json:"trigger_value,omitempty"`
	Quantity          float64              `json:"quantity,omitempty"`
	LimitPrice        domain.Money          `json:"limit_price,omitempty"`
	UpperTriggerValue float64              `json:"upper_trigger_value,omitempty"`
	UpperQuantity     float64              `json:"upper_quantity,omitempty"`
	UpperLimitPrice   domain.Money          `json:"upper_limit_price,omitempty"`
	LowerTriggerValue float64              `json:"lower_trigger_value,omitempty"`
	LowerQuantity     float64              `json:"lower_quantity,omitempty"`
	LowerLimitPrice   domain.Money          `json:"lower_limit_price,omitempty"`
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

// --- Telegram commands ---

// SetupTelegramCommand requests registering a user's Telegram chat ID.
type SetupTelegramCommand struct {
	Email  string `json:"email"`
	ChatID int64  `json:"chat_id"`
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

// --- Position commands ---

// ConvertPositionCommand requests converting a position from one product to another.
type ConvertPositionCommand struct {
	Email           string `json:"email"`
	Exchange        string `json:"exchange"`
	Tradingsymbol   string `json:"tradingsymbol"`
	TransactionType string `json:"transaction_type"`
	Quantity        int    `json:"quantity"`
	OldProduct      string `json:"old_product"`
	NewProduct      string `json:"new_product"`
	PositionType    string `json:"position_type"` // "day" or "overnight"
}

// --- Mutual Fund commands ---

// PlaceMFOrderCommand requests placing a mutual fund order.
type PlaceMFOrderCommand struct {
	Email           string  `json:"email"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	TransactionType string  `json:"transaction_type"`
	Amount          float64 `json:"amount,omitempty"`
	Quantity        float64 `json:"quantity,omitempty"`
	Tag             string  `json:"tag,omitempty"`
}

// CancelMFOrderCommand requests cancelling a mutual fund order.
type CancelMFOrderCommand struct {
	Email   string `json:"email"`
	OrderID string `json:"order_id"`
}

// PlaceMFSIPCommand requests placing a mutual fund SIP.
type PlaceMFSIPCommand struct {
	Email         string  `json:"email"`
	Tradingsymbol string  `json:"tradingsymbol"`
	Amount        float64 `json:"amount"`
	Frequency     string  `json:"frequency"`
	Instalments   int     `json:"instalments"`
	InitialAmount float64 `json:"initial_amount,omitempty"`
	InstalmentDay int     `json:"instalment_day,omitempty"`
	Tag           string  `json:"tag,omitempty"`
}

// CancelMFSIPCommand requests cancelling a mutual fund SIP.
type CancelMFSIPCommand struct {
	Email string `json:"email"`
	SIPID string `json:"sip_id"`
}

// --- Watchlist commands ---

// CreateWatchlistCommand requests creating a new named watchlist.
type CreateWatchlistCommand struct {
	Email string `json:"email"`
	Name  string `json:"name"`
}

// AddToWatchlistCommand requests adding an instrument to a watchlist.
type AddToWatchlistCommand struct {
	Email           string  `json:"email"`
	WatchlistID     string  `json:"watchlist_id"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	InstrumentToken uint32  `json:"instrument_token"`
	Notes           string  `json:"notes,omitempty"`
	TargetEntry     float64 `json:"target_entry,omitempty"`
	TargetExit      float64 `json:"target_exit,omitempty"`
}

// DeleteWatchlistCommand requests deleting a watchlist and all its items.
type DeleteWatchlistCommand struct {
	Email       string `json:"email"`
	WatchlistID string `json:"watchlist_id"`
}

// RemoveFromWatchlistCommand requests removing an instrument from a watchlist.
type RemoveFromWatchlistCommand struct {
	Email       string `json:"email"`
	WatchlistID string `json:"watchlist_id"`
	ItemID      string `json:"item_id"`
}

// --- Paper trading commands ---

// PaperTradingToggleCommand requests enabling or disabling paper trading.
type PaperTradingToggleCommand struct {
	Email       string  `json:"email"`
	Enable      bool    `json:"enable"`
	InitialCash float64 `json:"initial_cash,omitempty"`
}

// PaperTradingResetCommand requests resetting the virtual portfolio.
type PaperTradingResetCommand struct {
	Email string `json:"email"`
}

// --- Trailing stop commands ---

// SetTrailingStopCommand requests creating a trailing stop-loss.
type SetTrailingStopCommand struct {
	Email           string  `json:"email"`
	Exchange        string  `json:"exchange"`
	Tradingsymbol   string  `json:"tradingsymbol"`
	InstrumentToken uint32  `json:"instrument_token"`
	OrderID         string  `json:"order_id"`
	Variety         string  `json:"variety"`
	Direction       string  `json:"direction"`
	TrailAmount     float64 `json:"trail_amount,omitempty"`
	TrailPct        float64 `json:"trail_pct,omitempty"`
	CurrentStop     float64 `json:"current_stop"`
	ReferencePrice  float64 `json:"reference_price"`
}

// CancelTrailingStopCommand requests cancelling a trailing stop.
type CancelTrailingStopCommand struct {
	Email          string `json:"email"`
	TrailingStopID string `json:"trailing_stop_id"`
}

// --- Native alert commands ---

// PlaceNativeAlertCommand requests creating a server-side alert at Zerodha.
type PlaceNativeAlertCommand struct {
	Email  string `json:"email"`
	Params any    `json:"params"` // kiteconnect.AlertParams
}

// ModifyNativeAlertCommand requests modifying a native alert.
type ModifyNativeAlertCommand struct {
	Email  string `json:"email"`
	UUID   string `json:"uuid"`
	Params any    `json:"params"` // kiteconnect.AlertParams
}

// DeleteNativeAlertCommand requests deleting native alert(s).
type DeleteNativeAlertCommand struct {
	Email string   `json:"email"`
	UUIDs []string `json:"uuids"`
}

// --- Ticker commands ---

// StartTickerCommand requests starting a WebSocket ticker.
type StartTickerCommand struct {
	Email       string `json:"email"`
	APIKey      string `json:"api_key"`
	AccessToken string `json:"access_token"`
}

// StopTickerCommand requests stopping a WebSocket ticker.
type StopTickerCommand struct {
	Email string `json:"email"`
}

// SubscribeInstrumentsCommand requests subscribing to live tick data.
type SubscribeInstrumentsCommand struct {
	Email  string   `json:"email"`
	Tokens []uint32 `json:"tokens"`
	Mode   string   `json:"mode"` // "ltp", "quote", "full"
}

// UnsubscribeInstrumentsCommand requests removing instrument subscriptions.
type UnsubscribeInstrumentsCommand struct {
	Email  string   `json:"email"`
	Tokens []uint32 `json:"tokens"`
}

// --- Admin commands ---

// AdminSuspendUserCommand requests suspending a user account.
type AdminSuspendUserCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
	Reason      string `json:"reason"`
}

// AdminActivateUserCommand requests reactivating a user account.
type AdminActivateUserCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
}

// AdminChangeRoleCommand requests changing a user's role.
type AdminChangeRoleCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
	NewRole     string `json:"new_role"`
}

// AdminFreezeUserCommand requests freezing a user's trading.
type AdminFreezeUserCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
	Reason      string `json:"reason"`
}

// AdminUnfreezeUserCommand requests unfreezing a user's trading.
type AdminUnfreezeUserCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
}

// AdminFreezeGlobalCommand requests freezing all trading globally.
type AdminFreezeGlobalCommand struct {
	AdminEmail string `json:"admin_email"`
	Reason     string `json:"reason"`
}

// AdminUnfreezeGlobalCommand requests unfreezing global trading.
type AdminUnfreezeGlobalCommand struct {
	AdminEmail string `json:"admin_email"`
}

// --- Family commands ---

// AdminInviteFamilyMemberCommand requests inviting a family member to share
// an admin's billing plan. The invited user inherits the admin's tier.
type AdminInviteFamilyMemberCommand struct {
	AdminEmail   string `json:"admin_email"`
	InvitedEmail string `json:"invited_email"`
}

// AdminRemoveFamilyMemberCommand requests unlinking a family member from
// the admin's billing plan. The member loses inherited tier access.
type AdminRemoveFamilyMemberCommand struct {
	AdminEmail  string `json:"admin_email"`
	TargetEmail string `json:"target_email"`
}

// --- Setup commands ---

// LoginCommand requests generating a Kite login URL for the user.
type LoginCommand struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key,omitempty"`
	APISecret string `json:"api_secret,omitempty"`
}

// --- Account commands ---

// DeleteMyAccountCommand requests deleting the authenticated user's account.
type DeleteMyAccountCommand struct {
	Email string `json:"email"`
}

// UpdateMyCredentialsCommand requests updating the user's Kite credentials.
type UpdateMyCredentialsCommand struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}
