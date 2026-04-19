// Package zerodha — KiteSDK interface
//
// KiteSDK is the minimal surface of gokiteconnect/v4 that our broker
// implementation actually calls in production. Defining it here lets tests
// substitute a fake without touching real HTTP. The method set was derived
// by surveying every c.kite.X and kc.X call site in broker/zerodha/ (see
// .research/hexagonal-surface-survey.md for the raw counts).
//
// This file is purely additive in Phase 1. client.go and factory.go still
// hold *kiteconnect.Client directly; subsequent phases swap them over to
// this interface.
package zerodha

import (
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// KiteSDK is the minimal surface of gokiteconnect/v4 that the Zerodha broker
// adapter depends on. Only methods with a real production call site are
// listed — no speculative additions.
type KiteSDK interface {
	// --- connect / auth lifecycle ---
	SetAccessToken(accessToken string)
	SetBaseURI(baseURI string)
	GetLoginURL() string
	GenerateSession(requestToken string, apiSecret string) (kiteconnect.UserSession, error)
	InvalidateAccessToken() (bool, error)

	// --- user / portfolio ---
	GetUserProfile() (kiteconnect.UserProfile, error)
	GetUserMargins() (kiteconnect.AllMargins, error)
	GetHoldings() (kiteconnect.Holdings, error)
	GetPositions() (kiteconnect.Positions, error)
	ConvertPosition(params kiteconnect.ConvertPositionParams) (bool, error)

	// --- orders ---
	GetOrders() (kiteconnect.Orders, error)
	GetOrderHistory(orderID string) ([]kiteconnect.Order, error)
	GetTrades() (kiteconnect.Trades, error)
	GetOrderTrades(orderID string) ([]kiteconnect.Trade, error)
	PlaceOrder(variety string, orderParams kiteconnect.OrderParams) (kiteconnect.OrderResponse, error)
	ModifyOrder(variety string, orderID string, orderParams kiteconnect.OrderParams) (kiteconnect.OrderResponse, error)
	CancelOrder(variety string, orderID string, parentOrderID *string) (kiteconnect.OrderResponse, error)

	// --- market data ---
	GetLTP(instruments ...string) (kiteconnect.QuoteLTP, error)
	GetOHLC(instruments ...string) (kiteconnect.QuoteOHLC, error)
	GetQuote(instruments ...string) (kiteconnect.Quote, error)
	GetHistoricalData(instrumentToken int, interval string, fromDate time.Time, toDate time.Time, continuous bool, OI bool) ([]kiteconnect.HistoricalData, error)

	// --- GTT ---
	GetGTTs() (kiteconnect.GTTs, error)
	PlaceGTT(o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error)
	ModifyGTT(triggerID int, o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error)
	DeleteGTT(triggerID int) (kiteconnect.GTTResponse, error)

	// --- mutual funds ---
	GetMFOrders() (kiteconnect.MFOrders, error)
	GetMFSIPs() (kiteconnect.MFSIPs, error)
	GetMFHoldings() (kiteconnect.MFHoldings, error)
	PlaceMFOrder(orderParams kiteconnect.MFOrderParams) (kiteconnect.MFOrderResponse, error)
	CancelMFOrder(orderID string) (kiteconnect.MFOrderResponse, error)
	PlaceMFSIP(sipParams kiteconnect.MFSIPParams) (kiteconnect.MFSIPResponse, error)
	CancelMFSIP(sipID string) (kiteconnect.MFSIPResponse, error)

	// --- margin calculation ---
	GetOrderMargins(marparam kiteconnect.GetMarginParams) ([]kiteconnect.OrderMargins, error)
	GetBasketMargins(baskparam kiteconnect.GetBasketParams) (kiteconnect.BasketMargins, error)
	GetOrderCharges(chargeParam kiteconnect.GetChargesParams) ([]kiteconnect.OrderCharges, error)

	// --- native server-side alerts ---
	CreateAlert(params kiteconnect.AlertParams) (kiteconnect.Alert, error)
	GetAlerts(filters map[string]string) ([]kiteconnect.Alert, error)
	ModifyAlert(uuid string, params kiteconnect.AlertParams) (kiteconnect.Alert, error)
	DeleteAlerts(uuids ...string) error
	GetAlertHistory(uuid string) ([]kiteconnect.AlertHistory, error)
}

// compile-time proof that the real *kiteconnect.Client satisfies KiteSDK.
// If gokiteconnect ever changes a signature, this will refuse to build.
var _ KiteSDK = (*kiteconnect.Client)(nil)
