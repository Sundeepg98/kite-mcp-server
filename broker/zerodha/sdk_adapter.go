// Package zerodha — kiteSDKAdapter
//
// kiteSDKAdapter is a thin pass-through around *kiteconnect.Client that
// satisfies the KiteSDK interface via explicit delegation. The real
// *kiteconnect.Client already satisfies KiteSDK structurally (see
// sdk_interface.go), so this adapter exists to:
//
//  1. Give us a concrete seam where future instrumentation (logging,
//     metrics, retries, context cancellation) can attach without
//     touching every call site.
//  2. Provide an explicit construction point for phases 2-4 of the
//     hexagonal migration, where the Factory will build this adapter
//     rather than returning the raw SDK client.
//
// Phase 1 is additive only. Nothing in client.go or factory.go yet
// consumes this adapter.
package zerodha

import (
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// kiteSDKAdapter wraps a real *kiteconnect.Client and delegates every
// KiteSDK method to it. The indirection is intentional: it isolates the
// rest of the broker package from the concrete SDK type.
type kiteSDKAdapter struct {
	kc *kiteconnect.Client
}

// compile-time proof that *kiteSDKAdapter satisfies KiteSDK.
var _ KiteSDK = (*kiteSDKAdapter)(nil)

// newKiteSDKAdapter wraps an existing *kiteconnect.Client.
func newKiteSDKAdapter(kc *kiteconnect.Client) *kiteSDKAdapter {
	return &kiteSDKAdapter{kc: kc}
}

// defaultKiteSDKConstructor is the production SDK constructor used by
// Factory and Auth when no override is supplied. It builds a fresh
// *kiteconnect.Client and wraps it in *kiteSDKAdapter so the rest of
// the package can depend on the KiteSDK interface.
//
// Tests override this via WithSDKConstructor to inject a fake SDK
// without touching network code.
func defaultKiteSDKConstructor(apiKey string) KiteSDK {
	return newKiteSDKAdapter(kiteconnect.New(apiKey))
}

// newClientFromSDK builds a broker.Client from a KiteSDK instance.
//
// Phase 2 transitional helper: Client still stores *kiteconnect.Client
// internally (Phase 3 swaps this to KiteSDK). For now we unwrap the
// real adapter to recover the concrete SDK pointer. Test doubles that
// aren't *kiteSDKAdapter fall through to a nil-kite Client — which is
// fine because Phase 2 tests only assert the constructor is CALLED
// with the right apiKey; they don't exercise broker.Client methods.
//
// This unwrap branch goes away in Phase 3 when Client.kite becomes
// KiteSDK.
func newClientFromSDK(sdk KiteSDK) *Client {
	if adapter, ok := sdk.(*kiteSDKAdapter); ok {
		return New(adapter.kc)
	}
	// Fake SDK path — Client will have nil kite and cannot make
	// network calls, but Phase 2 tests don't need it to.
	return &Client{kite: nil}
}

// --- connect / auth lifecycle ---

func (a *kiteSDKAdapter) SetAccessToken(accessToken string) {
	a.kc.SetAccessToken(accessToken)
}

func (a *kiteSDKAdapter) GetLoginURL() string {
	return a.kc.GetLoginURL()
}

func (a *kiteSDKAdapter) GenerateSession(requestToken string, apiSecret string) (kiteconnect.UserSession, error) {
	return a.kc.GenerateSession(requestToken, apiSecret)
}

func (a *kiteSDKAdapter) InvalidateAccessToken() (bool, error) {
	return a.kc.InvalidateAccessToken()
}

// --- user / portfolio ---

func (a *kiteSDKAdapter) GetUserProfile() (kiteconnect.UserProfile, error) {
	return a.kc.GetUserProfile()
}

func (a *kiteSDKAdapter) GetUserMargins() (kiteconnect.AllMargins, error) {
	return a.kc.GetUserMargins()
}

func (a *kiteSDKAdapter) GetHoldings() (kiteconnect.Holdings, error) {
	return a.kc.GetHoldings()
}

func (a *kiteSDKAdapter) GetPositions() (kiteconnect.Positions, error) {
	return a.kc.GetPositions()
}

func (a *kiteSDKAdapter) ConvertPosition(params kiteconnect.ConvertPositionParams) (bool, error) {
	return a.kc.ConvertPosition(params)
}

// --- orders ---

func (a *kiteSDKAdapter) GetOrders() (kiteconnect.Orders, error) {
	return a.kc.GetOrders()
}

func (a *kiteSDKAdapter) GetOrderHistory(orderID string) ([]kiteconnect.Order, error) {
	return a.kc.GetOrderHistory(orderID)
}

func (a *kiteSDKAdapter) GetTrades() (kiteconnect.Trades, error) {
	return a.kc.GetTrades()
}

func (a *kiteSDKAdapter) GetOrderTrades(orderID string) ([]kiteconnect.Trade, error) {
	return a.kc.GetOrderTrades(orderID)
}

func (a *kiteSDKAdapter) PlaceOrder(variety string, orderParams kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
	return a.kc.PlaceOrder(variety, orderParams)
}

func (a *kiteSDKAdapter) ModifyOrder(variety string, orderID string, orderParams kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
	return a.kc.ModifyOrder(variety, orderID, orderParams)
}

func (a *kiteSDKAdapter) CancelOrder(variety string, orderID string, parentOrderID *string) (kiteconnect.OrderResponse, error) {
	return a.kc.CancelOrder(variety, orderID, parentOrderID)
}

// --- market data ---

func (a *kiteSDKAdapter) GetLTP(instruments ...string) (kiteconnect.QuoteLTP, error) {
	return a.kc.GetLTP(instruments...)
}

func (a *kiteSDKAdapter) GetOHLC(instruments ...string) (kiteconnect.QuoteOHLC, error) {
	return a.kc.GetOHLC(instruments...)
}

func (a *kiteSDKAdapter) GetQuote(instruments ...string) (kiteconnect.Quote, error) {
	return a.kc.GetQuote(instruments...)
}

func (a *kiteSDKAdapter) GetHistoricalData(instrumentToken int, interval string, fromDate time.Time, toDate time.Time, continuous bool, OI bool) ([]kiteconnect.HistoricalData, error) {
	return a.kc.GetHistoricalData(instrumentToken, interval, fromDate, toDate, continuous, OI)
}

// --- GTT ---

func (a *kiteSDKAdapter) GetGTTs() (kiteconnect.GTTs, error) {
	return a.kc.GetGTTs()
}

func (a *kiteSDKAdapter) PlaceGTT(o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error) {
	return a.kc.PlaceGTT(o)
}

func (a *kiteSDKAdapter) ModifyGTT(triggerID int, o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error) {
	return a.kc.ModifyGTT(triggerID, o)
}

func (a *kiteSDKAdapter) DeleteGTT(triggerID int) (kiteconnect.GTTResponse, error) {
	return a.kc.DeleteGTT(triggerID)
}

// --- mutual funds ---

func (a *kiteSDKAdapter) GetMFOrders() (kiteconnect.MFOrders, error) {
	return a.kc.GetMFOrders()
}

func (a *kiteSDKAdapter) GetMFSIPs() (kiteconnect.MFSIPs, error) {
	return a.kc.GetMFSIPs()
}

func (a *kiteSDKAdapter) GetMFHoldings() (kiteconnect.MFHoldings, error) {
	return a.kc.GetMFHoldings()
}

func (a *kiteSDKAdapter) PlaceMFOrder(orderParams kiteconnect.MFOrderParams) (kiteconnect.MFOrderResponse, error) {
	return a.kc.PlaceMFOrder(orderParams)
}

func (a *kiteSDKAdapter) CancelMFOrder(orderID string) (kiteconnect.MFOrderResponse, error) {
	return a.kc.CancelMFOrder(orderID)
}

func (a *kiteSDKAdapter) PlaceMFSIP(sipParams kiteconnect.MFSIPParams) (kiteconnect.MFSIPResponse, error) {
	return a.kc.PlaceMFSIP(sipParams)
}

func (a *kiteSDKAdapter) CancelMFSIP(sipID string) (kiteconnect.MFSIPResponse, error) {
	return a.kc.CancelMFSIP(sipID)
}

// --- margin calculation ---

func (a *kiteSDKAdapter) GetOrderMargins(marparam kiteconnect.GetMarginParams) ([]kiteconnect.OrderMargins, error) {
	return a.kc.GetOrderMargins(marparam)
}

func (a *kiteSDKAdapter) GetBasketMargins(baskparam kiteconnect.GetBasketParams) (kiteconnect.BasketMargins, error) {
	return a.kc.GetBasketMargins(baskparam)
}

func (a *kiteSDKAdapter) GetOrderCharges(chargeParam kiteconnect.GetChargesParams) ([]kiteconnect.OrderCharges, error) {
	return a.kc.GetOrderCharges(chargeParam)
}

// --- native server-side alerts ---

func (a *kiteSDKAdapter) CreateAlert(params kiteconnect.AlertParams) (kiteconnect.Alert, error) {
	return a.kc.CreateAlert(params)
}

func (a *kiteSDKAdapter) GetAlerts(filters map[string]string) ([]kiteconnect.Alert, error) {
	return a.kc.GetAlerts(filters)
}

func (a *kiteSDKAdapter) ModifyAlert(uuid string, params kiteconnect.AlertParams) (kiteconnect.Alert, error) {
	return a.kc.ModifyAlert(uuid, params)
}

func (a *kiteSDKAdapter) DeleteAlerts(uuids ...string) error {
	return a.kc.DeleteAlerts(uuids...)
}

func (a *kiteSDKAdapter) GetAlertHistory(uuid string) ([]kiteconnect.AlertHistory, error) {
	return a.kc.GetAlertHistory(uuid)
}
