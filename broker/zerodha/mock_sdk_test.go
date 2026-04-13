package zerodha

import (
	"sync"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

// MockKiteSDK is a configurable, call-recording stand-in for KiteSDK.
// Each method reads an optional *Func override; when the override is
// nil, the method returns a zero value and records the call. Tests
// can program specific behavior per call-site without stubbing every
// method.
//
// Concurrency: the call log and counters are protected by a mutex so
// parallel-running tests using a shared mock don't race.
//
// Phase 4 of the hexagonal refactor uses this mock to exercise every
// broker.Client code path (including error + retry branches) without
// touching HTTP. It replaces the Phase 2 fakeKiteSDK for richer tests.
type MockKiteSDK struct {
	mu sync.Mutex

	// --- connect / auth lifecycle ---
	SetAccessTokenFunc       func(accessToken string)
	GetLoginURLFunc          func() string
	GenerateSessionFunc      func(requestToken, apiSecret string) (kiteconnect.UserSession, error)
	InvalidateAccessTokenFunc func() (bool, error)

	// --- user / portfolio ---
	GetUserProfileFunc  func() (kiteconnect.UserProfile, error)
	GetUserMarginsFunc  func() (kiteconnect.AllMargins, error)
	GetHoldingsFunc     func() (kiteconnect.Holdings, error)
	GetPositionsFunc    func() (kiteconnect.Positions, error)
	ConvertPositionFunc func(params kiteconnect.ConvertPositionParams) (bool, error)

	// --- orders ---
	GetOrdersFunc       func() (kiteconnect.Orders, error)
	GetOrderHistoryFunc func(orderID string) ([]kiteconnect.Order, error)
	GetTradesFunc       func() (kiteconnect.Trades, error)
	GetOrderTradesFunc  func(orderID string) ([]kiteconnect.Trade, error)
	PlaceOrderFunc      func(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error)
	ModifyOrderFunc     func(variety, orderID string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error)
	CancelOrderFunc     func(variety, orderID string, parent *string) (kiteconnect.OrderResponse, error)

	// --- market data ---
	GetLTPFunc            func(instruments ...string) (kiteconnect.QuoteLTP, error)
	GetOHLCFunc           func(instruments ...string) (kiteconnect.QuoteOHLC, error)
	GetQuoteFunc          func(instruments ...string) (kiteconnect.Quote, error)
	GetHistoricalDataFunc func(token int, interval string, from, to time.Time, continuous, OI bool) ([]kiteconnect.HistoricalData, error)

	// --- GTT ---
	GetGTTsFunc   func() (kiteconnect.GTTs, error)
	PlaceGTTFunc  func(o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error)
	ModifyGTTFunc func(triggerID int, o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error)
	DeleteGTTFunc func(triggerID int) (kiteconnect.GTTResponse, error)

	// --- mutual funds ---
	GetMFOrdersFunc   func() (kiteconnect.MFOrders, error)
	GetMFSIPsFunc     func() (kiteconnect.MFSIPs, error)
	GetMFHoldingsFunc func() (kiteconnect.MFHoldings, error)
	PlaceMFOrderFunc  func(p kiteconnect.MFOrderParams) (kiteconnect.MFOrderResponse, error)
	CancelMFOrderFunc func(orderID string) (kiteconnect.MFOrderResponse, error)
	PlaceMFSIPFunc    func(p kiteconnect.MFSIPParams) (kiteconnect.MFSIPResponse, error)
	CancelMFSIPFunc   func(sipID string) (kiteconnect.MFSIPResponse, error)

	// --- margin calculation ---
	GetOrderMarginsFunc  func(p kiteconnect.GetMarginParams) ([]kiteconnect.OrderMargins, error)
	GetBasketMarginsFunc func(p kiteconnect.GetBasketParams) (kiteconnect.BasketMargins, error)
	GetOrderChargesFunc  func(p kiteconnect.GetChargesParams) ([]kiteconnect.OrderCharges, error)

	// --- native alerts ---
	CreateAlertFunc     func(p kiteconnect.AlertParams) (kiteconnect.Alert, error)
	GetAlertsFunc       func(filters map[string]string) ([]kiteconnect.Alert, error)
	ModifyAlertFunc     func(uuid string, p kiteconnect.AlertParams) (kiteconnect.Alert, error)
	DeleteAlertsFunc    func(uuids ...string) error
	GetAlertHistoryFunc func(uuid string) ([]kiteconnect.AlertHistory, error)

	// CallLog records the method name of every invocation in order.
	// Tests use it to assert wiring (e.g. retry actually called twice).
	CallLog []string
}

// compile-time proof that *MockKiteSDK satisfies KiteSDK.
var _ KiteSDK = (*MockKiteSDK)(nil)

// NewMockKiteSDK returns a fresh mock with empty call log.
func NewMockKiteSDK() *MockKiteSDK {
	return &MockKiteSDK{}
}

// Calls returns a snapshot of the call log.
func (m *MockKiteSDK) Calls() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]string, len(m.CallLog))
	copy(out, m.CallLog)
	return out
}

// CallCount returns the number of times a specific method was called.
func (m *MockKiteSDK) CallCount(method string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := 0
	for _, c := range m.CallLog {
		if c == method {
			n++
		}
	}
	return n
}

func (m *MockKiteSDK) record(method string) {
	m.mu.Lock()
	m.CallLog = append(m.CallLog, method)
	m.mu.Unlock()
}

// --- connect / auth lifecycle ---

func (m *MockKiteSDK) SetAccessToken(accessToken string) {
	m.record("SetAccessToken")
	if m.SetAccessTokenFunc != nil {
		m.SetAccessTokenFunc(accessToken)
	}
}

func (m *MockKiteSDK) GetLoginURL() string {
	m.record("GetLoginURL")
	if m.GetLoginURLFunc != nil {
		return m.GetLoginURLFunc()
	}
	return ""
}

func (m *MockKiteSDK) GenerateSession(requestToken, apiSecret string) (kiteconnect.UserSession, error) {
	m.record("GenerateSession")
	if m.GenerateSessionFunc != nil {
		return m.GenerateSessionFunc(requestToken, apiSecret)
	}
	return kiteconnect.UserSession{}, nil
}

func (m *MockKiteSDK) InvalidateAccessToken() (bool, error) {
	m.record("InvalidateAccessToken")
	if m.InvalidateAccessTokenFunc != nil {
		return m.InvalidateAccessTokenFunc()
	}
	return true, nil
}

// --- user / portfolio ---

func (m *MockKiteSDK) GetUserProfile() (kiteconnect.UserProfile, error) {
	m.record("GetUserProfile")
	if m.GetUserProfileFunc != nil {
		return m.GetUserProfileFunc()
	}
	return kiteconnect.UserProfile{}, nil
}

func (m *MockKiteSDK) GetUserMargins() (kiteconnect.AllMargins, error) {
	m.record("GetUserMargins")
	if m.GetUserMarginsFunc != nil {
		return m.GetUserMarginsFunc()
	}
	return kiteconnect.AllMargins{}, nil
}

func (m *MockKiteSDK) GetHoldings() (kiteconnect.Holdings, error) {
	m.record("GetHoldings")
	if m.GetHoldingsFunc != nil {
		return m.GetHoldingsFunc()
	}
	return kiteconnect.Holdings{}, nil
}

func (m *MockKiteSDK) GetPositions() (kiteconnect.Positions, error) {
	m.record("GetPositions")
	if m.GetPositionsFunc != nil {
		return m.GetPositionsFunc()
	}
	return kiteconnect.Positions{}, nil
}

func (m *MockKiteSDK) ConvertPosition(params kiteconnect.ConvertPositionParams) (bool, error) {
	m.record("ConvertPosition")
	if m.ConvertPositionFunc != nil {
		return m.ConvertPositionFunc(params)
	}
	return true, nil
}

// --- orders ---

func (m *MockKiteSDK) GetOrders() (kiteconnect.Orders, error) {
	m.record("GetOrders")
	if m.GetOrdersFunc != nil {
		return m.GetOrdersFunc()
	}
	return kiteconnect.Orders{}, nil
}

func (m *MockKiteSDK) GetOrderHistory(orderID string) ([]kiteconnect.Order, error) {
	m.record("GetOrderHistory")
	if m.GetOrderHistoryFunc != nil {
		return m.GetOrderHistoryFunc(orderID)
	}
	return nil, nil
}

func (m *MockKiteSDK) GetTrades() (kiteconnect.Trades, error) {
	m.record("GetTrades")
	if m.GetTradesFunc != nil {
		return m.GetTradesFunc()
	}
	return kiteconnect.Trades{}, nil
}

func (m *MockKiteSDK) GetOrderTrades(orderID string) ([]kiteconnect.Trade, error) {
	m.record("GetOrderTrades")
	if m.GetOrderTradesFunc != nil {
		return m.GetOrderTradesFunc(orderID)
	}
	return nil, nil
}

func (m *MockKiteSDK) PlaceOrder(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
	m.record("PlaceOrder")
	if m.PlaceOrderFunc != nil {
		return m.PlaceOrderFunc(variety, p)
	}
	return kiteconnect.OrderResponse{}, nil
}

func (m *MockKiteSDK) ModifyOrder(variety, orderID string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
	m.record("ModifyOrder")
	if m.ModifyOrderFunc != nil {
		return m.ModifyOrderFunc(variety, orderID, p)
	}
	return kiteconnect.OrderResponse{}, nil
}

func (m *MockKiteSDK) CancelOrder(variety, orderID string, parent *string) (kiteconnect.OrderResponse, error) {
	m.record("CancelOrder")
	if m.CancelOrderFunc != nil {
		return m.CancelOrderFunc(variety, orderID, parent)
	}
	return kiteconnect.OrderResponse{}, nil
}

// --- market data ---

func (m *MockKiteSDK) GetLTP(instruments ...string) (kiteconnect.QuoteLTP, error) {
	m.record("GetLTP")
	if m.GetLTPFunc != nil {
		return m.GetLTPFunc(instruments...)
	}
	return kiteconnect.QuoteLTP{}, nil
}

func (m *MockKiteSDK) GetOHLC(instruments ...string) (kiteconnect.QuoteOHLC, error) {
	m.record("GetOHLC")
	if m.GetOHLCFunc != nil {
		return m.GetOHLCFunc(instruments...)
	}
	return kiteconnect.QuoteOHLC{}, nil
}

func (m *MockKiteSDK) GetQuote(instruments ...string) (kiteconnect.Quote, error) {
	m.record("GetQuote")
	if m.GetQuoteFunc != nil {
		return m.GetQuoteFunc(instruments...)
	}
	return kiteconnect.Quote{}, nil
}

func (m *MockKiteSDK) GetHistoricalData(token int, interval string, from, to time.Time, continuous, OI bool) ([]kiteconnect.HistoricalData, error) {
	m.record("GetHistoricalData")
	if m.GetHistoricalDataFunc != nil {
		return m.GetHistoricalDataFunc(token, interval, from, to, continuous, OI)
	}
	return nil, nil
}

// --- GTT ---

func (m *MockKiteSDK) GetGTTs() (kiteconnect.GTTs, error) {
	m.record("GetGTTs")
	if m.GetGTTsFunc != nil {
		return m.GetGTTsFunc()
	}
	return kiteconnect.GTTs{}, nil
}

func (m *MockKiteSDK) PlaceGTT(o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error) {
	m.record("PlaceGTT")
	if m.PlaceGTTFunc != nil {
		return m.PlaceGTTFunc(o)
	}
	return kiteconnect.GTTResponse{}, nil
}

func (m *MockKiteSDK) ModifyGTT(triggerID int, o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error) {
	m.record("ModifyGTT")
	if m.ModifyGTTFunc != nil {
		return m.ModifyGTTFunc(triggerID, o)
	}
	return kiteconnect.GTTResponse{}, nil
}

func (m *MockKiteSDK) DeleteGTT(triggerID int) (kiteconnect.GTTResponse, error) {
	m.record("DeleteGTT")
	if m.DeleteGTTFunc != nil {
		return m.DeleteGTTFunc(triggerID)
	}
	return kiteconnect.GTTResponse{}, nil
}

// --- mutual funds ---

func (m *MockKiteSDK) GetMFOrders() (kiteconnect.MFOrders, error) {
	m.record("GetMFOrders")
	if m.GetMFOrdersFunc != nil {
		return m.GetMFOrdersFunc()
	}
	return kiteconnect.MFOrders{}, nil
}

func (m *MockKiteSDK) GetMFSIPs() (kiteconnect.MFSIPs, error) {
	m.record("GetMFSIPs")
	if m.GetMFSIPsFunc != nil {
		return m.GetMFSIPsFunc()
	}
	return kiteconnect.MFSIPs{}, nil
}

func (m *MockKiteSDK) GetMFHoldings() (kiteconnect.MFHoldings, error) {
	m.record("GetMFHoldings")
	if m.GetMFHoldingsFunc != nil {
		return m.GetMFHoldingsFunc()
	}
	return kiteconnect.MFHoldings{}, nil
}

func (m *MockKiteSDK) PlaceMFOrder(p kiteconnect.MFOrderParams) (kiteconnect.MFOrderResponse, error) {
	m.record("PlaceMFOrder")
	if m.PlaceMFOrderFunc != nil {
		return m.PlaceMFOrderFunc(p)
	}
	return kiteconnect.MFOrderResponse{}, nil
}

func (m *MockKiteSDK) CancelMFOrder(orderID string) (kiteconnect.MFOrderResponse, error) {
	m.record("CancelMFOrder")
	if m.CancelMFOrderFunc != nil {
		return m.CancelMFOrderFunc(orderID)
	}
	return kiteconnect.MFOrderResponse{}, nil
}

func (m *MockKiteSDK) PlaceMFSIP(p kiteconnect.MFSIPParams) (kiteconnect.MFSIPResponse, error) {
	m.record("PlaceMFSIP")
	if m.PlaceMFSIPFunc != nil {
		return m.PlaceMFSIPFunc(p)
	}
	return kiteconnect.MFSIPResponse{}, nil
}

func (m *MockKiteSDK) CancelMFSIP(sipID string) (kiteconnect.MFSIPResponse, error) {
	m.record("CancelMFSIP")
	if m.CancelMFSIPFunc != nil {
		return m.CancelMFSIPFunc(sipID)
	}
	return kiteconnect.MFSIPResponse{}, nil
}

// --- margin calculation ---

func (m *MockKiteSDK) GetOrderMargins(p kiteconnect.GetMarginParams) ([]kiteconnect.OrderMargins, error) {
	m.record("GetOrderMargins")
	if m.GetOrderMarginsFunc != nil {
		return m.GetOrderMarginsFunc(p)
	}
	return nil, nil
}

func (m *MockKiteSDK) GetBasketMargins(p kiteconnect.GetBasketParams) (kiteconnect.BasketMargins, error) {
	m.record("GetBasketMargins")
	if m.GetBasketMarginsFunc != nil {
		return m.GetBasketMarginsFunc(p)
	}
	return kiteconnect.BasketMargins{}, nil
}

func (m *MockKiteSDK) GetOrderCharges(p kiteconnect.GetChargesParams) ([]kiteconnect.OrderCharges, error) {
	m.record("GetOrderCharges")
	if m.GetOrderChargesFunc != nil {
		return m.GetOrderChargesFunc(p)
	}
	return nil, nil
}

// --- native alerts ---

func (m *MockKiteSDK) CreateAlert(p kiteconnect.AlertParams) (kiteconnect.Alert, error) {
	m.record("CreateAlert")
	if m.CreateAlertFunc != nil {
		return m.CreateAlertFunc(p)
	}
	return kiteconnect.Alert{}, nil
}

func (m *MockKiteSDK) GetAlerts(filters map[string]string) ([]kiteconnect.Alert, error) {
	m.record("GetAlerts")
	if m.GetAlertsFunc != nil {
		return m.GetAlertsFunc(filters)
	}
	return nil, nil
}

func (m *MockKiteSDK) ModifyAlert(uuid string, p kiteconnect.AlertParams) (kiteconnect.Alert, error) {
	m.record("ModifyAlert")
	if m.ModifyAlertFunc != nil {
		return m.ModifyAlertFunc(uuid, p)
	}
	return kiteconnect.Alert{}, nil
}

func (m *MockKiteSDK) DeleteAlerts(uuids ...string) error {
	m.record("DeleteAlerts")
	if m.DeleteAlertsFunc != nil {
		return m.DeleteAlertsFunc(uuids...)
	}
	return nil
}

func (m *MockKiteSDK) GetAlertHistory(uuid string) ([]kiteconnect.AlertHistory, error) {
	m.record("GetAlertHistory")
	if m.GetAlertHistoryFunc != nil {
		return m.GetAlertHistoryFunc(uuid)
	}
	return nil, nil
}
