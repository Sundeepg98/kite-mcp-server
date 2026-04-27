package zerodha

import (
	"errors"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// ---------------------------------------------------------------------------
// Phase 4 client tests — no HTTP, no flaky 429, no real Kite API.
//
// These tests exercise broker.Client via NewFromSDK(mock) so every code
// path is driven deterministically by MockKiteSDK function hooks. They
// cover ground that was previously impossible to test in isolation:
//   - network-error propagation from SDK to broker.Client
//   - retry behavior on transient errors (call-count assertions)
//   - field mapping from SDK response types into broker.* types
//   - error wrapping for non-transient errors
// ---------------------------------------------------------------------------

// --- Happy-path field mapping ---

func TestClientMock_GetProfile_MapsFields(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	mock.GetUserProfileFunc = func() (kiteconnect.UserProfile, error) {
		return kiteconnect.UserProfile{
			UserID:    "ZB9999",
			UserName:  "Mock User",
			Email:     "mock@example.com",
			Broker:    "ZERODHA",
			Exchanges: []string{"NSE", "BSE", "NFO"},
			Products:  []string{"CNC", "MIS", "NRML"},
		}, nil
	}
	c := NewFromSDK(mock)

	profile, err := c.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile: unexpected error: %v", err)
	}
	if profile.UserID != "ZB9999" {
		t.Errorf("UserID = %q, want ZB9999", profile.UserID)
	}
	if profile.UserName != "Mock User" {
		t.Errorf("UserName = %q, want Mock User", profile.UserName)
	}
	if profile.Email != "mock@example.com" {
		t.Errorf("Email = %q, want mock@example.com", profile.Email)
	}
	if profile.Broker != broker.Zerodha {
		t.Errorf("Broker = %q, want %q", profile.Broker, broker.Zerodha)
	}
	if len(profile.Exchanges) != 3 || profile.Exchanges[0] != "NSE" {
		t.Errorf("Exchanges = %v, want [NSE BSE NFO]", profile.Exchanges)
	}
	if mock.CallCount("GetUserProfile") != 1 {
		t.Errorf("expected exactly 1 GetUserProfile call, got %d", mock.CallCount("GetUserProfile"))
	}
}

func TestClientMock_GetHoldings_MapsFields(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	mock.GetHoldingsFunc = func() (kiteconnect.Holdings, error) {
		return kiteconnect.Holdings{
			{
				Tradingsymbol:      "RELIANCE",
				Exchange:           "NSE",
				ISIN:               "INE002A01018",
				Quantity:           10,
				AveragePrice:       2500.0,
				LastPrice:          2650.0,
				PnL:                1500.0,
				DayChangePercentage: 1.25,
				Product:            "CNC",
			},
			{
				Tradingsymbol: "TCS",
				Exchange:      "NSE",
				Quantity:      5,
				AveragePrice:  3200.0,
				LastPrice:     3400.0,
				Product:       "CNC",
			},
		}, nil
	}
	c := NewFromSDK(mock)

	holdings, err := c.GetHoldings()
	if err != nil {
		t.Fatalf("GetHoldings: unexpected error: %v", err)
	}
	if len(holdings) != 2 {
		t.Fatalf("want 2 holdings, got %d", len(holdings))
	}
	if holdings[0].Tradingsymbol != "RELIANCE" || holdings[0].Quantity != 10 {
		t.Errorf("holdings[0] = %+v", holdings[0])
	}
	if holdings[0].PnL.Float64() != 1500.0 {
		t.Errorf("holdings[0].PnL = %v, want 1500", holdings[0].PnL.Float64())
	}
	if holdings[1].Tradingsymbol != "TCS" {
		t.Errorf("holdings[1].Tradingsymbol = %q, want TCS", holdings[1].Tradingsymbol)
	}
}

func TestClientMock_PlaceOrder_MapsFieldsAndReturnsOrderID(t *testing.T) {
	t.Parallel()
	var capturedVariety string
	var capturedParams kiteconnect.OrderParams
	mock := NewMockKiteSDK()
	mock.PlaceOrderFunc = func(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
		capturedVariety = variety
		capturedParams = p
		return kiteconnect.OrderResponse{OrderID: "MOCK_ORD_42"}, nil
	}
	c := NewFromSDK(mock)

	resp, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Product:         "MIS",
		OrderType:       "LIMIT",
		Quantity:        5,
		Price:           1500.50,
		Variety:         "regular",
	})
	if err != nil {
		t.Fatalf("PlaceOrder: unexpected error: %v", err)
	}
	if resp.OrderID != "MOCK_ORD_42" {
		t.Errorf("OrderID = %q, want MOCK_ORD_42", resp.OrderID)
	}
	if capturedVariety != "regular" {
		t.Errorf("variety = %q, want 'regular'", capturedVariety)
	}
	if capturedParams.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want INFY", capturedParams.Tradingsymbol)
	}
	if capturedParams.Quantity != 5 {
		t.Errorf("Quantity = %v, want 5", capturedParams.Quantity)
	}
	if capturedParams.Price != 1500.50 {
		t.Errorf("Price = %v, want 1500.50", capturedParams.Price)
	}
	if mock.CallCount("PlaceOrder") != 1 {
		t.Errorf("expected 1 PlaceOrder call, got %d", mock.CallCount("PlaceOrder"))
	}
}

func TestClientMock_CancelOrder_UsesDefaultVarietyWhenEmpty(t *testing.T) {
	t.Parallel()
	var capturedVariety string
	mock := NewMockKiteSDK()
	mock.CancelOrderFunc = func(variety, orderID string, parent *string) (kiteconnect.OrderResponse, error) {
		capturedVariety = variety
		return kiteconnect.OrderResponse{OrderID: orderID}, nil
	}
	c := NewFromSDK(mock)

	_, err := c.CancelOrder("ORD123", "")
	if err != nil {
		t.Fatalf("CancelOrder: unexpected error: %v", err)
	}
	if capturedVariety != kiteconnect.VarietyRegular {
		t.Errorf("variety = %q, want VarietyRegular (%q)", capturedVariety, kiteconnect.VarietyRegular)
	}
}

// --- Error propagation (non-transient) ---

func TestClientMock_GetProfile_PropagatesNonTransientError(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	sdkErr := errors.New("TokenException: invalid api_key or access_token")
	mock.GetUserProfileFunc = func() (kiteconnect.UserProfile, error) {
		return kiteconnect.UserProfile{}, sdkErr
	}
	c := NewFromSDK(mock)

	_, err := c.GetProfile()
	if !errors.Is(err, sdkErr) {
		t.Errorf("expected wrapped SDK error, got: %v", err)
	}
	// Non-transient: retry logic must NOT loop.
	if got := mock.CallCount("GetUserProfile"); got != 1 {
		t.Errorf("non-transient error must not retry: got %d calls, want 1", got)
	}
}

func TestClientMock_PlaceOrder_PropagatesNonTransientError(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	sdkErr := errors.New("InputException: missing required field")
	mock.PlaceOrderFunc = func(variety string, p kiteconnect.OrderParams) (kiteconnect.OrderResponse, error) {
		return kiteconnect.OrderResponse{}, sdkErr
	}
	c := NewFromSDK(mock)

	_, err := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "SBIN",
		TransactionType: "BUY", OrderType: "MARKET", Quantity: 1,
	})
	if !errors.Is(err, sdkErr) {
		t.Errorf("expected wrapped SDK error, got: %v", err)
	}
	if got := mock.CallCount("PlaceOrder"); got != 1 {
		t.Errorf("non-transient error must not retry: got %d calls, want 1", got)
	}
}

// --- Retry behavior on transient errors ---

func TestClientMock_GetProfile_RetriesOnTransientThenSucceeds(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	attempts := 0
	mock.GetUserProfileFunc = func() (kiteconnect.UserProfile, error) {
		attempts++
		if attempts < 3 {
			return kiteconnect.UserProfile{}, errors.New("dial tcp: connection refused")
		}
		return kiteconnect.UserProfile{UserID: "RETRY_OK"}, nil
	}
	c := NewFromSDK(mock)

	start := time.Now()
	profile, err := c.GetProfile()
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("GetProfile: unexpected error after retries: %v", err)
	}
	if profile.UserID != "RETRY_OK" {
		t.Errorf("UserID = %q, want RETRY_OK", profile.UserID)
	}
	if got := mock.CallCount("GetUserProfile"); got != 3 {
		t.Errorf("expected 3 SDK calls (2 retries + success), got %d", got)
	}
	// retry.go uses 100ms * 2^i backoff: 100ms + 200ms = 300ms minimum
	if elapsed < 250*time.Millisecond {
		t.Errorf("elapsed = %v, expected at least 250ms from backoff", elapsed)
	}
}

func TestClientMock_GetOrders_RetriesExhaustedReturnsLastError(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	lastErr := errors.New("read: connection timeout")
	mock.GetOrdersFunc = func() (kiteconnect.Orders, error) {
		return nil, lastErr
	}
	c := NewFromSDK(mock)

	_, err := c.GetOrders()
	if !errors.Is(err, lastErr) {
		t.Errorf("expected wrapped last error, got: %v", err)
	}
	// retry.go: maxRetries=2 means 1 initial + 2 retries = 3 total calls
	if got := mock.CallCount("GetOrders"); got != 3 {
		t.Errorf("expected 3 SDK calls on exhausted retry, got %d", got)
	}
}

// --- Orders, trades, and market data ---

func TestClientMock_GetOrders_MapsOrderList(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	mock.GetOrdersFunc = func() (kiteconnect.Orders, error) {
		return kiteconnect.Orders{
			{
				OrderID:         "ORD1",
				Status:          "COMPLETE",
				Exchange:        "NSE",
				TradingSymbol:   "HDFC",
				TransactionType: "BUY",
				Quantity:        10,
				Price:           1600.0,
				AveragePrice:    1599.75,
				FilledQuantity:  10,
			},
			{
				OrderID:         "ORD2",
				Status:          "OPEN",
				Exchange:        "NSE",
				TradingSymbol:   "ICICIBANK",
				TransactionType: "SELL",
				Quantity:        20,
				Price:           950.0,
			},
		}, nil
	}
	c := NewFromSDK(mock)

	orders, err := c.GetOrders()
	if err != nil {
		t.Fatalf("GetOrders: unexpected error: %v", err)
	}
	if len(orders) != 2 {
		t.Fatalf("want 2 orders, got %d", len(orders))
	}
	if orders[0].OrderID != "ORD1" || orders[0].Status != "COMPLETE" {
		t.Errorf("orders[0] = %+v", orders[0])
	}
	if orders[1].TransactionType != "SELL" {
		t.Errorf("orders[1].TransactionType = %q, want SELL", orders[1].TransactionType)
	}
}

func TestClientMock_GetLTP_PassesInstrumentsThrough(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	var captured []string
	mock.GetLTPFunc = func(instruments ...string) (kiteconnect.QuoteLTP, error) {
		captured = append(captured, instruments...)
		return kiteconnect.QuoteLTP{
			"NSE:SBIN": {InstrumentToken: 779521, LastPrice: 650.5},
			"NSE:INFY": {InstrumentToken: 408065, LastPrice: 1550.75},
		}, nil
	}
	c := NewFromSDK(mock)

	ltp, err := c.GetLTP("NSE:SBIN", "NSE:INFY")
	if err != nil {
		t.Fatalf("GetLTP: unexpected error: %v", err)
	}
	if len(captured) != 2 || captured[0] != "NSE:SBIN" || captured[1] != "NSE:INFY" {
		t.Errorf("captured instruments = %v", captured)
	}
	if ltp["NSE:SBIN"].LastPrice != 650.5 {
		t.Errorf("SBIN LTP = %v, want 650.5", ltp["NSE:SBIN"].LastPrice)
	}
	if ltp["NSE:INFY"].LastPrice != 1550.75 {
		t.Errorf("INFY LTP = %v, want 1550.75", ltp["NSE:INFY"].LastPrice)
	}
}

// --- GTT (no retry wrapper — non-transient error bubbles straight) ---

func TestClientMock_PlaceGTT_HappyPath(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	var capturedParams kiteconnect.GTTParams
	mock.PlaceGTTFunc = func(o kiteconnect.GTTParams) (kiteconnect.GTTResponse, error) {
		capturedParams = o
		return kiteconnect.GTTResponse{TriggerID: 7788}, nil
	}
	c := NewFromSDK(mock)

	resp, err := c.PlaceGTT(broker.GTTParams{
		Type:            "single",
		Exchange:        "NSE",
		Tradingsymbol:   "SBIN",
		LastPrice:       650.0,
		TransactionType: "SELL",
		Product:         "CNC",
		TriggerValue:    700.0,
		Quantity:        10,
		LimitPrice:      702.0,
	})
	if err != nil {
		t.Fatalf("PlaceGTT: unexpected error: %v", err)
	}
	if resp.TriggerID != 7788 {
		t.Errorf("TriggerID = %d, want 7788", resp.TriggerID)
	}
	if capturedParams.Exchange != "NSE" {
		t.Errorf("captured Exchange = %q, want NSE", capturedParams.Exchange)
	}
	if capturedParams.Tradingsymbol != "SBIN" {
		t.Errorf("captured Tradingsymbol = %q, want SBIN", capturedParams.Tradingsymbol)
	}
}

func TestClientMock_DeleteGTT_PropagatesError(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	sdkErr := errors.New("NetworkException: gateway timeout")
	mock.DeleteGTTFunc = func(triggerID int) (kiteconnect.GTTResponse, error) {
		return kiteconnect.GTTResponse{}, sdkErr
	}
	c := NewFromSDK(mock)

	_, err := c.DeleteGTT(123)
	if !errors.Is(err, sdkErr) {
		t.Errorf("expected wrapped SDK error, got: %v", err)
	}
}

// --- Native alerts ---

func TestClientMock_CreateNativeAlert_HappyPath(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	mock.CreateAlertFunc = func(p kiteconnect.AlertParams) (kiteconnect.Alert, error) {
		return kiteconnect.Alert{
			UUID:   "alert-uuid-1",
			Name:   p.Name,
			Type:   p.Type,
			Status: kiteconnect.AlertStatusEnabled,
		}, nil
	}
	c := NewFromSDK(mock)

	alert, err := c.CreateNativeAlert(broker.NativeAlertParams{
		Name:             "SBIN above 700",
		Type:             "simple",
		Operator:         ">=",
		LHSExchange:      "NSE",
		LHSTradingSymbol: "SBIN",
		LHSAttribute:     "LastTradedPrice",
		RHSType:          "constant",
		RHSConstant:      700,
	})
	if err != nil {
		t.Fatalf("CreateNativeAlert: unexpected error: %v", err)
	}
	if alert.UUID != "alert-uuid-1" {
		t.Errorf("UUID = %q, want alert-uuid-1", alert.UUID)
	}
	if alert.Name != "SBIN above 700" {
		t.Errorf("Name = %q, want 'SBIN above 700'", alert.Name)
	}
}

// --- Call log ordering proof ---

func TestClientMock_CallLog_RecordsMethodsInOrder(t *testing.T) {
	t.Parallel()
	mock := NewMockKiteSDK()
	mock.GetUserProfileFunc = func() (kiteconnect.UserProfile, error) {
		return kiteconnect.UserProfile{UserID: "X"}, nil
	}
	mock.GetHoldingsFunc = func() (kiteconnect.Holdings, error) {
		return kiteconnect.Holdings{}, nil
	}
	mock.GetOrdersFunc = func() (kiteconnect.Orders, error) {
		return kiteconnect.Orders{}, nil
	}
	c := NewFromSDK(mock)

	_, _ = c.GetProfile()
	_, _ = c.GetHoldings()
	_, _ = c.GetOrders()

	calls := mock.Calls()
	if len(calls) != 3 {
		t.Fatalf("want 3 calls, got %d: %v", len(calls), calls)
	}
	want := []string{"GetUserProfile", "GetHoldings", "GetOrders"}
	for i, c := range calls {
		if c != want[i] {
			t.Errorf("calls[%d] = %q, want %q", i, c, want[i])
		}
	}
}
