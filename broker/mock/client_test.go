package mock

import (
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
)

func TestNew(t *testing.T) {
	c := New()
	if c == nil {
		t.Fatal("New() returned nil")
	}
	if c.BrokerName() != "mock" {
		t.Errorf("BrokerName() = %q, want %q", c.BrokerName(), "mock")
	}
}

func TestBrokerNameOverride(t *testing.T) {
	c := New()
	c.BrokerNameVal = broker.Zerodha
	if c.BrokerName() != broker.Zerodha {
		t.Errorf("BrokerName() = %q, want %q", c.BrokerName(), broker.Zerodha)
	}
}

func TestGetProfile(t *testing.T) {
	c := New()
	p, err := c.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile() error: %v", err)
	}
	if p.UserID != "MOCK01" {
		t.Errorf("UserID = %q, want %q", p.UserID, "MOCK01")
	}
}

func TestSetAndGetProfile(t *testing.T) {
	c := New()
	want := broker.Profile{
		UserID:   "TEST01",
		UserName: "Test User",
		Email:    "test@test.com",
		Broker:   broker.Zerodha,
	}
	c.SetProfile(want)
	got, err := c.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile() error: %v", err)
	}
	if got.UserID != want.UserID || got.Email != want.Email {
		t.Errorf("got %+v, want %+v", got, want)
	}
}

func TestGetMargins(t *testing.T) {
	c := New()
	m, err := c.GetMargins()
	if err != nil {
		t.Fatalf("GetMargins() error: %v", err)
	}
	if m.Equity.Available != 1_00_00_000 {
		t.Errorf("Equity.Available = %f, want 10000000", m.Equity.Available)
	}
}

func TestSetAndGetHoldings(t *testing.T) {
	c := New()
	want := []broker.Holding{
		{
			Tradingsymbol: "RELIANCE",
			Exchange:      "NSE",
			Quantity:      10,
			AveragePrice:  2400,
			LastPrice:     2500,
			PnL:           1000,
		},
		{
			Tradingsymbol: "INFY",
			Exchange:      "NSE",
			Quantity:      20,
			AveragePrice:  1500,
			LastPrice:     1600,
			PnL:           2000,
		},
	}
	c.SetHoldings(want)
	got, err := c.GetHoldings()
	if err != nil {
		t.Fatalf("GetHoldings() error: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("len(holdings) = %d, want 2", len(got))
	}
	if got[0].Tradingsymbol != "RELIANCE" {
		t.Errorf("holdings[0].Tradingsymbol = %q, want %q", got[0].Tradingsymbol, "RELIANCE")
	}
}

func TestSetAndGetPositions(t *testing.T) {
	c := New()
	want := broker.Positions{
		Day: []broker.Position{
			{Tradingsymbol: "SBIN", Exchange: "NSE", Product: "MIS", Quantity: 5},
		},
		Net: []broker.Position{
			{Tradingsymbol: "SBIN", Exchange: "NSE", Product: "MIS", Quantity: 5},
		},
	}
	c.SetPositions(want)
	got, err := c.GetPositions()
	if err != nil {
		t.Fatalf("GetPositions() error: %v", err)
	}
	if len(got.Day) != 1 || got.Day[0].Tradingsymbol != "SBIN" {
		t.Errorf("unexpected Day positions: %+v", got.Day)
	}
}

func TestPlaceOrder(t *testing.T) {
	c := New()

	// Place a LIMIT order (stays OPEN).
	resp, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           2400,
	})
	if err != nil {
		t.Fatalf("PlaceOrder() error: %v", err)
	}
	if resp.OrderID == "" {
		t.Fatal("PlaceOrder() returned empty order ID")
	}

	// Verify the order is in the list.
	orders, err := c.GetOrders()
	if err != nil {
		t.Fatalf("GetOrders() error: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("len(orders) = %d, want 1", len(orders))
	}
	if orders[0].Status != "OPEN" {
		t.Errorf("order status = %q, want %q", orders[0].Status, "OPEN")
	}
	if orders[0].OrderID != resp.OrderID {
		t.Errorf("order ID = %q, want %q", orders[0].OrderID, resp.OrderID)
	}
}

func TestPlaceMarketOrder(t *testing.T) {
	c := New()
	c.SetPrices(map[string]float64{"NSE:INFY": 1600})

	resp, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Product:         "CNC",
		Quantity:        5,
	})
	if err != nil {
		t.Fatalf("PlaceOrder() error: %v", err)
	}

	orders := c.Orders()
	if len(orders) != 1 {
		t.Fatalf("len(orders) = %d, want 1", len(orders))
	}
	if orders[0].Status != "COMPLETE" {
		t.Errorf("status = %q, want COMPLETE", orders[0].Status)
	}
	if orders[0].FilledQuantity != 5 {
		t.Errorf("filled_qty = %d, want 5", orders[0].FilledQuantity)
	}
	if orders[0].AveragePrice != 1600 {
		t.Errorf("avg_price = %f, want 1600", orders[0].AveragePrice)
	}

	// Verify a trade was created.
	trades := c.Trades()
	if len(trades) != 1 {
		t.Fatalf("len(trades) = %d, want 1", len(trades))
	}
	if trades[0].OrderID != resp.OrderID {
		t.Errorf("trade.OrderID = %q, want %q", trades[0].OrderID, resp.OrderID)
	}
}

func TestModifyOrder(t *testing.T) {
	c := New()

	resp, _ := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "TCS",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        10,
		Price:           3500,
	})

	// Modify the price.
	_, err := c.ModifyOrder(resp.OrderID, broker.OrderParams{
		Price: 3600,
	})
	if err != nil {
		t.Fatalf("ModifyOrder() error: %v", err)
	}

	orders := c.Orders()
	if orders[0].Price != 3600 {
		t.Errorf("price = %f, want 3600", orders[0].Price)
	}
}

func TestModifyNonExistentOrder(t *testing.T) {
	c := New()
	_, err := c.ModifyOrder("nonexistent", broker.OrderParams{Price: 100})
	if err == nil {
		t.Fatal("expected error for nonexistent order")
	}
}

func TestModifyFilledOrder(t *testing.T) {
	c := New()
	c.SetPrices(map[string]float64{"NSE:X": 100})
	resp, _ := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "X", TransactionType: "BUY",
		OrderType: "MARKET", Product: "CNC", Quantity: 1,
	})
	_, err := c.ModifyOrder(resp.OrderID, broker.OrderParams{Price: 200})
	if err == nil {
		t.Fatal("expected error when modifying a COMPLETE order")
	}
}

func TestCancelOrder(t *testing.T) {
	c := New()

	resp, _ := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "HDFC",
		TransactionType: "SELL",
		OrderType:       "LIMIT",
		Product:         "CNC",
		Quantity:        5,
		Price:           1700,
	})

	_, err := c.CancelOrder(resp.OrderID)
	if err != nil {
		t.Fatalf("CancelOrder() error: %v", err)
	}

	orders := c.Orders()
	if orders[0].Status != "CANCELLED" {
		t.Errorf("status = %q, want CANCELLED", orders[0].Status)
	}
}

func TestCancelNonExistentOrder(t *testing.T) {
	c := New()
	_, err := c.CancelOrder("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent order")
	}
}

func TestCancelAlreadyCancelledOrder(t *testing.T) {
	c := New()
	resp, _ := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "A", TransactionType: "BUY",
		OrderType: "LIMIT", Product: "CNC", Quantity: 1, Price: 100,
	})
	c.CancelOrder(resp.OrderID)
	_, err := c.CancelOrder(resp.OrderID)
	if err == nil {
		t.Fatal("expected error when cancelling already-cancelled order")
	}
}

func TestGetOrderHistory(t *testing.T) {
	c := New()

	resp, _ := c.PlaceOrder(broker.OrderParams{
		Exchange: "NSE", Tradingsymbol: "ITC", TransactionType: "BUY",
		OrderType: "LIMIT", Product: "CNC", Quantity: 100, Price: 450,
	})

	history, err := c.GetOrderHistory(resp.OrderID)
	if err != nil {
		t.Fatalf("GetOrderHistory() error: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len(history) = %d, want 1", len(history))
	}
	if history[0].OrderID != resp.OrderID {
		t.Errorf("history OrderID = %q, want %q", history[0].OrderID, resp.OrderID)
	}
}

func TestGetOrderHistoryNotFound(t *testing.T) {
	c := New()
	_, err := c.GetOrderHistory("unknown")
	if err == nil {
		t.Fatal("expected error for unknown order")
	}
}

func TestGetLTP(t *testing.T) {
	c := New()
	c.SetPrices(map[string]float64{
		"NSE:RELIANCE": 2500,
		"NSE:TCS":      3700,
	})

	ltp, err := c.GetLTP("NSE:RELIANCE", "NSE:TCS", "NSE:UNKNOWN")
	if err != nil {
		t.Fatalf("GetLTP() error: %v", err)
	}
	if ltp["NSE:RELIANCE"].LastPrice != 2500 {
		t.Errorf("RELIANCE LTP = %f, want 2500", ltp["NSE:RELIANCE"].LastPrice)
	}
	if _, ok := ltp["NSE:UNKNOWN"]; ok {
		t.Error("expected NSE:UNKNOWN to be absent from LTP map")
	}
}

func TestGetOHLC(t *testing.T) {
	c := New()
	c.SetOHLC(map[string]broker.OHLC{
		"NSE:RELIANCE": {Open: 2480, High: 2520, Low: 2470, Close: 2500, LastPrice: 2500},
	})

	ohlc, err := c.GetOHLC("NSE:RELIANCE")
	if err != nil {
		t.Fatalf("GetOHLC() error: %v", err)
	}
	if ohlc["NSE:RELIANCE"].High != 2520 {
		t.Errorf("RELIANCE High = %f, want 2520", ohlc["NSE:RELIANCE"].High)
	}
}

func TestGetHistoricalData(t *testing.T) {
	c := New()
	from := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 10, 0, 0, 0, 0, time.UTC)

	candles, err := c.GetHistoricalData(256265, "day", from, to)
	if err != nil {
		t.Fatalf("GetHistoricalData() error: %v", err)
	}
	if len(candles) == 0 {
		t.Fatal("expected non-empty candles")
	}
	// 10 days inclusive = 10 candles.
	if len(candles) != 10 {
		t.Errorf("len(candles) = %d, want 10", len(candles))
	}
	for _, c := range candles {
		if c.High < c.Low {
			t.Errorf("candle has High %f < Low %f", c.High, c.Low)
		}
		if c.Volume <= 0 {
			t.Errorf("candle has non-positive volume %d", c.Volume)
		}
	}
}

func TestGetHistoricalData5Minute(t *testing.T) {
	c := New()
	from := time.Date(2026, 1, 1, 9, 0, 0, 0, time.UTC)
	to := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC) // 1 hour = 12 five-minute candles + 1 (inclusive)

	candles, err := c.GetHistoricalData(100, "5minute", from, to)
	if err != nil {
		t.Fatalf("GetHistoricalData() error: %v", err)
	}
	if len(candles) != 13 { // 0, 5, 10, ..., 55, 60 = 13
		t.Errorf("len(candles) = %d, want 13", len(candles))
	}
}

// ---------------------------------------------------------------------------
// Error injection tests
// ---------------------------------------------------------------------------

func TestErrorInjection(t *testing.T) {
	injected := errors.New("injected error")

	tests := []struct {
		name string
		fn   func(c *Client) error
		set  func(c *Client)
	}{
		{"GetProfile", func(c *Client) error { _, e := c.GetProfile(); return e }, func(c *Client) { c.GetProfileErr = injected }},
		{"GetMargins", func(c *Client) error { _, e := c.GetMargins(); return e }, func(c *Client) { c.GetMarginsErr = injected }},
		{"GetHoldings", func(c *Client) error { _, e := c.GetHoldings(); return e }, func(c *Client) { c.GetHoldingsErr = injected }},
		{"GetPositions", func(c *Client) error { _, e := c.GetPositions(); return e }, func(c *Client) { c.GetPositionsErr = injected }},
		{"GetOrders", func(c *Client) error { _, e := c.GetOrders(); return e }, func(c *Client) { c.GetOrdersErr = injected }},
		{"GetOrderHistory", func(c *Client) error { _, e := c.GetOrderHistory("1"); return e }, func(c *Client) { c.GetOrderHistoryErr = injected }},
		{"GetTrades", func(c *Client) error { _, e := c.GetTrades(); return e }, func(c *Client) { c.GetTradesErr = injected }},
		{"PlaceOrder", func(c *Client) error {
			_, e := c.PlaceOrder(broker.OrderParams{})
			return e
		}, func(c *Client) { c.PlaceOrderErr = injected }},
		{"ModifyOrder", func(c *Client) error { _, e := c.ModifyOrder("1", broker.OrderParams{}); return e }, func(c *Client) { c.ModifyOrderErr = injected }},
		{"CancelOrder", func(c *Client) error { _, e := c.CancelOrder("1"); return e }, func(c *Client) { c.CancelOrderErr = injected }},
		{"GetLTP", func(c *Client) error { _, e := c.GetLTP("NSE:X"); return e }, func(c *Client) { c.GetLTPErr = injected }},
		{"GetOHLC", func(c *Client) error { _, e := c.GetOHLC("NSE:X"); return e }, func(c *Client) { c.GetOHLCErr = injected }},
		{"GetHistoricalData", func(c *Client) error {
			_, e := c.GetHistoricalData(1, "day", time.Now(), time.Now())
			return e
		}, func(c *Client) { c.GetHistoricalErr = injected }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := New()
			tt.set(c)
			err := tt.fn(c)
			if !errors.Is(err, injected) {
				t.Errorf("got err %v, want %v", err, injected)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Concurrency test
// ---------------------------------------------------------------------------

func TestConcurrency(t *testing.T) {
	c := New()
	c.SetPrices(map[string]float64{"NSE:RELIANCE": 2500})

	var wg sync.WaitGroup
	errs := make(chan error, 200)

	// Concurrent writers: place orders.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.PlaceOrder(broker.OrderParams{
				Exchange:        "NSE",
				Tradingsymbol:   "RELIANCE",
				TransactionType: "BUY",
				OrderType:       "MARKET",
				Product:         "CNC",
				Quantity:        1,
			})
			if err != nil {
				errs <- err
			}
		}()
	}

	// Concurrent readers: get orders, holdings, LTP.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.GetOrders(); err != nil {
				errs <- err
			}
			if _, err := c.GetHoldings(); err != nil {
				errs <- err
			}
			if _, err := c.GetLTP("NSE:RELIANCE"); err != nil {
				errs <- err
			}
			if _, err := c.GetProfile(); err != nil {
				errs <- err
			}
		}()
	}

	// Concurrent setters.
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.SetHoldings([]broker.Holding{{Tradingsymbol: "RELIANCE"}})
			c.SetPrices(map[string]float64{"NSE:RELIANCE": 2510})
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent operation error: %v", err)
	}

	// All 50 orders should be placed.
	orders := c.Orders()
	if len(orders) != 50 {
		t.Errorf("len(orders) = %d, want 50", len(orders))
	}
}

func TestInterfaceCompliance(t *testing.T) {
	// Verify that New() returns something usable as broker.Client.
	var client broker.Client = New()
	if client.BrokerName() != "mock" {
		t.Errorf("BrokerName() = %q, want %q", client.BrokerName(), "mock")
	}
}

func TestSetTrades(t *testing.T) {
	c := New()
	want := []broker.Trade{
		{TradeID: "T1", OrderID: "O1", Tradingsymbol: "RELIANCE", Quantity: 10, Price: 2500},
	}
	c.SetTrades(want)
	got, err := c.GetTrades()
	if err != nil {
		t.Fatalf("GetTrades() error: %v", err)
	}
	if len(got) != 1 || got[0].TradeID != "T1" {
		t.Errorf("unexpected trades: %+v", got)
	}
}

func TestSetMargins(t *testing.T) {
	c := New()
	want := broker.Margins{
		Equity: broker.SegmentMargin{Available: 500000, Used: 100000, Total: 600000},
	}
	c.SetMargins(want)
	got, err := c.GetMargins()
	if err != nil {
		t.Fatalf("GetMargins() error: %v", err)
	}
	if got.Equity.Available != 500000 {
		t.Errorf("Equity.Available = %f, want 500000", got.Equity.Available)
	}
}
