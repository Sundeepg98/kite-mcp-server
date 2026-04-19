package zerodha

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/broker"
)

// Silence unused import errors.
var _ = time.Now

// envelope wraps a Kite-style JSON response.
func jsonEnvelope(t *testing.T, data interface{}) string {
	t.Helper()
	b, err := json.Marshal(map[string]interface{}{"data": data})
	if err != nil {
		t.Fatalf("failed to marshal envelope: %v", err)
	}
	return string(b)
}

// newTestKiteClient creates a *kiteconnect.Client backed by the given httptest.Server.
func newTestKiteClient(ts *httptest.Server) *kiteconnect.Client {
	kc := kiteconnect.New("test_key")
	kc.SetBaseURI(ts.URL)
	kc.SetAccessToken("test_token")
	return kc
}

// ---------------------------------------------------------------------------
// GetProfile
// ---------------------------------------------------------------------------

func TestClient_GetProfile(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/profile" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"user_id":    "AB1234",
				"user_name":  "Test User",
				"email":      "test@example.com",
				"broker":     "ZERODHA",
				"exchanges":  []string{"NSE", "BSE"},
				"products":   []string{"CNC", "MIS"},
				"order_types": []string{"LIMIT", "MARKET"},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	p, err := c.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile error: %v", err)
	}
	if p.UserID != "AB1234" {
		t.Errorf("UserID = %q, want AB1234", p.UserID)
	}
	if p.UserName != "Test User" {
		t.Errorf("UserName = %q, want Test User", p.UserName)
	}
	if p.Broker != broker.Zerodha {
		t.Errorf("Broker = %q, want %q", p.Broker, broker.Zerodha)
	}
}

func TestClient_GetProfile_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"invalid session"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetProfile()
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "invalid session") {
		t.Errorf("error = %q, want to contain 'invalid session'", err.Error())
	}
}

// ---------------------------------------------------------------------------
// GetMargins
// ---------------------------------------------------------------------------

func TestClient_GetMargins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/user/margins" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"equity": map[string]interface{}{
					"enabled": true,
					"net":     100000,
					"available": map[string]interface{}{
						"cash": 50000, "collateral": 10000, "intraday_payin": 0, "opening_balance": 20000,
					},
					"utilised": map[string]interface{}{
						"debits": 5000, "exposure": 3000, "span": 2000, "option_premium": 1000,
					},
				},
				"commodity": map[string]interface{}{
					"enabled": false,
					"available": map[string]interface{}{
						"cash": 0, "collateral": 0, "intraday_payin": 0, "opening_balance": 0,
					},
					"utilised": map[string]interface{}{
						"debits": 0, "exposure": 0, "span": 0, "option_premium": 0,
					},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	m, err := c.GetMargins()
	if err != nil {
		t.Fatalf("GetMargins error: %v", err)
	}
	if m.Equity.Available != 80000 {
		t.Errorf("Equity Available = %f, want 80000", m.Equity.Available)
	}
	if m.Equity.Used != 11000 {
		t.Errorf("Equity Used = %f, want 11000", m.Equity.Used)
	}
}

func TestClient_GetMargins_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"token expired"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetMargins()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetHoldings
// ---------------------------------------------------------------------------

func TestClient_GetHoldings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portfolio/holdings" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"tradingsymbol":        "INFY",
					"exchange":             "NSE",
					"isin":                 "INE009A01021",
					"quantity":             10,
					"average_price":        1500.50,
					"last_price":           1600.75,
					"pnl":                  1002.50,
					"day_change_percentage": 1.25,
					"product":              "CNC",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	h, err := c.GetHoldings()
	if err != nil {
		t.Fatalf("GetHoldings error: %v", err)
	}
	if len(h) != 1 {
		t.Fatalf("len = %d, want 1", len(h))
	}
	if h[0].Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want INFY", h[0].Tradingsymbol)
	}
	if h[0].Quantity != 10 {
		t.Errorf("Quantity = %d, want 10", h[0].Quantity)
	}
}

func TestClient_GetHoldings_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"internal error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetHoldings()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetPositions
// ---------------------------------------------------------------------------

func TestClient_GetPositions(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portfolio/positions" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"day": []map[string]interface{}{
					{
						"tradingsymbol": "SBIN",
						"exchange":      "NSE",
						"product":       "MIS",
						"quantity":      100,
						"average_price": 550.25,
						"last_price":    555.00,
						"pnl":           475.00,
					},
				},
				"net": []map[string]interface{}{
					{
						"tradingsymbol": "SBIN",
						"exchange":      "NSE",
						"product":       "MIS",
						"quantity":      100,
						"average_price": 550.25,
						"last_price":    555.00,
						"pnl":           475.00,
					},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	p, err := c.GetPositions()
	if err != nil {
		t.Fatalf("GetPositions error: %v", err)
	}
	if len(p.Day) != 1 {
		t.Fatalf("Day len = %d, want 1", len(p.Day))
	}
	if p.Day[0].Tradingsymbol != "SBIN" {
		t.Errorf("Tradingsymbol = %q, want SBIN", p.Day[0].Tradingsymbol)
	}
	if len(p.Net) != 1 {
		t.Fatalf("Net len = %d, want 1", len(p.Net))
	}
}

func TestClient_GetPositions_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"bad request"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetPositions()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOrders
// ---------------------------------------------------------------------------

func TestClient_GetOrders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/orders" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"order_id":         "ORD001",
					"exchange":         "NSE",
					"tradingsymbol":    "INFY",
					"transaction_type": "BUY",
					"order_type":       "LIMIT",
					"product":          "CNC",
					"quantity":         10,
					"price":            1500.00,
					"trigger_price":    0,
					"status":           "COMPLETE",
					"filled_quantity":  10,
					"average_price":    1498.50,
					"order_timestamp":  "2026-04-03 09:30:00",
					"status_message":   "",
					"tag":              "mcp",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	orders, err := c.GetOrders()
	if err != nil {
		t.Fatalf("GetOrders error: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("len = %d, want 1", len(orders))
	}
	if orders[0].OrderID != "ORD001" {
		t.Errorf("OrderID = %q, want ORD001", orders[0].OrderID)
	}
	if orders[0].Status != "COMPLETE" {
		t.Errorf("Status = %q, want COMPLETE", orders[0].Status)
	}
}

func TestClient_GetOrders_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"expired"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOrders()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOrderHistory
// ---------------------------------------------------------------------------

func TestClient_GetOrderHistory(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/orders/") && !strings.Contains(r.URL.Path, "/trades") && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"order_id":         "ORD001",
					"exchange":         "NSE",
					"tradingsymbol":    "INFY",
					"transaction_type": "BUY",
					"order_type":       "LIMIT",
					"product":          "CNC",
					"quantity":         10,
					"price":            1500.00,
					"status":           "PUT ORDER REQ RECEIVED",
					"filled_quantity":  0,
					"order_timestamp":  "2026-04-03 09:30:00",
				},
				{
					"order_id":         "ORD001",
					"exchange":         "NSE",
					"tradingsymbol":    "INFY",
					"transaction_type": "BUY",
					"order_type":       "LIMIT",
					"product":          "CNC",
					"quantity":         10,
					"price":            1500.00,
					"status":           "COMPLETE",
					"filled_quantity":  10,
					"average_price":    1498.50,
					"order_timestamp":  "2026-04-03 09:30:01",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	history, err := c.GetOrderHistory("ORD001")
	if err != nil {
		t.Fatalf("GetOrderHistory error: %v", err)
	}
	if len(history) != 2 {
		t.Fatalf("len = %d, want 2", len(history))
	}
	if history[1].Status != "COMPLETE" {
		t.Errorf("Status = %q, want COMPLETE", history[1].Status)
	}
}

func TestClient_GetOrderHistory_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"order not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOrderHistory("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetTrades
// ---------------------------------------------------------------------------

func TestClient_GetTrades(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/trades" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"trade_id":         "TRD001",
					"order_id":         "ORD001",
					"exchange":         "NSE",
					"tradingsymbol":    "INFY",
					"transaction_type": "BUY",
					"quantity":         10,
					"average_price":    1498.50,
					"product":          "CNC",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	trades, err := c.GetTrades()
	if err != nil {
		t.Fatalf("GetTrades error: %v", err)
	}
	if len(trades) != 1 {
		t.Fatalf("len = %d, want 1", len(trades))
	}
	if trades[0].TradeID != "TRD001" {
		t.Errorf("TradeID = %q, want TRD001", trades[0].TradeID)
	}
}

func TestClient_GetTrades_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"server error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetTrades()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PlaceOrder
// ---------------------------------------------------------------------------

func TestClient_PlaceOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/orders/") && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "NEW_ORD_001",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Product:         "CNC",
		Quantity:        10,
		Variety:         "regular",
	})
	if err != nil {
		t.Fatalf("PlaceOrder error: %v", err)
	}
	if resp.OrderID != "NEW_ORD_001" {
		t.Errorf("OrderID = %q, want NEW_ORD_001", resp.OrderID)
	}
}

func TestClient_PlaceOrder_DefaultVariety(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Should default to "regular"
		if r.URL.Path == "/orders/regular" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "NEW_ORD_002",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"unexpected path: `+r.URL.Path+`"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Product:         "CNC",
		Quantity:        10,
		// No Variety — should default to "regular"
	})
	if err != nil {
		t.Fatalf("PlaceOrder error: %v", err)
	}
	if resp.OrderID != "NEW_ORD_002" {
		t.Errorf("OrderID = %q, want NEW_ORD_002", resp.OrderID)
	}
}

func TestClient_PlaceOrder_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"insufficient funds"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.PlaceOrder(broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		OrderType:       "MARKET",
		Product:         "CNC",
		Quantity:        10,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// ModifyOrder
// ---------------------------------------------------------------------------

func TestClient_ModifyOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/orders/") {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "ORD001",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.ModifyOrder("ORD001", broker.OrderParams{
		Price:    1505.00,
		Quantity: 15,
		Variety:  "regular",
	})
	if err != nil {
		t.Fatalf("ModifyOrder error: %v", err)
	}
	if resp.OrderID != "ORD001" {
		t.Errorf("OrderID = %q, want ORD001", resp.OrderID)
	}
}

func TestClient_ModifyOrder_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"order not open"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.ModifyOrder("ORD001", broker.OrderParams{Price: 1505.00, Variety: "regular"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// CancelOrder
// ---------------------------------------------------------------------------

func TestClient_CancelOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/orders/") {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "ORD001",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.CancelOrder("ORD001", "regular")
	if err != nil {
		t.Fatalf("CancelOrder error: %v", err)
	}
	if resp.OrderID != "ORD001" {
		t.Errorf("OrderID = %q, want ORD001", resp.OrderID)
	}
}

func TestClient_CancelOrder_DefaultVariety(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && r.URL.Path == "/orders/regular/ORD002" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "ORD002",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"unexpected: `+r.URL.Path+`"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.CancelOrder("ORD002", "") // empty variety should default to "regular"
	if err != nil {
		t.Fatalf("CancelOrder error: %v", err)
	}
	if resp.OrderID != "ORD002" {
		t.Errorf("OrderID = %q, want ORD002", resp.OrderID)
	}
}

func TestClient_CancelOrder_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"order not open"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.CancelOrder("ORD001", "regular")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetLTP
// ---------------------------------------------------------------------------

func TestClient_GetLTP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/quote" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"NSE:INFY": map[string]interface{}{
					"instrument_token": 256265,
					"last_price":       1600.75,
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	ltp, err := c.GetLTP("NSE:INFY")
	if err != nil {
		t.Fatalf("GetLTP error: %v", err)
	}
	if ltp["NSE:INFY"].LastPrice != 1600.75 {
		t.Errorf("LastPrice = %f, want 1600.75", ltp["NSE:INFY"].LastPrice)
	}
}

func TestClient_GetLTP_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid instrument"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetLTP("INVALID")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOHLC
// ---------------------------------------------------------------------------

func TestClient_GetOHLC(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/quote" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"NSE:INFY": map[string]interface{}{
					"instrument_token": 256265,
					"last_price":       1600.75,
					"ohlc": map[string]interface{}{
						"open": 1590.00, "high": 1610.00, "low": 1585.00, "close": 1595.00,
					},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	ohlc, err := c.GetOHLC("NSE:INFY")
	if err != nil {
		t.Fatalf("GetOHLC error: %v", err)
	}
	if ohlc["NSE:INFY"].Open != 1590.00 {
		t.Errorf("Open = %f, want 1590", ohlc["NSE:INFY"].Open)
	}
	if ohlc["NSE:INFY"].LastPrice != 1600.75 {
		t.Errorf("LastPrice = %f, want 1600.75", ohlc["NSE:INFY"].LastPrice)
	}
}

func TestClient_GetOHLC_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"bad input"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOHLC("INVALID")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetHistoricalData
// ---------------------------------------------------------------------------

func TestClient_GetHistoricalData(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/instruments/historical/") {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"candles": [][]interface{}{
					{"2026-04-01T09:15:00+0530", 1590.0, 1610.0, 1585.0, 1600.0, 150000},
					{"2026-04-02T09:15:00+0530", 1600.0, 1620.0, 1595.0, 1615.0, 120000},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	from := mustParseTime("2026-04-01")
	to := mustParseTime("2026-04-02")
	candles, err := c.GetHistoricalData(256265, "day", from, to)
	if err != nil {
		t.Fatalf("GetHistoricalData error: %v", err)
	}
	if len(candles) != 2 {
		t.Fatalf("len = %d, want 2", len(candles))
	}
	if candles[0].Open != 1590.0 {
		t.Errorf("Open = %f, want 1590", candles[0].Open)
	}
	if candles[0].Volume != 150000 {
		t.Errorf("Volume = %d, want 150000", candles[0].Volume)
	}
}

func TestClient_GetHistoricalData_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid token"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	from := mustParseTime("2026-04-01")
	to := mustParseTime("2026-04-02")
	_, err := c.GetHistoricalData(0, "day", from, to)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetQuotes
// ---------------------------------------------------------------------------

func TestClient_GetQuotes(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/quote" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"NSE:INFY": map[string]interface{}{
					"instrument_token":   256265,
					"last_price":         1600.75,
					"volume":             5000000,
					"buy_quantity":       1000000,
					"sell_quantity":      800000,
					"net_change":         25.0,
					"lower_circuit_limit": 1400.0,
					"upper_circuit_limit": 1800.0,
					"ohlc": map[string]interface{}{
						"open": 1590.0, "high": 1610.0, "low": 1585.0, "close": 1595.0,
					},
					"depth": map[string]interface{}{
						"buy": []map[string]interface{}{
							{"price": 1600.0, "quantity": 100, "orders": 5},
						},
						"sell": []map[string]interface{}{
							{"price": 1601.0, "quantity": 200, "orders": 10},
						},
					},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	quotes, err := c.GetQuotes("NSE:INFY")
	if err != nil {
		t.Fatalf("GetQuotes error: %v", err)
	}
	q := quotes["NSE:INFY"]
	if q.LastPrice != 1600.75 {
		t.Errorf("LastPrice = %f, want 1600.75", q.LastPrice)
	}
	if q.Volume != 5000000 {
		t.Errorf("Volume = %d, want 5000000", q.Volume)
	}
}

func TestClient_GetQuotes_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"bad input"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetQuotes("INVALID")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOrderTrades
// ---------------------------------------------------------------------------

func TestClient_GetOrderTrades(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/trades") && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"trade_id":         "TRD001",
					"order_id":         "ORD001",
					"exchange":         "NSE",
					"tradingsymbol":    "INFY",
					"transaction_type": "BUY",
					"quantity":         10,
					"average_price":    1498.50,
					"product":          "CNC",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	trades, err := c.GetOrderTrades("ORD001")
	if err != nil {
		t.Fatalf("GetOrderTrades error: %v", err)
	}
	if len(trades) != 1 {
		t.Fatalf("len = %d, want 1", len(trades))
	}
	if trades[0].TradeID != "TRD001" {
		t.Errorf("TradeID = %q, want TRD001", trades[0].TradeID)
	}
}

func TestClient_GetOrderTrades_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"order not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOrderTrades("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetGTTs
// ---------------------------------------------------------------------------

func TestClient_GetGTTs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gtt/triggers" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"id":     1001,
					"type":   "single",
					"status": "active",
					"condition": map[string]interface{}{
						"exchange":       "NSE",
						"tradingsymbol":  "RELIANCE",
						"trigger_values": []float64{2400.0},
						"last_price":     2500.0,
					},
					"orders": []map[string]interface{}{
						{
							"exchange":         "NSE",
							"tradingsymbol":    "RELIANCE",
							"transaction_type": "BUY",
							"quantity":         10,
							"order_type":       "LIMIT",
							"price":            2390.0,
							"product":          "CNC",
						},
					},
					"created_at": "2026-04-05 10:00:00",
					"updated_at": "2026-04-05 10:00:00",
					"expires_at": "2027-04-05 10:00:00",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	gtts, err := c.GetGTTs()
	if err != nil {
		t.Fatalf("GetGTTs error: %v", err)
	}
	if len(gtts) != 1 {
		t.Fatalf("len = %d, want 1", len(gtts))
	}
	if gtts[0].ID != 1001 {
		t.Errorf("ID = %d, want 1001", gtts[0].ID)
	}
}

func TestClient_GetGTTs_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"expired"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetGTTs()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PlaceGTT
// ---------------------------------------------------------------------------

func TestClient_PlaceGTT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/gtt/triggers" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"trigger_id": 2001,
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.PlaceGTT(broker.GTTParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		LastPrice:       1500,
		TransactionType: "BUY",
		Product:         "CNC",
		Type:            "single",
		TriggerValue:    1450,
		Quantity:        10,
		LimitPrice:      1445,
	})
	if err != nil {
		t.Fatalf("PlaceGTT error: %v", err)
	}
	if resp.TriggerID != 2001 {
		t.Errorf("TriggerID = %d, want 2001", resp.TriggerID)
	}
}

func TestClient_PlaceGTT_InvalidType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server for invalid GTT type")
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.PlaceGTT(broker.GTTParams{
		Exchange: "NSE",
		Type:     "triple-leg", // invalid
	})
	if err == nil {
		t.Fatal("expected error for invalid GTT type")
	}
}

func TestClient_PlaceGTT_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid trigger"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.PlaceGTT(broker.GTTParams{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Type:          "single",
		TriggerValue:  1450,
		Quantity:      10,
		LimitPrice:    1445,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// ModifyGTT
// ---------------------------------------------------------------------------

func TestClient_ModifyGTT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "PUT" && strings.HasPrefix(r.URL.Path, "/gtt/triggers/") {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"trigger_id": 1001,
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.ModifyGTT(1001, broker.GTTParams{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		LastPrice:     1500,
		Type:          "single",
		TriggerValue:  1400,
		Quantity:      15,
		LimitPrice:    1395,
	})
	if err != nil {
		t.Fatalf("ModifyGTT error: %v", err)
	}
	if resp.TriggerID != 1001 {
		t.Errorf("TriggerID = %d, want 1001", resp.TriggerID)
	}
}

func TestClient_ModifyGTT_InvalidType(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Fatal("should not reach server for invalid GTT type")
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.ModifyGTT(1001, broker.GTTParams{Type: "invalid"})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ModifyGTT_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"trigger not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.ModifyGTT(9999, broker.GTTParams{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Type:          "single",
		TriggerValue:  1450,
		Quantity:      10,
		LimitPrice:    1445,
	})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// DeleteGTT
// ---------------------------------------------------------------------------

func TestClient_DeleteGTT(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "DELETE" && strings.HasPrefix(r.URL.Path, "/gtt/triggers/") {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"trigger_id": 1001,
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.DeleteGTT(1001)
	if err != nil {
		t.Fatalf("DeleteGTT error: %v", err)
	}
	if resp.TriggerID != 1001 {
		t.Errorf("TriggerID = %d, want 1001", resp.TriggerID)
	}
}

func TestClient_DeleteGTT_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"GTT not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.DeleteGTT(9999)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// ConvertPosition
// ---------------------------------------------------------------------------

func TestClient_ConvertPosition(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/portfolio/positions" && r.Method == "PUT" {
			fmt.Fprint(w, `{"status":"success","data":true}`)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	ok, err := c.ConvertPosition(broker.ConvertPositionParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        10,
		OldProduct:      "MIS",
		NewProduct:      "CNC",
		PositionType:    "day",
	})
	if err != nil {
		t.Fatalf("ConvertPosition error: %v", err)
	}
	if !ok {
		t.Error("ConvertPosition returned false, want true")
	}
}

func TestClient_ConvertPosition_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid params"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.ConvertPosition(broker.ConvertPositionParams{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetMFOrders
// ---------------------------------------------------------------------------

func TestClient_GetMFOrders(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mf/orders" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"order_id":          "MF001",
					"tradingsymbol":     "INF846K01DP8",
					"fund":             "Axis Bluechip Fund",
					"transaction_type":  "BUY",
					"status":           "COMPLETE",
					"amount":           5000.0,
					"quantity":          123.456,
					"folio":            "1234567890",
					"order_timestamp":  "2026-04-10 09:30:00",
					"exchange_timestamp": "2026-04-10 09:30:05",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	orders, err := c.GetMFOrders()
	if err != nil {
		t.Fatalf("GetMFOrders error: %v", err)
	}
	if len(orders) != 1 {
		t.Fatalf("len = %d, want 1", len(orders))
	}
	if orders[0].OrderID != "MF001" {
		t.Errorf("OrderID = %q, want MF001", orders[0].OrderID)
	}
	if orders[0].Tradingsymbol != "INF846K01DP8" {
		t.Errorf("Tradingsymbol = %q, want INF846K01DP8", orders[0].Tradingsymbol)
	}
	if orders[0].Amount != 5000.0 {
		t.Errorf("Amount = %f, want 5000", orders[0].Amount)
	}
}

func TestClient_GetMFOrders_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"expired"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetMFOrders()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetMFSIPs
// ---------------------------------------------------------------------------

func TestClient_GetMFSIPs(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mf/sips" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"sip_id":            "SIP001",
					"tradingsymbol":     "INF846K01DP8",
					"fund_name":         "Axis Bluechip Fund",
					"frequency":         "monthly",
					"instalment_amount": 5000.0,
					"instalments":       120,
					"status":           "ACTIVE",
					"step_up":          map[string]interface{}{},
					"tag":              "auto",
					"created":          "2026-01-01 09:00:00",
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	sips, err := c.GetMFSIPs()
	if err != nil {
		t.Fatalf("GetMFSIPs error: %v", err)
	}
	if len(sips) != 1 {
		t.Fatalf("len = %d, want 1", len(sips))
	}
	if sips[0].SIPID != "SIP001" {
		t.Errorf("SIPID = %q, want SIP001", sips[0].SIPID)
	}
	if sips[0].Frequency != "monthly" {
		t.Errorf("Frequency = %q, want monthly", sips[0].Frequency)
	}
	if sips[0].Amount != 5000.0 {
		t.Errorf("Amount = %f, want 5000", sips[0].Amount)
	}
}

func TestClient_GetMFSIPs_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
		fmt.Fprint(w, `{"status":"error","error_type":"TokenException","message":"expired"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetMFSIPs()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetMFHoldings
// ---------------------------------------------------------------------------

func TestClient_GetMFHoldings(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mf/holdings" && r.Method == "GET" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"tradingsymbol": "INF846K01DP8",
					"folio":         "1234567890",
					"fund":          "Axis Bluechip Fund",
					"quantity":      1234.567,
					"average_price": 45.50,
					"last_price":    48.25,
					"pnl":           3393.56,
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	holdings, err := c.GetMFHoldings()
	if err != nil {
		t.Fatalf("GetMFHoldings error: %v", err)
	}
	if len(holdings) != 1 {
		t.Fatalf("len = %d, want 1", len(holdings))
	}
	if holdings[0].Tradingsymbol != "INF846K01DP8" {
		t.Errorf("Tradingsymbol = %q, want INF846K01DP8", holdings[0].Tradingsymbol)
	}
	if holdings[0].PnL != 3393.56 {
		t.Errorf("PnL = %f, want 3393.56", holdings[0].PnL)
	}
}

func TestClient_GetMFHoldings_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"internal error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetMFHoldings()
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PlaceMFOrder
// ---------------------------------------------------------------------------

func TestClient_PlaceMFOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mf/orders" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "MF002",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.PlaceMFOrder(broker.MFOrderParams{
		Tradingsymbol:   "INF846K01DP8",
		TransactionType: "BUY",
		Amount:          10000,
		Tag:             "auto",
	})
	if err != nil {
		t.Fatalf("PlaceMFOrder error: %v", err)
	}
	if resp.OrderID != "MF002" {
		t.Errorf("OrderID = %q, want MF002", resp.OrderID)
	}
}

func TestClient_PlaceMFOrder_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid fund"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.PlaceMFOrder(broker.MFOrderParams{Tradingsymbol: "INVALID"})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// CancelMFOrder
// ---------------------------------------------------------------------------

func TestClient_CancelMFOrder(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/mf/orders/") && r.Method == "DELETE" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"order_id": "MF001",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.CancelMFOrder("MF001")
	if err != nil {
		t.Fatalf("CancelMFOrder error: %v", err)
	}
	if resp.OrderID != "MF001" {
		t.Errorf("OrderID = %q, want MF001", resp.OrderID)
	}
}

func TestClient_CancelMFOrder_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"order not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.CancelMFOrder("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// PlaceMFSIP
// ---------------------------------------------------------------------------

func TestClient_PlaceMFSIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/mf/sips" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"sip_id": "SIP002",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.PlaceMFSIP(broker.MFSIPParams{
		Tradingsymbol: "INF846K01DP8",
		Amount:        5000,
		Frequency:     "monthly",
		Instalments:   120,
		InstalmentDay: 1,
	})
	if err != nil {
		t.Fatalf("PlaceMFSIP error: %v", err)
	}
	if resp.SIPID != "SIP002" {
		t.Errorf("SIPID = %q, want SIP002", resp.SIPID)
	}
}

func TestClient_PlaceMFSIP_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid SIP params"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.PlaceMFSIP(broker.MFSIPParams{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// CancelMFSIP
// ---------------------------------------------------------------------------

func TestClient_CancelMFSIP(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/mf/sips/") && r.Method == "DELETE" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"sip_id": "SIP001",
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	resp, err := c.CancelMFSIP("SIP001")
	if err != nil {
		t.Fatalf("CancelMFSIP error: %v", err)
	}
	if resp.SIPID != "SIP001" {
		t.Errorf("SIPID = %q, want SIP001", resp.SIPID)
	}
}

func TestClient_CancelMFSIP_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"OrderException","message":"SIP not found"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.CancelMFSIP("NONEXISTENT")
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOrderMargins
// ---------------------------------------------------------------------------

func TestClient_GetOrderMargins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/margins/orders" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"type":    "equity",
					"var":     1234.56,
					"span":    5678.90,
					"total":   6913.46,
					"charges": map[string]interface{}{"total": 15.0},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	result, err := c.GetOrderMargins([]broker.OrderMarginParam{
		{
			Exchange:        "NSE",
			Tradingsymbol:   "INFY",
			TransactionType: "BUY",
			Variety:         "regular",
			Product:         "CNC",
			OrderType:       "MARKET",
			Quantity:        10,
		},
	})
	if err != nil {
		t.Fatalf("GetOrderMargins error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func TestClient_GetOrderMargins_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid order params"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOrderMargins([]broker.OrderMarginParam{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetBasketMargins
// ---------------------------------------------------------------------------

func TestClient_GetBasketMargins(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/margins/basket" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, map[string]interface{}{
				"initial": map[string]interface{}{
					"type": "equity", "total": 15000.0,
				},
				"final": map[string]interface{}{
					"type": "equity", "total": 12000.0,
				},
				"orders": []map[string]interface{}{
					{"type": "equity", "total": 7500.0},
					{"type": "equity", "total": 7500.0},
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	result, err := c.GetBasketMargins([]broker.OrderMarginParam{
		{
			Exchange:        "NSE",
			Tradingsymbol:   "INFY",
			TransactionType: "BUY",
			Variety:         "regular",
			Product:         "CNC",
			OrderType:       "LIMIT",
			Quantity:        10,
			Price:           1500,
		},
		{
			Exchange:        "NSE",
			Tradingsymbol:   "RELIANCE",
			TransactionType: "BUY",
			Variety:         "regular",
			Product:         "CNC",
			OrderType:       "LIMIT",
			Quantity:        5,
			Price:           2500,
		},
	}, true)
	if err != nil {
		t.Fatalf("GetBasketMargins error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func TestClient_GetBasketMargins_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid basket"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetBasketMargins([]broker.OrderMarginParam{}, false)
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// GetOrderCharges
// ---------------------------------------------------------------------------

func TestClient_GetOrderCharges(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/charges/orders" && r.Method == "POST" {
			fmt.Fprint(w, jsonEnvelope(t, []map[string]interface{}{
				{
					"transaction_tax":       12.50,
					"total_charges":         25.75,
					"gst":                   map[string]interface{}{"total": 4.63},
					"exchange_turnover_charge": 3.50,
					"sebi_turnover_charge":  0.02,
					"stamp_duty":            1.50,
				},
			}))
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	result, err := c.GetOrderCharges([]broker.OrderChargesParam{
		{
			OrderID:         "ORD001",
			Exchange:        "NSE",
			Tradingsymbol:   "INFY",
			TransactionType: "BUY",
			Quantity:        10,
			AveragePrice:    1500.50,
			Product:         "CNC",
			OrderType:       "MARKET",
			Variety:         "regular",
		},
	})
	if err != nil {
		t.Fatalf("GetOrderCharges error: %v", err)
	}
	if result == nil {
		t.Fatal("result is nil")
	}
}

func TestClient_GetOrderCharges_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid charges params"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetOrderCharges([]broker.OrderChargesParam{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ---------------------------------------------------------------------------
// Factory
// ---------------------------------------------------------------------------

func TestFactory_BrokerName(t *testing.T) {
	t.Parallel()
	f := NewFactory()
	if f.BrokerName() != broker.Zerodha {
		t.Errorf("BrokerName = %q, want %q", f.BrokerName(), broker.Zerodha)
	}
}

func TestFactory_Create(t *testing.T) {
	t.Parallel()
	f := NewFactory()
	c, err := f.Create("test_api_key")
	if err != nil {
		t.Fatalf("Create error: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestFactory_CreateWithToken(t *testing.T) {
	t.Parallel()
	f := NewFactory()
	c, err := f.CreateWithToken("test_api_key", "test_access_token")
	if err != nil {
		t.Fatalf("CreateWithToken error: %v", err)
	}
	if c == nil {
		t.Fatal("client is nil")
	}
}

func TestAuth_GetLoginURL(t *testing.T) {
	t.Parallel()
	a := NewAuth()
	url := a.GetLoginURL("test_api_key")
	if url == "" {
		t.Fatal("GetLoginURL returned empty string")
	}
	if !strings.Contains(url, "test_api_key") {
		t.Errorf("URL = %q, want to contain api_key", url)
	}
}

func TestAuth_ExchangeToken_Error(t *testing.T) {
	t.Parallel()
	// ExchangeToken with invalid credentials should fail (no real server)
	a := NewAuth()
	_, err := a.ExchangeToken("bad_key", "bad_secret", "bad_token")
	if err == nil {
		t.Fatal("expected error from ExchangeToken with invalid credentials")
	}
}

func TestAuth_InvalidateToken_Error(t *testing.T) {
	t.Parallel()
	// InvalidateToken with invalid credentials should fail
	a := NewAuth()
	err := a.InvalidateToken("bad_key", "bad_token")
	if err == nil {
		t.Fatal("expected error from InvalidateToken with invalid credentials")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func mustParseTime(date string) time.Time {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		panic(err)
	}
	return t
}
