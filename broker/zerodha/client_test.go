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
// Helpers
// ---------------------------------------------------------------------------

func mustParseTime(date string) time.Time {
	t, err := time.Parse("2006-01-02", date)
	if err != nil {
		panic(err)
	}
	return t
}
