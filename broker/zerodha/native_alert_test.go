package zerodha

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/broker"
)

// --- convert helpers ---

func TestConvertNativeAlertParamsToKite(t *testing.T) {
	t.Parallel()
	p := broker.NativeAlertParams{
		Name:             "Test",
		Type:             "simple",
		LHSExchange:      "NSE",
		LHSTradingSymbol: "INFY",
		LHSAttribute:     "last_price",
		Operator:         ">=",
		RHSType:          "constant",
		RHSConstant:      1500,
	}
	kp := convertNativeAlertParamsToKite(p)
	if kp.Name != "Test" {
		t.Errorf("Name = %q, want Test", kp.Name)
	}
	if kp.LHSExchange != "NSE" {
		t.Errorf("LHSExchange = %q, want NSE", kp.LHSExchange)
	}
	if kp.Basket != nil {
		t.Error("expected nil basket for non-ATO alert")
	}
}

func TestConvertNativeAlertParamsToKite_WithBasket(t *testing.T) {
	t.Parallel()
	basketJSON := `{"name":"test_basket","type":"ato","tags":["tag1"],"items":[]}`
	p := broker.NativeAlertParams{
		Name:       "ATO Alert",
		Type:       "ato",
		BasketJSON: basketJSON,
	}
	kp := convertNativeAlertParamsToKite(p)
	if kp.Basket == nil {
		t.Fatal("expected basket to be set for ATO alert")
	}
	if kp.Basket.Name != "test_basket" {
		t.Errorf("Basket.Name = %q, want test_basket", kp.Basket.Name)
	}
}

func TestConvertNativeAlertParamsToKite_InvalidBasketJSON(t *testing.T) {
	t.Parallel()
	p := broker.NativeAlertParams{
		Name:       "ATO Alert",
		BasketJSON: "not json",
	}
	kp := convertNativeAlertParamsToKite(p)
	if kp.Basket != nil {
		t.Error("expected nil basket for invalid JSON")
	}
}

func TestConvertNativeAlert(t *testing.T) {
	t.Parallel()
	now := time.Now()
	a := kiteconnect.Alert{
		UUID:             "test-uuid",
		Name:             "Test Alert",
		Type:             kiteconnect.AlertTypeSimple,
		Status:           kiteconnect.AlertStatusEnabled,
		LHSExchange:      "NSE",
		LHSTradingSymbol: "INFY",
		LHSAttribute:     "last_price",
		Operator:         kiteconnect.AlertOperatorGE,
		RHSType:          "constant",
		RHSConstant:      1500,
		AlertCount:       2,
		CreatedAt:        models.Time{Time: now},
		UpdatedAt:        models.Time{Time: now},
	}
	result := convertNativeAlert(a)
	if result.UUID != "test-uuid" {
		t.Errorf("UUID = %q, want test-uuid", result.UUID)
	}
	if result.Name != "Test Alert" {
		t.Errorf("Name = %q, want Test Alert", result.Name)
	}
	if result.AlertCount != 2 {
		t.Errorf("AlertCount = %d, want 2", result.AlertCount)
	}
}

func TestConvertNativeAlerts(t *testing.T) {
	t.Parallel()
	alerts := []kiteconnect.Alert{
		{UUID: "a1", Name: "Alert 1"},
		{UUID: "a2", Name: "Alert 2"},
	}
	result := convertNativeAlerts(alerts)
	if len(result) != 2 {
		t.Fatalf("len = %d, want 2", len(result))
	}
	if result[0].UUID != "a1" {
		t.Errorf("result[0].UUID = %q, want a1", result[0].UUID)
	}
}

func TestConvertNativeAlertHistory(t *testing.T) {
	t.Parallel()
	now := time.Now()
	history := []kiteconnect.AlertHistory{
		{
			UUID:      "h1",
			Type:      kiteconnect.AlertTypeSimple,
			Condition: "INFY last_price >= 1500",
			CreatedAt: models.Time{Time: now},
			Meta:      []kiteconnect.AlertHistoryMeta{{TradingSymbol: "INFY"}},
			OrderMeta: "order-meta",
		},
	}
	result := convertNativeAlertHistory(history)
	if len(result) != 1 {
		t.Fatalf("len = %d, want 1", len(result))
	}
	if result[0].UUID != "h1" {
		t.Errorf("UUID = %q, want h1", result[0].UUID)
	}
	if result[0].Condition != "INFY last_price >= 1500" {
		t.Errorf("Condition = %q", result[0].Condition)
	}
}

// --- Client method tests ---

func TestClient_CreateNativeAlert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost && r.URL.Path == "/alerts" {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"uuid": "new-uuid",
					"name": "Price Alert",
					"type": "simple",
					"status": "enabled",
					"lhs_exchange": "NSE",
					"lhs_tradingsymbol": "INFY",
					"lhs_attribute": "last_price",
					"operator": ">=",
					"rhs_type": "constant",
					"rhs_constant": 1500,
					"alert_count": 0,
					"created_at": "2026-04-01 10:00:00",
					"updated_at": "2026-04-01 10:00:00",
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	alert, err := c.CreateNativeAlert(broker.NativeAlertParams{
		Name: "Price Alert", Type: "simple", LHSExchange: "NSE",
		LHSTradingSymbol: "INFY", LHSAttribute: "last_price",
		Operator: ">=", RHSType: "constant", RHSConstant: 1500,
	})
	if err != nil {
		t.Fatalf("CreateNativeAlert error: %v", err)
	}
	if alert.UUID != "new-uuid" {
		t.Errorf("UUID = %q, want new-uuid", alert.UUID)
	}
}

func TestClient_CreateNativeAlert_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"InputException","message":"invalid params"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.CreateNativeAlert(broker.NativeAlertParams{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetNativeAlerts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/alerts" {
			resp := map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"uuid": "a1", "name": "Alert 1", "type": "simple",
						"status": "enabled", "lhs_exchange": "NSE",
						"lhs_tradingsymbol": "INFY", "alert_count": 1,
						"created_at": "2026-04-01 10:00:00",
						"updated_at": "2026-04-01 10:00:00",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	alerts, err := c.GetNativeAlerts(nil)
	if err != nil {
		t.Fatalf("GetNativeAlerts error: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("len = %d, want 1", len(alerts))
	}
	if alerts[0].UUID != "a1" {
		t.Errorf("UUID = %q, want a1", alerts[0].UUID)
	}
}

func TestClient_GetNativeAlerts_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"status":"error","message":"server error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetNativeAlerts(nil)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_ModifyNativeAlert(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/alerts/test-uuid" {
			resp := map[string]interface{}{
				"data": map[string]interface{}{
					"uuid": "test-uuid", "name": "Modified Alert",
					"type": "simple", "status": "enabled",
					"created_at": "2026-04-01 10:00:00",
					"updated_at": "2026-04-01 11:00:00",
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	alert, err := c.ModifyNativeAlert("test-uuid", broker.NativeAlertParams{
		Name: "Modified Alert",
	})
	if err != nil {
		t.Fatalf("ModifyNativeAlert error: %v", err)
	}
	if alert.UUID != "test-uuid" {
		t.Errorf("UUID = %q, want test-uuid", alert.UUID)
	}
}

func TestClient_ModifyNativeAlert_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","message":"invalid"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.ModifyNativeAlert("test-uuid", broker.NativeAlertParams{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_DeleteNativeAlerts(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodDelete {
			fmt.Fprint(w, `{"status":"success","data":null}`)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	err := c.DeleteNativeAlerts("uuid1", "uuid2")
	if err != nil {
		t.Fatalf("DeleteNativeAlerts error: %v", err)
	}
}

func TestClient_DeleteNativeAlerts_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400)
		fmt.Fprint(w, `{"status":"error","error_type":"GeneralException","message":"server error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	err := c.DeleteNativeAlerts("uuid1")
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestClient_GetNativeAlertHistory(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && r.URL.Path == "/alerts/test-uuid/history" {
			resp := map[string]interface{}{
				"data": []map[string]interface{}{
					{
						"uuid": "h1", "type": "simple",
						"condition": "INFY >= 1500",
						"created_at": "2026-04-01 12:00:00",
					},
				},
			}
			json.NewEncoder(w).Encode(resp)
			return
		}
		http.Error(w, `{"status":"error","message":"not found"}`, 404)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	history, err := c.GetNativeAlertHistory("test-uuid")
	if err != nil {
		t.Fatalf("GetNativeAlertHistory error: %v", err)
	}
	if len(history) != 1 {
		t.Fatalf("len = %d, want 1", len(history))
	}
	if history[0].UUID != "h1" {
		t.Errorf("UUID = %q, want h1", history[0].UUID)
	}
}

func TestClient_GetNativeAlertHistory_Error(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
		fmt.Fprint(w, `{"status":"error","message":"server error"}`)
	}))
	defer ts.Close()

	c := New(newTestKiteClient(ts))
	_, err := c.GetNativeAlertHistory("test-uuid")
	if err == nil {
		t.Fatal("expected error")
	}
}

