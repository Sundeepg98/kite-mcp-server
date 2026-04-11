package mock

import (
	"errors"
	"testing"

	"github.com/zerodha/kite-mcp-server/broker"
)

// ---------------------------------------------------------------------------
// Tests for 0% coverage functions: SetOrders, SetQuotes, GetQuotes,
// GetOrderTrades, SetGTTs, GTTs, GetGTTs, PlaceGTT, ModifyGTT, DeleteGTT,
// NewDemoClient
// ---------------------------------------------------------------------------

func TestSetOrders(t *testing.T) {
	c := New()
	want := []broker.Order{
		{OrderID: "ORD1", Status: "COMPLETE", Tradingsymbol: "INFY"},
		{OrderID: "ORD2", Status: "OPEN", Tradingsymbol: "TCS"},
	}
	c.SetOrders(want)

	got := c.Orders()
	if len(got) != 2 {
		t.Fatalf("len(Orders()) = %d, want 2", len(got))
	}
	if got[0].OrderID != "ORD1" {
		t.Errorf("Orders()[0].OrderID = %q, want %q", got[0].OrderID, "ORD1")
	}
	if got[1].Status != "OPEN" {
		t.Errorf("Orders()[1].Status = %q, want %q", got[1].Status, "OPEN")
	}
}

func TestSetAndGetQuotes(t *testing.T) {
	c := New()
	c.SetQuotes(map[string]broker.Quote{
		"NSE:INFY":     {LastPrice: 1500, Volume: 100000},
		"NSE:RELIANCE": {LastPrice: 2800, Volume: 50000},
	})

	quotes, err := c.GetQuotes("NSE:INFY", "NSE:RELIANCE")
	if err != nil {
		t.Fatalf("GetQuotes() error: %v", err)
	}
	if len(quotes) != 2 {
		t.Fatalf("len(quotes) = %d, want 2", len(quotes))
	}
	if quotes["NSE:INFY"].LastPrice != 1500 {
		t.Errorf("INFY LastPrice = %f, want 1500", quotes["NSE:INFY"].LastPrice)
	}
	if quotes["NSE:RELIANCE"].Volume != 50000 {
		t.Errorf("RELIANCE Volume = %d, want 50000", quotes["NSE:RELIANCE"].Volume)
	}
}

func TestGetQuotes_Subset(t *testing.T) {
	c := New()
	c.SetQuotes(map[string]broker.Quote{
		"NSE:INFY": {LastPrice: 1500},
		"NSE:TCS":  {LastPrice: 4000},
	})

	// Only request one instrument
	quotes, err := c.GetQuotes("NSE:INFY")
	if err != nil {
		t.Fatalf("GetQuotes() error: %v", err)
	}
	if len(quotes) != 1 {
		t.Fatalf("len(quotes) = %d, want 1", len(quotes))
	}
	if _, ok := quotes["NSE:TCS"]; ok {
		t.Error("expected NSE:TCS to be absent from result")
	}
}

func TestGetQuotes_Unknown(t *testing.T) {
	c := New()
	quotes, err := c.GetQuotes("NSE:UNKNOWN")
	if err != nil {
		t.Fatalf("GetQuotes() error: %v", err)
	}
	if len(quotes) != 0 {
		t.Errorf("len(quotes) = %d, want 0 for unknown instrument", len(quotes))
	}
}

func TestGetQuotes_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("quotes error")
	c.GetQuotesErr = injected
	_, err := c.GetQuotes("NSE:INFY")
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

func TestGetOrderTrades(t *testing.T) {
	c := New()
	c.SetTrades([]broker.Trade{
		{TradeID: "T1", OrderID: "ORD1", Tradingsymbol: "INFY", Quantity: 10, Price: 1500},
		{TradeID: "T2", OrderID: "ORD1", Tradingsymbol: "INFY", Quantity: 5, Price: 1510},
		{TradeID: "T3", OrderID: "ORD2", Tradingsymbol: "TCS", Quantity: 1, Price: 4000},
	})

	trades, err := c.GetOrderTrades("ORD1")
	if err != nil {
		t.Fatalf("GetOrderTrades() error: %v", err)
	}
	if len(trades) != 2 {
		t.Fatalf("len(trades) = %d, want 2", len(trades))
	}
	if trades[0].TradeID != "T1" || trades[1].TradeID != "T2" {
		t.Errorf("unexpected trade IDs: %q, %q", trades[0].TradeID, trades[1].TradeID)
	}
}

func TestGetOrderTrades_NotFound(t *testing.T) {
	c := New()
	_, err := c.GetOrderTrades("nonexistent")
	if err == nil {
		t.Fatal("expected error for nonexistent order")
	}
}

func TestGetOrderTrades_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("order trades error")
	c.GetOrderTradesErr = injected
	_, err := c.GetOrderTrades("ORD1")
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

// ---------------------------------------------------------------------------
// GTT operations
// ---------------------------------------------------------------------------

func TestSetGTTs(t *testing.T) {
	c := New()
	want := []broker.GTTOrder{
		{ID: 1, Type: "single", Status: "active"},
		{ID: 2, Type: "two-leg", Status: "active"},
	}
	c.SetGTTs(want)

	got := c.GTTs()
	if len(got) != 2 {
		t.Fatalf("len(GTTs()) = %d, want 2", len(got))
	}
	if got[0].ID != 1 || got[1].ID != 2 {
		t.Errorf("unexpected GTT IDs: %d, %d", got[0].ID, got[1].ID)
	}
}

func TestGetGTTs(t *testing.T) {
	c := New()
	c.SetGTTs([]broker.GTTOrder{
		{ID: 1, Type: "single", Status: "active"},
	})

	gtts, err := c.GetGTTs()
	if err != nil {
		t.Fatalf("GetGTTs() error: %v", err)
	}
	if len(gtts) != 1 {
		t.Fatalf("len(gtts) = %d, want 1", len(gtts))
	}
	if gtts[0].ID != 1 {
		t.Errorf("GTT ID = %d, want 1", gtts[0].ID)
	}
}

func TestGetGTTs_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("gtt error")
	c.GetGTTsErr = injected
	_, err := c.GetGTTs()
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

func TestPlaceGTT_Single(t *testing.T) {
	c := New()
	resp, err := c.PlaceGTT(broker.GTTParams{
		Type:            "single",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		LastPrice:       1500,
		TransactionType: "BUY",
		TriggerValue:    1450,
		LimitPrice:      1440,
		Quantity:        10,
		Product:         "CNC",
	})
	if err != nil {
		t.Fatalf("PlaceGTT() error: %v", err)
	}
	if resp.TriggerID == 0 {
		t.Error("expected non-zero trigger ID")
	}

	gtts := c.GTTs()
	if len(gtts) != 1 {
		t.Fatalf("len(GTTs) = %d, want 1", len(gtts))
	}
	gtt := gtts[0]
	if gtt.Type != "single" {
		t.Errorf("type = %q, want %q", gtt.Type, "single")
	}
	if gtt.Status != "active" {
		t.Errorf("status = %q, want %q", gtt.Status, "active")
	}
	if len(gtt.Condition.TriggerValues) != 1 || gtt.Condition.TriggerValues[0] != 1450 {
		t.Errorf("TriggerValues = %v, want [1450]", gtt.Condition.TriggerValues)
	}
	if len(gtt.Orders) != 1 {
		t.Fatalf("len(Orders) = %d, want 1", len(gtt.Orders))
	}
	if gtt.Orders[0].Price != 1440 {
		t.Errorf("order price = %f, want 1440", gtt.Orders[0].Price)
	}
}

func TestPlaceGTT_TwoLeg(t *testing.T) {
	c := New()
	resp, err := c.PlaceGTT(broker.GTTParams{
		Type:              "two-leg",
		Exchange:          "NSE",
		Tradingsymbol:     "INFY",
		LastPrice:         1500,
		TransactionType:   "SELL",
		LowerTriggerValue: 1400,
		UpperTriggerValue: 1600,
		LowerLimitPrice:   1390,
		UpperLimitPrice:   1610,
		LowerQuantity:     5,
		UpperQuantity:     5,
		Product:           "CNC",
	})
	if err != nil {
		t.Fatalf("PlaceGTT() error: %v", err)
	}
	if resp.TriggerID == 0 {
		t.Error("expected non-zero trigger ID")
	}

	gtts := c.GTTs()
	if len(gtts) != 1 {
		t.Fatalf("len(GTTs) = %d, want 1", len(gtts))
	}
	if len(gtts[0].Condition.TriggerValues) != 2 {
		t.Fatalf("TriggerValues len = %d, want 2", len(gtts[0].Condition.TriggerValues))
	}
	if len(gtts[0].Orders) != 2 {
		t.Fatalf("Orders len = %d, want 2", len(gtts[0].Orders))
	}
	if gtts[0].Orders[0].Price != 1390 {
		t.Errorf("lower order price = %f, want 1390", gtts[0].Orders[0].Price)
	}
	if gtts[0].Orders[1].Price != 1610 {
		t.Errorf("upper order price = %f, want 1610", gtts[0].Orders[1].Price)
	}
}

func TestPlaceGTT_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("place gtt error")
	c.PlaceGTTErr = injected
	_, err := c.PlaceGTT(broker.GTTParams{})
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

func TestModifyGTT(t *testing.T) {
	c := New()
	resp, _ := c.PlaceGTT(broker.GTTParams{
		Type:          "single",
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		LastPrice:     1500,
		TriggerValue:  1450,
		Product:       "CNC",
	})

	// Modify
	modResp, err := c.ModifyGTT(resp.TriggerID, broker.GTTParams{
		Type:      "single",
		LastPrice: 1600,
	})
	if err != nil {
		t.Fatalf("ModifyGTT() error: %v", err)
	}
	if modResp.TriggerID != resp.TriggerID {
		t.Errorf("trigger ID = %d, want %d", modResp.TriggerID, resp.TriggerID)
	}

	gtts := c.GTTs()
	if gtts[0].Condition.LastPrice != 1600 {
		t.Errorf("LastPrice after modify = %f, want 1600", gtts[0].Condition.LastPrice)
	}
}

func TestModifyGTT_NotFound(t *testing.T) {
	c := New()
	_, err := c.ModifyGTT(99999, broker.GTTParams{})
	if err == nil {
		t.Fatal("expected error for nonexistent GTT")
	}
}

func TestModifyGTT_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("modify gtt error")
	c.ModifyGTTErr = injected
	_, err := c.ModifyGTT(1, broker.GTTParams{})
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

func TestDeleteGTT(t *testing.T) {
	c := New()
	resp, _ := c.PlaceGTT(broker.GTTParams{
		Type:          "single",
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		LastPrice:     1500,
		TriggerValue:  1450,
		Product:       "CNC",
	})

	delResp, err := c.DeleteGTT(resp.TriggerID)
	if err != nil {
		t.Fatalf("DeleteGTT() error: %v", err)
	}
	if delResp.TriggerID != resp.TriggerID {
		t.Errorf("trigger ID = %d, want %d", delResp.TriggerID, resp.TriggerID)
	}
	if len(c.GTTs()) != 0 {
		t.Errorf("expected 0 GTTs after delete, got %d", len(c.GTTs()))
	}
}

func TestDeleteGTT_NotFound(t *testing.T) {
	c := New()
	_, err := c.DeleteGTT(99999)
	if err == nil {
		t.Fatal("expected error for nonexistent GTT")
	}
}

func TestDeleteGTT_ErrorInjection(t *testing.T) {
	c := New()
	injected := errors.New("delete gtt error")
	c.DeleteGTTErr = injected
	_, err := c.DeleteGTT(1)
	if !errors.Is(err, injected) {
		t.Errorf("got err %v, want %v", err, injected)
	}
}

// ---------------------------------------------------------------------------
// Multiple GTTs: PlaceGTT increments IDs
// ---------------------------------------------------------------------------

func TestPlaceGTT_IncrementingIDs(t *testing.T) {
	c := New()
	var ids []int
	for i := 0; i < 3; i++ {
		resp, err := c.PlaceGTT(broker.GTTParams{
			Type:          "single",
			Exchange:      "NSE",
			Tradingsymbol: "INFY",
			LastPrice:     1500,
			TriggerValue:  1450,
			Product:       "CNC",
		})
		if err != nil {
			t.Fatalf("PlaceGTT[%d] error: %v", i, err)
		}
		ids = append(ids, resp.TriggerID)
	}
	// Each ID should be unique and incrementing
	for i := 1; i < len(ids); i++ {
		if ids[i] <= ids[i-1] {
			t.Errorf("IDs should be incrementing: %v", ids)
		}
	}
}

// ---------------------------------------------------------------------------
// NewDemoClient
// ---------------------------------------------------------------------------

func TestNewDemoClient(t *testing.T) {
	c := NewDemoClient()
	if c == nil {
		t.Fatal("NewDemoClient() returned nil")
	}

	p, err := c.GetProfile()
	if err != nil {
		t.Fatalf("GetProfile() error: %v", err)
	}
	if p.UserID != "DEMO01" {
		t.Errorf("UserID = %q, want %q", p.UserID, "DEMO01")
	}
	if p.Email != "demo@kitemcp.dev" {
		t.Errorf("Email = %q, want %q", p.Email, "demo@kitemcp.dev")
	}

	h, err := c.GetHoldings()
	if err != nil {
		t.Fatalf("GetHoldings() error: %v", err)
	}
	if len(h) != 5 {
		t.Errorf("len(holdings) = %d, want 5", len(h))
	}

	m, err := c.GetMargins()
	if err != nil {
		t.Fatalf("GetMargins() error: %v", err)
	}
	if m.Equity.Available != 450000.0 {
		t.Errorf("Equity.Available = %f, want 450000", m.Equity.Available)
	}

	ltp, err := c.GetLTP("NSE:RELIANCE")
	if err != nil {
		t.Fatalf("GetLTP() error: %v", err)
	}
	if ltp["NSE:RELIANCE"].LastPrice != 2812.50 {
		t.Errorf("RELIANCE LTP = %f, want 2812.50", ltp["NSE:RELIANCE"].LastPrice)
	}
}

// ---------------------------------------------------------------------------
// GTTs() returns a copy
// ---------------------------------------------------------------------------

func TestGTTs_ReturnsCopy(t *testing.T) {
	c := New()
	c.PlaceGTT(broker.GTTParams{
		Type: "single", Exchange: "NSE", Tradingsymbol: "INFY",
		LastPrice: 1500, TriggerValue: 1450, Product: "CNC",
	})

	got := c.GTTs()
	got[0].Status = "mutated"

	// The store should be unaffected
	original := c.GTTs()
	if original[0].Status == "mutated" {
		t.Error("GTTs() should return a copy, but store was mutated")
	}
}
