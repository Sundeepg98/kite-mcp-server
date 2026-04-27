package zerodha

import (
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/broker"
)

func TestConvertProfile(t *testing.T) {
	t.Parallel()
	kp := kiteconnect.UserProfile{
		UserID:    "AB1234",
		UserName:  "Test User",
		Email:     "test@example.com",
		Broker:    "ZERODHA",
		Exchanges: []string{"NSE", "BSE", "NFO"},
		Products:  []string{"CNC", "MIS", "NRML"},
	}

	p := convertProfile(kp)

	if p.UserID != "AB1234" {
		t.Errorf("UserID = %q, want %q", p.UserID, "AB1234")
	}
	if p.UserName != "Test User" {
		t.Errorf("UserName = %q, want %q", p.UserName, "Test User")
	}
	if p.Email != "test@example.com" {
		t.Errorf("Email = %q, want %q", p.Email, "test@example.com")
	}
	if p.Broker != broker.Zerodha {
		t.Errorf("Broker = %q, want %q", p.Broker, broker.Zerodha)
	}
	if len(p.Exchanges) != 3 {
		t.Errorf("Exchanges count = %d, want 3", len(p.Exchanges))
	}
	if len(p.Products) != 3 {
		t.Errorf("Products count = %d, want 3", len(p.Products))
	}
}

func TestConvertHoldings(t *testing.T) {
	t.Parallel()
	kh := kiteconnect.Holdings{
		{
			Tradingsymbol:       "INFY",
			Exchange:            "NSE",
			ISIN:                "INE009A01021",
			Quantity:            10,
			AveragePrice:        1500.50,
			LastPrice:           1600.75,
			PnL:                 1002.50,
			DayChangePercentage: 1.25,
			Product:             "CNC",
		},
		{
			Tradingsymbol:       "RELIANCE",
			Exchange:            "BSE",
			ISIN:                "INE002A01018",
			Quantity:            5,
			AveragePrice:        2400.00,
			LastPrice:           2350.00,
			PnL:                 -250.00,
			DayChangePercentage: -0.85,
			Product:             "CNC",
		},
	}

	holdings := convertHoldings(kh)

	if len(holdings) != 2 {
		t.Fatalf("len = %d, want 2", len(holdings))
	}

	h := holdings[0]
	if h.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want %q", h.Tradingsymbol, "INFY")
	}
	if h.Exchange != "NSE" {
		t.Errorf("Exchange = %q, want %q", h.Exchange, "NSE")
	}
	if h.ISIN != "INE009A01021" {
		t.Errorf("ISIN = %q, want %q", h.ISIN, "INE009A01021")
	}
	if h.Quantity != 10 {
		t.Errorf("Quantity = %d, want 10", h.Quantity)
	}
	if h.AveragePrice != 1500.50 {
		t.Errorf("AveragePrice = %f, want 1500.50", h.AveragePrice)
	}
	if h.LastPrice != 1600.75 {
		t.Errorf("LastPrice = %f, want 1600.75", h.LastPrice)
	}
	if h.PnL.Float64() != 1002.50 {
		t.Errorf("PnL = %f, want 1002.50", h.PnL.Float64())
	}
	if h.DayChangePct != 1.25 {
		t.Errorf("DayChangePct = %f, want 1.25", h.DayChangePct)
	}
	if h.Product != "CNC" {
		t.Errorf("Product = %q, want %q", h.Product, "CNC")
	}
}

func TestConvertHoldingsEmpty(t *testing.T) {
	t.Parallel()
	holdings := convertHoldings(kiteconnect.Holdings{})
	if len(holdings) != 0 {
		t.Errorf("len = %d, want 0", len(holdings))
	}
}

func TestConvertPositions(t *testing.T) {
	t.Parallel()
	kp := kiteconnect.Positions{
		Day: []kiteconnect.Position{
			{
				Tradingsymbol: "SBIN",
				Exchange:      "NSE",
				Product:       "MIS",
				Quantity:      100,
				AveragePrice:  550.25,
				LastPrice:     555.00,
				PnL:           475.00,
			},
		},
		Net: []kiteconnect.Position{
			{
				Tradingsymbol: "SBIN",
				Exchange:      "NSE",
				Product:       "MIS",
				Quantity:      100,
				AveragePrice:  550.25,
				LastPrice:     555.00,
				PnL:           475.00,
			},
		},
	}

	pos := convertPositions(kp)

	if len(pos.Day) != 1 {
		t.Fatalf("Day len = %d, want 1", len(pos.Day))
	}
	if len(pos.Net) != 1 {
		t.Fatalf("Net len = %d, want 1", len(pos.Net))
	}

	d := pos.Day[0]
	if d.Tradingsymbol != "SBIN" {
		t.Errorf("Tradingsymbol = %q, want %q", d.Tradingsymbol, "SBIN")
	}
	if d.Quantity != 100 {
		t.Errorf("Quantity = %d, want 100", d.Quantity)
	}
}

func TestConvertOrders(t *testing.T) {
	t.Parallel()
	ts := models.Time{Time: time.Date(2026, 4, 3, 9, 30, 0, 0, time.UTC)}
	ko := kiteconnect.Orders{
		{
			OrderID:         "ORD001",
			Exchange:        "NSE",
			TradingSymbol:   "INFY",
			TransactionType: "BUY",
			OrderType:       "LIMIT",
			Product:         "CNC",
			Quantity:        10,
			Price:           1500.00,
			TriggerPrice:    0,
			Status:          "COMPLETE",
			FilledQuantity:  10,
			AveragePrice:    1498.50,
			OrderTimestamp:  ts,
			StatusMessage:   "",
			Tag:             "mcp",
		},
	}

	orders := convertOrders(ko)

	if len(orders) != 1 {
		t.Fatalf("len = %d, want 1", len(orders))
	}

	o := orders[0]
	if o.OrderID != "ORD001" {
		t.Errorf("OrderID = %q, want %q", o.OrderID, "ORD001")
	}
	if o.Exchange != "NSE" {
		t.Errorf("Exchange = %q, want %q", o.Exchange, "NSE")
	}
	if o.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want %q", o.Tradingsymbol, "INFY")
	}
	if o.TransactionType != "BUY" {
		t.Errorf("TransactionType = %q, want %q", o.TransactionType, "BUY")
	}
	if o.Quantity != 10 {
		t.Errorf("Quantity = %d, want 10", o.Quantity)
	}
	if o.FilledQuantity != 10 {
		t.Errorf("FilledQuantity = %d, want 10", o.FilledQuantity)
	}
	if o.Status != "COMPLETE" {
		t.Errorf("Status = %q, want %q", o.Status, "COMPLETE")
	}
	if o.Tag != "mcp" {
		t.Errorf("Tag = %q, want %q", o.Tag, "mcp")
	}
}

func TestConvertTrades(t *testing.T) {
	t.Parallel()
	kt := kiteconnect.Trades{
		{
			TradeID:         "TRD001",
			OrderID:         "ORD001",
			Exchange:        "NSE",
			TradingSymbol:   "INFY",
			TransactionType: "BUY",
			Quantity:        10,
			AveragePrice:    1498.50,
			Product:         "CNC",
		},
	}

	trades := convertTrades(kt)

	if len(trades) != 1 {
		t.Fatalf("len = %d, want 1", len(trades))
	}

	tr := trades[0]
	if tr.TradeID != "TRD001" {
		t.Errorf("TradeID = %q, want %q", tr.TradeID, "TRD001")
	}
	if tr.OrderID != "ORD001" {
		t.Errorf("OrderID = %q, want %q", tr.OrderID, "ORD001")
	}
	if tr.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want %q", tr.Tradingsymbol, "INFY")
	}
	// Price in broker.Trade maps to AveragePrice from kite Trade
	if tr.Price != 1498.50 {
		t.Errorf("Price = %f, want 1498.50", tr.Price)
	}
}

func TestConvertOrderParamsToKite(t *testing.T) {
	t.Parallel()
	bp := broker.OrderParams{
		Exchange:         "NSE",
		Tradingsymbol:    "INFY",
		TransactionType:  "BUY",
		OrderType:        "LIMIT",
		Product:          "CNC",
		Quantity:         10,
		Price:            1500.00,
		TriggerPrice:     0,
		Validity:         "DAY",
		Tag:              "mcp",
		Variety:          "amo",
		DisclosedQty:     5,
		MarketProtection: -1,
	}

	variety, kp := convertOrderParamsToKite(bp)

	if variety != "amo" {
		t.Errorf("variety = %q, want %q", variety, "amo")
	}
	if kp.Exchange != "NSE" {
		t.Errorf("Exchange = %q, want %q", kp.Exchange, "NSE")
	}
	if kp.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want %q", kp.Tradingsymbol, "INFY")
	}
	if kp.Quantity != 10 {
		t.Errorf("Quantity = %d, want 10", kp.Quantity)
	}
	if kp.Price != 1500.00 {
		t.Errorf("Price = %f, want 1500.00", kp.Price)
	}
	if kp.DisclosedQuantity != 5 {
		t.Errorf("DisclosedQuantity = %d, want 5", kp.DisclosedQuantity)
	}
	if kp.MarketProtection != -1 {
		t.Errorf("MarketProtection = %f, want -1", kp.MarketProtection)
	}
}

func TestConvertOrderParamsDefaultVariety(t *testing.T) {
	t.Parallel()
	bp := broker.OrderParams{
		Exchange: "NSE",
		// Variety is empty
	}

	variety, _ := convertOrderParamsToKite(bp)

	if variety != "regular" {
		t.Errorf("variety = %q, want %q", variety, "regular")
	}
}

func TestConvertLTP(t *testing.T) {
	t.Parallel()
	kl := kiteconnect.QuoteLTP{
		"NSE:INFY": {
			InstrumentToken: 408065,
			LastPrice:       1600.75,
		},
		"NSE:SBIN": {
			InstrumentToken: 779521,
			LastPrice:       555.00,
		},
	}

	ltp := convertLTP(kl)

	if len(ltp) != 2 {
		t.Fatalf("len = %d, want 2", len(ltp))
	}
	if ltp["NSE:INFY"].LastPrice != 1600.75 {
		t.Errorf("NSE:INFY LastPrice = %f, want 1600.75", ltp["NSE:INFY"].LastPrice)
	}
	if ltp["NSE:SBIN"].LastPrice != 555.00 {
		t.Errorf("NSE:SBIN LastPrice = %f, want 555.00", ltp["NSE:SBIN"].LastPrice)
	}
}

func TestConvertOHLC(t *testing.T) {
	t.Parallel()
	ko := kiteconnect.QuoteOHLC{
		"NSE:INFY": {
			InstrumentToken: 408065,
			LastPrice:       1600.75,
			OHLC: models.OHLC{
				Open:  1590.00,
				High:  1610.00,
				Low:   1585.00,
				Close: 1595.00,
			},
		},
	}

	ohlc := convertOHLC(ko)

	if len(ohlc) != 1 {
		t.Fatalf("len = %d, want 1", len(ohlc))
	}
	o := ohlc["NSE:INFY"]
	if o.Open != 1590.00 {
		t.Errorf("Open = %f, want 1590.00", o.Open)
	}
	if o.High != 1610.00 {
		t.Errorf("High = %f, want 1610.00", o.High)
	}
	if o.Low != 1585.00 {
		t.Errorf("Low = %f, want 1585.00", o.Low)
	}
	if o.Close != 1595.00 {
		t.Errorf("Close = %f, want 1595.00", o.Close)
	}
	if o.LastPrice != 1600.75 {
		t.Errorf("LastPrice = %f, want 1600.75", o.LastPrice)
	}
}

func TestConvertHistoricalData(t *testing.T) {
	t.Parallel()
	ts := models.Time{Time: time.Date(2026, 4, 1, 9, 15, 0, 0, time.UTC)}
	kh := []kiteconnect.HistoricalData{
		{
			Date:   ts,
			Open:   1590.00,
			High:   1610.00,
			Low:    1585.00,
			Close:  1600.00,
			Volume: 150000,
		},
	}

	candles := convertHistoricalData(kh)

	if len(candles) != 1 {
		t.Fatalf("len = %d, want 1", len(candles))
	}
	c := candles[0]
	if c.Open != 1590.00 {
		t.Errorf("Open = %f, want 1590.00", c.Open)
	}
	if c.Volume != 150000 {
		t.Errorf("Volume = %d, want 150000", c.Volume)
	}
	if c.Date.Year() != 2026 {
		t.Errorf("Date year = %d, want 2026", c.Date.Year())
	}
}

func TestConvertSegmentMargin(t *testing.T) {
	t.Parallel()
	km := kiteconnect.Margins{
		Enabled: true,
		Net:     100000,
		Available: kiteconnect.AvailableMargins{
			Cash:           50000,
			Collateral:     20000,
			IntradayPayin:  5000,
			OpeningBalance: 30000,
		},
		Used: kiteconnect.UsedMargins{
			Debits:        10000,
			Exposure:      5000,
			Span:          3000,
			OptionPremium: 2000,
		},
	}

	sm := convertSegmentMargin(km)

	// Available = Cash + Collateral + IntradayPayin + OpeningBalance = 105000
	if sm.Available != 105000 {
		t.Errorf("Available = %f, want 105000", sm.Available)
	}
	// Used = Debits + Exposure + Span + OptionPremium = 20000
	if sm.Used != 20000 {
		t.Errorf("Used = %f, want 20000", sm.Used)
	}
	// Total = Available + Used = 125000
	if sm.Total != 125000 {
		t.Errorf("Total = %f, want 125000", sm.Total)
	}
}

func TestBrokerName(t *testing.T) {
	t.Parallel()
	c := &Client{}
	if c.BrokerName() != broker.Zerodha {
		t.Errorf("BrokerName = %q, want %q", c.BrokerName(), broker.Zerodha)
	}
}

func TestNew(t *testing.T) {
	t.Parallel()
	kite := kiteconnect.New("test-api-key")
	c := New(kite)
	if c == nil {
		t.Fatal("New should return non-nil Client")
	}
	// Phase 3: sdk is a KiteSDK interface backed by the real
	// *kiteSDKAdapter wrapping the passed *kiteconnect.Client.
	adapter, ok := c.sdk.(*kiteSDKAdapter)
	if !ok {
		t.Fatalf("sdk field should be *kiteSDKAdapter, got %T", c.sdk)
	}
	if adapter.kc != kite {
		t.Error("kiteSDKAdapter should wrap the passed *kiteconnect.Client")
	}
}

func TestKite(t *testing.T) {
	t.Parallel()
	kite := kiteconnect.New("test-api-key")
	c := New(kite)
	if c.Kite() != kite {
		t.Error("Kite() should return the underlying *kiteconnect.Client via adapter unwrap")
	}
}

func TestConvertMargins(t *testing.T) {
	t.Parallel()
	km := kiteconnect.AllMargins{
		Equity: kiteconnect.Margins{
			Available: kiteconnect.AvailableMargins{
				Cash: 50000, Collateral: 10000, IntradayPayin: 0, OpeningBalance: 20000,
			},
			Used: kiteconnect.UsedMargins{
				Debits: 5000, Exposure: 3000, Span: 2000, OptionPremium: 1000,
			},
		},
		Commodity: kiteconnect.Margins{
			Available: kiteconnect.AvailableMargins{
				Cash: 10000, Collateral: 5000, IntradayPayin: 1000, OpeningBalance: 4000,
			},
			Used: kiteconnect.UsedMargins{
				Debits: 1000, Exposure: 500, Span: 500, OptionPremium: 0,
			},
		},
	}

	m := convertMargins(km)

	// Equity: Available = 50000 + 10000 + 0 + 20000 = 80000
	if m.Equity.Available != 80000 {
		t.Errorf("Equity Available = %f, want 80000", m.Equity.Available)
	}
	// Equity: Used = 5000 + 3000 + 2000 + 1000 = 11000
	if m.Equity.Used != 11000 {
		t.Errorf("Equity Used = %f, want 11000", m.Equity.Used)
	}
	// Equity: Total = 80000 + 11000 = 91000
	if m.Equity.Total != 91000 {
		t.Errorf("Equity Total = %f, want 91000", m.Equity.Total)
	}

	// Commodity: Available = 10000 + 5000 + 1000 + 4000 = 20000
	if m.Commodity.Available != 20000 {
		t.Errorf("Commodity Available = %f, want 20000", m.Commodity.Available)
	}
	// Commodity: Used = 1000 + 500 + 500 + 0 = 2000
	if m.Commodity.Used != 2000 {
		t.Errorf("Commodity Used = %f, want 2000", m.Commodity.Used)
	}
}

func TestConvertQuotes(t *testing.T) {
	t.Parallel()
	kq := kiteconnect.Quote{
		"NSE:RELIANCE": {
			InstrumentToken:   738561,
			LastPrice:         2500.0,
			LastQuantity:      100,
			AveragePrice:      2490.0,
			Volume:            5000000,
			BuyQuantity:       1000000,
			SellQuantity:      800000,
			NetChange:         25.0,
			OI:                0,
			OIDayHigh:         0,
			OIDayLow:          0,
			LowerCircuitLimit: 2000.0,
			UpperCircuitLimit: 3000.0,
			OHLC: models.OHLC{
				Open:  2480.0,
				High:  2510.0,
				Low:   2475.0,
				Close: 2475.0,
			},
			Depth: models.Depth{
				Buy: [5]models.DepthItem{
					{Price: 2499.0, Quantity: 100, Orders: 5},
					{Price: 2498.0, Quantity: 200, Orders: 10},
				},
				Sell: [5]models.DepthItem{
					{Price: 2501.0, Quantity: 150, Orders: 8},
					{Price: 2502.0, Quantity: 300, Orders: 12},
				},
			},
		},
	}

	quotes := convertQuotes(kq)

	if len(quotes) != 1 {
		t.Fatalf("len = %d, want 1", len(quotes))
	}
	q := quotes["NSE:RELIANCE"]
	if q.InstrumentToken != 738561 {
		t.Errorf("InstrumentToken = %d, want 738561", q.InstrumentToken)
	}
	if q.LastPrice != 2500.0 {
		t.Errorf("LastPrice = %f, want 2500", q.LastPrice)
	}
	if q.Volume != 5000000 {
		t.Errorf("Volume = %d, want 5000000", q.Volume)
	}
	if q.OHLC.Open != 2480.0 {
		t.Errorf("OHLC.Open = %f, want 2480", q.OHLC.Open)
	}
	if q.LowerCircuitLimit != 2000.0 {
		t.Errorf("LowerCircuitLimit = %f, want 2000", q.LowerCircuitLimit)
	}
	if q.UpperCircuitLimit != 3000.0 {
		t.Errorf("UpperCircuitLimit = %f, want 3000", q.UpperCircuitLimit)
	}
	if q.NetChange != 25.0 {
		t.Errorf("NetChange = %f, want 25", q.NetChange)
	}
	// Depth.
	if q.Depth.Buy[0].Price != 2499.0 {
		t.Errorf("Depth.Buy[0].Price = %f, want 2499", q.Depth.Buy[0].Price)
	}
	if q.Depth.Buy[0].Quantity != 100 {
		t.Errorf("Depth.Buy[0].Quantity = %d, want 100", q.Depth.Buy[0].Quantity)
	}
	if q.Depth.Sell[0].Price != 2501.0 {
		t.Errorf("Depth.Sell[0].Price = %f, want 2501", q.Depth.Sell[0].Price)
	}
	if q.Depth.Sell[1].Orders != 12 {
		t.Errorf("Depth.Sell[1].Orders = %d, want 12", q.Depth.Sell[1].Orders)
	}
}

func TestConvertQuotesEmpty(t *testing.T) {
	t.Parallel()
	quotes := convertQuotes(kiteconnect.Quote{})
	if len(quotes) != 0 {
		t.Errorf("len = %d, want 0", len(quotes))
	}
}

func TestConvertGTTs(t *testing.T) {
	t.Parallel()
	ts := models.Time{Time: time.Date(2026, 4, 5, 10, 0, 0, 0, time.UTC)}
	kgtts := kiteconnect.GTTs{
		{
			ID:     1001,
			Type:   "single",
			Status: "active",
			Condition: kiteconnect.GTTCondition{
				Exchange:      "NSE",
				Tradingsymbol: "RELIANCE",
				TriggerValues: []float64{2400.0},
				LastPrice:     2500.0,
			},
			Orders: []kiteconnect.Order{
				{
					Exchange:        "NSE",
					TradingSymbol:   "RELIANCE",
					TransactionType: "BUY",
					Quantity:        10,
					OrderType:       "LIMIT",
					Price:           2390.0,
					Product:         "CNC",
				},
			},
			CreatedAt: ts,
			UpdatedAt: ts,
			ExpiresAt: ts,
		},
	}

	gtts := convertGTTs(kgtts)

	if len(gtts) != 1 {
		t.Fatalf("len = %d, want 1", len(gtts))
	}
	g := gtts[0]
	if g.ID != 1001 {
		t.Errorf("ID = %d, want 1001", g.ID)
	}
	if g.Type != "single" {
		t.Errorf("Type = %q, want %q", g.Type, "single")
	}
	if g.Status != "active" {
		t.Errorf("Status = %q, want %q", g.Status, "active")
	}
	if g.Condition.Exchange != "NSE" {
		t.Errorf("Condition.Exchange = %q, want %q", g.Condition.Exchange, "NSE")
	}
	if g.Condition.Tradingsymbol != "RELIANCE" {
		t.Errorf("Condition.Tradingsymbol = %q, want %q", g.Condition.Tradingsymbol, "RELIANCE")
	}
	if len(g.Condition.TriggerValues) != 1 || g.Condition.TriggerValues[0] != 2400.0 {
		t.Errorf("TriggerValues = %v, want [2400]", g.Condition.TriggerValues)
	}
	if len(g.Orders) != 1 {
		t.Fatalf("Orders len = %d, want 1", len(g.Orders))
	}
	if g.Orders[0].Tradingsymbol != "RELIANCE" {
		t.Errorf("Order.Tradingsymbol = %q, want %q", g.Orders[0].Tradingsymbol, "RELIANCE")
	}
	if g.Orders[0].Quantity != 10 {
		t.Errorf("Order.Quantity = %d, want 10", g.Orders[0].Quantity)
	}
}

func TestConvertGTTsEmpty(t *testing.T) {
	t.Parallel()
	gtts := convertGTTs(kiteconnect.GTTs{})
	if len(gtts) != 0 {
		t.Errorf("len = %d, want 0", len(gtts))
	}
}

func TestConvertGTTParamsToKite_Single(t *testing.T) {
	t.Parallel()
	bp := broker.GTTParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		LastPrice:       1500.0,
		TransactionType: "BUY",
		Product:         "CNC",
		Type:            "single",
		TriggerValue:    1450.0,
		Quantity:        10,
		LimitPrice:      1445.0,
	}

	kp, err := convertGTTParamsToKite(bp)
	if err != nil {
		t.Fatalf("convertGTTParamsToKite error: %v", err)
	}
	if kp.Exchange != "NSE" {
		t.Errorf("Exchange = %q, want %q", kp.Exchange, "NSE")
	}
	if kp.Tradingsymbol != "INFY" {
		t.Errorf("Tradingsymbol = %q, want %q", kp.Tradingsymbol, "INFY")
	}
	if kp.LastPrice != 1500.0 {
		t.Errorf("LastPrice = %f, want 1500", kp.LastPrice)
	}
	if kp.Trigger == nil {
		t.Fatal("Trigger should not be nil")
	}
}

func TestConvertGTTParamsToKite_TwoLeg(t *testing.T) {
	t.Parallel()
	bp := broker.GTTParams{
		Exchange:          "NSE",
		Tradingsymbol:     "RELIANCE",
		LastPrice:         2500.0,
		TransactionType:   "SELL",
		Product:           "CNC",
		Type:              "two-leg",
		UpperTriggerValue: 2600.0,
		UpperQuantity:     5,
		UpperLimitPrice:   2595.0,
		LowerTriggerValue: 2400.0,
		LowerQuantity:     5,
		LowerLimitPrice:   2405.0,
	}

	kp, err := convertGTTParamsToKite(bp)
	if err != nil {
		t.Fatalf("convertGTTParamsToKite error: %v", err)
	}
	if kp.Trigger == nil {
		t.Fatal("Trigger should not be nil")
	}
}

func TestConvertGTTParamsToKite_InvalidType(t *testing.T) {
	t.Parallel()
	bp := broker.GTTParams{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
		Type:          "triple-leg",
	}

	_, err := convertGTTParamsToKite(bp)
	if err == nil {
		t.Fatal("Expected error for invalid GTT type")
	}
}
