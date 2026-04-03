package zerodha

import (
	"testing"
	"time"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
	"github.com/zerodha/kite-mcp-server/broker"
)

func TestConvertProfile(t *testing.T) {
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
	if h.PnL != 1002.50 {
		t.Errorf("PnL = %f, want 1002.50", h.PnL)
	}
	if h.DayChangePct != 1.25 {
		t.Errorf("DayChangePct = %f, want 1.25", h.DayChangePct)
	}
	if h.Product != "CNC" {
		t.Errorf("Product = %q, want %q", h.Product, "CNC")
	}
}

func TestConvertHoldingsEmpty(t *testing.T) {
	holdings := convertHoldings(kiteconnect.Holdings{})
	if len(holdings) != 0 {
		t.Errorf("len = %d, want 0", len(holdings))
	}
}

func TestConvertPositions(t *testing.T) {
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
	c := &Client{}
	if c.BrokerName() != broker.Zerodha {
		t.Errorf("BrokerName = %q, want %q", c.BrokerName(), broker.Zerodha)
	}
}
