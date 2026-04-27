package mock

import (
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/money"
)

// NewDemoClient returns a mock broker pre-populated with a realistic Indian
// equity portfolio.  Intended for DEV_MODE so MCP tools work without a real
// Kite login.
func NewDemoClient() *Client {
	c := New()

	c.SetProfile(broker.Profile{
		UserID:    "DEMO01",
		UserName:  "Demo Trader",
		Email:     "demo@kitemcp.dev",
		Broker:    "zerodha",
		Exchanges: []string{"NSE", "BSE"},
		Products:  []string{"CNC", "MIS", "NRML"},
	})

	c.SetHoldings([]broker.Holding{
		{Tradingsymbol: "RELIANCE", Exchange: "NSE", Quantity: 10, AveragePrice: 2450.0, LastPrice: 2812.50, PnL: money.NewINR(3625.0)},
		{Tradingsymbol: "INFY", Exchange: "NSE", Quantity: 25, AveragePrice: 1720.0, LastPrice: 1895.30, PnL: money.NewINR(4382.50)},
		{Tradingsymbol: "TCS", Exchange: "NSE", Quantity: 8, AveragePrice: 3950.0, LastPrice: 4120.75, PnL: money.NewINR(1366.0)},
		{Tradingsymbol: "HDFCBANK", Exchange: "NSE", Quantity: 15, AveragePrice: 1650.0, LastPrice: 1580.40, PnL: money.NewINR(-1044.0)},
		{Tradingsymbol: "ICICIBANK", Exchange: "NSE", Quantity: 20, AveragePrice: 1180.0, LastPrice: 1265.80, PnL: money.NewINR(1716.0)},
	})

	c.SetPrices(map[string]float64{
		"NSE:NIFTY 50":   24850.0,
		"NSE:NIFTY BANK": 52100.0,
		"BSE:SENSEX":     81500.0,
		"NSE:RELIANCE":   2812.50,
		"NSE:INFY":       1895.30,
		"NSE:TCS":        4120.75,
		"NSE:HDFCBANK":   1580.40,
		"NSE:ICICIBANK":  1265.80,
	})

	c.SetMargins(broker.Margins{
		Equity: broker.SegmentMargin{
			Available: 450000.0,
			Used:      50000.0,
			Total:     500000.0,
		},
	})

	return c
}
