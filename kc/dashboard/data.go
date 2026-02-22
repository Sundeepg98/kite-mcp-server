package dashboard

import (
	"encoding/json"
	"net/http"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// DashboardData is the JSON response for /api/dashboard/data.
type DashboardData struct {
	Holdings  []HoldingItem  `json:"holdings"`
	Positions []PositionItem `json:"positions"`
	Summary   Summary        `json:"summary"`
}

// HoldingItem represents a single holding with P&L.
type HoldingItem struct {
	Tradingsymbol   string  `json:"tradingsymbol"`
	Exchange        string  `json:"exchange"`
	InstrumentToken uint32  `json:"instrument_token"`
	Quantity        int     `json:"quantity"`
	AveragePrice    float64 `json:"average_price"`
	LastPrice       float64 `json:"last_price"`
	PnL             float64 `json:"pnl"`
	DayChange       float64 `json:"day_change"`
	DayChangePct    float64 `json:"day_change_pct"`
}

// PositionItem represents an open position.
type PositionItem struct {
	Tradingsymbol   string  `json:"tradingsymbol"`
	Exchange        string  `json:"exchange"`
	InstrumentToken uint32  `json:"instrument_token"`
	Quantity        int     `json:"quantity"`
	AveragePrice    float64 `json:"average_price"`
	LastPrice       float64 `json:"last_price"`
	PnL             float64 `json:"pnl"`
	Product         string  `json:"product"`
}

// Summary holds aggregate P&L numbers.
type Summary struct {
	TotalInvestment float64 `json:"total_investment"`
	CurrentValue    float64 `json:"current_value"`
	OverallPnL      float64 `json:"overall_pnl"`
	OverallPnLPct   float64 `json:"overall_pnl_pct"`
	DayPnL          float64 `json:"day_pnl"`
}

// serveData returns JSON with holdings, positions, and P&L.
func (h *Handler) serveData(w http.ResponseWriter, r *http.Request) {
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Get a Kite client for this user
	apiKey := h.manager.GetAPIKeyForEmail(email)
	accessToken := h.manager.GetAccessTokenForEmail(email)
	if accessToken == "" {
		http.Error(w, "Not logged in to Kite. Use the MCP login tool first.", http.StatusUnauthorized)
		return
	}

	kd := kc.NewKiteConnect(apiKey)
	kd.Client.SetAccessToken(accessToken)

	data := DashboardData{}

	// Fetch holdings
	holdings, err := kd.Client.GetHoldings()
	if err != nil {
		h.logger.Error("Failed to fetch holdings for dashboard", "email", email, "error", err)
	} else {
		var totalInvestment, currentValue, dayPnL float64

		for _, holding := range holdings {
			item := HoldingItem{
				Tradingsymbol:   holding.Tradingsymbol,
				Exchange:        holding.Exchange,
				InstrumentToken: holding.InstrumentToken,
				Quantity:        int(holding.Quantity),
				AveragePrice:    holding.AveragePrice,
				LastPrice:       holding.LastPrice,
				PnL:             holding.PnL,
				DayChange:       holding.DayChange,
				DayChangePct:    holding.DayChangePercentage,
			}
			data.Holdings = append(data.Holdings, item)

			totalInvestment += holding.AveragePrice * float64(holding.Quantity)
			currentValue += holding.LastPrice * float64(holding.Quantity)
			dayPnL += holding.DayChange * float64(holding.Quantity)
		}

		data.Summary.TotalInvestment = totalInvestment
		data.Summary.CurrentValue = currentValue
		data.Summary.OverallPnL = currentValue - totalInvestment
		if totalInvestment > 0 {
			data.Summary.OverallPnLPct = ((currentValue - totalInvestment) / totalInvestment) * 100
		}
		data.Summary.DayPnL = dayPnL
	}

	// Fetch positions
	positions, err := kd.Client.GetPositions()
	if err != nil {
		h.logger.Error("Failed to fetch positions for dashboard", "email", email, "error", err)
	} else {
		for _, pos := range positions.Net {
			if pos.Quantity == 0 {
				continue
			}
			item := PositionItem{
				Tradingsymbol:   pos.Tradingsymbol,
				Exchange:        pos.Exchange,
				InstrumentToken: pos.InstrumentToken,
				Quantity:        int(pos.Quantity),
				AveragePrice:    pos.AveragePrice,
				LastPrice:       pos.LastPrice,
				PnL:             pos.PnL,
				Product:         pos.Product,
			}
			data.Positions = append(data.Positions, item)
		}
	}

	// Ensure ticker is running for live updates
	h.ensureTickerForUser(email)

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
