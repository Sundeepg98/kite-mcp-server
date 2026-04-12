package ops

import (
	"fmt"
	"math"
	"net/http"
	"sort"
	"strings"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Portfolio types ---

type holdingItem struct {
	Tradingsymbol    string  `json:"tradingsymbol"`
	Exchange         string  `json:"exchange"`
	Quantity         int     `json:"quantity"`
	AveragePrice     float64 `json:"average_price"`
	LastPrice        float64 `json:"last_price"`
	PnL              float64 `json:"pnl"`
	DayChangePercent float64 `json:"day_change_percentage"`
	Product          string  `json:"product"`
}

type positionItem struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Quantity      int     `json:"quantity"`
	AveragePrice  float64 `json:"average_price"`
	LastPrice     float64 `json:"last_price"`
	PnL           float64 `json:"pnl"`
	Product       string  `json:"product"`
}

type portfolioSummary struct {
	HoldingsCount  int     `json:"holdings_count"`
	TotalInvested  float64 `json:"total_invested"`
	TotalCurrent   float64 `json:"total_current"`
	TotalPnL       float64 `json:"total_pnl"`
	PositionsCount int     `json:"positions_count"`
	PositionsPnL   float64 `json:"positions_pnl"`
}

type portfolioResponse struct {
	Holdings  []holdingItem    `json:"holdings"`
	Positions []positionItem   `json:"positions"`
	Summary   portfolioSummary `json:"summary"`
}

// --- Sector Exposure types ---

type dashboardSectorAllocation struct {
	Sector      string  `json:"sector"`
	Value       float64 `json:"value"`
	Pct         float64 `json:"pct"`
	Holdings    int     `json:"holdings"`
	OverExposed bool    `json:"over_exposed,omitempty"`
}

type sectorExposureAPIResponse struct {
	TotalValue    float64                     `json:"total_value"`
	HoldingsCount int                         `json:"holdings_count"`
	MappedCount   int                         `json:"mapped_count"`
	UnmappedCount int                         `json:"unmapped_count"`
	Sectors       []dashboardSectorAllocation `json:"sectors"`
	Warnings      []string                    `json:"warnings,omitempty"`
}

// marketIndices returns OHLC data for NIFTY 50, BANK NIFTY, and SENSEX.
func (h *PortfolioHandler) marketIndices(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "no_credentials",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "no_session",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	ohlcData, err := client.GetOHLC("NSE:NIFTY 50", "NSE:NIFTY BANK", "BSE:SENSEX")
	if err != nil {
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch market indices from Kite: "+err.Error())
		return
	}

	result := make(map[string]any, len(ohlcData))
	for k, v := range ohlcData {
		change := v.LastPrice - v.OHLC.Close
		changePct := 0.0
		if v.OHLC.Close > 0 {
			changePct = (change / v.OHLC.Close) * 100
		}
		result[k] = map[string]any{
			"last_price": v.LastPrice,
			"close":      v.OHLC.Close,
			"open":       v.OHLC.Open,
			"high":       v.OHLC.High,
			"low":        v.OHLC.Low,
			"change":     math.Round(change*100) / 100,
			"change_pct": math.Round(changePct*100) / 100,
		}
	}
	d.writeJSON(w, result)
}

// portfolio fetches holdings and positions from the Kite API for the authenticated user.
func (h *PortfolioHandler) portfolio(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found. Please register your API credentials via your MCP client.")
		return
	}

	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found. Please re-authenticate via your MCP client.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	holdings, holdingsErr := client.GetHoldings()
	if holdingsErr != nil {
		d.logger.Error("Failed to fetch holdings", "email", email, "error", holdingsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings from Kite: "+holdingsErr.Error())
		return
	}

	positions, positionsErr := client.GetPositions()
	if positionsErr != nil {
		d.logger.Error("Failed to fetch positions", "email", email, "error", positionsErr)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch positions from Kite: "+positionsErr.Error())
		return
	}

	resp := buildPortfolioResponse(holdings, positions)
	d.writeJSON(w, resp)
}

// buildPortfolioResponse maps gokiteconnect holdings/positions to the dashboard response format.
func buildPortfolioResponse(holdings kiteconnect.Holdings, positions kiteconnect.Positions) portfolioResponse {
	holdingItems := make([]holdingItem, 0, len(holdings))
	var totalInvested, totalCurrent, totalPnL float64
	for _, h := range holdings {
		holdingItems = append(holdingItems, holdingItem{
			Tradingsymbol:    h.Tradingsymbol,
			Exchange:         h.Exchange,
			Quantity:         h.Quantity,
			AveragePrice:     h.AveragePrice,
			LastPrice:        h.LastPrice,
			PnL:              h.PnL,
			DayChangePercent: h.DayChangePercentage,
			Product:          h.Product,
		})
		totalInvested += h.AveragePrice * float64(h.Quantity)
		totalCurrent += h.LastPrice * float64(h.Quantity)
		totalPnL += h.PnL
	}

	positionItems := make([]positionItem, 0, len(positions.Net))
	var positionsPnL float64
	for _, p := range positions.Net {
		positionItems = append(positionItems, positionItem{
			Tradingsymbol: p.Tradingsymbol,
			Exchange:      p.Exchange,
			Quantity:      p.Quantity,
			AveragePrice:  p.AveragePrice,
			LastPrice:     p.LastPrice,
			PnL:           p.PnL,
			Product:       p.Product,
		})
		positionsPnL += p.PnL
	}

	return portfolioResponse{
		Holdings:  holdingItems,
		Positions: positionItems,
		Summary: portfolioSummary{
			HoldingsCount:  len(holdings),
			TotalInvested:  totalInvested,
			TotalCurrent:   totalCurrent,
			TotalPnL:       totalPnL,
			PositionsCount: len(positions.Net),
			PositionsPnL:   positionsPnL,
		},
	}
}

// sectorExposureAPI returns sector allocation data for the authenticated user's holdings.
func (h *PortfolioHandler) sectorExposureAPI(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated", "Not authenticated.")
		return
	}

	credEntry, hasCreds := d.manager.CredentialStore().Get(email)
	if !hasCreds {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite credentials not found.")
		return
	}
	tokenEntry, hasToken := d.manager.TokenStore().Get(email)
	if !hasToken {
		d.writeJSONError(w, http.StatusUnauthorized, "not_authenticated",
			"Kite token expired or not found.")
		return
	}

	client := d.manager.KiteClientFactory().NewClientWithToken(credEntry.APIKey, tokenEntry.AccessToken)

	holdings, err := client.GetHoldings()
	if err != nil {
		d.logger.Error("Failed to fetch holdings for sector exposure", "email", email, "error", err)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings: "+err.Error())
		return
	}

	if len(holdings) == 0 {
		d.writeJSON(w, sectorExposureAPIResponse{
			Sectors: []dashboardSectorAllocation{},
		})
		return
	}

	resp := computeDashboardSectorExposure(holdings)
	d.writeJSON(w, resp)
}

// computeDashboardSectorExposure maps holdings to sectors and computes allocation percentages.
func computeDashboardSectorExposure(holdings kiteconnect.Holdings) sectorExposureAPIResponse {
	const overExposureThresh = 30.0

	var totalValue float64
	for _, h := range holdings {
		totalValue += h.LastPrice * float64(h.Quantity)
	}

	if totalValue == 0 {
		return sectorExposureAPIResponse{
			HoldingsCount: len(holdings),
			Sectors:       []dashboardSectorAllocation{},
		}
	}

	type sectorAccum struct {
		value    float64
		holdings int
	}
	sectorMap := make(map[string]*sectorAccum)
	mappedCount := 0
	unmappedCount := 0

	for _, h := range holdings {
		val := h.LastPrice * float64(h.Quantity)
		symbol := dashboardNormalizeSymbol(h.Tradingsymbol)
		sector, ok := dashboardStockSectors[symbol]
		if !ok {
			unmappedCount++
			sector = "Other"
		} else {
			mappedCount++
		}

		acc, exists := sectorMap[sector]
		if !exists {
			acc = &sectorAccum{}
			sectorMap[sector] = acc
		}
		acc.value += val
		acc.holdings++
	}

	sectors := make([]dashboardSectorAllocation, 0, len(sectorMap))
	var warnings []string
	for name, acc := range sectorMap {
		pct := math.Round(acc.value/totalValue*10000) / 100
		overExposed := pct > overExposureThresh
		sectors = append(sectors, dashboardSectorAllocation{
			Sector:      name,
			Value:       math.Round(acc.value*100) / 100,
			Pct:         pct,
			Holdings:    acc.holdings,
			OverExposed: overExposed,
		})
		if overExposed {
			warnings = append(warnings, fmt.Sprintf("%s is over-exposed at %.1f%% of portfolio (threshold: 30%%)", name, pct))
		}
	}

	sort.Slice(sectors, func(i, j int) bool {
		return sectors[i].Pct > sectors[j].Pct
	})

	return sectorExposureAPIResponse{
		TotalValue:    math.Round(totalValue*100) / 100,
		HoldingsCount: len(holdings),
		MappedCount:   mappedCount,
		UnmappedCount: unmappedCount,
		Sectors:       sectors,
		Warnings:      warnings,
	}
}

// dashboardNormalizeSymbol strips common suffixes for sector lookup.
func dashboardNormalizeSymbol(ts string) string {
	s := strings.ToUpper(strings.TrimSpace(ts))
	for _, suffix := range []string{"-BE", "-EQ", "-BZ", "-BL"} {
		s = strings.TrimSuffix(s, suffix)
	}
	return s
}

// dashboardStockSectors maps NSE/BSE trading symbols to their primary sector.
// Duplicated from mcp/sector_tool.go to avoid cross-package import.
var dashboardStockSectors = map[string]string{
	// Banking
	"HDFCBANK": "Banking", "ICICIBANK": "Banking", "SBIN": "Banking",
	"KOTAKBANK": "Banking", "AXISBANK": "Banking", "INDUSINDBK": "Banking",
	"BANKBARODA": "Banking", "PNB": "Banking", "IDFCFIRSTB": "Banking",
	"FEDERALBNK": "Banking", "AUBANK": "Banking", "BANDHANBNK": "Banking",
	"CANBK": "Banking", "UNIONBANK": "Banking", "YESBANK": "Banking",
	// IT
	"TCS": "IT", "INFY": "IT", "HCLTECH": "IT", "WIPRO": "IT",
	"TECHM": "IT", "LTIM": "IT", "MPHASIS": "IT", "COFORGE": "IT",
	"PERSISTENT": "IT", "LTTS": "IT", "TATAELXSI": "IT",
	// FMCG
	"HINDUNILVR": "FMCG", "ITC": "FMCG", "NESTLEIND": "FMCG",
	"BRITANNIA": "FMCG", "DABUR": "FMCG", "TATACONSUM": "FMCG",
	"MARICO": "FMCG", "GODREJCP": "FMCG", "COLPAL": "FMCG",
	// Pharma / Healthcare
	"SUNPHARMA": "Pharma", "DRREDDY": "Pharma", "CIPLA": "Pharma",
	"DIVISLAB": "Pharma", "LUPIN": "Pharma", "AUROPHARMA": "Pharma",
	"BIOCON": "Pharma", "APOLLOHOSP": "Healthcare", "MAXHEALTH": "Healthcare",
	"FORTIS": "Healthcare",
	// Auto
	"MARUTI": "Auto", "TATAMOTORS": "Auto", "M&M": "Auto",
	"HEROMOTOCO": "Auto", "EICHERMOT": "Auto", "BAJAJ-AUTO": "Auto",
	"ASHOKLEY": "Auto", "TVSMOTOR": "Auto", "MOTHERSON": "Auto",
	// Energy
	"RELIANCE": "Energy", "NTPC": "Energy", "POWERGRID": "Energy",
	"ONGC": "Energy", "COALINDIA": "Energy", "BPCL": "Energy",
	"IOC": "Energy", "GAIL": "Energy", "TATAPOWER": "Energy",
	"ADANIGREEN": "Energy", "NHPC": "Energy",
	// Metals
	"TATASTEEL": "Metals", "JSWSTEEL": "Metals", "HINDALCO": "Metals",
	"VEDL": "Metals", "JINDALSTEL": "Metals", "NMDC": "Metals", "SAIL": "Metals",
	// Infra
	"LT": "Infra", "ADANIPORTS": "Infra", "SIEMENS": "Infra",
	"ABB": "Infra", "HAVELLS": "Infra", "POLYCAB": "Infra",
	"BEL": "Infra", "BHEL": "Infra",
	// Cement
	"ULTRACEMCO": "Cement", "GRASIM": "Cement", "SHREECEM": "Cement",
	"AMBUJACEM": "Cement", "ACC": "Cement",
	// NBFC / Insurance
	"BAJFINANCE": "NBFC", "BAJAJFINSV": "NBFC", "SBILIFE": "Insurance",
	"HDFCLIFE": "Insurance", "ICICIGI": "Insurance", "MUTHOOTFIN": "NBFC",
	"SHRIRAMFIN": "NBFC", "CHOLAFIN": "NBFC", "PFC": "NBFC", "RECLTD": "NBFC",
	// Telecom
	"BHARTIARTL": "Telecom", "IDEA": "Telecom",
	// Consumer
	"TITAN": "Consumer", "ASIANPAINT": "Consumer", "PIDILITIND": "Consumer",
	"TRENT": "Consumer", "DMART": "Consumer",
	// Tech / New Economy
	"ZOMATO": "Tech", "PAYTM": "Tech", "NYKAA": "Tech",
	"POLICYBZR": "Tech", "INFOEDGE": "Tech",
	// Defence
	"HAL": "Defence", "BDL": "Defence", "MAZAGON": "Defence",
	// Conglomerate
	"ADANIENT": "Conglomerate",
	// Real Estate
	"DLF": "Real Estate", "GODREJPROP": "Real Estate", "OBEROIRLTY": "Real Estate",
	// Chemicals
	"PIIND": "Chemicals", "SRF": "Chemicals", "DEEPAKNTR": "Chemicals",
	// Services
	"IRCTC": "Services", "INDIGO": "Aviation",
}
