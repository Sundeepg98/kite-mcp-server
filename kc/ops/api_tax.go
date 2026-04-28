package ops

import (
	"math"
	"net/http"
	"sort"

	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- Tax Analysis types ---

type taxHoldingEntry struct {
	Symbol         string  `json:"symbol"`
	Exchange       string  `json:"exchange"`
	Quantity       int     `json:"quantity"`
	AveragePrice   float64 `json:"average_price"`
	LastPrice      float64 `json:"last_price"`
	InvestedValue  float64 `json:"invested_value"`
	CurrentValue   float64 `json:"current_value"`
	UnrealizedPnL  float64 `json:"unrealized_pnl"`
	Classification string  `json:"classification"` // "LTCG" or "STCG"
	TaxRate        float64 `json:"tax_rate"`
	TaxIfSold      float64 `json:"tax_if_sold"`
	Harvestable    bool    `json:"harvestable"`
}

type taxSummary struct {
	TotalLTCGGains     float64 `json:"total_ltcg_gains"`
	TotalSTCGGains     float64 `json:"total_stcg_gains"`
	TotalLTCGLosses    float64 `json:"total_ltcg_losses"`
	TotalSTCGLosses    float64 `json:"total_stcg_losses"`
	HarvestableLoss    float64 `json:"harvestable_loss"`
	PotentialTaxSaving float64 `json:"potential_tax_saving"`
	HoldingsAnalyzed   int     `json:"holdings_analyzed"`
}

type taxAnalysisResponse struct {
	Holdings []taxHoldingEntry `json:"holdings"`
	Summary  taxSummary        `json:"summary"`
}

// taxAnalysisAPI returns tax classification and harvesting opportunities for holdings.
func (h *TaxHandler) taxAnalysisAPI(w http.ResponseWriter, r *http.Request) {
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
		d.loggerPort.Error(r.Context(), "Failed to fetch holdings for tax analysis", err, "email", email)
		d.writeJSONError(w, http.StatusBadGateway, "kite_error",
			"Failed to fetch holdings: "+err.Error())
		return
	}

	if len(holdings) == 0 {
		d.writeJSON(w, taxAnalysisResponse{
			Holdings: []taxHoldingEntry{},
		})
		return
	}

	resp := computeTaxAnalysis(holdings)
	d.writeJSON(w, resp)
}

// computeTaxAnalysis classifies holdings and computes tax harvesting opportunities.
// Indian tax rates (FY 2025-26): STCG on equity = 20%, LTCG on equity = 12.5%.
func computeTaxAnalysis(holdings kiteconnect.Holdings) taxAnalysisResponse {
	const (
		stcgRate = 20.0
		ltcgRate = 12.5
	)
	_ = ltcgRate

	entries := make([]taxHoldingEntry, 0, len(holdings))
	var summary taxSummary
	summary.HoldingsAnalyzed = len(holdings)

	for _, h := range holdings {
		invested := h.AveragePrice * float64(h.Quantity)
		current := h.LastPrice * float64(h.Quantity)
		unrealizedPnL := current - invested

		classification := "STCG"
		taxRate := stcgRate

		taxIfSold := 0.0
		if unrealizedPnL > 0 {
			taxIfSold = math.Round(unrealizedPnL*taxRate) / 100
		}

		harvestable := unrealizedPnL < 0

		entry := taxHoldingEntry{
			Symbol:         h.Tradingsymbol,
			Exchange:       h.Exchange,
			Quantity:       h.Quantity,
			AveragePrice:   h.AveragePrice,
			LastPrice:      h.LastPrice,
			InvestedValue:  math.Round(invested*100) / 100,
			CurrentValue:   math.Round(current*100) / 100,
			UnrealizedPnL:  math.Round(unrealizedPnL*100) / 100,
			Classification: classification,
			TaxRate:        taxRate,
			TaxIfSold:      math.Round(taxIfSold*100) / 100,
			Harvestable:    harvestable,
		}
		entries = append(entries, entry)

		if unrealizedPnL > 0 {
			if classification == "LTCG" {
				summary.TotalLTCGGains += unrealizedPnL
			} else {
				summary.TotalSTCGGains += unrealizedPnL
			}
		} else if unrealizedPnL < 0 {
			if classification == "LTCG" {
				summary.TotalLTCGLosses += unrealizedPnL
			} else {
				summary.TotalSTCGLosses += unrealizedPnL
			}
			summary.HarvestableLoss += unrealizedPnL
		}
	}

	summary.TotalLTCGGains = math.Round(summary.TotalLTCGGains*100) / 100
	summary.TotalSTCGGains = math.Round(summary.TotalSTCGGains*100) / 100
	summary.TotalLTCGLosses = math.Round(summary.TotalLTCGLosses*100) / 100
	summary.TotalSTCGLosses = math.Round(summary.TotalSTCGLosses*100) / 100
	summary.HarvestableLoss = math.Round(summary.HarvestableLoss*100) / 100

	if summary.HarvestableLoss < 0 {
		summary.PotentialTaxSaving = math.Round(math.Abs(summary.HarvestableLoss)*stcgRate) / 100
	}

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].Harvestable != entries[j].Harvestable {
			return entries[i].Harvestable
		}
		return entries[i].UnrealizedPnL < entries[j].UnrealizedPnL
	})

	return taxAnalysisResponse{
		Holdings: entries,
		Summary:  summary,
	}
}
