package ops

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// scannerHandler is the per-user dashboard endpoint that returns a filtered
// list of tradable instruments. Phase 1 of the scanner feature (Axis C
// feature gap C.F1 from .research/abc-100pct-complete-paths.md). Phase 1
// supports min_price / max_price / exchange / limit URL params; subsequent
// phases will add sector + market-cap filters.
//
// Default behavior:
//   - min_price=0          (no lower bound; matches everything ≥ 0)
//   - max_price=∞          (no upper bound)
//   - exchange=""          (no exchange filter; matches all)
//   - limit=50             (clamped to [1, 200])
//
// Results are sorted by last_price ascending for deterministic UI rendering.
type ScannerHandler struct {
	core *DashboardHandler
}

func newScannerHandler(core *DashboardHandler) *ScannerHandler {
	return &ScannerHandler{core: core}
}

// scannerResponseEntry is a slim projection of an instrument tailored for
// scanner table rendering. Includes only fields the scanner UI displays.
type scannerResponseEntry struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Name          string  `json:"name"`
	LastPrice     float64 `json:"last_price"`
	Segment       string  `json:"segment"`
}

// scannerResponseShape is the JSON envelope returned by GET /dashboard/api/scanner.
type scannerResponseShape struct {
	Total   int                    `json:"total"`
	Limit   int                    `json:"limit"`
	Results []scannerResponseEntry `json:"results"`
}

func (h *ScannerHandler) scannerAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	// Parse + validate URL params.
	minPrice := floatParam(r, "min_price", 0)
	maxPrice := floatParam(r, "max_price", 0) // 0 means "no upper bound" (handled below)
	exchange := r.URL.Query().Get("exchange")

	// Limit clamp: default 50, max 200, min 1.
	limit := intParam(r, "limit", 50)
	if limit < 1 {
		limit = 1
	}
	if limit > 200 {
		limit = 200
	}

	// Filter via instruments.Manager.Filter — single-pass over the in-memory map.
	instrMgr := h.core.manager.InstrumentsManagerConcrete()
	if instrMgr == nil {
		h.core.writeJSONError(w, http.StatusServiceUnavailable, "not_available", "Instruments manager not configured")
		return
	}

	matches := instrMgr.Filter(func(inst instruments.Instrument) bool {
		// Phase 1 only includes equity instruments; defer F&O/MF to later phases.
		if inst.InstrumentType != "EQ" {
			return false
		}
		if !inst.Active {
			return false
		}
		if exchange != "" && inst.Exchange != exchange {
			return false
		}
		if minPrice > 0 && inst.LastPrice < minPrice {
			return false
		}
		if maxPrice > 0 && inst.LastPrice > maxPrice {
			return false
		}
		return true
	})

	// Sort by last_price ascending for deterministic rendering.
	sort.Slice(matches, func(i, j int) bool {
		return matches[i].LastPrice < matches[j].LastPrice
	})

	total := len(matches)
	if len(matches) > limit {
		matches = matches[:limit]
	}

	results := make([]scannerResponseEntry, 0, len(matches))
	for _, inst := range matches {
		results = append(results, scannerResponseEntry{
			Tradingsymbol: inst.Tradingsymbol,
			Exchange:      inst.Exchange,
			Name:          inst.Name,
			LastPrice:     inst.LastPrice,
			Segment:       inst.Segment,
		})
	}

	h.core.writeJSON(w, scannerResponseShape{
		Total:   total,
		Limit:   limit,
		Results: results,
	})
}

// floatParam parses a query-string param as a float64, returning defaultVal
// on missing/invalid input. Mirror of intParam in the same package.
func floatParam(r *http.Request, key string, defaultVal float64) float64 {
	raw := r.URL.Query().Get(key)
	if raw == "" {
		return defaultVal
	}
	v, err := strconv.ParseFloat(raw, 64)
	if err != nil {
		return defaultVal
	}
	return v
}
