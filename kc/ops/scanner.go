package ops

import (
	"net/http"
	"sort"
	"strconv"

	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-sectors"
	"github.com/algo2go/kite-mcp-oauth"
)

// scannerHandler is the per-user dashboard endpoint that returns a filtered
// list of tradable instruments. Closes Axis C feature gap C.F1 from
// .research/abc-100pct-complete-paths.md.
//
// URL params (all optional):
//   - min_price (float)    — lower price bound; 0 means no bound
//   - max_price (float)    — upper price bound; 0 means no bound
//   - exchange (string)    — exact match (NSE/BSE); empty means any
//   - sector (string)      — sector match via kc/sectors.Lookup
//                            (strips -BE/-EQ suffixes; case-sensitive
//                            sector value match e.g. "Banking", "IT")
//   - limit (int)          — result cap; default 50, clamped to [1, 200]
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
	sectorFilter := r.URL.Query().Get("sector")

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
		// Equity-only universe; defer F&O/MF to later phases.
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
		if sectorFilter != "" {
			// Use kc/sectors.Lookup which normalizes the symbol (strips
			// -BE/-EQ suffixes, uppercase, trim) before mapping to a
			// sector. Unmapped symbols fail this predicate; the user
			// must explicitly clear the sector filter to see them.
			matched, ok := sectors.Lookup(inst.Tradingsymbol)
			if !ok || matched != sectorFilter {
				return false
			}
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

// serveScannerPageSSR renders the /dashboard/scanner page. The page itself
// is JS-driven — filters POST to /dashboard/api/scanner via fetch — so SSR
// only needs to hand back the shell with topbar context (email, role,
// token validity). Pattern matches dashboard_paper.go.
func (h *ScannerHandler) serveScannerPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.scannerTmpl == nil {
		d.servePageFallback(w, "scanner.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := ScannerPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.scannerTmpl.Execute(w, data); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to render scanner page", err)
	}
}
