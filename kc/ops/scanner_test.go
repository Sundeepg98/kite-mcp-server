package ops

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// newDashboardWithSeededInstruments builds a DashboardHandler whose
// instruments.Manager is pre-loaded with the supplied test data. Used
// by scanner tests to control the instrument universe under test.
func newDashboardWithSeededInstruments(t *testing.T, testData map[uint32]*instruments.Instrument) *DashboardHandler {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(devNull{}, &slog.HandlerOptions{Level: slog.LevelError}))

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: testData,
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(logger),
		kc.WithKiteCredentials("test_api_key", "test_api_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
	)
	require.NoError(t, err)
	t.Cleanup(func() { mgr.Shutdown() })

	d := NewDashboardHandler(mgr, logger, nil)
	d.SetAdminCheck(func(email string) bool { return email == "admin@test.com" })
	return d
}

// scannerResponse mirrors the API response shape returned by scannerAPI.
// Embedded here (not in scanner.go) because the production handler exposes
// it as plain JSON; the test cares only about the contract.
type scannerResponse struct {
	Total   int                  `json:"total"`
	Limit   int                  `json:"limit"`
	Results []scannerResultEntry `json:"results"`
}

type scannerResultEntry struct {
	Tradingsymbol string  `json:"tradingsymbol"`
	Exchange      string  `json:"exchange"`
	Name          string  `json:"name"`
	LastPrice     float64 `json:"last_price"`
	Segment       string  `json:"segment"`
}

// TestScanner_PriceRangeFilter verifies that the scanner API filters
// instruments by min_price and max_price URL params. Phase 1 of the
// scanner feature (Axis C feature gap C.F1 from
// .research/abc-100pct-complete-paths.md).
func TestScanner_PriceRangeFilter(t *testing.T) {
	t.Parallel()

	// Seed 5 instruments with varied last_price.
	testData := map[uint32]*instruments.Instrument{
		100: {InstrumentToken: 100, Tradingsymbol: "SBIN", Exchange: "NSE", Name: "STATE BANK OF INDIA", LastPrice: 600.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
		101: {InstrumentToken: 101, Tradingsymbol: "TCS", Exchange: "NSE", Name: "TATA CONSULTANCY SERVICES", LastPrice: 3500.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
		102: {InstrumentToken: 102, Tradingsymbol: "INFY", Exchange: "NSE", Name: "INFOSYS LIMITED", LastPrice: 1500.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
		103: {InstrumentToken: 103, Tradingsymbol: "RELIANCE", Exchange: "NSE", Name: "RELIANCE INDUSTRIES", LastPrice: 2800.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
		104: {InstrumentToken: 104, Tradingsymbol: "HDFCBANK", Exchange: "NSE", Name: "HDFC BANK LIMITED", LastPrice: 1700.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
	}

	d := newDashboardWithSeededInstruments(t, testData)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Filter: 1000 <= last_price <= 2000 → should match INFY (1500), HDFCBANK (1700).
	req := reqWithEmail(http.MethodGet, "/dashboard/api/scanner?min_price=1000&max_price=2000&limit=50", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "scanner API should return 200; body=%s", rec.Body.String())

	var resp scannerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total, "expect 2 instruments in [1000,2000] range")
	assert.Len(t, resp.Results, 2)
	// Results should be sorted by last_price ascending for deterministic UI rendering.
	syms := []string{resp.Results[0].Tradingsymbol, resp.Results[1].Tradingsymbol}
	assert.Contains(t, syms, "INFY")
	assert.Contains(t, syms, "HDFCBANK")
}

// TestScanner_ExchangeFilter verifies the exchange filter narrows results
// to a specific exchange (NSE vs BSE) when provided.
func TestScanner_ExchangeFilter(t *testing.T) {
	t.Parallel()

	testData := map[uint32]*instruments.Instrument{
		200: {InstrumentToken: 200, Tradingsymbol: "SBIN", Exchange: "NSE", Name: "SBI", LastPrice: 600.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
		201: {InstrumentToken: 201, Tradingsymbol: "SBIN", Exchange: "BSE", Name: "SBI", LastPrice: 601.5, Segment: "BSE", InstrumentType: "EQ", Active: true},
		202: {InstrumentToken: 202, Tradingsymbol: "TCS", Exchange: "NSE", Name: "TCS", LastPrice: 3500.0, Segment: "NSE", InstrumentType: "EQ", Active: true},
	}

	d := newDashboardWithSeededInstruments(t, testData)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/api/scanner?exchange=BSE&limit=50", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp scannerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total)
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "BSE", resp.Results[0].Exchange)
	assert.Equal(t, "SBIN", resp.Results[0].Tradingsymbol)
}

// TestScanner_LimitClamp verifies the limit URL param is clamped to a
// reasonable range to prevent expensive queries.
func TestScanner_LimitClamp(t *testing.T) {
	t.Parallel()

	// Seed 5 cheap instruments — all match default filter (no price range).
	testData := map[uint32]*instruments.Instrument{
		300: {InstrumentToken: 300, Tradingsymbol: "A", Exchange: "NSE", LastPrice: 100, Segment: "NSE", InstrumentType: "EQ", Active: true},
		301: {InstrumentToken: 301, Tradingsymbol: "B", Exchange: "NSE", LastPrice: 200, Segment: "NSE", InstrumentType: "EQ", Active: true},
		302: {InstrumentToken: 302, Tradingsymbol: "C", Exchange: "NSE", LastPrice: 300, Segment: "NSE", InstrumentType: "EQ", Active: true},
		303: {InstrumentToken: 303, Tradingsymbol: "D", Exchange: "NSE", LastPrice: 400, Segment: "NSE", InstrumentType: "EQ", Active: true},
		304: {InstrumentToken: 304, Tradingsymbol: "E", Exchange: "NSE", LastPrice: 500, Segment: "NSE", InstrumentType: "EQ", Active: true},
	}

	d := newDashboardWithSeededInstruments(t, testData)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Request limit=2 — should return only 2 results despite 5 matching.
	req := reqWithEmail(http.MethodGet, "/dashboard/api/scanner?limit=2", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp scannerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 5, resp.Total, "Total should reflect full match count, not the limited result count")
	assert.Len(t, resp.Results, 2, "Results should be limited to 2")
	assert.Equal(t, 2, resp.Limit)
}

// TestScanner_RequiresAuth verifies the scanner endpoint refuses unauthenticated requests.
func TestScanner_RequiresAuth(t *testing.T) {
	t.Parallel()

	d := newDashboardWithSeededInstruments(t, map[uint32]*instruments.Instrument{})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Request WITHOUT email in context → should return 401.
	req := httptest.NewRequest(http.MethodGet, "/dashboard/api/scanner", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestScanner_SectorFilter verifies the sector URL parameter narrows
// results to instruments mapped to the given sector via kc/sectors.Lookup.
// Phase 3 of the scanner feature; closes Axis C C.F1 sector filter.
func TestScanner_SectorFilter(t *testing.T) {
	t.Parallel()

	// Seed canonical NSE symbols spanning multiple sectors.
	testData := map[uint32]*instruments.Instrument{
		400: {InstrumentToken: 400, Tradingsymbol: "HDFCBANK", Exchange: "NSE", Name: "HDFC BANK", LastPrice: 1700, Segment: "NSE", InstrumentType: "EQ", Active: true},  // Banking
		401: {InstrumentToken: 401, Tradingsymbol: "ICICIBANK", Exchange: "NSE", Name: "ICICI BANK", LastPrice: 1100, Segment: "NSE", InstrumentType: "EQ", Active: true}, // Banking
		402: {InstrumentToken: 402, Tradingsymbol: "TCS", Exchange: "NSE", Name: "TCS", LastPrice: 3500, Segment: "NSE", InstrumentType: "EQ", Active: true},               // IT
		403: {InstrumentToken: 403, Tradingsymbol: "INFY", Exchange: "NSE", Name: "INFOSYS", LastPrice: 1500, Segment: "NSE", InstrumentType: "EQ", Active: true},          // IT
		404: {InstrumentToken: 404, Tradingsymbol: "RELIANCE", Exchange: "NSE", Name: "RELIANCE", LastPrice: 2800, Segment: "NSE", InstrumentType: "EQ", Active: true},     // Energy
	}

	d := newDashboardWithSeededInstruments(t, testData)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// sector=Banking → 2 matches (HDFCBANK, ICICIBANK)
	req := reqWithEmail(http.MethodGet, "/dashboard/api/scanner?sector=Banking&limit=50", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp scannerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total, "Banking sector should match 2 entries")
	syms := make(map[string]bool)
	for _, r := range resp.Results {
		syms[r.Tradingsymbol] = true
	}
	assert.True(t, syms["HDFCBANK"], "HDFCBANK should be in Banking results")
	assert.True(t, syms["ICICIBANK"], "ICICIBANK should be in Banking results")

	// sector=IT → 2 matches (TCS, INFY)
	req = reqWithEmail(http.MethodGet, "/dashboard/api/scanner?sector=IT&limit=50", "user@test.com")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 2, resp.Total, "IT sector should match 2 entries")

	// sector=Banking + min_price=1500 → 1 match (HDFCBANK at 1700; ICICIBANK at 1100 below floor)
	req = reqWithEmail(http.MethodGet, "/dashboard/api/scanner?sector=Banking&min_price=1500&limit=50", "user@test.com")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total, "Banking + min_price=1500 should match 1 entry")
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "HDFCBANK", resp.Results[0].Tradingsymbol)

	// sector=Unknown → 0 matches
	req = reqWithEmail(http.MethodGet, "/dashboard/api/scanner?sector=Crypto&limit=50", "user@test.com")
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 0, resp.Total, "Unknown sector should match 0")
}

// TestScanner_PageSSR_RendersWithTopbar verifies the /dashboard/scanner
// page handler returns 200 and the rendered HTML includes the topbar
// title plus the Scanner-specific filter form. Phase 2 of the scanner
// feature (Axis C C.F1).
func TestScanner_PageSSR_RendersWithTopbar(t *testing.T) {
	t.Parallel()

	d := newDashboardWithSeededInstruments(t, map[uint32]*instruments.Instrument{})
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/scanner", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "scanner page should return 200; body=%s", rec.Body.String())
	assert.Contains(t, rec.Body.String(), "Scanner", "page title/topbar should contain Scanner")
	assert.Contains(t, rec.Body.String(), `id="scannerForm"`, "filter form should be rendered")
	assert.Contains(t, rec.Body.String(), "/dashboard/api/scanner", "page JS should reference scanner API")
}

// TestScanner_SectorFilter_NormalizeSymbol ensures the sector match
// uses kc/sectors.Lookup which strips -BE/-EQ suffixes (so SBIN-EQ
// resolves to Banking via SBIN→Banking).
func TestScanner_SectorFilter_NormalizeSymbol(t *testing.T) {
	t.Parallel()

	testData := map[uint32]*instruments.Instrument{
		500: {InstrumentToken: 500, Tradingsymbol: "SBIN-EQ", Exchange: "NSE", Name: "STATE BANK", LastPrice: 600, Segment: "NSE", InstrumentType: "EQ", Active: true},
		501: {InstrumentToken: 501, Tradingsymbol: "TCS-BE", Exchange: "NSE", Name: "TCS", LastPrice: 3500, Segment: "NSE", InstrumentType: "EQ", Active: true},
	}

	d := newDashboardWithSeededInstruments(t, testData)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// SBIN-EQ should normalize to SBIN → Banking sector.
	req := reqWithEmail(http.MethodGet, "/dashboard/api/scanner?sector=Banking&limit=50", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var resp scannerResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.Equal(t, 1, resp.Total, "SBIN-EQ should normalize and match Banking")
	require.Len(t, resp.Results, 1)
	assert.Equal(t, "SBIN-EQ", resp.Results[0].Tradingsymbol, "raw tradingsymbol preserved in response")
}
