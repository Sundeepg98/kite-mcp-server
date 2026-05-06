package ops

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPayoff_RenderSVG_BullCallSpread verifies the pure SVG renderer
// produces a valid SVG with axis lines, breakeven marker, and at least
// one P&L curve segment for a bull-call-spread strategy.
//
// Phase C.1 of payoff-viz (Option (c) per coordinator pivot — accepts
// pre-built strategy JSON; refactor to use case in Phase (a) later).
func TestPayoff_RenderSVG_BullCallSpread(t *testing.T) {
	t.Parallel()

	// Bull call spread: BUY CE@100 + SELL CE@110, lot size 100.
	// Net debit = 5 (paid 8 - received 3).
	// Max profit at spot >= 110: (110-100-5) * 100 = 500
	// Max loss at spot <= 100: 5 * 100 = 500 (the net debit)
	// Breakeven: 100 + 5 = 105
	resp := payoffStrategyResponse{
		Strategy:   "bull_call_spread",
		Underlying: "NIFTY",
		Expiry:     "2026-05-29",
		Legs: []payoffStrategyLeg{
			{TradingSymbol: "NIFTY26MAY100CE", OptionType: "CE", Strike: 100, Action: "BUY", Lots: 1, Quantity: 100, Premium: 8, TotalPremium: 800},
			{TradingSymbol: "NIFTY26MAY110CE", OptionType: "CE", Strike: 110, Action: "SELL", Lots: 1, Quantity: 100, Premium: 3, TotalPremium: 300},
		},
		NetPremium:   -500, // net debit
		MaxProfit:    "500.00",
		MaxLoss:      "500.00",
		MaxProfitAmt: 500,
		MaxLossAmt:   500,
		Breakevens:   []float64{105},
		RiskReward:   "1:1.00",
		LotSize:      100,
		TotalLots:    1,
	}

	svg := renderPayoffSVG(resp, 80, 130, 51) // spot 80→130, 51 sample points

	// Sanity: looks like SVG.
	assert.True(t, strings.HasPrefix(svg, `<svg`), "should start with <svg")
	assert.True(t, strings.HasSuffix(svg, `</svg>`), "should end with </svg>")

	// Has axis labels for both ends of spot range.
	assert.Contains(t, svg, "80", "x-axis should show min spot")
	assert.Contains(t, svg, "130", "x-axis should show max spot")

	// Has breakeven marker (vertical line + label at spot=105).
	assert.Contains(t, svg, "105", "breakeven 105 should be labeled")

	// Has a P&L curve (polyline).
	assert.Contains(t, svg, "<polyline", "should render P&L curve as polyline")

	// Strategy name annotation.
	assert.Contains(t, svg, "bull_call_spread", "strategy name should appear in annotation")

	// Max profit/loss markers.
	assert.Contains(t, svg, "Max Profit", "max profit marker label")
	assert.Contains(t, svg, "Max Loss", "max loss marker label")
}

// TestPayoff_ComputeLegPnL verifies per-leg P&L at expiry follows the
// canonical option-payoff formulas:
//   Long CE: max(spot-strike, 0) - premium
//   Short CE: premium - max(spot-strike, 0)
//   Long PE: max(strike-spot, 0) - premium
//   Short PE: premium - max(strike-spot, 0)
func TestPayoff_ComputeLegPnL(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		leg     payoffStrategyLeg
		spot    float64
		wantPnL float64 // per-share
	}{
		{"long CE ITM", payoffStrategyLeg{OptionType: "CE", Strike: 100, Action: "BUY", Premium: 5}, 110, 5},   // max(10,0) - 5
		{"long CE OTM", payoffStrategyLeg{OptionType: "CE", Strike: 100, Action: "BUY", Premium: 5}, 90, -5},   // max(0,0) - 5
		{"short CE ITM", payoffStrategyLeg{OptionType: "CE", Strike: 100, Action: "SELL", Premium: 5}, 110, -5}, // 5 - max(10,0)
		{"short CE OTM", payoffStrategyLeg{OptionType: "CE", Strike: 100, Action: "SELL", Premium: 5}, 90, 5},   // 5 - 0
		{"long PE ITM", payoffStrategyLeg{OptionType: "PE", Strike: 100, Action: "BUY", Premium: 5}, 90, 5},     // max(10,0) - 5
		{"long PE OTM", payoffStrategyLeg{OptionType: "PE", Strike: 100, Action: "BUY", Premium: 5}, 110, -5},   // max(-10→0) - 5
		{"short PE ITM", payoffStrategyLeg{OptionType: "PE", Strike: 100, Action: "SELL", Premium: 5}, 90, -5},  // 5 - max(10,0)
		{"short PE OTM", payoffStrategyLeg{OptionType: "PE", Strike: 100, Action: "SELL", Premium: 5}, 110, 5},  // 5 - 0
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := computeLegPnL(tc.leg, tc.spot)
			assert.InDelta(t, tc.wantPnL, got, 0.001, "computeLegPnL(%s, spot=%.0f)", tc.name, tc.spot)
		})
	}
}

// TestPayoff_API_PostStrategy verifies the /dashboard/api/payoff endpoint
// accepts a strategyResponse JSON body via POST and returns SVG inline
// inside a JSON envelope. Auth is required.
func TestPayoff_API_PostStrategy(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := payoffStrategyResponse{
		Strategy:     "bull_call_spread",
		Underlying:   "NIFTY",
		Expiry:       "2026-05-29",
		Legs: []payoffStrategyLeg{
			{TradingSymbol: "NIFTY26MAY100CE", OptionType: "CE", Strike: 100, Action: "BUY", Lots: 1, Quantity: 100, Premium: 8, TotalPremium: 800},
			{TradingSymbol: "NIFTY26MAY110CE", OptionType: "CE", Strike: 110, Action: "SELL", Lots: 1, Quantity: 100, Premium: 3, TotalPremium: 300},
		},
		NetPremium:   -500,
		MaxProfit:    "500.00",
		MaxLoss:      "500.00",
		MaxProfitAmt: 500,
		MaxLossAmt:   500,
		Breakevens:   []float64{105},
		RiskReward:   "1:1.00",
		LotSize:      100,
		TotalLots:    1,
	}
	bodyJSON, err := json.Marshal(body)
	require.NoError(t, err)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/payoff", "user@test.com")
	req.Body = io.NopCloser(bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())

	var resp payoffAPIResponse
	require.NoError(t, json.NewDecoder(rec.Body).Decode(&resp))
	assert.NotEmpty(t, resp.SVG, "SVG must be non-empty")
	assert.True(t, strings.HasPrefix(resp.SVG, "<svg"), "SVG must start with <svg")
	assert.Equal(t, "bull_call_spread", resp.Strategy)
	assert.InDelta(t, 105.0, resp.SpotMin, 50.0, "SpotMin should be in reasonable range")
	assert.InDelta(t, 105.0, resp.SpotMax, 50.0, "SpotMax should be in reasonable range")
}

// TestPayoff_API_RequiresAuth verifies unauthenticated POSTs return 401.
func TestPayoff_API_RequiresAuth(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := httptest.NewRequest(http.MethodPost, "/dashboard/api/payoff", strings.NewReader("{}"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusUnauthorized, rec.Code)
}

// TestPayoff_API_RejectsBadJSON verifies a malformed body yields 400.
func TestPayoff_API_RejectsBadJSON(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodPost, "/dashboard/api/payoff", "user@test.com")
	req.Body = io.NopCloser(strings.NewReader("not-json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestPayoff_API_RejectsEmptyLegs verifies a strategy with zero legs
// yields 400 (renderer can't compute anything).
//
// After Phase (a) refactor: empty `legs` field triggers server-side
// build mode; if `strategy`+`strike1` is also incomplete, command-shape
// pre-validation kicks in and returns 400.
func TestPayoff_API_RejectsEmptyLegs(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := `{"strategy":"empty","underlying":"X","legs":[]}`
	req := reqWithEmail(http.MethodPost, "/dashboard/api/payoff", "user@test.com")
	req.Body = io.NopCloser(strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
}

// TestPayoff_API_BuildModeMissingStrikes verifies the server-side build
// path returns 400 when the build-command is incomplete (no strikes).
// Phase (a) addition: this path didn't exist pre-refactor.
func TestPayoff_API_BuildModeMissingStrikes(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	// Build-command shape (no `legs`) but missing strike1.
	body := `{"strategy":"straddle","underlying":"NIFTY","expiry":"2026-05-29"}`
	req := reqWithEmail(http.MethodPost, "/dashboard/api/payoff", "user@test.com")
	req.Body = io.NopCloser(strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "strike1")
}

// TestPayoff_API_BuildModeUnknownStrategy verifies the server-side build
// path returns 400 with canonical "Unknown strategy" wording before
// touching the broker — pre-validation matches the MCP tool's behavior.
func TestPayoff_API_BuildModeUnknownStrategy(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	body := `{"strategy":"no_such","underlying":"NIFTY","expiry":"2026-05-29","strike1":24000}`
	req := reqWithEmail(http.MethodPost, "/dashboard/api/payoff", "user@test.com")
	req.Body = io.NopCloser(strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, rec.Body.String(), "Unknown strategy")
}

// TestPayoff_PageSSR verifies the /dashboard/payoff page renders 200
// with the expected form + script hooks.
func TestPayoff_PageSSR(t *testing.T) {
	t.Parallel()

	d := newDashboardWithAuditAndPaper(t)
	mux := http.NewServeMux()
	d.RegisterRoutes(mux, noopAuth)

	req := reqWithEmail(http.MethodGet, "/dashboard/payoff", "user@test.com")
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code, "body=%s", rec.Body.String())
	body := rec.Body.String()
	assert.Contains(t, body, "Payoff", "page title/topbar should mention Payoff")
	assert.Contains(t, body, "/dashboard/api/payoff", "page JS should reference payoff API")
	assert.Contains(t, body, `id="payoffStrategyInput"`, "input form should be rendered")
}
