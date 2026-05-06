package ops

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/zerodha/kite-mcp-server/oauth"
)

// PayoffHandler renders option-strategy payoff curves on the user
// dashboard. Phase C of payoff-viz (Option (c) per coordinator pivot —
// accepts the existing options_payoff_builder MCP-tool output JSON
// shape directly; the AI client builds the strategy via MCP, then
// posts the JSON here for visualization).
//
// This is the "data flows in from outside" entry point. A future
// Option (a) refactor will extract options_payoff_builder logic to
// kc/usecases/options_strategy.go and replace this entry point with a
// server-side call that builds the strategy itself; the SVG renderer
// (renderPayoffSVG + computeLegPnL below) is reusable across both
// data-flow paths.
type PayoffHandler struct {
	core *DashboardHandler
}

func newPayoffHandler(core *DashboardHandler) *PayoffHandler {
	return &PayoffHandler{core: core}
}

// payoffStrategyLeg mirrors mcp/trade/strategyLeg JSON shape. Declared
// locally rather than imported from mcp/trade because the contract is
// JSON-on-the-wire (POSTed body), not Go type identity. This keeps
// kc/ops dependency-free of mcp/.
type payoffStrategyLeg struct {
	TradingSymbol string  `json:"tradingsymbol"`
	OptionType    string  `json:"option_type"` // CE or PE
	Strike        float64 `json:"strike"`
	Action        string  `json:"action"` // BUY or SELL
	Lots          int     `json:"lots"`
	Quantity      int     `json:"quantity"`
	Premium       float64 `json:"premium"` // per-share LTP
	TotalPremium  float64 `json:"total_premium"`
}

// payoffStrategyResponse mirrors mcp/trade/strategyResponse JSON shape.
// Populated by the AI client calling options_payoff_builder MCP tool;
// the dashboard accepts the JSON body directly for SVG rendering.
type payoffStrategyResponse struct {
	Strategy     string              `json:"strategy"`
	Underlying   string              `json:"underlying"`
	Expiry       string              `json:"expiry"`
	Legs         []payoffStrategyLeg `json:"legs"`
	NetPremium   float64             `json:"net_premium"`
	MaxProfit    string              `json:"max_profit"`
	MaxLoss      string              `json:"max_loss"`
	MaxProfitAmt float64             `json:"max_profit_amt"`
	MaxLossAmt   float64             `json:"max_loss_amt"`
	Breakevens   []float64           `json:"breakevens"`
	RiskReward   string              `json:"risk_reward_ratio"`
	LotSize      int                 `json:"lot_size"`
	TotalLots    int                 `json:"total_lots"`
}

// payoffAPIResponse is the JSON envelope returned by /dashboard/api/payoff.
// SVG is embedded inline (no separate image-fetch round-trip; the
// dashboard injects it directly into the page via innerHTML).
type payoffAPIResponse struct {
	Strategy string  `json:"strategy"`
	SVG      string  `json:"svg"`
	SpotMin  float64 `json:"spot_min"`
	SpotMax  float64 `json:"spot_max"`
}

// computeLegPnL returns the per-share P&L of a single leg at the given
// spot price at expiry. Standard option-payoff formulas:
//
//	Long CE:  max(spot - strike, 0) - premium
//	Short CE: premium - max(spot - strike, 0)
//	Long PE:  max(strike - spot, 0) - premium
//	Short PE: premium - max(strike - spot, 0)
//
// Sign convention: positive P&L = profit. Premium is the per-share
// LTP at strategy entry (already paid for BUY, already received for SELL).
func computeLegPnL(leg payoffStrategyLeg, spot float64) float64 {
	var intrinsic float64
	switch strings.ToUpper(leg.OptionType) {
	case "CE":
		intrinsic = math.Max(spot-leg.Strike, 0)
	case "PE":
		intrinsic = math.Max(leg.Strike-spot, 0)
	default:
		return 0
	}
	if strings.ToUpper(leg.Action) == "BUY" {
		return intrinsic - leg.Premium
	}
	// SELL
	return leg.Premium - intrinsic
}

// renderPayoffSVG produces an SVG visualization of the strategy payoff
// curve across [spotMin, spotMax] with the requested number of sample
// points. Returns the full <svg>…</svg> string ready to embed inline.
//
// Layout:
//   - Width 720px, height 360px (16:8 aspect; mobile-friendly)
//   - X-axis: spot price (linear)
//   - Y-axis: P&L (per single-lot share count)
//   - Zero P&L line (horizontal, dashed)
//   - Breakeven markers (vertical dashed lines + labels)
//   - P&L curve (polyline, accent color)
//   - Strategy name + Max P/L annotations
func renderPayoffSVG(resp payoffStrategyResponse, spotMin, spotMax float64, samples int) string {
	if samples < 2 {
		samples = 2
	}
	// Compute P&L curve (per-share, summed across legs).
	xs := make([]float64, samples)
	ys := make([]float64, samples)
	for i := range samples {
		spot := spotMin + (spotMax-spotMin)*float64(i)/float64(samples-1)
		xs[i] = spot
		var total float64
		for _, leg := range resp.Legs {
			total += computeLegPnL(leg, spot)
		}
		ys[i] = total
	}

	// Y-axis bounds (with 10% padding).
	yMin, yMax := ys[0], ys[0]
	for _, y := range ys {
		if y < yMin {
			yMin = y
		}
		if y > yMax {
			yMax = y
		}
	}
	yPad := (yMax - yMin) * 0.10
	if yPad < 1 {
		yPad = 1
	}
	yMin -= yPad
	yMax += yPad

	// SVG layout constants.
	const (
		w           = 720
		h           = 360
		marginLeft  = 60
		marginRight = 20
		marginTop   = 40
		marginBot   = 40
	)
	plotW := float64(w - marginLeft - marginRight)
	plotH := float64(h - marginTop - marginBot)

	// Coordinate transforms.
	xToPx := func(x float64) float64 {
		return float64(marginLeft) + (x-spotMin)/(spotMax-spotMin)*plotW
	}
	yToPx := func(y float64) float64 {
		return float64(marginTop) + (yMax-y)/(yMax-yMin)*plotH
	}

	var b strings.Builder
	fmt.Fprintf(&b, `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="100%%" preserveAspectRatio="xMidYMid meet" role="img" aria-label="Payoff curve for %s">`, w, h, resp.Strategy)

	// Background.
	b.WriteString(`<rect width="100%" height="100%" fill="#0f1218"/>`)

	// Plot area background (subtle).
	fmt.Fprintf(&b, `<rect x="%d" y="%d" width="%.0f" height="%.0f" fill="#161b24" stroke="#252d3a"/>`, marginLeft, marginTop, plotW, plotH)

	// Zero-P&L horizontal line (dashed grey).
	zeroY := yToPx(0)
	fmt.Fprintf(&b, `<line x1="%d" y1="%.1f" x2="%.1f" y2="%.1f" stroke="#64748b" stroke-width="1" stroke-dasharray="4,3"/>`, marginLeft, zeroY, float64(marginLeft)+plotW, zeroY)

	// Breakeven vertical lines + labels.
	for _, be := range resp.Breakevens {
		if be < spotMin || be > spotMax {
			continue
		}
		px := xToPx(be)
		fmt.Fprintf(&b, `<line x1="%.1f" y1="%d" x2="%.1f" y2="%.0f" stroke="#fbbf24" stroke-width="1" stroke-dasharray="3,3"/>`, px, marginTop, px, float64(marginTop)+plotH)
		fmt.Fprintf(&b, `<text x="%.1f" y="%d" fill="#fbbf24" font-family="JetBrains Mono, monospace" font-size="11" text-anchor="middle">BE %.0f</text>`, px, marginTop-6, be)
	}

	// X-axis labels (min, mid, max spot).
	mid := (spotMin + spotMax) / 2
	fmt.Fprintf(&b, `<text x="%d" y="%.0f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="start">%.0f</text>`, marginLeft, float64(marginTop)+plotH+18, spotMin)
	fmt.Fprintf(&b, `<text x="%.1f" y="%.0f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="middle">%.0f</text>`, float64(marginLeft)+plotW/2, float64(marginTop)+plotH+18, mid)
	fmt.Fprintf(&b, `<text x="%.0f" y="%.0f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">%.0f</text>`, float64(marginLeft)+plotW, float64(marginTop)+plotH+18, spotMax)

	// Y-axis labels (yMin, 0, yMax).
	fmt.Fprintf(&b, `<text x="%d" y="%.1f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">%.0f</text>`, marginLeft-6, float64(marginTop)+10, yMax)
	fmt.Fprintf(&b, `<text x="%d" y="%.1f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">0</text>`, marginLeft-6, zeroY+3)
	fmt.Fprintf(&b, `<text x="%d" y="%.1f" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="10" text-anchor="end">%.0f</text>`, marginLeft-6, float64(marginTop)+plotH-2, yMin)

	// P&L polyline.
	b.WriteString(`<polyline fill="none" stroke="#22d3ee" stroke-width="2" points="`)
	for i := range samples {
		fmt.Fprintf(&b, "%.1f,%.1f ", xToPx(xs[i]), yToPx(ys[i]))
	}
	b.WriteString(`"/>`)

	// Title (top-left).
	fmt.Fprintf(&b, `<text x="%d" y="22" fill="#e2e8f0" font-family="DM Sans, sans-serif" font-size="14" font-weight="600">%s · %s · expiry %s</text>`,
		marginLeft, resp.Strategy, resp.Underlying, resp.Expiry)

	// Max P/L summary (top-right).
	mpStr := resp.MaxProfit
	if mpStr == "" {
		mpStr = "—"
	}
	mlStr := resp.MaxLoss
	if mlStr == "" {
		mlStr = "—"
	}
	fmt.Fprintf(&b, `<text x="%d" y="22" fill="#94a3b8" font-family="JetBrains Mono, monospace" font-size="11" text-anchor="end">Max Profit: ₹%s · Max Loss: ₹%s</text>`,
		w-marginRight, mpStr, mlStr)

	b.WriteString(`</svg>`)
	return b.String()
}

// payoffAPI handles POST /dashboard/api/payoff. Accepts a strategy
// JSON body matching options_payoff_builder MCP tool output, returns
// {strategy, svg, spot_min, spot_max} JSON envelope.
func (h *PayoffHandler) payoffAPI(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	email := oauth.EmailFromContext(r.Context())
	if email == "" {
		http.Error(w, "not authenticated", http.StatusUnauthorized)
		return
	}

	var body payoffStrategyResponse
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}
	if len(body.Legs) == 0 {
		http.Error(w, "strategy must have at least one leg", http.StatusBadRequest)
		return
	}

	// Compute spot range: ±20% around the average strike across legs.
	// Falls back to [80, 120] if no strikes present (defensive — rejected above
	// by len(Legs)==0, but guards against a leg with strike=0).
	var sumStrikes float64
	var nStrikes int
	for _, leg := range body.Legs {
		if leg.Strike > 0 {
			sumStrikes += leg.Strike
			nStrikes++
		}
	}
	avgStrike := 100.0
	if nStrikes > 0 {
		avgStrike = sumStrikes / float64(nStrikes)
	}
	spotMin := avgStrike * 0.80
	spotMax := avgStrike * 1.20

	svg := renderPayoffSVG(body, spotMin, spotMax, 81) // 81 sample points → smooth curve

	h.core.writeJSON(w, payoffAPIResponse{
		Strategy: body.Strategy,
		SVG:      svg,
		SpotMin:  spotMin,
		SpotMax:  spotMax,
	})
}

// servePayoffPageSSR renders the /dashboard/payoff page. JS-driven —
// the page accepts pasted strategy JSON, POSTs to /dashboard/api/payoff,
// and injects the returned SVG inline.
func (h *PayoffHandler) servePayoffPageSSR(w http.ResponseWriter, r *http.Request) {
	d := h.core
	if d.payoffTmpl == nil {
		d.servePageFallback(w, "payoff.html")
		return
	}

	email, role, tokenValid := d.userContext(r)
	data := PayoffPageData{
		Email:      email,
		Role:       role,
		TokenValid: tokenValid,
		UpdatedAt:  nowTimestamp(),
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := d.payoffTmpl.Execute(w, data); err != nil {
		d.loggerPort.Error(r.Context(), "Failed to render payoff page", err)
	}
}
