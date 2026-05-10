package ops

import (
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"strings"

	"github.com/algo2go/kite-mcp-broker"
	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-usecases"
	"github.com/algo2go/kite-mcp-oauth"
)

// PayoffHandler renders option-strategy payoff curves on the user
// dashboard. Phase (a) refactor: the API endpoint now accepts a
// strategy build-command (strategy + strikes + expiry) and constructs
// the StrategyResponse server-side via the BuildOptionsStrategy use
// case. The pure SVG renderer (renderPayoffSVG + computeLegPnL) is
// shared with the use case output.
//
// Pre-refactor (commit 1408871) accepted pre-built JSON via Option (c).
// The API handler retains backward-compat for that path: if the POST
// body has 'legs' populated, it skips the use case build and renders
// the supplied data directly. New callers should send the build-
// command shape (strategy/underlying/expiry/strike1..4/lots) and let
// the server resolve LTPs and compute legs.
type PayoffHandler struct {
	core *DashboardHandler
	uc   *usecases.BuildOptionsStrategyUseCase
}

func newPayoffHandler(core *DashboardHandler) *PayoffHandler {
	uc := usecases.NewBuildOptionsStrategyUseCase(
		dashboardBrokerResolverAdapter{core: core},
		dashboardOptionInstrumentLookupAdapter{core: core},
		nil, // logger threaded via context
	)
	return &PayoffHandler{core: core, uc: uc}
}

// dashboardBrokerResolverAdapter bridges *kc.Manager to the
// usecases.BrokerResolver port. Mirrors the brokerResolverAdapter in
// mcp/trade/options_greeks_tool.go but lives at the kc/ops composition
// root.
type dashboardBrokerResolverAdapter struct {
	core *DashboardHandler
}

func (a dashboardBrokerResolverAdapter) GetBrokerForEmail(email string) (broker.Client, error) {
	if a.core == nil || a.core.manager == nil {
		return nil, fmt.Errorf("manager not configured")
	}
	return a.core.manager.GetBrokerForEmail(email)
}

// dashboardOptionInstrumentLookupAdapter bridges kc.InstrumentManagerInterface
// to usecases.OptionInstrumentLookup. Mirrors the adapter in mcp/trade.
type dashboardOptionInstrumentLookupAdapter struct {
	core *DashboardHandler
}

func (a dashboardOptionInstrumentLookupAdapter) FindOption(underlying, optionType string, strike float64, expiry string) (usecases.OptionInstrument, bool) {
	if a.core == nil || a.core.manager == nil {
		return usecases.OptionInstrument{}, false
	}
	mgr := a.core.manager.InstrumentsManager()
	if mgr == nil {
		return usecases.OptionInstrument{}, false
	}
	found := mgr.Filter(func(inst instruments.Instrument) bool {
		return inst.Exchange == "NFO" &&
			strings.EqualFold(inst.Name, underlying) &&
			inst.InstrumentType == optionType &&
			inst.Strike == strike &&
			strings.HasPrefix(inst.ExpiryDate, expiry)
	})
	if len(found) == 0 {
		return usecases.OptionInstrument{}, false
	}
	inst := found[0]
	return usecases.OptionInstrument{
		Tradingsymbol: inst.Tradingsymbol,
		Underlying:    inst.Name,
		OptionType:    inst.InstrumentType,
		Strike:        inst.Strike,
		Expiry:        expiry,
		LotSize:       inst.LotSize,
	}, true
}

func (a dashboardOptionInstrumentLookupAdapter) DefaultLotSize(underlying string) (int, bool) {
	if a.core == nil || a.core.manager == nil {
		return 0, false
	}
	mgr := a.core.manager.InstrumentsManager()
	if mgr == nil || mgr.Count() == 0 {
		return 0, false
	}
	found := mgr.Filter(func(inst instruments.Instrument) bool {
		return inst.Exchange == "NFO" &&
			strings.EqualFold(inst.Name, underlying) &&
			(inst.InstrumentType == "CE" || inst.InstrumentType == "PE") &&
			inst.LotSize > 0
	})
	if len(found) == 0 {
		return 0, false
	}
	return found[0].LotSize, true
}

// payoffStrategyLeg + payoffStrategyResponse are type aliases of the
// canonical usecases types. The aliases keep existing test signatures
// and the SVG renderer's parameter names readable without forcing the
// renderer to import mcp/trade or duplicating types.
type payoffStrategyLeg = usecases.StrategyLeg
type payoffStrategyResponse = usecases.StrategyResponse

// payoffAPIRequest is the build-command shape for POST
// /dashboard/api/payoff. Used by the new server-side-build path.
// Backward-compat: if the body's `legs` field is non-empty (indicating
// a pre-built response from the AI client), the handler bypasses the
// use case and renders directly.
type payoffAPIRequest struct {
	// Build-command fields (used when Legs is empty)
	Strategy   string  `json:"strategy"`
	Underlying string  `json:"underlying"`
	Expiry     string  `json:"expiry"`
	Strike1    float64 `json:"strike1"`
	Strike2    float64 `json:"strike2"`
	Strike3    float64 `json:"strike3"`
	Strike4    float64 `json:"strike4"`
	LotSize    int     `json:"lot_size"`
	Lots       int     `json:"lots"`
	// Pre-built-response field (used when populated, bypasses build).
	Legs         []payoffStrategyLeg `json:"legs,omitempty"`
	NetPremium   float64             `json:"net_premium,omitempty"`
	MaxProfit    string              `json:"max_profit,omitempty"`
	MaxLoss      string              `json:"max_loss,omitempty"`
	MaxProfitAmt float64             `json:"max_profit_amt,omitempty"`
	MaxLossAmt   float64             `json:"max_loss_amt,omitempty"`
	Breakevens   []float64           `json:"breakevens,omitempty"`
	RiskReward   string              `json:"risk_reward_ratio,omitempty"`
}

// payoffAPIResponse is the JSON envelope returned by /dashboard/api/payoff.
// Strategy field carries the canonical strategy name; SVG is embedded
// inline; SpotMin/SpotMax are the spot-price range used for plotting;
// StrategyResponse is the full structured payload (use case output OR
// the pre-built body) so the page can render the legs table without
// re-sending the input.
type payoffAPIResponse struct {
	Strategy         string                  `json:"strategy"`
	SVG              string                  `json:"svg"`
	SpotMin          float64                 `json:"spot_min"`
	SpotMax          float64                 `json:"spot_max"`
	StrategyResponse *payoffStrategyResponse `json:"strategy_response,omitempty"`
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

// payoffAPI handles POST /dashboard/api/payoff. Two modes:
//
// (1) Server-side build (preferred) — body has strategy + strikes +
//     expiry; the BuildOptionsStrategy use case fetches LTPs and
//     computes legs/breakevens/max-P&L server-side.
//
// (2) Backward-compat pre-built JSON — body has populated legs[]
//     (from a prior options_payoff_builder MCP-tool call); handler
//     skips the use case and renders directly. Preserves the
//     Option (c) flow shipped at commit 1408871.
//
// Mode is auto-detected: if `legs` is non-empty, mode (2); else mode (1).
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

	var body payoffAPIRequest
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON body: "+err.Error(), http.StatusBadRequest)
		return
	}

	var resp *payoffStrategyResponse
	if len(body.Legs) > 0 {
		// Mode (2): pre-built body. Wrap the input fields into a
		// StrategyResponse for the renderer.
		resp = &payoffStrategyResponse{
			Strategy:     body.Strategy,
			Underlying:   body.Underlying,
			Expiry:       body.Expiry,
			Legs:         body.Legs,
			NetPremium:   body.NetPremium,
			MaxProfit:    body.MaxProfit,
			MaxLoss:      body.MaxLoss,
			MaxProfitAmt: body.MaxProfitAmt,
			MaxLossAmt:   body.MaxLossAmt,
			Breakevens:   body.Breakevens,
			RiskReward:   body.RiskReward,
			LotSize:      body.LotSize,
			TotalLots:    body.Lots,
		}
	} else {
		// Mode (1): server-side build. Validate command shape first
		// (so users see arg-shape errors before broker resolution).
		cmd := usecases.BuildOptionsStrategyCommand{
			Email:      email,
			Strategy:   body.Strategy,
			Underlying: body.Underlying,
			Expiry:     body.Expiry,
			Strike1:    body.Strike1,
			Strike2:    body.Strike2,
			Strike3:    body.Strike3,
			Strike4:    body.Strike4,
			LotSize:    body.LotSize,
			Lots:       body.Lots,
		}
		if cmd.Strategy == "" || cmd.Underlying == "" || cmd.Expiry == "" || cmd.Strike1 <= 0 {
			http.Error(w, "strategy, underlying, expiry, and strike1 are required when legs is empty", http.StatusBadRequest)
			return
		}
		if _, err := usecases.ValidateOptionsStrategyCommand(cmd); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		built, err := h.uc.Execute(r.Context(), cmd)
		if err != nil {
			h.core.loggerPort.Error(r.Context(), "Failed to build options strategy", err, "email", email)
			http.Error(w, "build failed: "+err.Error(), http.StatusBadRequest)
			return
		}
		resp = built
	}

	if len(resp.Legs) == 0 {
		http.Error(w, "strategy must have at least one leg", http.StatusBadRequest)
		return
	}

	// Compute spot range: ±20% around the average strike across legs.
	var sumStrikes float64
	var nStrikes int
	for _, leg := range resp.Legs {
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

	svg := renderPayoffSVG(*resp, spotMin, spotMax, 81)

	h.core.writeJSON(w, payoffAPIResponse{
		Strategy:         resp.Strategy,
		SVG:              svg,
		SpotMin:          spotMin,
		SpotMax:          spotMax,
		StrategyResponse: resp,
	})
}

// servePayoffPageSSR renders the /dashboard/payoff page. Server-side
// build mode is now the default: the page presents a strategy picker
// (sector/strikes/expiry/lots) and POSTs to /dashboard/api/payoff
// without needing the user to copy-paste from the AI client first.
// Pre-built JSON paste path remains supported (degrades gracefully
// for users who already have an MCP-tool response).
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
