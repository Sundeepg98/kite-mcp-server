package usecases

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"strings"
	"time"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// OptionInstrument is the slim instrument projection that the options
// strategy use case needs: enough to resolve a tradingsymbol from
// (underlying, type, strike, expiry) and to know the lot size.
//
// Mirrors fields from kc/instruments.Instrument but kept local to
// kc/usecases to avoid cross-module coupling — the adapter that
// implements OptionInstrumentLookup against the real instruments.Manager
// is wired at composition root (app/wire.go) where both packages are
// already imported.
type OptionInstrument struct {
	Tradingsymbol string
	Underlying    string  // e.g. "NIFTY"
	OptionType    string  // "CE" or "PE"
	Strike        float64
	Expiry        string  // YYYY-MM-DD prefix match
	LotSize       int
}

// OptionInstrumentLookup is the narrow port the use case needs for
// option-instrument resolution. Two methods cover the strategy build:
//   - FindOption: get the tradingsymbol + lot size for a (underlying,
//     type, strike, expiry) tuple
//   - DefaultLotSize: get a fallback lot size when the user hasn't
//     overridden it (uses the first matching option for the underlying)
//
// F5 rename precedent: same package already has LotSizeLookup
// (lot/tick metadata) and InstrumentResolver (token resolution). This
// is a third narrow port for option-specific lookup; intentionally
// distinct from the others to keep the use case dependencies narrow.
type OptionInstrumentLookup interface {
	FindOption(underlying, optionType string, strike float64, expiry string) (OptionInstrument, bool)
	DefaultLotSize(underlying string) (int, bool)
}

// StrategyLeg is the per-leg projection of an options strategy. JSON
// tags match the original mcp/trade/strategyLeg shape so the existing
// MCP tool handler + dashboard data path stay wire-compatible after
// the refactor (commit 1408871's payoffStrategyLeg consumes this same
// JSON shape).
type StrategyLeg struct {
	TradingSymbol string  `json:"tradingsymbol"`
	OptionType    string  `json:"option_type"` // CE or PE
	Strike        float64 `json:"strike"`
	Action        string  `json:"action"` // BUY or SELL
	Lots          int     `json:"lots"`
	Quantity      int     `json:"quantity"`
	Premium       float64 `json:"premium"`        // per-share LTP
	TotalPremium  float64 `json:"total_premium"`
}

// StrategyResponse is the use case output. JSON tags match the
// original mcp/trade/strategyResponse shape (wire-compat invariant).
type StrategyResponse struct {
	Strategy     string        `json:"strategy"`
	Underlying   string        `json:"underlying"`
	Expiry       string        `json:"expiry"`
	Legs         []StrategyLeg `json:"legs"`
	NetPremium   float64       `json:"net_premium"`
	MaxProfit    string        `json:"max_profit"`
	MaxLoss      string        `json:"max_loss"`
	MaxProfitAmt float64       `json:"max_profit_amt"`
	MaxLossAmt   float64       `json:"max_loss_amt"`
	Breakevens   []float64     `json:"breakevens"`
	RiskReward   string        `json:"risk_reward_ratio"`
	LotSize      int           `json:"lot_size"`
	TotalLots    int           `json:"total_lots"`
}

// BuildOptionsStrategyCommand is the input shape for the use case.
// Mirrors the URL/MCP-arg surface of options_payoff_builder.
type BuildOptionsStrategyCommand struct {
	Email      string
	Strategy   string  // bull_call_spread, bear_put_spread, ..., butterfly
	Underlying string  // NIFTY, BANKNIFTY, RELIANCE, ...
	Expiry     string  // YYYY-MM-DD
	Strike1    float64
	Strike2    float64
	Strike3    float64
	Strike4    float64
	LotSize    int     // 0 = auto-detect via OptionInstrumentLookup.DefaultLotSize
	Lots       int     // 0 or negative coerced to 1
}

// legSpec is the internal leg-build specification used during strategy
// expansion. Matches the prior mcp/trade legSpec shape.
type legSpec struct {
	strike     float64
	optionType string // CE or PE
	action     string // BUY or SELL
	lotsMulti  int    // multiplier (e.g., 2 for butterfly middle leg)
}

// BuildOptionsStrategyUseCase orchestrates the full options-strategy
// build: validate input → expand legs by strategy name → resolve
// instruments → fetch LTPs → compute P&L formulas → return populated
// StrategyResponse.
//
// Refactor invariant (Phase (a)): output JSON shape matches the
// pre-refactor mcp/trade strategyResponse so consumers (dashboard
// payoff page, MCP tool handler) work unchanged after the data-flow
// swap. The MCP tool handler becomes a thin arg-parse + use-case-call
// shell; the dashboard endpoint also calls the same use case.
type BuildOptionsStrategyUseCase struct {
	brokerResolver BrokerResolver
	instruments    OptionInstrumentLookup
	logger         logport.Logger
}

// NewBuildOptionsStrategyUseCase creates a BuildOptionsStrategyUseCase
// with all dependencies injected. Mirrors the constructor pattern used
// by other usecases in this package (see queries.go, place_order.go).
func NewBuildOptionsStrategyUseCase(resolver BrokerResolver, instruments OptionInstrumentLookup, logger *slog.Logger) *BuildOptionsStrategyUseCase {
	return &BuildOptionsStrategyUseCase{
		brokerResolver: resolver,
		instruments:    instruments,
		logger:         logport.NewSlog(logger),
	}
}

// Execute builds the options strategy and computes its payoff metrics.
// All input validation, leg expansion, instrument resolution, LTP
// fetching, and P&L formula application happen here.
func (uc *BuildOptionsStrategyUseCase) Execute(ctx context.Context, cmd BuildOptionsStrategyCommand) (*StrategyResponse, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	strategy := strings.ToLower(strings.TrimSpace(cmd.Strategy))
	if strategy == "" {
		return nil, fmt.Errorf("usecases: strategy is required")
	}
	underlying := strings.ToUpper(strings.TrimSpace(cmd.Underlying))
	if underlying == "" {
		return nil, fmt.Errorf("usecases: underlying is required")
	}
	if _, err := time.Parse("2006-01-02", cmd.Expiry); err != nil {
		return nil, fmt.Errorf("usecases: expiry must be in YYYY-MM-DD format: %w", err)
	}
	if cmd.Strike1 <= 0 {
		return nil, fmt.Errorf("usecases: strike1 is required (must be > 0)")
	}
	lots := cmd.Lots
	if lots < 1 {
		lots = 1
	}

	// Expand strategy → leg specs.
	specs, err := buildLegSpecs(strategy, cmd.Strike1, cmd.Strike2, cmd.Strike3, cmd.Strike4)
	if err != nil {
		return nil, err
	}

	// Resolve lot size: prefer caller override, else default from instrument lookup.
	lotSize := cmd.LotSize
	if lotSize <= 0 {
		if uc.instruments != nil {
			if defLot, ok := uc.instruments.DefaultLotSize(underlying); ok {
				lotSize = defLot
			}
		}
		if lotSize <= 0 {
			lotSize = 1 // last-resort fallback
		}
	}

	// Resolve trading symbols + collect instrument keys for batch LTP fetch.
	symbolForSpec := make([]string, len(specs))
	instrumentKeys := make([]string, 0, len(specs))
	for i, spec := range specs {
		if uc.instruments == nil {
			return nil, fmt.Errorf("usecases: instrument lookup not configured")
		}
		inst, ok := uc.instruments.FindOption(underlying, spec.optionType, spec.strike, cmd.Expiry)
		if !ok {
			return nil, fmt.Errorf("usecases: no instrument found for %s %s %.0f expiry %s", underlying, spec.optionType, spec.strike, cmd.Expiry)
		}
		symbolForSpec[i] = inst.Tradingsymbol
		instrumentKeys = append(instrumentKeys, "NFO:"+inst.Tradingsymbol)
	}

	// Batch LTP fetch via broker client.
	client, err := uc.brokerResolver.GetBrokerForEmail(cmd.Email)
	if err != nil {
		return nil, fmt.Errorf("usecases: resolve broker: %w", err)
	}
	if len(instrumentKeys) > 500 {
		instrumentKeys = instrumentKeys[:500]
	}
	ltpResp, err := client.GetLTP(instrumentKeys...)
	if err != nil {
		uc.logger.Error(ctx, "Failed to get LTP for strategy legs", err, "email", cmd.Email)
		return nil, fmt.Errorf("usecases: get LTP: %w", err)
	}

	// Build legs with premiums + compute net premium.
	legs := make([]StrategyLeg, 0, len(specs))
	netPremium := 0.0
	for i, spec := range specs {
		sym := symbolForSpec[i]
		key := "NFO:" + sym
		quote, ok := ltpResp[key]
		if !ok || quote.LastPrice <= 0 {
			return nil, fmt.Errorf("usecases: no LTP available for %s — market may be closed or symbol invalid", key)
		}
		premium := quote.LastPrice
		legLots := lots * spec.lotsMulti
		qty := legLots * lotSize
		totalPremium := premium * float64(qty)
		legs = append(legs, StrategyLeg{
			TradingSymbol: sym,
			OptionType:    spec.optionType,
			Strike:        spec.strike,
			Action:        spec.action,
			Lots:          legLots,
			Quantity:      qty,
			Premium:       round2(premium),
			TotalPremium:  round2(totalPremium),
		})
		if spec.action == "SELL" {
			netPremium += totalPremium
		} else {
			netPremium -= totalPremium
		}
	}

	// Compute strategy-level metrics.
	resp := &StrategyResponse{
		Strategy:   strategy,
		Underlying: underlying,
		Expiry:     cmd.Expiry,
		Legs:       legs,
		NetPremium: round2(netPremium),
		LotSize:    lotSize,
		TotalLots:  lots,
	}
	applyStrategyMetrics(resp, strategy, cmd.Strike1, cmd.Strike2, cmd.Strike3, cmd.Strike4, lotSize*lots)
	return resp, nil
}

// buildLegSpecs maps a strategy name + strikes to its leg specifications.
// Returns an error for unknown strategies or invalid strike orderings.
//
// Supported (mirror of pre-refactor mcp/trade options_payoff_builder):
//   - bull_call_spread, bear_put_spread, bear_call_spread, bull_put_spread
//   - straddle, strangle
//   - iron_condor (4 legs)
//   - butterfly (3 legs, middle sold 2x)
func buildLegSpecs(strategy string, strike1, strike2, strike3, strike4 float64) ([]legSpec, error) {
	switch strategy {
	case "bull_call_spread":
		if strike2 <= strike1 {
			return nil, fmt.Errorf("bull_call_spread requires strike2 > strike1")
		}
		return []legSpec{{strike1, "CE", "BUY", 1}, {strike2, "CE", "SELL", 1}}, nil

	case "bear_put_spread":
		if strike2 <= strike1 {
			return nil, fmt.Errorf("bear_put_spread requires strike2 > strike1 (sell lower put, buy higher put)")
		}
		return []legSpec{{strike1, "PE", "SELL", 1}, {strike2, "PE", "BUY", 1}}, nil

	case "bear_call_spread":
		if strike2 <= strike1 {
			return nil, fmt.Errorf("bear_call_spread requires strike2 > strike1 (sell lower call, buy higher call)")
		}
		return []legSpec{{strike1, "CE", "SELL", 1}, {strike2, "CE", "BUY", 1}}, nil

	case "bull_put_spread":
		if strike2 <= strike1 {
			return nil, fmt.Errorf("bull_put_spread requires strike2 > strike1 (buy lower put, sell higher put)")
		}
		return []legSpec{{strike1, "PE", "BUY", 1}, {strike2, "PE", "SELL", 1}}, nil

	case "straddle":
		return []legSpec{{strike1, "CE", "BUY", 1}, {strike1, "PE", "BUY", 1}}, nil

	case "strangle":
		if strike2 <= 0 {
			return nil, fmt.Errorf("strangle requires strike2 (OTM CE strike)")
		}
		return []legSpec{{strike1, "PE", "BUY", 1}, {strike2, "CE", "BUY", 1}}, nil

	case "iron_condor":
		if strike2 <= 0 || strike3 <= 0 || strike4 <= 0 {
			return nil, fmt.Errorf("iron_condor requires strike1 (buy PE) < strike2 (sell PE) < strike3 (sell CE) < strike4 (buy CE)")
		}
		if !(strike1 < strike2 && strike2 < strike3 && strike3 < strike4) {
			return nil, fmt.Errorf("iron_condor strikes must be ordered: strike1 < strike2 < strike3 < strike4")
		}
		return []legSpec{
			{strike1, "PE", "BUY", 1},
			{strike2, "PE", "SELL", 1},
			{strike3, "CE", "SELL", 1},
			{strike4, "CE", "BUY", 1},
		}, nil

	case "butterfly":
		if strike2 <= 0 || strike3 <= 0 {
			return nil, fmt.Errorf("butterfly requires strike1 < strike2 (middle, sold 2x) < strike3")
		}
		if !(strike1 < strike2 && strike2 < strike3) {
			return nil, fmt.Errorf("butterfly strikes must be ordered: strike1 < strike2 < strike3")
		}
		return []legSpec{
			{strike1, "CE", "BUY", 1},
			{strike2, "CE", "SELL", 2},
			{strike3, "CE", "BUY", 1},
		}, nil
	}
	return nil, fmt.Errorf("unknown strategy %q: supported are bull_call_spread, bear_put_spread, bear_call_spread, bull_put_spread, straddle, strangle, iron_condor, butterfly", strategy)
}

// applyStrategyMetrics fills in MaxProfit/Loss/Breakevens/RiskReward
// fields on the response, using strategy-specific payoff formulas.
// Caller has already populated Legs with premiums, NetPremium, etc.
//
// `qty` is the per-unit quantity = lotSize * lots (legs[i].Quantity
// already includes lotsMulti, so use the per-unit qty here).
func applyStrategyMetrics(resp *StrategyResponse, strategy string, strike1, strike2, strike3, strike4 float64, qty int) {
	qf := float64(qty)
	maxProfitStr := ""
	maxLossStr := ""
	maxProfitAmt := 0.0
	maxLossAmt := 0.0
	var breakevens []float64

	switch strategy {
	case "bull_call_spread":
		// BUY CE@K1 + SELL CE@K2 (K1<K2). Net debit.
		p1 := resp.Legs[0].Premium
		p2 := resp.Legs[1].Premium
		netDebit := p1 - p2
		maxProfitAmt = round2((strike2 - strike1 - netDebit) * qf)
		maxLossAmt = round2(netDebit * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{round2(strike1 + netDebit)}

	case "bear_put_spread":
		// SELL PE@K1 + BUY PE@K2 (K1<K2). Net debit.
		p1 := resp.Legs[0].Premium // received
		p2 := resp.Legs[1].Premium // paid
		netDebit := p2 - p1
		maxProfitAmt = round2((strike2 - strike1 - netDebit) * qf)
		maxLossAmt = round2(netDebit * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{round2(strike2 - netDebit)}

	case "bear_call_spread":
		// SELL CE@K1 + BUY CE@K2 (K1<K2). Net credit.
		p1 := resp.Legs[0].Premium // received
		p2 := resp.Legs[1].Premium // paid
		netCredit := p1 - p2
		maxProfitAmt = round2(netCredit * qf)
		maxLossAmt = round2((strike2 - strike1 - netCredit) * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{round2(strike1 + netCredit)}

	case "bull_put_spread":
		// BUY PE@K1 + SELL PE@K2 (K1<K2). Net credit.
		p1 := resp.Legs[0].Premium // paid
		p2 := resp.Legs[1].Premium // received
		netCredit := p2 - p1
		maxProfitAmt = round2(netCredit * qf)
		maxLossAmt = round2((strike2 - strike1 - netCredit) * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{round2(strike2 - netCredit)}

	case "straddle":
		// BUY CE + BUY PE @ same strike. Net debit. Unlimited profit.
		totalDebit := resp.Legs[0].Premium + resp.Legs[1].Premium
		maxProfitStr = "unlimited"
		maxLossAmt = round2(totalDebit * qf)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{
			round2(strike1 - totalDebit),
			round2(strike1 + totalDebit),
		}

	case "strangle":
		// BUY PE@K1 + BUY CE@K2. Net debit. Unlimited profit.
		totalDebit := resp.Legs[0].Premium + resp.Legs[1].Premium
		maxProfitStr = "unlimited"
		maxLossAmt = round2(totalDebit * qf)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{
			round2(strike1 - totalDebit),
			round2(strike2 + totalDebit),
		}

	case "iron_condor":
		// BUY PE@K1, SELL PE@K2, SELL CE@K3, BUY CE@K4. Net credit.
		p1 := resp.Legs[0].Premium // paid
		p2 := resp.Legs[1].Premium // received
		p3 := resp.Legs[2].Premium // received
		p4 := resp.Legs[3].Premium // paid
		netCredit := (p2 + p3) - (p1 + p4)
		putWing := strike2 - strike1
		callWing := strike4 - strike3
		widerWing := math.Max(putWing, callWing)
		maxProfitAmt = round2(netCredit * qf)
		maxLossAmt = round2((widerWing - netCredit) * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{
			round2(strike2 - netCredit),
			round2(strike3 + netCredit),
		}

	case "butterfly":
		// BUY CE@K1, SELL 2x CE@K2, BUY CE@K3. Net debit.
		p1 := resp.Legs[0].Premium
		p2 := resp.Legs[1].Premium
		p3 := resp.Legs[2].Premium
		netDebit := p1 - 2*p2 + p3
		if netDebit < 0 {
			netDebit = 0 // credit butterfly: floor at 0 for max-loss calc
		}
		wingWidth := strike2 - strike1
		maxProfitAmt = round2((wingWidth - netDebit) * qf)
		maxLossAmt = round2(netDebit * qf)
		maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
		maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
		breakevens = []float64{
			round2(strike1 + netDebit),
			round2(strike3 - netDebit),
		}
	}

	// Risk-reward ratio.
	rrStr := "N/A"
	if maxProfitAmt > 0 && maxLossAmt > 0 {
		rr := maxLossAmt / maxProfitAmt
		rrStr = fmt.Sprintf("1:%.2f", 1/rr)
	} else if maxProfitStr == "unlimited" && maxLossAmt > 0 {
		rrStr = "unlimited upside"
	}

	resp.MaxProfit = maxProfitStr
	resp.MaxLoss = maxLossStr
	resp.MaxProfitAmt = maxProfitAmt
	resp.MaxLossAmt = maxLossAmt
	resp.Breakevens = breakevens
	resp.RiskReward = rrStr
}

// round2 rounds to 2 decimal places. Matches the rounding helper used
// in mcp/trade pre-refactor for premium / max-profit / max-loss display.
func round2(x float64) float64 {
	return math.Round(x*100) / 100
}
