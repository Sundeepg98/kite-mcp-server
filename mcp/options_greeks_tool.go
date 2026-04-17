package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ---------------------------------------------------------------------------
// Black-Scholes primitives (pure Go, no external deps)
// ---------------------------------------------------------------------------

// normalCDF returns the cumulative distribution function of the standard normal.
func normalCDF(x float64) float64 {
	return 0.5 * (1 + math.Erf(x/math.Sqrt2))
}

// normalPDF returns the probability density function of the standard normal.
func normalPDF(x float64) float64 {
	return math.Exp(-x*x/2) / math.Sqrt(2*math.Pi)
}

// bsD1 computes the d1 parameter of Black-Scholes.
func bsD1(S, K, T, r, sigma float64) float64 {
	return (math.Log(S/K) + (r+sigma*sigma/2)*T) / (sigma * math.Sqrt(T))
}

// blackScholesPrice computes the theoretical option price.
// S = spot, K = strike, T = time to expiry (years), r = risk-free rate,
// sigma = volatility, isCall = true for CE / false for PE.
func blackScholesPrice(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		// At or past expiry, return intrinsic value.
		if isCall {
			return math.Max(S-K, 0)
		}
		return math.Max(K-S, 0)
	}
	d1 := bsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	if isCall {
		return S*normalCDF(d1) - K*math.Exp(-r*T)*normalCDF(d2)
	}
	return K*math.Exp(-r*T)*normalCDF(-d2) - S*normalCDF(-d1)
}

// bsDelta returns the Black-Scholes delta.
func bsDelta(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := bsD1(S, K, T, r, sigma)
	if isCall {
		return normalCDF(d1)
	}
	return normalCDF(d1) - 1
}

// bsGamma returns the Black-Scholes gamma (same for calls and puts).
func bsGamma(S, K, T, r, sigma float64) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := bsD1(S, K, T, r, sigma)
	return normalPDF(d1) / (S * sigma * math.Sqrt(T))
}

// bsTheta returns the Black-Scholes theta per calendar day.
func bsTheta(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := bsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	common := -(S * normalPDF(d1) * sigma) / (2 * math.Sqrt(T))
	if isCall {
		return (common - r*K*math.Exp(-r*T)*normalCDF(d2)) / 365.25
	}
	return (common + r*K*math.Exp(-r*T)*normalCDF(-d2)) / 365.25
}

// bsVega returns the Black-Scholes vega per 1% move in volatility.
func bsVega(S, K, T, r, sigma float64) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := bsD1(S, K, T, r, sigma)
	return S * normalPDF(d1) * math.Sqrt(T) / 100
}

// bsRho returns the Black-Scholes rho per 1% move in the risk-free rate.
func bsRho(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := bsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	if isCall {
		return K * T * math.Exp(-r*T) * normalCDF(d2) / 100
	}
	return -K * T * math.Exp(-r*T) * normalCDF(-d2) / 100
}

// impliedVolatility solves for sigma such that BS(sigma) ~ marketPrice,
// using Newton-Raphson with a bisection fallback.
func impliedVolatility(marketPrice, S, K, T, r float64, isCall bool) (float64, bool) {
	if T <= 0 || marketPrice <= 0 {
		return 0, false
	}

	// Intrinsic value check — IV cannot be computed if price < intrinsic.
	intrinsic := 0.0
	if isCall {
		intrinsic = math.Max(S-K*math.Exp(-r*T), 0)
	} else {
		intrinsic = math.Max(K*math.Exp(-r*T)-S, 0)
	}
	if marketPrice < intrinsic-0.01 {
		return 0, false
	}

	sigma := 0.3 // initial guess
	for range 100 {
		price := blackScholesPrice(S, K, T, r, sigma, isCall)
		v := bsVega(S, K, T, r, sigma) * 100 // undo the /100 to get raw vega
		if v < 1e-10 {
			break
		}
		diff := price - marketPrice
		sigma -= diff / v
		if sigma < 0.001 {
			sigma = 0.001
		}
		if sigma > 10.0 {
			sigma = 10.0
		}
		if math.Abs(diff) < 0.01 {
			return sigma, true
		}
	}

	// Bisection fallback if Newton-Raphson didn't converge well.
	lo, hi := 0.001, 10.0
	for range 200 {
		mid := (lo + hi) / 2
		price := blackScholesPrice(S, K, T, r, mid, isCall)
		if math.Abs(price-marketPrice) < 0.01 {
			return mid, true
		}
		if price > marketPrice {
			hi = mid
		} else {
			lo = mid
		}
	}
	return (lo + hi) / 2, true
}

// ---------------------------------------------------------------------------
// Tool 1: options_greeks
// ---------------------------------------------------------------------------

type OptionsGreeksTool struct{}

func (*OptionsGreeksTool) Tool() gomcp.Tool {
	return gomcp.NewTool("options_greeks",
		gomcp.WithDescription("Compute Black-Scholes Greeks (delta, gamma, theta, vega, rho) and implied volatility for an option. Requires the option's trading symbol, underlying price, strike price, expiry date, and option type (CE/PE)."),
		gomcp.WithTitleAnnotation("Options Greeks"),
		gomcp.WithReadOnlyHintAnnotation(true),
		gomcp.WithOpenWorldHintAnnotation(true),
		gomcp.WithString("exchange", gomcp.Description("Exchange (NFO, BFO)"), gomcp.Required()),
		gomcp.WithString("tradingsymbol", gomcp.Description("Option trading symbol (e.g., NIFTY2440324000CE)"), gomcp.Required()),
		gomcp.WithNumber("underlying_price", gomcp.Description("Current price of the underlying (e.g., NIFTY spot). If omitted, fetched via LTP.")),
		gomcp.WithNumber("strike_price", gomcp.Description("Strike price of the option"), gomcp.Required()),
		gomcp.WithString("expiry_date", gomcp.Description("Expiry date in YYYY-MM-DD format"), gomcp.Required()),
		gomcp.WithString("option_type", gomcp.Description("CE for Call, PE for Put"), gomcp.Required()),
		gomcp.WithNumber("risk_free_rate", gomcp.Description("Annual risk-free rate (default: 0.07 for India 7%)")),
	)
}

// greeksResponse is the structured output for options_greeks.
type greeksResponse struct {
	TradingSymbol   string  `json:"tradingsymbol"`
	Exchange        string  `json:"exchange"`
	OptionType      string  `json:"option_type"`
	UnderlyingPrice float64 `json:"underlying_price"`
	StrikePrice     float64 `json:"strike_price"`
	ExpiryDate      string  `json:"expiry_date"`
	OptionPrice     float64 `json:"option_price"`
	TimeToExpiry    float64 `json:"time_to_expiry_years"`
	DaysToExpiry    int     `json:"days_to_expiry"`
	RiskFreeRate    float64 `json:"risk_free_rate"`

	// Greeks
	ImpliedVolatility float64 `json:"implied_volatility"`
	IVPercent         float64 `json:"iv_percent"`
	Delta             float64 `json:"delta"`
	Gamma             float64 `json:"gamma"`
	Theta             float64 `json:"theta_per_day"`
	Vega              float64 `json:"vega_per_pct"`
	Rho               float64 `json:"rho_per_pct"`

	// Value decomposition
	IntrinsicValue float64 `json:"intrinsic_value"`
	TimeValue      float64 `json:"time_value"`
	Moneyness      string  `json:"moneyness"` // ITM, ATM, OTM
}

// extractUnderlyingSymbol extracts the underlying name from an options
// trading symbol. For example, "NIFTY2440324000CE" -> "NIFTY",
// "BANKNIFTY24403CE" -> "BANKNIFTY", "RELIANCE2440324000CE" -> "RELIANCE".
func extractUnderlyingSymbol(tradingsymbol string) string {
	// Trading symbols follow the pattern: NAME + YYMDD + STRIKE + CE/PE.
	// The name portion is all leading alpha characters.
	for i, ch := range tradingsymbol {
		if ch >= '0' && ch <= '9' {
			return tradingsymbol[:i]
		}
	}
	return tradingsymbol
}

func (*OptionsGreeksTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "options_greeks")
		args := request.GetArguments()

		if err := ValidateRequired(args, "exchange", "tradingsymbol", "strike_price", "expiry_date", "option_type"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		exchange := strings.ToUpper(p.String("exchange", "NFO"))
		tradingsymbol := strings.ToUpper(p.String("tradingsymbol", ""))
		strikePrice := p.Float("strike_price", 0)
		expiryStr := p.String("expiry_date", "")
		optionTypeStr := strings.ToUpper(p.String("option_type", ""))
		riskFreeRate := p.Float("risk_free_rate", 0.07)
		underlyingPriceArg := p.Float("underlying_price", 0)

		if optionTypeStr != "CE" && optionTypeStr != "PE" {
			return gomcp.NewToolResultError("option_type must be CE or PE"), nil
		}
		isCall := optionTypeStr == "CE"

		if strikePrice <= 0 {
			return gomcp.NewToolResultError("strike_price must be positive"), nil
		}

		expiryDate, err := time.Parse("2006-01-02", expiryStr)
		if err != nil {
			return gomcp.NewToolResultError("expiry_date must be in YYYY-MM-DD format"), nil
		}

		// IST offset: Kite operates in IST. Expiry is at 15:30 IST on expiry day.
		ist := time.FixedZone("IST", 5*3600+30*60)
		expiryTime := time.Date(expiryDate.Year(), expiryDate.Month(), expiryDate.Day(), 15, 30, 0, 0, ist)
		now := time.Now().In(ist)
		timeToExpiry := expiryTime.Sub(now).Hours() / (365.25 * 24)
		daysToExpiry := int(math.Ceil(expiryTime.Sub(now).Hours() / 24))
		if timeToExpiry < 0 {
			timeToExpiry = 0
			daysToExpiry = 0
		}

		return handler.WithSession(ctx, "options_greeks", func(session *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
			// Fetch option LTP
			optionKey := exchange + ":" + tradingsymbol
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: []string{optionKey}})
			if err != nil {
				return gomcp.NewToolResultError(fmt.Sprintf("Failed to fetch option LTP for %s: %s", optionKey, err.Error())), nil
			}
			ltpResp := raw.(map[string]broker.LTP)
			optionPrice := 0.0
			if q, ok := ltpResp[optionKey]; ok {
				optionPrice = q.LastPrice
			}
			if optionPrice <= 0 {
				return gomcp.NewToolResultError(fmt.Sprintf("No LTP available for %s — market may be closed or symbol is invalid", optionKey)), nil
			}

			// Fetch underlying price if not provided
			underlyingPrice := underlyingPriceArg
			if underlyingPrice <= 0 {
				underlying := extractUnderlyingSymbol(tradingsymbol)
				spotKeys := []string{
					"NSE:" + underlying,
					"NSE:" + underlying + "-EQ",
				}
				if spotRaw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: spotKeys}); err == nil {
					spotResp := spotRaw.(map[string]broker.LTP)
					for _, key := range spotKeys {
						if q, ok := spotResp[key]; ok && q.LastPrice > 0 {
							underlyingPrice = q.LastPrice
							break
						}
					}
				}
				if underlyingPrice <= 0 {
					return gomcp.NewToolResultError(fmt.Sprintf("Could not fetch underlying price for %s. Please provide underlying_price manually.", underlying)), nil
				}
			}

			// Compute IV
			iv, ivOk := impliedVolatility(optionPrice, underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, isCall)
			if !ivOk {
				iv = 0
			}

			// Compute Greeks using the IV
			delta := bsDelta(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)
			gamma := bsGamma(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv)
			theta := bsTheta(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)
			vega := bsVega(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv)
			rho := bsRho(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)

			// Intrinsic and time value
			intrinsic := 0.0
			if isCall {
				intrinsic = math.Max(underlyingPrice-strikePrice, 0)
			} else {
				intrinsic = math.Max(strikePrice-underlyingPrice, 0)
			}
			timeVal := math.Max(optionPrice-intrinsic, 0)

			// Moneyness
			moneyness := "ATM"
			threshold := strikePrice * 0.005 // 0.5% band for ATM
			if isCall {
				if underlyingPrice > strikePrice+threshold {
					moneyness = "ITM"
				} else if underlyingPrice < strikePrice-threshold {
					moneyness = "OTM"
				}
			} else {
				if underlyingPrice < strikePrice-threshold {
					moneyness = "ITM"
				} else if underlyingPrice > strikePrice+threshold {
					moneyness = "OTM"
				}
			}

			resp := greeksResponse{
				TradingSymbol:     tradingsymbol,
				Exchange:          exchange,
				OptionType:        optionTypeStr,
				UnderlyingPrice:   round4(underlyingPrice),
				StrikePrice:       strikePrice,
				ExpiryDate:        expiryStr,
				OptionPrice:       round4(optionPrice),
				TimeToExpiry:      round6(timeToExpiry),
				DaysToExpiry:      daysToExpiry,
				RiskFreeRate:      riskFreeRate,
				ImpliedVolatility: round6(iv),
				IVPercent:         round2(iv * 100),
				Delta:             round6(delta),
				Gamma:             round6(gamma),
				Theta:             round4(theta),
				Vega:              round4(vega),
				Rho:               round4(rho),
				IntrinsicValue:    round2(intrinsic),
				TimeValue:         round2(timeVal),
				Moneyness:         moneyness,
			}

			return handler.MarshalResponse(resp, "options_greeks")
		})
	}
}

// ---------------------------------------------------------------------------
// Tool 2: options_payoff_builder
// ---------------------------------------------------------------------------

type OptionsStrategyTool struct{}

func (*OptionsStrategyTool) Tool() gomcp.Tool {
	return gomcp.NewTool("options_payoff_builder",
		gomcp.WithDescription("Build multi-leg option position payoff diagrams (straddle, iron condor, butterfly, etc.) showing max profit, max loss, breakevens, and P&L curve. Educational visualization. Not investment advice."),
		gomcp.WithTitleAnnotation("Options Payoff Builder"),
		gomcp.WithReadOnlyHintAnnotation(true),
		gomcp.WithOpenWorldHintAnnotation(true),
		gomcp.WithString("strategy", gomcp.Description("Strategy name: bull_call_spread, bear_put_spread, bear_call_spread, bull_put_spread, straddle, strangle, iron_condor, butterfly, custom"), gomcp.Required()),
		gomcp.WithString("underlying", gomcp.Description("Underlying symbol (e.g., NIFTY, BANKNIFTY)"), gomcp.Required()),
		gomcp.WithString("expiry", gomcp.Description("Expiry date YYYY-MM-DD"), gomcp.Required()),
		gomcp.WithNumber("strike1", gomcp.Description("First strike price (lower for spreads, ATM for straddle)"), gomcp.Required()),
		gomcp.WithNumber("strike2", gomcp.Description("Second strike price (higher for spreads, OTM for strangle)")),
		gomcp.WithNumber("strike3", gomcp.Description("Third strike (for iron condor/butterfly)")),
		gomcp.WithNumber("strike4", gomcp.Description("Fourth strike (for iron condor)")),
		gomcp.WithNumber("lot_size", gomcp.Description("Lot size (default: auto-detect from instruments)")),
		gomcp.WithNumber("lots", gomcp.Description("Number of lots (default: 1)")),
	)
}

// strategyLeg describes one leg of an options strategy.
type strategyLeg struct {
	TradingSymbol string  `json:"tradingsymbol"`
	OptionType    string  `json:"option_type"` // CE or PE
	Strike        float64 `json:"strike"`
	Action        string  `json:"action"` // BUY or SELL
	Lots          int     `json:"lots"`
	Quantity      int     `json:"quantity"`
	Premium       float64 `json:"premium"` // per-share premium (LTP)
	TotalPremium  float64 `json:"total_premium"`
}

// strategyResponse is the full output for options_payoff_builder.
type strategyResponse struct {
	Strategy     string        `json:"strategy"`
	Underlying   string        `json:"underlying"`
	Expiry       string        `json:"expiry"`
	Legs         []strategyLeg `json:"legs"`
	NetPremium   float64       `json:"net_premium"`   // positive = credit, negative = debit
	MaxProfit    string        `json:"max_profit"`     // may be "unlimited"
	MaxLoss      string        `json:"max_loss"`       // may be "unlimited"
	MaxProfitAmt float64       `json:"max_profit_amt"` // 0 when unlimited
	MaxLossAmt   float64       `json:"max_loss_amt"`   // 0 when unlimited
	Breakevens   []float64     `json:"breakevens"`
	RiskReward   string        `json:"risk_reward_ratio"`
	LotSize      int           `json:"lot_size"`
	TotalLots    int           `json:"total_lots"`
}

// legSpec is an internal representation used to build legs before fetching premiums.
type legSpec struct {
	strike     float64
	optionType string // CE or PE
	action     string // BUY or SELL
	lotsMulti  int    // multiplier on the number of lots (e.g., 2 for butterfly middle leg)
}

func (*OptionsStrategyTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "options_payoff_builder")
		args := request.GetArguments()

		if err := ValidateRequired(args, "strategy", "underlying", "expiry", "strike1"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		strategy := strings.ToLower(p.String("strategy", ""))
		underlying := strings.ToUpper(p.String("underlying", ""))
		expiryStr := p.String("expiry", "")
		strike1 := p.Float("strike1", 0)
		strike2 := p.Float("strike2", 0)
		strike3 := p.Float("strike3", 0)
		strike4 := p.Float("strike4", 0)
		lotSizeOverride := p.Int("lot_size", 0)
		lots := p.Int("lots", 1)
		lots = max(lots, 1)

		// Validate expiry
		if _, err := time.Parse("2006-01-02", expiryStr); err != nil {
			return gomcp.NewToolResultError("expiry must be in YYYY-MM-DD format"), nil
		}

		// Build leg specs based on strategy
		var specs []legSpec

		switch strategy {
		case "bull_call_spread":
			if strike2 <= strike1 {
				return gomcp.NewToolResultError("bull_call_spread requires strike2 > strike1"), nil
			}
			specs = []legSpec{
				{strike1, "CE", "BUY", 1},
				{strike2, "CE", "SELL", 1},
			}

		case "bear_put_spread":
			if strike2 <= strike1 {
				return gomcp.NewToolResultError("bear_put_spread requires strike2 > strike1 (buy higher put, sell lower put)"), nil
			}
			specs = []legSpec{
				{strike1, "PE", "SELL", 1},
				{strike2, "PE", "BUY", 1},
			}

		case "bear_call_spread":
			if strike2 <= strike1 {
				return gomcp.NewToolResultError("bear_call_spread requires strike2 > strike1 (sell lower call, buy higher call)"), nil
			}
			specs = []legSpec{
				{strike1, "CE", "SELL", 1},
				{strike2, "CE", "BUY", 1},
			}

		case "bull_put_spread":
			if strike2 <= strike1 {
				return gomcp.NewToolResultError("bull_put_spread requires strike2 > strike1 (buy lower put, sell higher put)"), nil
			}
			specs = []legSpec{
				{strike1, "PE", "BUY", 1},
				{strike2, "PE", "SELL", 1},
			}

		case "straddle":
			specs = []legSpec{
				{strike1, "CE", "BUY", 1},
				{strike1, "PE", "BUY", 1},
			}

		case "strangle":
			if strike2 <= 0 {
				return gomcp.NewToolResultError("strangle requires strike2 (OTM CE strike)"), nil
			}
			specs = []legSpec{
				{strike1, "PE", "BUY", 1},
				{strike2, "CE", "BUY", 1},
			}

		case "iron_condor":
			if strike2 <= 0 || strike3 <= 0 || strike4 <= 0 {
				return gomcp.NewToolResultError("iron_condor requires strike1 (buy PE) < strike2 (sell PE) < strike3 (sell CE) < strike4 (buy CE)"), nil
			}
			if !(strike1 < strike2 && strike2 < strike3 && strike3 < strike4) {
				return gomcp.NewToolResultError("iron_condor strikes must be ordered: strike1 < strike2 < strike3 < strike4"), nil
			}
			specs = []legSpec{
				{strike1, "PE", "BUY", 1},
				{strike2, "PE", "SELL", 1},
				{strike3, "CE", "SELL", 1},
				{strike4, "CE", "BUY", 1},
			}

		case "butterfly":
			if strike2 <= 0 || strike3 <= 0 {
				return gomcp.NewToolResultError("butterfly requires strike1 < strike2 (middle, sold 2x) < strike3"), nil
			}
			if !(strike1 < strike2 && strike2 < strike3) {
				return gomcp.NewToolResultError("butterfly strikes must be ordered: strike1 < strike2 < strike3"), nil
			}
			specs = []legSpec{
				{strike1, "CE", "BUY", 1},
				{strike2, "CE", "SELL", 2},
				{strike3, "CE", "BUY", 1},
			}

		default:
			return gomcp.NewToolResultError(fmt.Sprintf("Unknown strategy '%s'. Supported: bull_call_spread, bear_put_spread, bear_call_spread, bull_put_spread, straddle, strangle, iron_condor, butterfly", strategy)), nil
		}

		// Detect lot size from instruments if not overridden
		lotSize := lotSizeOverride
		if lotSize <= 0 {
			if manager.Instruments != nil && manager.Instruments.Count() > 0 {
				found := manager.Instruments.Filter(func(inst instruments.Instrument) bool {
					return inst.Exchange == "NFO" &&
						strings.EqualFold(inst.Name, underlying) &&
						(inst.InstrumentType == "CE" || inst.InstrumentType == "PE") &&
						inst.LotSize > 0
				})
				if len(found) > 0 {
					lotSize = found[0].LotSize
				}
			}
			if lotSize <= 0 {
				lotSize = 1 // fallback
			}
		}

		return handler.WithSession(ctx, "options_payoff_builder", func(session *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
			// Resolve trading symbols and fetch premiums for each leg
			legs := make([]strategyLeg, 0, len(specs))
			instrumentKeys := make([]string, 0, len(specs))
			symbolForSpec := make([]string, len(specs))

			// Find trading symbols from the instruments store
			for i, spec := range specs {
				optType := spec.optionType
				found := manager.Instruments.Filter(func(inst instruments.Instrument) bool {
					return inst.Exchange == "NFO" &&
						strings.EqualFold(inst.Name, underlying) &&
						inst.InstrumentType == optType &&
						inst.Strike == spec.strike &&
						strings.HasPrefix(inst.ExpiryDate, expiryStr)
				})
				if len(found) == 0 {
					return gomcp.NewToolResultError(fmt.Sprintf("No instrument found for %s %s %.0f expiry %s on NFO", underlying, spec.optionType, spec.strike, expiryStr)), nil
				}
				sym := found[0].Tradingsymbol
				symbolForSpec[i] = sym
				key := "NFO:" + sym
				instrumentKeys = append(instrumentKeys, key)
			}

			// Batch LTP fetch
			if len(instrumentKeys) > 500 {
				instrumentKeys = instrumentKeys[:500]
			}
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: instrumentKeys})
			if err != nil {
				return gomcp.NewToolResultError(fmt.Sprintf("Failed to fetch option premiums: %s", err.Error())), nil
			}
			ltpResp := raw.(map[string]broker.LTP)

			netPremium := 0.0 // positive = net credit, negative = net debit
			for i, spec := range specs {
				sym := symbolForSpec[i]
				key := "NFO:" + sym
				premium := 0.0
				if q, ok := ltpResp[key]; ok {
					premium = q.LastPrice
				}
				if premium <= 0 {
					return gomcp.NewToolResultError(fmt.Sprintf("No LTP available for %s — market may be closed or symbol is invalid", key)), nil
				}

				legLots := lots * spec.lotsMulti
				qty := legLots * lotSize
				totalPremium := premium * float64(qty)

				leg := strategyLeg{
					TradingSymbol: sym,
					OptionType:    spec.optionType,
					Strike:        spec.strike,
					Action:        spec.action,
					Lots:          legLots,
					Quantity:      qty,
					Premium:       round2(premium),
					TotalPremium:  round2(totalPremium),
				}
				legs = append(legs, leg)

				if spec.action == "SELL" {
					netPremium += totalPremium
				} else {
					netPremium -= totalPremium
				}
			}

			// Calculate max profit, max loss, breakevens per strategy
			qty := float64(lots * lotSize) // per-unit quantity (1x lots)
			maxProfitStr := ""
			maxLossStr := ""
			maxProfitAmt := 0.0
			maxLossAmt := 0.0
			var breakevens []float64

			// Per-share premiums (positive = received, negative = paid)
			perSharePremiums := make(map[string]float64)
			for _, leg := range legs {
				key := fmt.Sprintf("%s_%.0f", leg.OptionType, leg.Strike)
				sign := -1.0
				if leg.Action == "SELL" {
					sign = 1.0
				}
				perSharePremiums[key] += sign * leg.Premium
			}

			switch strategy {
			case "bull_call_spread":
				// Buy CE@K1, Sell CE@K2 (K1 < K2). Net debit.
				p1 := legs[0].Premium // paid
				p2 := legs[1].Premium // received
				netDebit := p1 - p2
				maxProfitAmt = round2((strike2 - strike1 - netDebit) * qty)
				maxLossAmt = round2(netDebit * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{round2(strike1 + netDebit)}

			case "bear_put_spread":
				// Sell PE@K1, Buy PE@K2 (K1 < K2). Net debit.
				p1 := legs[0].Premium // received (sell)
				p2 := legs[1].Premium // paid (buy)
				netDebit := p2 - p1
				maxProfitAmt = round2((strike2 - strike1 - netDebit) * qty)
				maxLossAmt = round2(netDebit * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{round2(strike2 - netDebit)}

			case "bear_call_spread":
				// Sell CE@K1, Buy CE@K2 (K1 < K2). Net credit.
				p1 := legs[0].Premium // received (sell)
				p2 := legs[1].Premium // paid (buy)
				netCredit := p1 - p2
				maxProfitAmt = round2(netCredit * qty)
				maxLossAmt = round2((strike2 - strike1 - netCredit) * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{round2(strike1 + netCredit)}

			case "bull_put_spread":
				// Buy PE@K1, Sell PE@K2 (K1 < K2). Net credit.
				p1 := legs[0].Premium // paid (buy)
				p2 := legs[1].Premium // received (sell)
				netCredit := p2 - p1
				maxProfitAmt = round2(netCredit * qty)
				maxLossAmt = round2((strike2 - strike1 - netCredit) * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{round2(strike2 - netCredit)}

			case "straddle":
				// Buy CE + PE at same strike. Net debit. Unlimited profit.
				totalDebit := legs[0].Premium + legs[1].Premium
				maxProfitStr = "unlimited"
				maxLossAmt = round2(totalDebit * qty)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{
					round2(strike1 - totalDebit),
					round2(strike1 + totalDebit),
				}

			case "strangle":
				// Buy PE@K1 + Buy CE@K2. Net debit. Unlimited profit.
				totalDebit := legs[0].Premium + legs[1].Premium
				maxProfitStr = "unlimited"
				maxLossAmt = round2(totalDebit * qty)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{
					round2(strike1 - totalDebit),
					round2(strike2 + totalDebit),
				}

			case "iron_condor":
				// Buy PE@K1, Sell PE@K2, Sell CE@K3, Buy CE@K4. Net credit.
				p1 := legs[0].Premium // paid
				p2 := legs[1].Premium // received
				p3 := legs[2].Premium // received
				p4 := legs[3].Premium // paid
				netCredit := (p2 + p3) - (p1 + p4)
				// Max loss is the wider wing minus credit.
				putWing := strike2 - strike1
				callWing := strike4 - strike3
				widerWing := math.Max(putWing, callWing)
				maxProfitAmt = round2(netCredit * qty)
				maxLossAmt = round2((widerWing - netCredit) * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{
					round2(strike2 - netCredit),
					round2(strike3 + netCredit),
				}

			case "butterfly":
				// Buy CE@K1, Sell 2x CE@K2, Buy CE@K3. Net debit.
				p1 := legs[0].Premium
				p2 := legs[1].Premium // sold 2x (but Premium is per-share)
				p3 := legs[2].Premium
				netDebit := p1 - 2*p2 + p3
				if netDebit < 0 {
					netDebit = 0 // credit butterfly
				}
				wingWidth := strike2 - strike1
				maxProfitAmt = round2((wingWidth - netDebit) * qty)
				maxLossAmt = round2(netDebit * qty)
				maxProfitStr = fmt.Sprintf("%.2f", maxProfitAmt)
				maxLossStr = fmt.Sprintf("%.2f", maxLossAmt)
				breakevens = []float64{
					round2(strike1 + netDebit),
					round2(strike3 - netDebit),
				}
			}

			// Risk-reward ratio
			rrStr := "N/A"
			if maxProfitAmt > 0 && maxLossAmt > 0 {
				rr := maxLossAmt / maxProfitAmt
				rrStr = fmt.Sprintf("1:%.2f", 1/rr)
			} else if maxProfitStr == "unlimited" && maxLossAmt > 0 {
				rrStr = "unlimited upside"
			}

			resp := strategyResponse{
				Strategy:     strategy,
				Underlying:   underlying,
				Expiry:       expiryStr,
				Legs:         legs,
				NetPremium:   round2(netPremium),
				MaxProfit:    maxProfitStr,
				MaxLoss:      maxLossStr,
				MaxProfitAmt: maxProfitAmt,
				MaxLossAmt:   maxLossAmt,
				Breakevens:   breakevens,
				RiskReward:   rrStr,
				LotSize:      lotSize,
				TotalLots:    lots,
			}

			return handler.MarshalResponse(resp, "options_payoff_builder")
		})
	}
}

// ---------------------------------------------------------------------------
// Rounding helpers
// ---------------------------------------------------------------------------

func round2(x float64) float64 {
	return math.Round(x*100) / 100
}

func round4(x float64) float64 {
	return math.Round(x*10000) / 10000
}

func round6(x float64) float64 {
	return math.Round(x*1000000) / 1000000
}
