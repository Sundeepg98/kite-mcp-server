package trade

import (
	"context"
	"fmt"
	"math"
	"strings"
	"time"

	gomcp "github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/algo2go/kite-mcp-broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/algo2go/kite-mcp-cqrs"
	"github.com/algo2go/kite-mcp-instruments"
	"github.com/algo2go/kite-mcp-usecases"
	"github.com/zerodha/kite-mcp-server/mcp/common"
	"github.com/zerodha/kite-mcp-server/mcp/plugin"
)

// ---------------------------------------------------------------------------
// Black-Scholes primitives (pure Go, no external deps)
// ---------------------------------------------------------------------------

// NormalCDF returns the cumulative distribution function of the standard normal.
func NormalCDF(x float64) float64 {
	return 0.5 * (1 + math.Erf(x/math.Sqrt2))
}

// NormalPDF returns the probability density function of the standard normal.
func NormalPDF(x float64) float64 {
	return math.Exp(-x*x/2) / math.Sqrt(2*math.Pi)
}

// BsD1 computes the d1 parameter of Black-Scholes.
func BsD1(S, K, T, r, sigma float64) float64 {
	return (math.Log(S/K) + (r+sigma*sigma/2)*T) / (sigma * math.Sqrt(T))
}

// BlackScholesPrice computes the theoretical option price.
// S = spot, K = strike, T = time to expiry (years), r = risk-free rate,
// sigma = volatility, isCall = true for CE / false for PE.
func BlackScholesPrice(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		// At or past expiry, return intrinsic value.
		if isCall {
			return math.Max(S-K, 0)
		}
		return math.Max(K-S, 0)
	}
	d1 := BsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	if isCall {
		return S*NormalCDF(d1) - K*math.Exp(-r*T)*NormalCDF(d2)
	}
	return K*math.Exp(-r*T)*NormalCDF(-d2) - S*NormalCDF(-d1)
}

// BsDelta returns the Black-Scholes delta.
func BsDelta(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := BsD1(S, K, T, r, sigma)
	if isCall {
		return NormalCDF(d1)
	}
	return NormalCDF(d1) - 1
}

// BsGamma returns the Black-Scholes gamma (same for calls and puts).
func BsGamma(S, K, T, r, sigma float64) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := BsD1(S, K, T, r, sigma)
	return NormalPDF(d1) / (S * sigma * math.Sqrt(T))
}

// BsTheta returns the Black-Scholes theta per calendar day.
func BsTheta(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := BsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	common := -(S * NormalPDF(d1) * sigma) / (2 * math.Sqrt(T))
	if isCall {
		return (common - r*K*math.Exp(-r*T)*NormalCDF(d2)) / 365.25
	}
	return (common + r*K*math.Exp(-r*T)*NormalCDF(-d2)) / 365.25
}

// BsVega returns the Black-Scholes vega per 1% move in volatility.
func BsVega(S, K, T, r, sigma float64) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := BsD1(S, K, T, r, sigma)
	return S * NormalPDF(d1) * math.Sqrt(T) / 100
}

// BsRho returns the Black-Scholes rho per 1% move in the risk-free rate.
func BsRho(S, K, T, r, sigma float64, isCall bool) float64 {
	if T <= 0 || sigma <= 0 {
		return 0
	}
	d1 := BsD1(S, K, T, r, sigma)
	d2 := d1 - sigma*math.Sqrt(T)
	if isCall {
		return K * T * math.Exp(-r*T) * NormalCDF(d2) / 100
	}
	return -K * T * math.Exp(-r*T) * NormalCDF(-d2) / 100
}

// ImpliedVolatility solves for sigma such that BS(sigma) ~ marketPrice,
// using Newton-Raphson with a bisection fallback.
func ImpliedVolatility(marketPrice, S, K, T, r float64, isCall bool) (float64, bool) {
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
		price := BlackScholesPrice(S, K, T, r, sigma, isCall)
		v := BsVega(S, K, T, r, sigma) * 100 // undo the /100 to get raw vega
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
		price := BlackScholesPrice(S, K, T, r, mid, isCall)
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

// ExtractUnderlyingSymbol extracts the underlying name from an options
// trading symbol. For example, "NIFTY2440324000CE" -> "NIFTY",
// "BANKNIFTY24403CE" -> "BANKNIFTY", "RELIANCE2440324000CE" -> "RELIANCE".
func ExtractUnderlyingSymbol(tradingsymbol string) string {
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
	handler := common.NewToolHandler(manager)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.TrackToolCall(ctx, "options_greeks")
		args := request.GetArguments()

		if err := common.ValidateRequired(args, "exchange", "tradingsymbol", "strike_price", "expiry_date", "option_type"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		p := common.NewArgParser(args)
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
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: []string{optionKey}})
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
				underlying := ExtractUnderlyingSymbol(tradingsymbol)
				spotKeys := []string{
					"NSE:" + underlying,
					"NSE:" + underlying + "-EQ",
				}
				if spotRaw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetLTPQuery{Email: session.Email, Instruments: spotKeys}); err == nil {
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
			iv, ivOk := ImpliedVolatility(optionPrice, underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, isCall)
			if !ivOk {
				iv = 0
			}

			// Compute Greeks using the IV
			delta := BsDelta(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)
			gamma := BsGamma(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv)
			theta := BsTheta(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)
			vega := BsVega(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv)
			rho := BsRho(underlyingPrice, strikePrice, timeToExpiry, riskFreeRate, iv, isCall)

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
				UnderlyingPrice:   Round4(underlyingPrice),
				StrikePrice:       strikePrice,
				ExpiryDate:        expiryStr,
				OptionPrice:       Round4(optionPrice),
				TimeToExpiry:      Round6(timeToExpiry),
				DaysToExpiry:      daysToExpiry,
				RiskFreeRate:      riskFreeRate,
				ImpliedVolatility: Round6(iv),
				IVPercent:         round2(iv * 100),
				Delta:             Round6(delta),
				Gamma:             Round6(gamma),
				Theta:             Round4(theta),
				Vega:              Round4(vega),
				Rho:               Round4(rho),
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

// optionInstrumentLookupAdapter bridges kc.InstrumentManagerInterface
// (which exposes a generic Filter predicate) to the narrow port that
// the use case needs (FindOption + DefaultLotSize). Lives here in
// mcp/trade rather than kc/usecases because (a) it imports kc and
// kc/instruments, both of which usecases is decoupled from, and (b)
// the adapter is only needed at the MCP-tool composition root and the
// dashboard composition root — not in the use case layer.
type optionInstrumentLookupAdapter struct {
	mgr kc.InstrumentManagerInterface
}

func (a optionInstrumentLookupAdapter) FindOption(underlying, optionType string, strike float64, expiry string) (usecases.OptionInstrument, bool) {
	if a.mgr == nil {
		return usecases.OptionInstrument{}, false
	}
	found := a.mgr.Filter(func(inst instruments.Instrument) bool {
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

func (a optionInstrumentLookupAdapter) DefaultLotSize(underlying string) (int, bool) {
	if a.mgr == nil || a.mgr.Count() == 0 {
		return 0, false
	}
	found := a.mgr.Filter(func(inst instruments.Instrument) bool {
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

// brokerResolverAdapter bridges *kc.Manager (which exposes the
// post-Anchor-6 GetBrokerForEmail accessor directly) to the narrow
// usecases.BrokerResolver port. Lives here at the composition root.
type brokerResolverAdapter struct {
	manager *kc.Manager
}

func (a brokerResolverAdapter) GetBrokerForEmail(email string) (broker.Client, error) {
	if a.manager == nil {
		return nil, fmt.Errorf("manager not configured")
	}
	return a.manager.GetBrokerForEmail(email)
}

func (*OptionsStrategyTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := common.NewToolHandler(manager)
	uc := usecases.NewBuildOptionsStrategyUseCase(
		brokerResolverAdapter{manager: manager},
		optionInstrumentLookupAdapter{mgr: handler.Instruments()},
		nil, // logger threaded via context inside the use case
	)
	return func(ctx context.Context, request gomcp.CallToolRequest) (*gomcp.CallToolResult, error) {
		handler.TrackToolCall(ctx, "options_payoff_builder")
		args := request.GetArguments()

		if err := common.ValidateRequired(args, "strategy", "underlying", "expiry", "strike1"); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}
		p := common.NewArgParser(args)
		cmd := usecases.BuildOptionsStrategyCommand{
			Strategy:   p.String("strategy", ""),
			Underlying: p.String("underlying", ""),
			Expiry:     p.String("expiry", ""),
			Strike1:    p.Float("strike1", 0),
			Strike2:    p.Float("strike2", 0),
			Strike3:    p.Float("strike3", 0),
			Strike4:    p.Float("strike4", 0),
			LotSize:    p.Int("lot_size", 0),
			Lots:       p.Int("lots", 1),
		}

		// Pre-validate strategy + expiry + strike-ordering BEFORE the session
		// gate. Pre-refactor handler did this same ordering: arg-shape
		// errors should surface before "Please log in first" so a user
		// correcting a typo doesn't have to log in just to see the typo.
		if _, err := usecases.ValidateOptionsStrategyCommand(cmd); err != nil {
			return gomcp.NewToolResultError(err.Error()), nil
		}

		// WithSession scopes Email from the validated session.
		return handler.WithSession(ctx, "options_payoff_builder", func(session *kc.KiteSessionData) (*gomcp.CallToolResult, error) {
			cmd.Email = session.Email
			resp, err := uc.Execute(ctx, cmd)
			if err != nil {
				return gomcp.NewToolResultError(err.Error()), nil
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

func Round4(x float64) float64 {
	return math.Round(x*10000) / 10000
}

func Round6(x float64) float64 {
	return math.Round(x*1000000) / 1000000
}

func init() {
	plugin.RegisterInternalTool(&OptionsGreeksTool{})
	plugin.RegisterInternalTool(&OptionsStrategyTool{})
}
