package mcp

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

type OptionChainTool struct{}

func (*OptionChainTool) Tool() mcp.Tool {
	return mcp.NewTool("get_option_chain",
		mcp.WithDescription("Get option chain for an underlying — all strikes with LTP, OI, volume for the nearest expiry. Useful for options analysis, OI-based directional view, and hedging decisions."),
		mcp.WithTitleAnnotation("Get Option Chain"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("underlying",
			mcp.Description("Underlying symbol (e.g., NIFTY, BANKNIFTY, RELIANCE)"),
			mcp.Required(),
		),
		mcp.WithString("expiry",
			mcp.Description("Expiry date YYYY-MM-DD (optional, defaults to nearest)"),
		),
		mcp.WithNumber("strikes_around_atm",
			mcp.Description("Number of strikes above and below ATM to show (default 10)"),
		),
	)
}

// optionChainEntry represents one strike row in the chain.
type optionChainEntry struct {
	Strike          float64 `json:"strike"`
	CELTP           float64 `json:"ce_ltp"`
	CEOI            float64 `json:"ce_oi"`
	CEVolume        int     `json:"ce_volume"`
	CETradingsymbol string  `json:"ce_tradingsymbol,omitempty"`
	PELTP           float64 `json:"pe_ltp"`
	PEOI            float64 `json:"pe_oi"`
	PEVolume        int     `json:"pe_volume"`
	PETradingsymbol string  `json:"pe_tradingsymbol,omitempty"`
}

// optionChainResponse is the full response returned to the caller.
type optionChainResponse struct {
	Underlying string             `json:"underlying"`
	SpotPrice  float64            `json:"spot_price"`
	Expiry     string             `json:"expiry"`
	ATMStrike  float64            `json:"atm_strike"`
	Chain      []optionChainEntry `json:"chain"`
	MaxPain    float64            `json:"max_pain"`
	PCR        float64            `json:"pcr"`
}

func (*OptionChainTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_option_chain")
		args := request.GetArguments()

		if err := ValidateRequired(args, "underlying"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		underlying := strings.ToUpper(p.String("underlying", ""))
		requestedExpiry := p.String("expiry", "")
		strikesAround := p.Int("strikes_around_atm", 10)
		if strikesAround <= 0 {
			strikesAround = 10
		}

		if manager.Instruments.Count() == 0 {
			return mcp.NewToolResultError("No instruments loaded. Please wait for instruments to be fetched."), nil
		}

		// Step 1: Find all NFO options for this underlying
		allNFO := manager.Instruments.Filter(func(inst instruments.Instrument) bool {
			return inst.Exchange == "NFO" &&
				strings.EqualFold(inst.Name, underlying) &&
				(inst.InstrumentType == "CE" || inst.InstrumentType == "PE")
		})

		if len(allNFO) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("No options found for underlying %s in NFO", underlying)), nil
		}

		// Step 2: Determine target expiry (nearest or requested)
		expirySet := make(map[string]bool)
		for _, inst := range allNFO {
			if inst.ExpiryDate != "" {
				expirySet[inst.ExpiryDate] = true
			}
		}
		expiries := make([]string, 0, len(expirySet))
		for e := range expirySet {
			expiries = append(expiries, e)
		}
		sort.Strings(expiries)

		targetExpiry := ""
		if requestedExpiry != "" {
			// Match the requested expiry
			for _, e := range expiries {
				if strings.HasPrefix(e, requestedExpiry) {
					targetExpiry = e
					break
				}
			}
			if targetExpiry == "" {
				return mcp.NewToolResultError(fmt.Sprintf("Expiry %s not found. Available expiries: %s", requestedExpiry, strings.Join(expiries, ", "))), nil
			}
		} else {
			// Use nearest expiry
			if len(expiries) > 0 {
				targetExpiry = expiries[0]
			}
		}

		// Step 3: Filter to target expiry, split into CE and PE
		type optInst struct {
			inst   instruments.Instrument
			strike float64
		}
		ceByStrike := make(map[float64]instruments.Instrument)
		peByStrike := make(map[float64]instruments.Instrument)
		strikeSet := make(map[float64]bool)

		for _, inst := range allNFO {
			if inst.ExpiryDate != targetExpiry {
				continue
			}
			strike := inst.Strike
			strikeSet[strike] = true
			if inst.InstrumentType == "CE" {
				ceByStrike[strike] = inst
			} else if inst.InstrumentType == "PE" {
				peByStrike[strike] = inst
			}
		}

		if len(strikeSet) == 0 {
			return mcp.NewToolResultError(fmt.Sprintf("No option strikes found for %s expiry %s", underlying, targetExpiry)), nil
		}

		strikes := make([]float64, 0, len(strikeSet))
		for s := range strikeSet {
			strikes = append(strikes, s)
		}
		sort.Float64s(strikes)

		return handler.WithSession(ctx, "get_option_chain", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Step 4: Get spot price of the underlying to determine ATM
			// Try common spot instrument IDs
			spotPrice := 0.0
			spotKeys := []string{
				"NSE:" + underlying,
				"NSE:" + underlying + "-EQ",
				"NFO:" + underlying, // index futures sometimes
			}

			// For indices like NIFTY, BANKNIFTY the spot is on NSE as an index
			ltpUC := usecases.NewGetLTPUseCase(manager.SessionSvc(), manager.Logger)
			ltpResp, err := ltpUC.Execute(ctx, session.Email, cqrs.GetLTPQuery{Instruments: spotKeys})
			if err == nil {
				for _, key := range spotKeys {
					if q, ok := ltpResp[key]; ok && q.LastPrice > 0 {
						spotPrice = q.LastPrice
						break
					}
				}
			}

			// Fallback: use midpoint of available strikes if no spot price found
			if spotPrice <= 0 {
				spotPrice = (strikes[0] + strikes[len(strikes)-1]) / 2
			}

			// Step 5: Determine ATM strike (closest to spot)
			atmStrike := strikes[0]
			minDiff := math.Abs(spotPrice - strikes[0])
			for _, s := range strikes[1:] {
				diff := math.Abs(spotPrice - s)
				if diff < minDiff {
					minDiff = diff
					atmStrike = s
				}
			}

			// Step 6: Filter strikes around ATM
			atmIdx := sort.SearchFloat64s(strikes, atmStrike)
			lo := atmIdx - strikesAround
			hi := atmIdx + strikesAround + 1
			if lo < 0 {
				lo = 0
			}
			if hi > len(strikes) {
				hi = len(strikes)
			}
			selectedStrikes := strikes[lo:hi]

			// Step 7: Build instrument list for batch quote
			instrumentKeys := make([]string, 0, len(selectedStrikes)*2)
			for _, strike := range selectedStrikes {
				if inst, ok := ceByStrike[strike]; ok {
					instrumentKeys = append(instrumentKeys, "NFO:"+inst.Tradingsymbol)
				}
				if inst, ok := peByStrike[strike]; ok {
					instrumentKeys = append(instrumentKeys, "NFO:"+inst.Tradingsymbol)
				}
			}

			if len(instrumentKeys) == 0 {
				return mcp.NewToolResultError("No option instruments to fetch quotes for"), nil
			}

			// Cap at 500 (API limit)
			if len(instrumentKeys) > 500 {
				instrumentKeys = instrumentKeys[:500]
			}

			// Step 8: Batch get quotes
			quotesUC := usecases.NewGetQuotesUseCase(manager.SessionSvc(), manager.Logger)
			quotes, err := quotesUC.Execute(ctx, session.Email, cqrs.GetQuotesQuery{Instruments: instrumentKeys})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch option quotes: %s", err.Error())), nil
			}

			// Step 9: Build the chain
			chain := make([]optionChainEntry, 0, len(selectedStrikes))
			var totalPutOI, totalCallOI float64

			// For max pain: track OI per strike per type
			type oiData struct {
				ceOI float64
				peOI float64
			}
			oiByStrike := make(map[float64]*oiData, len(selectedStrikes))

			for _, strike := range selectedStrikes {
				entry := optionChainEntry{Strike: strike}
				oid := &oiData{}

				if inst, ok := ceByStrike[strike]; ok {
					entry.CETradingsymbol = inst.Tradingsymbol
					key := "NFO:" + inst.Tradingsymbol
					if q, ok := quotes[key]; ok {
						entry.CELTP = q.LastPrice
						entry.CEOI = q.OI
						entry.CEVolume = q.Volume
						totalCallOI += q.OI
						oid.ceOI = q.OI
					}
				}

				if inst, ok := peByStrike[strike]; ok {
					entry.PETradingsymbol = inst.Tradingsymbol
					key := "NFO:" + inst.Tradingsymbol
					if q, ok := quotes[key]; ok {
						entry.PELTP = q.LastPrice
						entry.PEOI = q.OI
						entry.PEVolume = q.Volume
						totalPutOI += q.OI
						oid.peOI = q.OI
					}
				}

				oiByStrike[strike] = oid
				chain = append(chain, entry)
			}

			// Step 10: Compute PCR
			pcr := 0.0
			if totalCallOI > 0 {
				pcr = math.Round(totalPutOI/totalCallOI*100) / 100
			}

			// Step 11: Compute Max Pain
			// Max pain = strike where sum of (call ITM pain + put ITM pain) is minimum
			maxPain := atmStrike
			minPain := math.MaxFloat64

			for _, testStrike := range selectedStrikes {
				totalPain := 0.0
				for _, s := range selectedStrikes {
					oid := oiByStrike[s]
					if oid == nil {
						continue
					}
					// Call holders lose money when expiry < strike (they bought CE)
					// If testStrike < strike, call expires worthless, no pain to call buyers from this strike
					// If testStrike > strike, call is ITM, call buyers gain (no pain)
					// Wait - max pain is the price where option BUYERS lose most, i.e. options expire worthless
					// Call buyers lose when expiry < their strike -> call OI * max(0, testStrike - strike)
					// Actually: call buyer pays premium, if expiry at testStrike:
					//   call intrinsic = max(0, testStrike - strike) -- this is what call buyer GETS
					//   put intrinsic = max(0, strike - testStrike) -- this is what put buyer GETS
					// Max pain = strike where total intrinsic value paid out is MINIMIZED

					// Call intrinsic value at testStrike for calls at strike s
					if testStrike > s {
						totalPain += oid.ceOI * (testStrike - s)
					}
					// Put intrinsic value at testStrike for puts at strike s
					if s > testStrike {
						totalPain += oid.peOI * (s - testStrike)
					}
				}
				if totalPain < minPain {
					minPain = totalPain
					maxPain = testStrike
				}
			}

			resp := optionChainResponse{
				Underlying: underlying,
				SpotPrice:  spotPrice,
				Expiry:     targetExpiry,
				ATMStrike:  atmStrike,
				Chain:      chain,
				MaxPain:    maxPain,
				PCR:        pcr,
			}

			return handler.MarshalResponse(resp, "get_option_chain")
		})
	}
}
