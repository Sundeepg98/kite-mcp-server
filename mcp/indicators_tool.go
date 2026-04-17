package mcp

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

type TechnicalIndicatorsTool struct{}

func (*TechnicalIndicatorsTool) Tool() mcp.Tool {
	return mcp.NewTool("technical_indicators",
		mcp.WithDescription("Compute technical indicators (RSI, SMA, EMA, Bollinger Bands, MACD) for an instrument from historical data. Returns the most recent values plus trading signals for trend analysis."),
		mcp.WithTitleAnnotation("Technical Indicators"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithString("exchange", mcp.Description("Exchange (NSE, BSE, NFO)"), mcp.Required()),
		mcp.WithString("tradingsymbol", mcp.Description("Trading symbol (e.g., RELIANCE, INFY)"), mcp.Required()),
		mcp.WithString("interval", mcp.Description("Candle interval: day, 15minute, 60minute"), mcp.DefaultString("day")),
		mcp.WithNumber("days", mcp.Description("Number of days of history to analyze (default 90, max 365)"), mcp.DefaultString("90")),
	)
}

func (*TechnicalIndicatorsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "technical_indicators")
		args := request.GetArguments()

		if err := ValidateRequired(args, "exchange", "tradingsymbol"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		exchange := p.String("exchange", "NSE")
		symbol := p.String("tradingsymbol", "")
		interval := p.String("interval", "day")
		days := p.Int("days", 90)
		days = min(days, 365)
		days = max(days, 14)

		return handler.WithSession(ctx, "technical_indicators", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Resolve instrument token via exchange:tradingsymbol lookup
			inst := manager.Instruments
			if inst == nil {
				return mcp.NewToolResultError("Instruments not loaded"), nil
			}

			instrument, err := inst.GetByTradingsymbol(exchange, symbol)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Instrument not found: %s:%s", exchange, symbol)), nil
			}
			token := int(instrument.InstrumentToken)

			// Fetch historical data
			now := time.Now()
			from := now.AddDate(0, 0, -days)
			raw, err := manager.QueryBus().DispatchWithResult(ctx, cqrs.GetHistoricalDataQuery{
				Email:           session.Email,
				InstrumentToken: token,
				Interval:        interval,
				From:            from,
				To:              now,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch historical data: %s", err.Error())), nil
			}
			candles := raw.([]broker.HistoricalCandle)

			if len(candles) < 14 {
				return mcp.NewToolResultError(fmt.Sprintf("Insufficient data: got %d candles, need at least 14", len(candles))), nil
			}

			// Extract closing prices
			closes := make([]float64, len(candles))
			for i, c := range candles {
				closes[i] = c.Close
			}

			// Compute indicators
			rsi14 := computeRSI(closes, 14)
			sma20 := computeSMA(closes, 20)
			sma50 := computeSMA(closes, 50)
			ema12 := computeEMA(closes, 12)
			ema26 := computeEMA(closes, 26)
			bbUpper, bbMiddle, bbLower := computeBollingerBands(closes, 20, 2.0)

			// MACD = EMA12 - EMA26, Signal = EMA9 of MACD line
			macdLine := make([]float64, len(closes))
			for i := range closes {
				if i < len(ema12) && i < len(ema26) {
					macdLine[i] = ema12[i] - ema26[i]
				}
			}
			macdSignal := computeEMA(macdLine, 9)

			// Get latest values
			last := len(closes) - 1
			currentPrice := closes[last]

			result := map[string]any{
				"symbol":        exchange + ":" + symbol,
				"interval":      interval,
				"candles":       len(candles),
				"current_price": currentPrice,
				"indicators": map[string]any{
					"rsi_14": safeLastValue(rsi14),
					"sma_20": safeLastValue(sma20),
					"sma_50": safeLastValue(sma50),
					"ema_12": safeLastValue(ema12),
					"ema_26": safeLastValue(ema26),
					"macd": map[string]any{
						"line":      safeLastValue(macdLine),
						"signal":    safeLastValue(macdSignal),
						"histogram": safeLastValue(macdLine) - safeLastValue(macdSignal),
					},
					"bollinger_bands": map[string]any{
						"upper":  safeLastValue(bbUpper),
						"middle": safeLastValue(bbMiddle),
						"lower":  safeLastValue(bbLower),
						"width":  safeBBWidth(bbUpper, bbLower, bbMiddle),
					},
				},
				"signals": computeSignals(closes, rsi14, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal),
			}

			return handler.MarshalResponse(result, "technical_indicators")
		})
	}
}

// --- Indicator computations ---

func computeRSI(prices []float64, period int) []float64 {
	if len(prices) < period+1 {
		return nil
	}
	rsi := make([]float64, len(prices))
	var avgGain, avgLoss float64
	for i := 1; i <= period; i++ {
		change := prices[i] - prices[i-1]
		if change > 0 {
			avgGain += change
		} else {
			avgLoss += -change
		}
	}
	avgGain /= float64(period)
	avgLoss /= float64(period)
	if avgLoss == 0 {
		rsi[period] = 100
	} else {
		rs := avgGain / avgLoss
		rsi[period] = 100 - (100 / (1 + rs))
	}
	for i := period + 1; i < len(prices); i++ {
		change := prices[i] - prices[i-1]
		var gain, loss float64
		if change > 0 {
			gain = change
		} else {
			loss = -change
		}
		avgGain = (avgGain*float64(period-1) + gain) / float64(period)
		avgLoss = (avgLoss*float64(period-1) + loss) / float64(period)
		if avgLoss == 0 {
			rsi[i] = 100
		} else {
			rs := avgGain / avgLoss
			rsi[i] = 100 - (100 / (1 + rs))
		}
	}
	return rsi
}

func computeSMA(prices []float64, period int) []float64 {
	if len(prices) < period {
		return nil
	}
	sma := make([]float64, len(prices))
	var sum float64
	for i := range period {
		sum += prices[i]
	}
	sma[period-1] = sum / float64(period)
	for i := period; i < len(prices); i++ {
		sum += prices[i] - prices[i-period]
		sma[i] = sum / float64(period)
	}
	return sma
}

func computeEMA(prices []float64, period int) []float64 {
	if len(prices) < period {
		return nil
	}
	ema := make([]float64, len(prices))
	multiplier := 2.0 / float64(period+1)
	var sum float64
	for i := range period {
		sum += prices[i]
	}
	ema[period-1] = sum / float64(period)
	for i := period; i < len(prices); i++ {
		ema[i] = (prices[i]-ema[i-1])*multiplier + ema[i-1]
	}
	return ema
}

func computeBollingerBands(prices []float64, period int, stdDevMult float64) (upper, middle, lower []float64) {
	if len(prices) < period {
		return nil, nil, nil
	}
	upper = make([]float64, len(prices))
	middle = make([]float64, len(prices))
	lower = make([]float64, len(prices))
	for i := period - 1; i < len(prices); i++ {
		window := prices[i-period+1 : i+1]
		var sum float64
		for _, v := range window {
			sum += v
		}
		mean := sum / float64(period)
		var sqSum float64
		for _, v := range window {
			sqSum += (v - mean) * (v - mean)
		}
		stdDev := math.Sqrt(sqSum / float64(period))
		middle[i] = mean
		upper[i] = mean + stdDevMult*stdDev
		lower[i] = mean - stdDevMult*stdDev
	}
	return
}

func computeSignals(closes, rsi, sma20, sma50, ema12, ema26, bbUpper, bbLower, macdLine, macdSignal []float64) []string {
	signals := []string{}
	last := len(closes) - 1
	price := closes[last]

	// RSI signals
	if r := safeLastValue(rsi); r > 0 {
		if r > 70 {
			signals = append(signals, fmt.Sprintf("RSI overbought (%.1f)", r))
		}
		if r < 30 {
			signals = append(signals, fmt.Sprintf("RSI oversold (%.1f)", r))
		}
	}

	// SMA crossover
	if s20, s50 := safeLastValue(sma20), safeLastValue(sma50); s20 > 0 && s50 > 0 {
		if s20 > s50 {
			signals = append(signals, "SMA20 above SMA50 (bullish)")
		}
		if s20 < s50 {
			signals = append(signals, "SMA20 below SMA50 (bearish)")
		}
	}

	// Bollinger Band signals
	if u, l := safeLastValue(bbUpper), safeLastValue(bbLower); u > 0 {
		if price > u {
			signals = append(signals, "Price above upper Bollinger Band (overbought)")
		}
		if price < l {
			signals = append(signals, "Price below lower Bollinger Band (oversold)")
		}
	}

	// MACD crossover
	if m, s := safeLastValue(macdLine), safeLastValue(macdSignal); m != 0 || s != 0 {
		if m > s {
			signals = append(signals, "MACD above signal (bullish)")
		}
		if m < s {
			signals = append(signals, "MACD below signal (bearish)")
		}
	}

	// Price vs SMA
	if s20 := safeLastValue(sma20); s20 > 0 {
		pct := (price - s20) / s20 * 100
		if pct > 5 {
			signals = append(signals, fmt.Sprintf("Price %.1f%% above SMA20", pct))
		}
		if pct < -5 {
			signals = append(signals, fmt.Sprintf("Price %.1f%% below SMA20", pct))
		}
	}

	if len(signals) == 0 {
		signals = append(signals, "No strong signals")
	}
	return signals
}

func safeLastValue(arr []float64) float64 {
	if len(arr) == 0 {
		return 0
	}
	return arr[len(arr)-1]
}

func safeBBWidth(upper, lower, middle []float64) float64 {
	u, l, m := safeLastValue(upper), safeLastValue(lower), safeLastValue(middle)
	if m == 0 {
		return 0
	}
	return (u - l) / m * 100
}
