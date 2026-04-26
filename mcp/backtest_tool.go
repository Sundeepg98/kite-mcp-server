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

// BacktestStrategyTool backtests trading strategies against historical data.
type BacktestStrategyTool struct{}

func (*BacktestStrategyTool) Tool() mcp.Tool {
	return mcp.NewTool("historical_price_analyzer",
		mcp.WithDescription("Analyze historical price behavior over a period using simple rule-based entry/exit conditions. Returns statistics (return %, drawdown, win rate) for educational comparison. Not investment advice."),
		mcp.WithTitleAnnotation("Historical Price Analyzer"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("strategy",
			mcp.Description("Strategy: sma_crossover, rsi_reversal, breakout, mean_reversion"),
			mcp.Required(),
		),
		mcp.WithString("exchange",
			mcp.Description("Exchange (NSE, BSE)"),
			mcp.Required(),
		),
		mcp.WithString("tradingsymbol",
			mcp.Description("Symbol to backtest"),
			mcp.Required(),
		),
		mcp.WithNumber("days",
			mcp.Description("Historical days to backtest (default: 365, max: 730)"),
			mcp.DefaultString("365"),
		),
		mcp.WithNumber("initial_capital",
			mcp.Description("Starting capital in INR (default: 1000000)"),
			mcp.DefaultString("1000000"),
		),
		mcp.WithNumber("param1",
			mcp.Description("Strategy parameter 1: SMA short period (default 20), RSI period (14), breakout days (20), BB period (20)"),
		),
		mcp.WithNumber("param2",
			mcp.Description("Strategy parameter 2: SMA long period (default 50), RSI overbought (70), breakout exit days (10), BB std dev (2.0)"),
		),
		mcp.WithNumber("position_size_pct",
			mcp.Description("Percentage of capital per trade (default: 100 for all-in, use 10-20 for partial)"),
			mcp.DefaultString("100"),
		),
	)
}

// BacktestResult holds the full backtest output.
type BacktestResult struct {
	Strategy       string          `json:"strategy"`
	Symbol         string          `json:"symbol"`
	Period         string          `json:"period"`
	InitialCapital float64         `json:"initial_capital"`
	FinalCapital   float64         `json:"final_capital"`
	TotalReturn    float64         `json:"total_return_pct"`
	MaxDrawdown    float64         `json:"max_drawdown_pct"`
	SharpeRatio    float64         `json:"sharpe_ratio"`
	WinRate        float64         `json:"win_rate_pct"`
	TotalTrades    int             `json:"total_trades"`
	WinningTrades  int             `json:"winning_trades"`
	LosingTrades   int             `json:"losing_trades"`
	AvgWin         float64         `json:"avg_win_pct"`
	AvgLoss        float64         `json:"avg_loss_pct"`
	BuyAndHold     float64         `json:"buy_and_hold_pct"`
	TradeLog       []BacktestTrade `json:"trade_log"`
}

// BacktestTrade represents a single round-trip trade.
type BacktestTrade struct {
	EntryDate  string  `json:"entry_date"`
	EntryPrice float64 `json:"entry_price"`
	ExitDate   string  `json:"exit_date"`
	ExitPrice  float64 `json:"exit_price"`
	Side       string  `json:"side"`
	Quantity   int     `json:"quantity"`
	PnL        float64 `json:"pnl"`
	PnLPct     float64 `json:"pnl_pct"`
	Reason     string  `json:"reason"`
}

// backtestSignal represents a buy or sell signal from a strategy.
type backtestSignal struct {
	action string // "BUY" or "SELL"
	reason string
}

func (*BacktestStrategyTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "historical_price_analyzer")
		args := request.GetArguments()

		if err := ValidateRequired(args, "strategy", "exchange", "tradingsymbol"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		strategy := p.String("strategy", "")
		exchange := p.String("exchange", "NSE")
		symbol := p.String("tradingsymbol", "")
		days := p.Int("days", 365)
		initialCapital := p.Float("initial_capital", 1000000)
		positionSizePct := p.Float("position_size_pct", 100)

		// Validate strategy
		validStrategies := map[string]bool{
			"sma_crossover":  true,
			"rsi_reversal":   true,
			"breakout":       true,
			"mean_reversion": true,
		}
		if !validStrategies[strategy] {
			return mcp.NewToolResultError(fmt.Sprintf("Unknown strategy '%s'. Valid: sma_crossover, rsi_reversal, breakout, mean_reversion", strategy)), nil
		}

		// Clamp days
		days = max(days, 30)
		days = min(days, 730)

		// Clamp position size
		if positionSizePct <= 0 || positionSizePct > 100 {
			positionSizePct = 100
		}

		// Parse strategy-specific parameters with defaults
		param1, param2 := backtestDefaults(strategy, args)

		return handler.WithSession(ctx, "historical_price_analyzer", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Resolve instrument token
			inst := manager.Instruments
			if inst == nil {
				return mcp.NewToolResultError("Instruments not loaded"), nil
			}
			instrument, err := inst.GetByTradingsymbol(exchange, symbol)
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Instrument not found: %s:%s", exchange, symbol)), nil
			}
			token := int(instrument.InstrumentToken)

			// Fetch daily historical data
			now := time.Now()
			from := now.AddDate(0, 0, -days)
			raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetHistoricalDataQuery{
				Email:           session.Email,
				InstrumentToken: token,
				Interval:        "day",
				From:            from,
				To:              now,
			})
			if err != nil {
				return mcp.NewToolResultError(fmt.Sprintf("Failed to fetch historical data: %s", err.Error())), nil
			}
			candles := raw.([]broker.HistoricalCandle)

			if len(candles) < 50 {
				return mcp.NewToolResultError(fmt.Sprintf("Insufficient data: got %d candles, need at least 50 for backtesting", len(candles))), nil
			}

			// Run the backtest
			result := runBacktest(candles, strategy, exchange, symbol, initialCapital, positionSizePct, param1, param2)

			return handler.MarshalResponse(result, "historical_price_analyzer")
		})
	}
}

// backtestDefaults returns strategy-specific default param1/param2.
func backtestDefaults(strategy string, args map[string]any) (float64, float64) {
	var p1Default, p2Default float64
	switch strategy {
	case "sma_crossover":
		p1Default, p2Default = 20, 50
	case "rsi_reversal":
		p1Default, p2Default = 14, 70
	case "breakout":
		p1Default, p2Default = 20, 10
	case "mean_reversion":
		p1Default, p2Default = 20, 2.0
	}
	ap := NewArgParser(args)
	p1 := ap.Float("param1", p1Default)
	p2 := ap.Float("param2", p2Default)
	return p1, p2
}

// runBacktest executes the strategy and returns results.
func runBacktest(candles []broker.HistoricalCandle, strategy, exchange, symbol string, initialCapital, positionSizePct, param1, param2 float64) *BacktestResult {
	closes := make([]float64, len(candles))
	highs := make([]float64, len(candles))
	lows := make([]float64, len(candles))
	for i, c := range candles {
		closes[i] = c.Close
		highs[i] = c.High
		lows[i] = c.Low
	}

	// Generate signals for each bar
	signals := generateSignals(strategy, closes, highs, lows, param1, param2)

	// Simulate trades
	trades := simulateTrades(candles, signals, initialCapital, positionSizePct)

	// Compute final capital and metrics
	finalCapital := initialCapital
	for _, t := range trades {
		finalCapital += t.PnL
	}

	totalReturn := (finalCapital - initialCapital) / initialCapital * 100
	buyAndHold := (closes[len(closes)-1] - closes[0]) / closes[0] * 100

	// Compute win/loss stats
	var winCount, lossCount int
	var totalWinPct, totalLossPct float64
	for _, t := range trades {
		if t.PnL > 0 {
			winCount++
			totalWinPct += t.PnLPct
		} else {
			lossCount++
			totalLossPct += t.PnLPct
		}
	}

	var winRate, avgWin, avgLoss float64
	totalTrades := len(trades)
	if totalTrades > 0 {
		winRate = float64(winCount) / float64(totalTrades) * 100
	}
	if winCount > 0 {
		avgWin = totalWinPct / float64(winCount)
	}
	if lossCount > 0 {
		avgLoss = totalLossPct / float64(lossCount)
	}

	// Max drawdown from equity curve
	maxDD := computeMaxDrawdown(trades, initialCapital)

	// Sharpe ratio from trade returns
	sharpe := computeSharpeRatio(trades, initialCapital)

	period := fmt.Sprintf("%s to %s",
		candles[0].Date.Format("2006-01-02"),
		candles[len(candles)-1].Date.Format("2006-01-02"),
	)

	// Limit trade log to 50 entries to keep response manageable
	tradeLog := trades
	if len(tradeLog) > 50 {
		tradeLog = tradeLog[len(tradeLog)-50:]
	}

	return &BacktestResult{
		Strategy:       strategy,
		Symbol:         exchange + ":" + symbol,
		Period:         period,
		InitialCapital: initialCapital,
		FinalCapital:   round2(finalCapital),
		TotalReturn:    round2(totalReturn),
		MaxDrawdown:    round2(maxDD),
		SharpeRatio:    round2(sharpe),
		WinRate:        round2(winRate),
		TotalTrades:    totalTrades,
		WinningTrades:  winCount,
		LosingTrades:   lossCount,
		AvgWin:         round2(avgWin),
		AvgLoss:        round2(avgLoss),
		BuyAndHold:     round2(buyAndHold),
		TradeLog:       tradeLog,
	}
}

// generateSignals produces a buy/sell signal (or nil) for each bar.
func generateSignals(strategy string, closes, highs, lows []float64, param1, param2 float64) []*backtestSignal {
	n := len(closes)
	signals := make([]*backtestSignal, n)

	switch strategy {
	case "sma_crossover":
		signals = signalsSMACrossover(closes, int(param1), int(param2))
	case "rsi_reversal":
		signals = signalsRSIReversal(closes, int(param1), param2)
	case "breakout":
		signals = signalsBreakout(closes, highs, lows, int(param1), int(param2))
	case "mean_reversion":
		signals = signalsMeanReversion(closes, int(param1), param2)
	}

	return signals
}

// signalsSMACrossover generates signals when short SMA crosses long SMA.
func signalsSMACrossover(closes []float64, shortPeriod, longPeriod int) []*backtestSignal {
	n := len(closes)
	signals := make([]*backtestSignal, n)

	smaShort := computeSMA(closes, shortPeriod)
	smaLong := computeSMA(closes, longPeriod)
	if smaShort == nil || smaLong == nil {
		return signals
	}

	// Start from longPeriod so both SMAs are valid
	for i := longPeriod; i < n; i++ {
		if smaShort[i] == 0 || smaLong[i] == 0 || smaShort[i-1] == 0 || smaLong[i-1] == 0 {
			continue
		}
		// Crossover: short crosses above long
		if smaShort[i-1] <= smaLong[i-1] && smaShort[i] > smaLong[i] {
			signals[i] = &backtestSignal{
				action: "BUY",
				reason: fmt.Sprintf("SMA%d (%.2f) crossed above SMA%d (%.2f)", shortPeriod, smaShort[i], longPeriod, smaLong[i]),
			}
		}
		// Crossunder: short crosses below long
		if smaShort[i-1] >= smaLong[i-1] && smaShort[i] < smaLong[i] {
			signals[i] = &backtestSignal{
				action: "SELL",
				reason: fmt.Sprintf("SMA%d (%.2f) crossed below SMA%d (%.2f)", shortPeriod, smaShort[i], longPeriod, smaLong[i]),
			}
		}
	}
	return signals
}

// signalsRSIReversal generates signals on RSI oversold/overbought.
func signalsRSIReversal(closes []float64, period int, overbought float64) []*backtestSignal {
	n := len(closes)
	signals := make([]*backtestSignal, n)
	oversold := 100 - overbought

	rsi := computeRSI(closes, period)
	if rsi == nil {
		return signals
	}

	for i := period + 1; i < n; i++ {
		if rsi[i] == 0 {
			continue
		}
		// Buy when RSI drops below oversold level
		if rsi[i] < oversold && rsi[i-1] >= oversold {
			signals[i] = &backtestSignal{
				action: "BUY",
				reason: fmt.Sprintf("RSI (%.1f) crossed below %.0f (oversold)", rsi[i], oversold),
			}
		}
		// Sell when RSI rises above overbought level
		if rsi[i] > overbought && rsi[i-1] <= overbought {
			signals[i] = &backtestSignal{
				action: "SELL",
				reason: fmt.Sprintf("RSI (%.1f) crossed above %.0f (overbought)", rsi[i], overbought),
			}
		}
	}
	return signals
}

// signalsBreakout generates signals on N-day high/low breakout.
func signalsBreakout(closes, highs, lows []float64, entryLookback, exitLookback int) []*backtestSignal {
	n := len(closes)
	signals := make([]*backtestSignal, n)

	for i := entryLookback; i < n; i++ {
		// Highest high of last entryLookback days (excluding current)
		highestHigh := 0.0
		for j := i - entryLookback; j < i; j++ {
			if highs[j] > highestHigh {
				highestHigh = highs[j]
			}
		}
		// Buy when close breaks above the highest high
		if closes[i] > highestHigh {
			signals[i] = &backtestSignal{
				action: "BUY",
				reason: fmt.Sprintf("Close (%.2f) broke above %d-day high (%.2f)", closes[i], entryLookback, highestHigh),
			}
		}

		// Lowest low of last exitLookback days (excluding current)
		if i >= exitLookback {
			lowestLow := math.MaxFloat64
			for j := i - exitLookback; j < i; j++ {
				if lows[j] < lowestLow {
					lowestLow = lows[j]
				}
			}
			// Sell when close breaks below the lowest low
			if closes[i] < lowestLow && signals[i] == nil {
				signals[i] = &backtestSignal{
					action: "SELL",
					reason: fmt.Sprintf("Close (%.2f) broke below %d-day low (%.2f)", closes[i], exitLookback, lowestLow),
				}
			}
		}
	}
	return signals
}

// signalsMeanReversion generates signals using Bollinger Bands.
func signalsMeanReversion(closes []float64, period int, stdDevMult float64) []*backtestSignal {
	n := len(closes)
	signals := make([]*backtestSignal, n)

	bbUpper, _, bbLower := computeBollingerBands(closes, period, stdDevMult)
	if bbUpper == nil || bbLower == nil {
		return signals
	}

	for i := period; i < n; i++ {
		if bbLower[i] == 0 && bbUpper[i] == 0 {
			continue
		}
		// Buy when price drops below lower band
		if closes[i] < bbLower[i] && (i == period || closes[i-1] >= bbLower[i-1]) {
			signals[i] = &backtestSignal{
				action: "BUY",
				reason: fmt.Sprintf("Close (%.2f) below lower BB (%.2f)", closes[i], bbLower[i]),
			}
		}
		// Sell when price rises above upper band
		if closes[i] > bbUpper[i] && (i == period || closes[i-1] <= bbUpper[i-1]) {
			signals[i] = &backtestSignal{
				action: "SELL",
				reason: fmt.Sprintf("Close (%.2f) above upper BB (%.2f)", closes[i], bbUpper[i]),
			}
		}
	}
	return signals
}

// simulateTrades walks through signals and produces round-trip trades.
func simulateTrades(candles []broker.HistoricalCandle, signals []*backtestSignal, initialCapital, positionSizePct float64) []BacktestTrade {
	var trades []BacktestTrade
	capital := initialCapital
	inPosition := false
	var entryPrice float64
	var entryDate string
	var entryReason string
	var qty int

	for i, sig := range signals {
		if sig == nil {
			continue
		}

		price := candles[i].Close
		dateStr := candles[i].Date.Format("2006-01-02")

		if sig.action == "BUY" && !inPosition {
			// Enter position
			allocatedCapital := capital * positionSizePct / 100
			qty = int(allocatedCapital / price)
			if qty <= 0 {
				continue
			}
			entryPrice = price
			entryDate = dateStr
			entryReason = sig.reason
			inPosition = true
		} else if sig.action == "SELL" && inPosition {
			// Exit position
			pnl := float64(qty) * (price - entryPrice)
			pnlPct := (price - entryPrice) / entryPrice * 100
			capital += pnl

			trades = append(trades, BacktestTrade{
				EntryDate:  entryDate,
				EntryPrice: round2(entryPrice),
				ExitDate:   dateStr,
				ExitPrice:  round2(price),
				Side:       "BUY",
				Quantity:   qty,
				PnL:        round2(pnl),
				PnLPct:     round2(pnlPct),
				Reason:     entryReason + " -> " + sig.reason,
			})
			inPosition = false
		}
	}

	// Force-close open position at last candle
	if inPosition && len(candles) > 0 {
		last := candles[len(candles)-1]
		price := last.Close
		pnl := float64(qty) * (price - entryPrice)
		pnlPct := (price - entryPrice) / entryPrice * 100

		trades = append(trades, BacktestTrade{
			EntryDate:  entryDate,
			EntryPrice: round2(entryPrice),
			ExitDate:   last.Date.Format("2006-01-02"),
			ExitPrice:  round2(price),
			Side:       "BUY",
			Quantity:   qty,
			PnL:        round2(pnl),
			PnLPct:     round2(pnlPct),
			Reason:     entryReason + " -> forced close (end of backtest)",
		})
	}

	return trades
}

// computeMaxDrawdown calculates the maximum peak-to-trough decline in the equity curve.
func computeMaxDrawdown(trades []BacktestTrade, initialCapital float64) float64 {
	if len(trades) == 0 {
		return 0
	}

	equity := initialCapital
	peak := equity
	maxDD := 0.0

	for _, t := range trades {
		equity += t.PnL
		if equity > peak {
			peak = equity
		}
		dd := (peak - equity) / peak * 100
		if dd > maxDD {
			maxDD = dd
		}
	}
	return maxDD
}

// computeSharpeRatio calculates annualized Sharpe ratio from trade returns.
// Uses risk-free rate of 6.5% (Indian T-bill proxy).
func computeSharpeRatio(trades []BacktestTrade, initialCapital float64) float64 {
	if len(trades) < 2 {
		return 0
	}

	// Compute per-trade return percentage
	returns := make([]float64, len(trades))
	for i, t := range trades {
		returns[i] = t.PnLPct
	}

	// Mean return
	var sum float64
	for _, r := range returns {
		sum += r
	}
	mean := sum / float64(len(returns))

	// Standard deviation
	var sqSum float64
	for _, r := range returns {
		sqSum += (r - mean) * (r - mean)
	}
	stdDev := math.Sqrt(sqSum / float64(len(returns)))
	if stdDev == 0 {
		return 0
	}

	// Annualize: assume ~20 trades/year as a rough proxy,
	// or use sqrt(252/avg_holding_period). Simplified: annualize by sqrt(trades).
	// Risk-free per trade: 6.5% annual / trades
	riskFreePerTrade := 6.5 / float64(len(returns))
	sharpe := (mean - riskFreePerTrade) / stdDev * math.Sqrt(float64(len(returns)))

	return sharpe
}

// round2 is defined in options_greeks_tool.go (shared within the mcp package).
