package analytics

import (
	"math"
	"time"

	"github.com/algo2go/kite-mcp-broker"
)

// Anchor 1 PR 1.7: test helpers duplicated from mcp/tools_pure_test.go
// because mcp/analytics/tools_pure_backtest_test.go uses them and the
// originals live in package mcp (not analytics).

// makeCandles builds a synthetic OHLC candle series with simple price
// drift (volatility-driven, alternating up/down). Used for backtest
// strategy stress tests.
func makeCandles(n int, startPrice float64, volatility float64) []broker.HistoricalCandle {
	candles := make([]broker.HistoricalCandle, n)
	price := startPrice
	for i := range n {
		// Simple price movement: alternate up/down with drift
		delta := volatility * float64((i%7)-3) / 3.0
		price += delta
		if price < 1 {
			price = 1
		}
		candles[i] = broker.HistoricalCandle{
			Date:   time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC).AddDate(0, 0, i),
			Open:   price - 1,
			High:   price + 2,
			Low:    price - 2,
			Close:  price,
			Volume: 1000 + i*10,
		}
	}
	return candles
}

// makeCandlesHelper builds a synthetic OHLC candle series from a price
// list, one candle per day starting at startDate.
func makeCandlesHelper(prices []float64, startDate time.Time) []broker.HistoricalCandle {
	candles := make([]broker.HistoricalCandle, len(prices))
	for i, p := range prices {
		candles[i] = broker.HistoricalCandle{
			Date:   startDate.AddDate(0, 0, i),
			Open:   p * 0.99,
			High:   p * 1.02,
			Low:    p * 0.98,
			Close:  p,
			Volume: 100000,
		}
	}
	return candles
}

// makeOscillatingPricesHelper produces a sinusoidal price series for
// testing oscillator-based strategies (RSI, mean-reversion).
func makeOscillatingPricesHelper(n int) []float64 {
	prices := make([]float64, n)
	for i := range prices {
		prices[i] = 100 + 20*math.Sin(float64(i)*0.15) + float64(i%3)
	}
	return prices
}

// makeTrendingPricesHelper produces a linear-trending price series with
// minor noise for testing trend-following strategies (SMA crossover,
// breakout).
func makeTrendingPricesHelper(n int, startPrice float64) []float64 {
	prices := make([]float64, n)
	for i := range prices {
		trend := float64(i) * 0.5
		noise := float64(i%7) - 3
		prices[i] = startPrice + trend + noise
	}
	return prices
}
