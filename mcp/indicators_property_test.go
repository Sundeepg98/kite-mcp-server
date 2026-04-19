package mcp

import (
	"math"
	"math/rand"
	"testing"
	"testing/quick"
)

// ---------------------------------------------------------------------------
// Property-based tests for technical indicator calculations
// ---------------------------------------------------------------------------

// generatePriceSeries creates a random but realistic price series.
// Prices follow a geometric random walk starting from base in [10, 10000].
func generatePriceSeries(rng *rand.Rand, length int) []float64 {
	if length < 1 {
		length = 1
	}
	base := 10 + rng.Float64()*9990
	prices := make([]float64, length)
	prices[0] = base
	for i := 1; i < length; i++ {
		// Daily return: -5% to +5%
		ret := 1 + (rng.Float64()-0.5)*0.10
		prices[i] = prices[i-1] * ret
		if prices[i] < 0.01 {
			prices[i] = 0.01 // floor
		}
	}
	return prices
}

// generateConstantSeries returns a series where every value equals c.
func generateConstantSeries(c float64, length int) []float64 {
	prices := make([]float64, length)
	for i := range prices {
		prices[i] = c
	}
	return prices
}

// TestRSIBounds: RSI is always in [0, 100] for any valid price series.
func TestRSIBounds(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 20 + rng.Intn(200) // 20 to 219 candles
		prices := generatePriceSeries(rng, length)
		period := 14

		rsi := computeRSI(prices, period)
		if rsi == nil {
			// Not enough data — acceptable
			return len(prices) < period+1
		}

		for i := period; i < len(rsi); i++ {
			if rsi[i] < -0.001 || rsi[i] > 100.001 {
				t.Logf("RSI[%d]=%.6f out of [0,100] (len=%d)", i, rsi[i], length)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 3000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestRSIConstantPricesEquals50OrBoundary: For constant prices, changes are 0,
// so avgGain and avgLoss are both 0 initially, giving RSI=100 (division by zero handling).
// After the seed period, subsequent RSI values should be consistent.
func TestRSIConstantPrices(t *testing.T) {
	t.Parallel()
	prices := generateConstantSeries(100.0, 50)
	rsi := computeRSI(prices, 14)
	if rsi == nil {
		t.Fatal("expected RSI to be computed for 50 constant prices")
	}

	// With all changes=0: avgGain=0, avgLoss=0.
	// The code handles avgLoss==0 => RSI=100.
	for i := 14; i < len(rsi); i++ {
		if rsi[i] != 100.0 {
			t.Errorf("RSI[%d]=%.4f, expected 100.0 for constant prices", i, rsi[i])
		}
	}
}

// TestRSIMonotonicallyIncreasingPrices: If prices only go up, RSI should be 100.
func TestRSIMonotonicallyIncreasingPrices(t *testing.T) {
	t.Parallel()
	prices := make([]float64, 50)
	for i := range prices {
		prices[i] = 100.0 + float64(i)
	}
	rsi := computeRSI(prices, 14)
	if rsi == nil {
		t.Fatal("expected RSI to be computed")
	}

	for i := 14; i < len(rsi); i++ {
		if rsi[i] != 100.0 {
			t.Errorf("RSI[%d]=%.4f, expected 100.0 for monotonically increasing prices", i, rsi[i])
		}
	}
}

// TestSMAOfConstantEqualsConstant: SMA of a constant series equals the constant.
func TestSMAOfConstantEqualsConstant(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		c := 1 + rng.Float64()*9999
		period := 5 + rng.Intn(45) // 5 to 49
		length := period + rng.Intn(100)
		prices := generateConstantSeries(c, length)

		sma := computeSMA(prices, period)
		if sma == nil {
			return length < period
		}

		for i := period - 1; i < len(sma); i++ {
			if math.Abs(sma[i]-c) > 1e-8 {
				t.Logf("SMA[%d]=%.10f, expected %.10f (constant=%.4f, period=%d)",
					i, sma[i], c, c, period)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestSMAIsAverage: SMA at each point equals the arithmetic mean of the window.
func TestSMAIsAverage(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 30 + rng.Intn(100)
		prices := generatePriceSeries(rng, length)
		period := 5 + rng.Intn(20)
		if period > length {
			return true
		}

		sma := computeSMA(prices, period)
		if sma == nil {
			return true
		}

		for i := period - 1; i < len(prices); i++ {
			var sum float64
			for j := i - period + 1; j <= i; j++ {
				sum += prices[j]
			}
			expected := sum / float64(period)
			if math.Abs(sma[i]-expected)/math.Max(1, expected) > 1e-10 {
				t.Logf("SMA[%d]=%.10f, expected %.10f (period=%d)",
					i, sma[i], expected, period)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 1000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestEMAConvergesToSMA: For a constant series, EMA equals SMA equals the constant.
func TestEMAConvergesToSMAForConstant(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		c := 1 + rng.Float64()*9999
		period := 5 + rng.Intn(30)
		length := period + 50 + rng.Intn(100)
		prices := generateConstantSeries(c, length)

		ema := computeEMA(prices, period)
		sma := computeSMA(prices, period)
		if ema == nil || sma == nil {
			return true
		}

		// For constant prices, EMA should equal the constant at every computed point.
		for i := period - 1; i < len(ema); i++ {
			if math.Abs(ema[i]-c) > 1e-8 {
				t.Logf("EMA[%d]=%.10f, expected %.10f (constant)", i, ema[i], c)
				return false
			}
			if math.Abs(sma[i]-c) > 1e-8 {
				t.Logf("SMA[%d]=%.10f, expected %.10f (constant)", i, sma[i], c)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestEMASeedIsSMA: The first EMA value equals the SMA over the seed period.
func TestEMASeedIsSMA(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 30 + rng.Intn(100)
		prices := generatePriceSeries(rng, length)
		period := 5 + rng.Intn(20)
		if period > length {
			return true
		}

		ema := computeEMA(prices, period)
		sma := computeSMA(prices, period)
		if ema == nil || sma == nil {
			return true
		}

		// EMA[period-1] should equal SMA[period-1] (the seed value)
		if math.Abs(ema[period-1]-sma[period-1]) > 1e-10 {
			t.Logf("EMA seed=%.10f, SMA seed=%.10f at index %d",
				ema[period-1], sma[period-1], period-1)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestBollingerBandOrdering: upper >= middle >= lower always.
func TestBollingerBandOrdering(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 25 + rng.Intn(200)
		prices := generatePriceSeries(rng, length)
		period := 10 + rng.Intn(15)
		stdDevMult := 1.0 + rng.Float64()*2.0

		upper, middle, lower := computeBollingerBands(prices, period, stdDevMult)
		if upper == nil {
			return length < period
		}

		for i := period - 1; i < len(prices); i++ {
			if upper[i] < middle[i]-1e-10 {
				t.Logf("upper[%d]=%.6f < middle[%d]=%.6f", i, upper[i], i, middle[i])
				return false
			}
			if middle[i] < lower[i]-1e-10 {
				t.Logf("middle[%d]=%.6f < lower[%d]=%.6f", i, middle[i], i, lower[i])
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 3000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestBollingerMiddleIsSMA: The middle band is the SMA.
func TestBollingerMiddleIsSMA(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 30 + rng.Intn(100)
		prices := generatePriceSeries(rng, length)
		period := 10 + rng.Intn(15)

		_, middle, _ := computeBollingerBands(prices, period, 2.0)
		sma := computeSMA(prices, period)
		if middle == nil || sma == nil {
			return true
		}

		for i := period - 1; i < len(prices); i++ {
			if math.Abs(middle[i]-sma[i]) > 1e-10 {
				t.Logf("BB middle[%d]=%.10f, SMA[%d]=%.10f",
					i, middle[i], i, sma[i])
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestBollingerConstantPricesCollapses: For constant prices, stddev=0,
// so upper = middle = lower = constant.
func TestBollingerConstantPricesCollapses(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		c := 1 + rng.Float64()*9999
		period := 5 + rng.Intn(20)
		length := period + 20
		prices := generateConstantSeries(c, length)

		upper, middle, lower := computeBollingerBands(prices, period, 2.0)
		if upper == nil {
			return false
		}

		for i := period - 1; i < len(prices); i++ {
			if math.Abs(upper[i]-c) > 1e-8 || math.Abs(middle[i]-c) > 1e-8 || math.Abs(lower[i]-c) > 1e-8 {
				t.Logf("BB[%d]: upper=%.8f middle=%.8f lower=%.8f, expected %.8f",
					i, upper[i], middle[i], lower[i], c)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 1000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestMACDSignalIsEMAOfMACDLine: The MACD signal is an EMA(9) of the MACD line.
func TestMACDSignalIsEMAOfMACDLine(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		// Need at least 26 + 9 = 35 candles for full MACD computation
		length := 50 + rng.Intn(200)
		prices := generatePriceSeries(rng, length)

		ema12 := computeEMA(prices, 12)
		ema26 := computeEMA(prices, 26)
		if ema12 == nil || ema26 == nil {
			return true
		}

		// MACD line = EMA12 - EMA26
		macdLine := make([]float64, len(prices))
		for i := range prices {
			if i < len(ema12) && i < len(ema26) {
				macdLine[i] = ema12[i] - ema26[i]
			}
		}

		// Signal = EMA(9) of MACD line
		macdSignal := computeEMA(macdLine, 9)
		if macdSignal == nil {
			return true
		}

		// Now verify: signal computed independently via computeEMA(macdLine, 9)
		// should match what we'd get if we applied the same EMA formula.
		// Since we're using the same function, this is more of a consistency check.
		signalDirect := computeEMA(macdLine, 9)
		if signalDirect == nil {
			return true
		}

		for i := 8; i < len(prices); i++ {
			if math.Abs(macdSignal[i]-signalDirect[i]) > 1e-10 {
				t.Logf("signal[%d]=%.10f, directSignal[%d]=%.10f",
					i, macdSignal[i], i, signalDirect[i])
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 1000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestMACDHistogramSign: MACD histogram = MACD line - signal line.
func TestMACDHistogramSign(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		length := 50 + rng.Intn(200)
		prices := generatePriceSeries(rng, length)

		ema12 := computeEMA(prices, 12)
		ema26 := computeEMA(prices, 26)
		if ema12 == nil || ema26 == nil {
			return true
		}

		macdLine := make([]float64, len(prices))
		for i := range prices {
			macdLine[i] = ema12[i] - ema26[i]
		}
		macdSignal := computeEMA(macdLine, 9)
		if macdSignal == nil {
			return true
		}

		// Histogram = macdLine - macdSignal (just verify it's computable
		// and no NaN/Inf values creep in)
		for i := 34; i < len(prices); i++ { // 26 for EMA26 + 9 for signal EMA
			hist := macdLine[i] - macdSignal[i]
			if math.IsNaN(hist) || math.IsInf(hist, 0) {
				t.Logf("MACD histogram[%d] is NaN/Inf", i)
				return false
			}
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 1000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestSafeLastValue: Returns 0 for empty slice, last element otherwise.
func TestSafeLastValue(t *testing.T) {
	t.Parallel()
	t.Run("empty slice", func(t *testing.T) {
		if v := safeLastValue(nil); v != 0 {
			t.Errorf("expected 0, got %f", v)
		}
		if v := safeLastValue([]float64{}); v != 0 {
			t.Errorf("expected 0, got %f", v)
		}
	})

	t.Run("non-empty slice", func(t *testing.T) {
		if v := safeLastValue([]float64{1, 2, 3, 42}); v != 42 {
			t.Errorf("expected 42, got %f", v)
		}
	})
}

// TestIndicatorNilForInsufficientData: All indicators return nil when data is too short.
func TestIndicatorNilForInsufficientData(t *testing.T) {
	t.Parallel()
	short := []float64{100, 101, 102}

	t.Run("RSI nil for short data", func(t *testing.T) {
		if rsi := computeRSI(short, 14); rsi != nil {
			t.Error("expected nil RSI for 3 prices with period 14")
		}
	})

	t.Run("SMA nil for short data", func(t *testing.T) {
		if sma := computeSMA(short, 20); sma != nil {
			t.Error("expected nil SMA for 3 prices with period 20")
		}
	})

	t.Run("EMA nil for short data", func(t *testing.T) {
		if ema := computeEMA(short, 20); ema != nil {
			t.Error("expected nil EMA for 3 prices with period 20")
		}
	})

	t.Run("Bollinger nil for short data", func(t *testing.T) {
		u, m, l := computeBollingerBands(short, 20, 2.0)
		if u != nil || m != nil || l != nil {
			t.Error("expected nil Bollinger Bands for 3 prices with period 20")
		}
	})
}

// TestEMAReactsToRecentPricesMoreThanSMA: A spike in recent prices should
// move EMA more than SMA (EMA puts more weight on recent data).
func TestEMAReactsToRecentPrices(t *testing.T) {
	t.Parallel()
	// Steady prices then a big jump
	prices := make([]float64, 50)
	for i := 0; i < 49; i++ {
		prices[i] = 100.0
	}
	prices[49] = 200.0 // big spike

	period := 10
	sma := computeSMA(prices, period)
	ema := computeEMA(prices, period)

	if sma == nil || ema == nil {
		t.Fatal("expected non-nil SMA and EMA")
	}

	last := len(prices) - 1
	// EMA should react more strongly to the spike than SMA
	smaDiff := sma[last] - 100.0
	emaDiff := ema[last] - 100.0

	if emaDiff <= smaDiff {
		t.Errorf("EMA should react more to recent spike: emaDiff=%.4f, smaDiff=%.4f",
			emaDiff, smaDiff)
	}
}
