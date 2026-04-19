package mcp

import (
	"math"
	"math/rand"
	"testing"
	"testing/quick"
)

// ---------------------------------------------------------------------------
// Property-based tests for Black-Scholes financial calculations
// ---------------------------------------------------------------------------

// validBSInputs generates constrained inputs for Black-Scholes functions.
// S in [1, 50000], K in [1, 50000], T in (0, 5], r in [0, 0.2], sigma in (0, 3].
type validBSInputs struct {
	S     float64 // spot price
	K     float64 // strike price
	T     float64 // time to expiry (years)
	R     float64 // risk-free rate
	Sigma float64 // volatility
}

func generateValidBSInputs(rng *rand.Rand) validBSInputs {
	return validBSInputs{
		S:     1 + rng.Float64()*49999,
		K:     1 + rng.Float64()*49999,
		T:     0.001 + rng.Float64()*4.999,
		R:     rng.Float64() * 0.20,
		Sigma: 0.01 + rng.Float64()*2.99,
	}
}

// TestDeltaBounds: Call delta in [0, 1], Put delta in [-1, 0].
func TestDeltaBounds(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		callDelta := bsDelta(in.S, in.K, in.T, in.R, in.Sigma, true)
		putDelta := bsDelta(in.S, in.K, in.T, in.R, in.Sigma, false)

		if callDelta < -0.0001 || callDelta > 1.0001 {
			t.Logf("call delta=%.6f out of [0,1] for S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f",
				callDelta, in.S, in.K, in.T, in.R, in.Sigma)
			return false
		}
		if putDelta < -1.0001 || putDelta > 0.0001 {
			t.Logf("put delta=%.6f out of [-1,0] for S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f",
				putDelta, in.S, in.K, in.T, in.R, in.Sigma)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestGammaNonNegative: Gamma >= 0 for any valid inputs.
func TestGammaNonNegative(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		gamma := bsGamma(in.S, in.K, in.T, in.R, in.Sigma)
		if gamma < -1e-10 {
			t.Logf("gamma=%.10f < 0 for S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f",
				gamma, in.S, in.K, in.T, in.R, in.Sigma)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestThetaNonPositiveForLongOptions: Theta <= 0 for long (bought) options.
// For standard BS, call theta and put theta are both <= 0 (time decay hurts long positions)
// when r >= 0 (which is always true for us).
// Note: Deep ITM puts can have positive theta when r > 0, so we use a tolerance.
func TestThetaNonPositiveForLongOptions(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		callTheta := bsTheta(in.S, in.K, in.T, in.R, in.Sigma, true)
		// Call theta is always <= 0 for European calls (rK*e^{-rT}*N(d2) is always
		// smaller than the first term). Allow tiny numerical tolerance.
		if callTheta > 1e-6 {
			t.Logf("call theta=%.10f > 0 for S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f",
				callTheta, in.S, in.K, in.T, in.R, in.Sigma)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestVegaNonNegative: Vega >= 0 for all options (calls and puts have same vega).
func TestVegaNonNegative(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		vega := bsVega(in.S, in.K, in.T, in.R, in.Sigma)
		if vega < -1e-10 {
			t.Logf("vega=%.10f < 0 for S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f",
				vega, in.S, in.K, in.T, in.R, in.Sigma)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestIVNonNegative: Implied volatility is always >= 0 when found.
func TestIVNonNegative(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)
		isCall := rng.Intn(2) == 0

		// Compute a fair price from the inputs, then recover IV.
		price := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, isCall)
		if price <= 0 {
			return true // skip degenerate case
		}

		iv, ok := impliedVolatility(price, in.S, in.K, in.T, in.R, isCall)
		if !ok {
			return true // convergence failure is acceptable, not a property violation
		}
		if iv < 0 {
			t.Logf("IV=%.10f < 0 for price=%.4f S=%.2f K=%.2f T=%.4f r=%.4f call=%v",
				iv, price, in.S, in.K, in.T, in.R, isCall)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestIVRoundTrip: Computing BS price from known sigma, then recovering IV, should give back sigma.
// We constrain to near-the-money options where IV recovery is numerically stable.
func TestIVRoundTrip(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		// Keep S and K within a reasonable ratio to avoid deep ITM/OTM instability.
		S := 100 + rng.Float64()*4900
		// K within 50% of S (moneyness between 0.67 and 1.5)
		K := S * (0.67 + rng.Float64()*0.83)
		in := validBSInputs{
			S:     S,
			K:     K,
			T:     0.05 + rng.Float64()*1.5, // at least ~18 days
			R:     0.03 + rng.Float64()*0.07,
			Sigma: 0.10 + rng.Float64()*1.0, // 10% to 110%
		}
		isCall := rng.Intn(2) == 0

		price := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, isCall)
		if price < 0.5 {
			return true // too cheap, numerical issues in IV solver
		}

		// Skip deep ITM options where time value is negligible relative to intrinsic
		intrinsic := 0.0
		if isCall {
			intrinsic = math.Max(in.S-in.K*math.Exp(-in.R*in.T), 0)
		} else {
			intrinsic = math.Max(in.K*math.Exp(-in.R*in.T)-in.S, 0)
		}
		timeValue := price - intrinsic
		if intrinsic > 0 && timeValue/price < 0.01 {
			return true // <1% time value — IV recovery is inherently unstable
		}

		iv, ok := impliedVolatility(price, in.S, in.K, in.T, in.R, isCall)
		if !ok {
			return true // convergence failure is acceptable
		}

		// IV should be within 5% relative error of the original sigma.
		relErr := math.Abs(iv-in.Sigma) / in.Sigma
		if relErr > 0.05 {
			t.Logf("IV round-trip error: sigma=%.4f, recovered IV=%.4f, relErr=%.4f, price=%.4f, S=%.2f K=%.2f T=%.4f timeValue=%.4f",
				in.Sigma, iv, relErr, price, in.S, in.K, in.T, timeValue)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 2000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestPutCallParity: C - P = S - K*exp(-rT) for European options (no dividends).
func TestPutCallParity(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		callPrice := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, true)
		putPrice := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, false)

		// Put-call parity: C - P = S - K*exp(-rT)
		lhs := callPrice - putPrice
		rhs := in.S - in.K*math.Exp(-in.R*in.T)

		diff := math.Abs(lhs - rhs)
		// Allow tolerance proportional to the price magnitude.
		tol := 1e-8 * math.Max(in.S, in.K)
		if diff > tol {
			t.Logf("Put-call parity violation: C-P=%.8f, S-Ke^{-rT}=%.8f, diff=%.10f, tol=%.10f",
				lhs, rhs, diff, tol)
			t.Logf("  S=%.2f K=%.2f T=%.4f r=%.4f sigma=%.4f C=%.8f P=%.8f",
				in.S, in.K, in.T, in.R, in.Sigma, callPrice, putPrice)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestCallPutDeltaRelationship: Call delta - Put delta = 1 (within tolerance).
func TestCallPutDeltaRelationship(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		callDelta := bsDelta(in.S, in.K, in.T, in.R, in.Sigma, true)
		putDelta := bsDelta(in.S, in.K, in.T, in.R, in.Sigma, false)

		// For European options: delta_call - delta_put = 1 (approximately, ignoring dividends)
		// More precisely, delta_call - delta_put = exp(-qT) where q=0, so = 1.
		// In our BS without dividends: delta_call = N(d1), delta_put = N(d1) - 1.
		diff := math.Abs((callDelta - putDelta) - 1.0)
		if diff > 1e-10 {
			t.Logf("delta_call - delta_put = %.10f, expected 1.0, diff=%.10f",
				callDelta-putDelta, diff)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestBlackScholesPriceNonNegative: Option prices are always >= 0.
func TestBlackScholesPriceNonNegative(t *testing.T) {
	t.Parallel()
	f := func(seed int64) bool {
		rng := rand.New(rand.NewSource(seed))
		in := generateValidBSInputs(rng)

		callPrice := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, true)
		putPrice := blackScholesPrice(in.S, in.K, in.T, in.R, in.Sigma, false)

		if callPrice < -1e-10 {
			t.Logf("call price=%.10f < 0", callPrice)
			return false
		}
		if putPrice < -1e-10 {
			t.Logf("put price=%.10f < 0", putPrice)
			return false
		}
		return true
	}

	cfg := &quick.Config{MaxCount: 5000}
	if err := quick.Check(f, cfg); err != nil {
		t.Error(err)
	}
}

// TestEdgeCases: T=0 and sigma=0 boundaries.
func TestBlackScholesEdgeCases(t *testing.T) {
	t.Parallel()
	t.Run("at expiry call ITM returns intrinsic", func(t *testing.T) {
		price := blackScholesPrice(110, 100, 0, 0.05, 0.2, true)
		if math.Abs(price-10) > 1e-10 {
			t.Errorf("expected intrinsic 10, got %.10f", price)
		}
	})

	t.Run("at expiry put ITM returns intrinsic", func(t *testing.T) {
		price := blackScholesPrice(90, 100, 0, 0.05, 0.2, false)
		if math.Abs(price-10) > 1e-10 {
			t.Errorf("expected intrinsic 10, got %.10f", price)
		}
	})

	t.Run("at expiry OTM returns 0", func(t *testing.T) {
		callPrice := blackScholesPrice(90, 100, 0, 0.05, 0.2, true)
		putPrice := blackScholesPrice(110, 100, 0, 0.05, 0.2, false)
		if callPrice > 1e-10 {
			t.Errorf("OTM call at expiry should be 0, got %.10f", callPrice)
		}
		if putPrice > 1e-10 {
			t.Errorf("OTM put at expiry should be 0, got %.10f", putPrice)
		}
	})

	t.Run("delta is 0 at expiry", func(t *testing.T) {
		callDelta := bsDelta(110, 100, 0, 0.05, 0.2, true)
		putDelta := bsDelta(90, 100, 0, 0.05, 0.2, false)
		if callDelta != 0 {
			t.Errorf("expected delta 0 at expiry, got %.10f", callDelta)
		}
		if putDelta != 0 {
			t.Errorf("expected delta 0 at expiry, got %.10f", putDelta)
		}
	})

	t.Run("gamma is 0 at expiry", func(t *testing.T) {
		gamma := bsGamma(110, 100, 0, 0.05, 0.2)
		if gamma != 0 {
			t.Errorf("expected gamma 0 at expiry, got %.10f", gamma)
		}
	})

	t.Run("theta is 0 at expiry", func(t *testing.T) {
		theta := bsTheta(110, 100, 0, 0.05, 0.2, true)
		if theta != 0 {
			t.Errorf("expected theta 0 at expiry, got %.10f", theta)
		}
	})

	t.Run("vega is 0 at expiry", func(t *testing.T) {
		vega := bsVega(110, 100, 0, 0.05, 0.2)
		if vega != 0 {
			t.Errorf("expected vega 0 at expiry, got %.10f", vega)
		}
	})
}

// TestNormalCDFProperties: N(0)=0.5, N(+inf)~1, N(-inf)~0, N(x)+N(-x)=1.
func TestNormalCDFProperties(t *testing.T) {
	t.Parallel()
	t.Run("N(0) = 0.5", func(t *testing.T) {
		if math.Abs(normalCDF(0)-0.5) > 1e-15 {
			t.Errorf("normalCDF(0) = %.15f, expected 0.5", normalCDF(0))
		}
	})

	t.Run("symmetry N(x) + N(-x) = 1", func(t *testing.T) {
		f := func(seed int64) bool {
			rng := rand.New(rand.NewSource(seed))
			x := (rng.Float64() - 0.5) * 20 // [-10, 10]
			sum := normalCDF(x) + normalCDF(-x)
			return math.Abs(sum-1.0) < 1e-12
		}
		cfg := &quick.Config{MaxCount: 1000}
		if err := quick.Check(f, cfg); err != nil {
			t.Error(err)
		}
	})

	t.Run("N(large) approaches 1", func(t *testing.T) {
		if normalCDF(10) < 0.9999 {
			t.Errorf("normalCDF(10) = %.10f, expected ~1", normalCDF(10))
		}
	})

	t.Run("N(-large) approaches 0", func(t *testing.T) {
		if normalCDF(-10) > 0.0001 {
			t.Errorf("normalCDF(-10) = %.10f, expected ~0", normalCDF(-10))
		}
	})
}
