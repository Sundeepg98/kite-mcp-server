package domain

import "testing"

// --- QuantitySpec tests ---

func TestQuantitySpec_WithinBounds(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 100)
	if !spec.IsSatisfiedBy(50) {
		t.Errorf("expected 50 to satisfy [1, 100]")
	}
}

func TestQuantitySpec_AtBounds(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 100)
	if !spec.IsSatisfiedBy(1) {
		t.Error("expected min bound 1 to satisfy")
	}
	if !spec.IsSatisfiedBy(100) {
		t.Error("expected max bound 100 to satisfy")
	}
}

func TestQuantitySpec_BelowMin(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(10, 100)
	if spec.IsSatisfiedBy(5) {
		t.Error("expected 5 to fail with min=10")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason")
	}
}

func TestQuantitySpec_AboveMax(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 100)
	if spec.IsSatisfiedBy(101) {
		t.Error("expected 101 to fail with max=100")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason")
	}
}

func TestQuantitySpec_ZeroQuantity(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 100)
	if spec.IsSatisfiedBy(0) {
		t.Error("expected 0 to fail")
	}
}

func TestQuantitySpec_NegativeQuantity(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 100)
	if spec.IsSatisfiedBy(-5) {
		t.Error("expected -5 to fail")
	}
}

func TestQuantitySpec_NoMaxBound(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(1, 0) // max=0 means no upper bound
	if !spec.IsSatisfiedBy(999999) {
		t.Error("expected large quantity to satisfy when max=0")
	}
}

func TestQuantitySpec_DefaultMin(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(0, 100) // min=0 defaults to 1
	if spec.Min != 1 {
		t.Errorf("expected Min=1 after default, got %d", spec.Min)
	}
	if spec.IsSatisfiedBy(0) {
		t.Error("expected 0 to fail even with default min")
	}
}

func TestQuantitySpec_NegativeMinDefaultsTo1(t *testing.T) {
	t.Parallel()
	spec := NewQuantitySpec(-5, 100)
	if spec.Min != 1 {
		t.Errorf("expected Min=1 for negative input, got %d", spec.Min)
	}
}

// --- PriceSpec tests ---

func TestPriceSpec_ValidPrice(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(100000)
	if !spec.IsSatisfiedBy(2500.50) {
		t.Error("expected 2500.50 to satisfy")
	}
}

func TestPriceSpec_ZeroPrice(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(100000)
	if spec.IsSatisfiedBy(0) {
		t.Error("expected 0 to fail (must be positive)")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason")
	}
}

func TestPriceSpec_NegativePrice(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(100000)
	if spec.IsSatisfiedBy(-10) {
		t.Error("expected negative to fail")
	}
}

func TestPriceSpec_AboveMax(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(500000)
	if spec.IsSatisfiedBy(600000) {
		t.Error("expected 600000 to fail with max=500000")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason")
	}
}

func TestPriceSpec_NoMaxBound(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(0)
	if !spec.IsSatisfiedBy(99999999) {
		t.Error("expected large price to satisfy when max=0")
	}
}

func TestPriceSpec_AtMax(t *testing.T) {
	t.Parallel()
	spec := NewPriceSpec(500)
	if !spec.IsSatisfiedBy(500) {
		t.Error("expected price at max to satisfy")
	}
}

// --- OrderSpec tests ---

func TestOrderSpec_ValidBuyLimit(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           2500,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
	}
	if !spec.IsSatisfiedBy(candidate) {
		t.Errorf("expected valid order to satisfy: %s", spec.Reason())
	}
}

func TestOrderSpec_MarketOrderSkipsPriceCheck(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           0, // MARKET orders have price=0
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "MARKET",
	}
	if !spec.IsSatisfiedBy(candidate) {
		t.Errorf("MARKET order with price=0 should pass: %s", spec.Reason())
	}
}

func TestOrderSpec_SLMOrderSkipsPriceCheck(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           0,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "SELL",
		OrderType:       "SL-M",
	}
	if !spec.IsSatisfiedBy(candidate) {
		t.Errorf("SL-M order with price=0 should pass: %s", spec.Reason())
	}
}

func TestOrderSpec_MissingTradingsymbol(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           2500,
		TransactionType: "BUY",
		OrderType:       "LIMIT",
	}
	if spec.IsSatisfiedBy(candidate) {
		t.Error("expected missing tradingsymbol to fail")
	}
}

func TestOrderSpec_InvalidTransactionType(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           2500,
		Tradingsymbol:   "RELIANCE",
		TransactionType: "HOLD", // invalid
		OrderType:       "LIMIT",
	}
	if spec.IsSatisfiedBy(candidate) {
		t.Error("expected invalid transaction type to fail")
	}
}

func TestOrderSpec_QtyFails(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(10, 100), NewPriceSpec(500000))
	candidate := OrderCandidate{
		Quantity:        5, // below min
		Price:           2500,
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		OrderType:       "LIMIT",
	}
	if spec.IsSatisfiedBy(candidate) {
		t.Error("expected quantity below min to fail")
	}
}

func TestOrderSpec_PriceFails(t *testing.T) {
	t.Parallel()
	spec := NewOrderSpec(NewQuantitySpec(1, 10000), NewPriceSpec(1000))
	candidate := OrderCandidate{
		Quantity:        100,
		Price:           2000, // above max
		Tradingsymbol:   "RELIANCE",
		TransactionType: "SELL",
		OrderType:       "LIMIT",
	}
	if spec.IsSatisfiedBy(candidate) {
		t.Error("expected price above max to fail")
	}
}

// --- AndSpec tests ---

func TestAndSpec_BothSatisfied(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(1, 100)
	right := NewQuantitySpec(10, 200)
	spec := And[int](left, right)
	if !spec.IsSatisfiedBy(50) {
		t.Error("expected 50 to satisfy both [1,100] AND [10,200]")
	}
}

func TestAndSpec_LeftFails(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(10, 100)
	right := NewQuantitySpec(1, 200)
	spec := And[int](left, right)
	if spec.IsSatisfiedBy(5) {
		t.Error("expected 5 to fail left spec [10,100]")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason from left")
	}
}

func TestAndSpec_RightFails(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(1, 200)
	right := NewQuantitySpec(10, 50)
	spec := And[int](left, right)
	if spec.IsSatisfiedBy(100) {
		t.Error("expected 100 to fail right spec [10,50]")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason from right")
	}
}

// --- OrSpec tests ---

func TestOrSpec_LeftSatisfied(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(1, 10)
	right := NewQuantitySpec(100, 200)
	spec := Or[int](left, right)
	if !spec.IsSatisfiedBy(5) {
		t.Error("expected 5 to satisfy left [1,10]")
	}
}

func TestOrSpec_RightSatisfied(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(1, 10)
	right := NewQuantitySpec(100, 200)
	spec := Or[int](left, right)
	if !spec.IsSatisfiedBy(150) {
		t.Error("expected 150 to satisfy right [100,200]")
	}
}

func TestOrSpec_NeitherSatisfied(t *testing.T) {
	t.Parallel()
	left := NewQuantitySpec(1, 10)
	right := NewQuantitySpec(100, 200)
	spec := Or[int](left, right)
	if spec.IsSatisfiedBy(50) {
		t.Error("expected 50 to fail both [1,10] OR [100,200]")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty combined reason")
	}
}

// --- NotSpec tests ---

func TestNotSpec_InnerSatisfied(t *testing.T) {
	t.Parallel()
	inner := NewQuantitySpec(1, 100)
	spec := Not[int](inner)
	if spec.IsSatisfiedBy(50) {
		t.Error("expected NOT to fail when inner is satisfied")
	}
	if spec.Reason() == "" {
		t.Error("expected non-empty reason")
	}
}

func TestNotSpec_InnerNotSatisfied(t *testing.T) {
	t.Parallel()
	inner := NewQuantitySpec(10, 100)
	spec := Not[int](inner)
	if !spec.IsSatisfiedBy(5) {
		t.Error("expected NOT to pass when inner fails")
	}
}

// --- Glossary type compile-time checks ---

func TestGlossaryTypes_CompileTimeCheck(t *testing.T) {
	t.Parallel()
	// These assignments verify the type aliases resolve correctly at compile time.
	var _ AdminActor = "admin@example.com"
	var _ AdminRole = true
	var _ MCPSessionID = "kitemcp-abc123"
	var _ KiteToken = "some-access-token"
	var _ OAuthToken = "eyJhbGciOiJIUzI1NiJ9..."
	var _ OrderFreezeReason = "circuit_breaker"
	var _ GlobalFreezeReason = "market_emergency"
}

func TestGlossaryConstants(t *testing.T) {
	t.Parallel()
	// Transaction types
	if TransactionBuy != "BUY" {
		t.Errorf("TransactionBuy = %q", TransactionBuy)
	}
	if TransactionSell != "SELL" {
		t.Errorf("TransactionSell = %q", TransactionSell)
	}

	// Order types
	if OrderTypeMarket != "MARKET" {
		t.Errorf("OrderTypeMarket = %q", OrderTypeMarket)
	}
	if OrderTypeLimit != "LIMIT" {
		t.Errorf("OrderTypeLimit = %q", OrderTypeLimit)
	}
	if OrderTypeSL != "SL" {
		t.Errorf("OrderTypeSL = %q", OrderTypeSL)
	}
	if OrderTypeSLM != "SL-M" {
		t.Errorf("OrderTypeSLM = %q", OrderTypeSLM)
	}

	// Product types
	if ProductCNC != "CNC" {
		t.Errorf("ProductCNC = %q", ProductCNC)
	}
	if ProductMIS != "MIS" {
		t.Errorf("ProductMIS = %q", ProductMIS)
	}
	if ProductNRML != "NRML" {
		t.Errorf("ProductNRML = %q", ProductNRML)
	}

	// Exchange codes
	if ExchangeNSE != "NSE" {
		t.Errorf("ExchangeNSE = %q", ExchangeNSE)
	}
	if ExchangeBSE != "BSE" {
		t.Errorf("ExchangeBSE = %q", ExchangeBSE)
	}
	if ExchangeNFO != "NFO" {
		t.Errorf("ExchangeNFO = %q", ExchangeNFO)
	}
	if ExchangeBFO != "BFO" {
		t.Errorf("ExchangeBFO = %q", ExchangeBFO)
	}
	if ExchangeMCX != "MCX" {
		t.Errorf("ExchangeMCX = %q", ExchangeMCX)
	}
	if ExchangeCDS != "CDS" {
		t.Errorf("ExchangeCDS = %q", ExchangeCDS)
	}
}
