package domain

// order_placement_test.go — unit tests for order-placement invariants.
// Covers strict value-object constructors (Money, InstrumentKey) and the
// iceberg disclosure rule. Quantity already has NewQuantity tested in
// quantity_test.go — reused here for composition tests only.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- Money strict constructor ---

func TestNewMoney_RejectsNegative(t *testing.T) {
	t.Parallel()

	_, err := NewMoney(-0.01)
	assert.Error(t, err)
}

func TestNewMoney_RejectsZero(t *testing.T) {
	t.Parallel()

	_, err := NewMoney(0)
	assert.Error(t, err)
}

func TestNewMoney_AcceptsPositive(t *testing.T) {
	t.Parallel()

	m, err := NewMoney(123.45)
	assert.NoError(t, err)
	assert.Equal(t, 123.45, m.Amount)
	assert.Equal(t, "INR", m.Currency)
	assert.True(t, m.IsPositive())
}

// --- InstrumentKey strict constructor ---

func TestNewInstrumentKeyStrict_RejectsEmptyExchange(t *testing.T) {
	t.Parallel()

	_, err := NewInstrumentKeyStrict("", "RELIANCE")
	assert.Error(t, err)
}

func TestNewInstrumentKeyStrict_RejectsEmptySymbol(t *testing.T) {
	t.Parallel()

	_, err := NewInstrumentKeyStrict("NSE", "")
	assert.Error(t, err)
}

func TestNewInstrumentKeyStrict_RejectsUnknownExchange(t *testing.T) {
	t.Parallel()

	_, err := NewInstrumentKeyStrict("FAKE", "RELIANCE")
	assert.Error(t, err)
}

func TestNewInstrumentKeyStrict_AcceptsWhitelisted(t *testing.T) {
	t.Parallel()

	// Kite's canonical exchanges.
	for _, exch := range []string{"NSE", "BSE", "NFO", "BFO", "MCX", "CDS", "BCD"} {
		k, err := NewInstrumentKeyStrict(exch, "SOMETHING")
		assert.NoError(t, err, "exchange %q must be accepted", exch)
		assert.Equal(t, exch, k.Exchange)
	}
}

func TestNewInstrumentKeyStrict_Normalises(t *testing.T) {
	t.Parallel()

	k, err := NewInstrumentKeyStrict("  nse  ", "  reliance  ")
	assert.NoError(t, err)
	assert.Equal(t, "NSE", k.Exchange)
	assert.Equal(t, "RELIANCE", k.Tradingsymbol)
}

// --- Iceberg disclosure rule ---

func TestNewIcebergLegs_RejectsDisclosedGreaterThanTotal(t *testing.T) {
	t.Parallel()

	err := ValidateIceberg(100, 150)
	assert.Error(t, err)
}

func TestNewIcebergLegs_RejectsZeroDisclosed(t *testing.T) {
	t.Parallel()

	err := ValidateIceberg(100, 0)
	assert.Error(t, err)
}

func TestNewIcebergLegs_RejectsNegative(t *testing.T) {
	t.Parallel()

	err := ValidateIceberg(-10, 5)
	assert.Error(t, err)
}

func TestNewIcebergLegs_AcceptsDisclosedEqualToTotal(t *testing.T) {
	t.Parallel()

	err := ValidateIceberg(100, 100)
	assert.NoError(t, err)
}

func TestNewIcebergLegs_AcceptsDisclosedLessThanTotal(t *testing.T) {
	t.Parallel()

	err := ValidateIceberg(100, 25)
	assert.NoError(t, err)
}

// --- Composed order placement request ---

func TestNewOrderPlacement_HappyPath(t *testing.T) {
	t.Parallel()

	qty, _ := NewQuantity(10)
	price, _ := NewMoney(2500.50)
	inst, _ := NewInstrumentKeyStrict("NSE", "RELIANCE")

	req, err := NewOrderPlacement(inst, qty, price, "BUY", "LIMIT")
	assert.NoError(t, err)
	assert.Equal(t, "RELIANCE", req.Instrument().Tradingsymbol)
	assert.Equal(t, 10, req.Quantity().Int())
}

func TestNewOrderPlacement_LimitRequiresPrice(t *testing.T) {
	t.Parallel()

	qty, _ := NewQuantity(10)
	var zeroPrice Money // zero-value Money, not valid
	inst, _ := NewInstrumentKeyStrict("NSE", "RELIANCE")

	_, err := NewOrderPlacement(inst, qty, zeroPrice, "BUY", "LIMIT")
	assert.Error(t, err, "LIMIT order must carry a valid price")
}

func TestNewOrderPlacement_MarketTolerateszero(t *testing.T) {
	t.Parallel()

	qty, _ := NewQuantity(10)
	var zeroPrice Money
	inst, _ := NewInstrumentKeyStrict("NSE", "RELIANCE")

	req, err := NewOrderPlacement(inst, qty, zeroPrice, "BUY", "MARKET")
	assert.NoError(t, err, "MARKET orders have price=0 by design")
	assert.Equal(t, "MARKET", req.OrderType())
}

func TestNewOrderPlacement_RejectsBadTransactionType(t *testing.T) {
	t.Parallel()

	qty, _ := NewQuantity(10)
	price, _ := NewMoney(100)
	inst, _ := NewInstrumentKeyStrict("NSE", "RELIANCE")

	_, err := NewOrderPlacement(inst, qty, price, "HOLD", "LIMIT")
	assert.Error(t, err)
}

func TestNewOrderPlacement_RejectsInvalidInstrument(t *testing.T) {
	t.Parallel()

	qty, _ := NewQuantity(10)
	price, _ := NewMoney(100)
	var badInst InstrumentKey // zero-value

	_, err := NewOrderPlacement(badInst, qty, price, "BUY", "LIMIT")
	assert.Error(t, err)
}

func TestNewOrderPlacement_RejectsInvalidQuantity(t *testing.T) {
	t.Parallel()

	price, _ := NewMoney(100)
	inst, _ := NewInstrumentKeyStrict("NSE", "RELIANCE")
	var badQty Quantity // zero-value

	_, err := NewOrderPlacement(inst, badQty, price, "BUY", "LIMIT")
	assert.Error(t, err)
}
