package domain

// instrument_spec_test.go — unit tests for instrument-level order
// invariants. Exchange whitelist + NewInstrumentKeyStrict are already
// covered in order_placement_test.go; this file tests the two rules
// that depend on instrument metadata (lot size, tick size) and the
// tradingsymbol format check.

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// --- ValidateLotSize ---

func TestValidateLotSize_AcceptsMultiple(t *testing.T) {
	t.Parallel()

	err := ValidateLotSize(50, 25)
	assert.NoError(t, err)
}

func TestValidateLotSize_AcceptsExactMatch(t *testing.T) {
	t.Parallel()

	err := ValidateLotSize(25, 25)
	assert.NoError(t, err)
}

func TestValidateLotSize_RejectsPartialLot(t *testing.T) {
	t.Parallel()

	err := ValidateLotSize(37, 25)
	assert.Error(t, err)
}

func TestValidateLotSize_RejectsZeroQty(t *testing.T) {
	t.Parallel()

	err := ValidateLotSize(0, 25)
	assert.Error(t, err)
}

func TestValidateLotSize_LotSizeOneAcceptsAnyQty(t *testing.T) {
	t.Parallel()

	// Equity typically has lot size 1 — every positive qty is valid.
	err := ValidateLotSize(7, 1)
	assert.NoError(t, err)
}

func TestValidateLotSize_RejectsBadLotSize(t *testing.T) {
	t.Parallel()

	err := ValidateLotSize(10, 0)
	assert.Error(t, err, "lot size 0 is invalid config")
}

// --- ValidateTickSize ---

func TestValidateTickSize_AcceptsAlignedPrice(t *testing.T) {
	t.Parallel()

	// NSE equity tick is typically 0.05.
	err := ValidateTickSize(2500.45, 0.05)
	assert.NoError(t, err)
}

func TestValidateTickSize_AcceptsExactIntegerPrice(t *testing.T) {
	t.Parallel()

	err := ValidateTickSize(100.00, 0.05)
	assert.NoError(t, err)
}

func TestValidateTickSize_RejectsMisalignedPrice(t *testing.T) {
	t.Parallel()

	err := ValidateTickSize(2500.47, 0.05)
	assert.Error(t, err)
}

func TestValidateTickSize_RejectsNegativePrice(t *testing.T) {
	t.Parallel()

	err := ValidateTickSize(-100, 0.05)
	assert.Error(t, err)
}

func TestValidateTickSize_ZeroTickIsNoOp(t *testing.T) {
	t.Parallel()

	// Some indexes / MF entries have tick_size = 0 — we treat that as
	// "no alignment rule" rather than an error.
	err := ValidateTickSize(123.4567, 0)
	assert.NoError(t, err)
}

func TestValidateTickSize_RejectsNegativeTick(t *testing.T) {
	t.Parallel()

	err := ValidateTickSize(100, -0.05)
	assert.Error(t, err)
}

// --- ValidateTradingsymbolFormat ---

func TestValidateTradingsymbolFormat_AcceptsEquity(t *testing.T) {
	t.Parallel()

	for _, sym := range []string{"RELIANCE", "SBIN", "HDFCBANK", "TCS"} {
		err := ValidateTradingsymbolFormat(sym)
		assert.NoError(t, err, "equity symbol %q must be accepted", sym)
	}
}

func TestValidateTradingsymbolFormat_AcceptsFNO(t *testing.T) {
	t.Parallel()

	for _, sym := range []string{"NIFTY25APRFUT", "BANKNIFTY25APR50000CE", "RELIANCE25APR2500PE"} {
		err := ValidateTradingsymbolFormat(sym)
		assert.NoError(t, err, "F&O symbol %q must be accepted", sym)
	}
}

func TestValidateTradingsymbolFormat_RejectsEmpty(t *testing.T) {
	t.Parallel()

	err := ValidateTradingsymbolFormat("")
	assert.Error(t, err)
}

func TestValidateTradingsymbolFormat_RejectsWhitespace(t *testing.T) {
	t.Parallel()

	err := ValidateTradingsymbolFormat("REL IANCE")
	assert.Error(t, err)
}

func TestValidateTradingsymbolFormat_RejectsControlChars(t *testing.T) {
	t.Parallel()

	err := ValidateTradingsymbolFormat("RELIANCE\x00")
	assert.Error(t, err)
}

// --- Composed: NewInstrumentRules ---

func TestNewInstrumentRules_CheckQuantity_Reject(t *testing.T) {
	t.Parallel()

	rules := NewInstrumentRules("NFO", "NIFTY25APRFUT", 50, 0.05)
	err := rules.CheckQuantity(30)
	assert.Error(t, err, "30 is not a multiple of lot size 50")
}

func TestNewInstrumentRules_CheckQuantity_Accept(t *testing.T) {
	t.Parallel()

	rules := NewInstrumentRules("NFO", "NIFTY25APRFUT", 50, 0.05)
	err := rules.CheckQuantity(100)
	assert.NoError(t, err)
}

func TestNewInstrumentRules_CheckPrice_Reject(t *testing.T) {
	t.Parallel()

	rules := NewInstrumentRules("NFO", "NIFTY25APRFUT", 50, 0.05)
	err := rules.CheckPrice(100.03)
	assert.Error(t, err, "100.03 is not aligned to tick 0.05")
}

func TestNewInstrumentRules_CheckPrice_Accept(t *testing.T) {
	t.Parallel()

	rules := NewInstrumentRules("NFO", "NIFTY25APRFUT", 50, 0.05)
	err := rules.CheckPrice(100.05)
	assert.NoError(t, err)
}
