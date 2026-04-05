package domain

import (
	"fmt"
	"strings"
)

// InstrumentKey is a value object identifying a tradable instrument by
// exchange and trading symbol. This is the canonical format used across
// the Kite Connect API ("NSE:RELIANCE", "BSE:INFY", "NFO:NIFTY25APRFUT").
type InstrumentKey struct {
	Exchange      string
	Tradingsymbol string
}

// NewInstrumentKey creates an InstrumentKey from an exchange and symbol.
func NewInstrumentKey(exchange, symbol string) InstrumentKey {
	return InstrumentKey{
		Exchange:      strings.ToUpper(exchange),
		Tradingsymbol: strings.ToUpper(symbol),
	}
}

// String returns the canonical "EXCHANGE:SYMBOL" representation.
func (k InstrumentKey) String() string {
	return k.Exchange + ":" + k.Tradingsymbol
}

// IsZero returns true if the key is unset.
func (k InstrumentKey) IsZero() bool {
	return k.Exchange == "" && k.Tradingsymbol == ""
}

// ParseInstrumentKey parses a string like "NSE:RELIANCE" into an InstrumentKey.
// Returns an error if the format is invalid.
func ParseInstrumentKey(s string) (InstrumentKey, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return InstrumentKey{}, fmt.Errorf("domain: invalid instrument key %q, expected EXCHANGE:SYMBOL", s)
	}
	return NewInstrumentKey(parts[0], parts[1]), nil
}
