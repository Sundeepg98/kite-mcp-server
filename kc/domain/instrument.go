package domain

import (
	"fmt"
	"strings"
)

// validExchanges is the whitelist enforced by NewInstrumentKeyStrict. Mirrors
// the canonical exchange codes Kite Connect returns: NSE / BSE (equity),
// NFO / BFO (F&O), MCX (commodities), CDS / BCD (currency). Additions here
// should match https://kite.trade/docs/connect/v3/market-quotes/ exchange enum.
var validExchanges = map[string]struct{}{
	"NSE": {},
	"BSE": {},
	"NFO": {},
	"BFO": {},
	"MCX": {},
	"CDS": {},
	"BCD": {},
}

// InstrumentKey is a value object identifying a tradable instrument by
// exchange and trading symbol. This is the canonical format used across
// the Kite Connect API ("NSE:RELIANCE", "BSE:INFY", "NFO:NIFTY25APRFUT").
type InstrumentKey struct {
	Exchange      string
	Tradingsymbol string
}

// NewInstrumentKey creates an InstrumentKey from an exchange and symbol
// without strict validation. Retained for existing callers (tests, legacy
// adapters) that feed in already-trusted broker data. New call sites that
// sit on the order-placement boundary should prefer NewInstrumentKeyStrict.
func NewInstrumentKey(exchange, symbol string) InstrumentKey {
	return InstrumentKey{
		Exchange:      strings.ToUpper(exchange),
		Tradingsymbol: strings.ToUpper(symbol),
	}
}

// NewInstrumentKeyStrict constructs an InstrumentKey with construction
// invariants enforced: non-empty exchange, non-empty trading symbol, and
// exchange against the whitelist. Whitespace is trimmed; result is
// uppercase. Use at system boundaries (MCP tool handlers, order commands)
// to reject bad input at domain entry rather than surfacing ambiguous
// broker errors later.
func NewInstrumentKeyStrict(exchange, symbol string) (InstrumentKey, error) {
	exch := strings.ToUpper(strings.TrimSpace(exchange))
	sym := strings.ToUpper(strings.TrimSpace(symbol))
	if exch == "" {
		return InstrumentKey{}, fmt.Errorf("domain: instrument exchange must not be empty")
	}
	if sym == "" {
		return InstrumentKey{}, fmt.Errorf("domain: instrument tradingsymbol must not be empty")
	}
	if _, ok := validExchanges[exch]; !ok {
		return InstrumentKey{}, fmt.Errorf("domain: unknown exchange %q (want one of NSE/BSE/NFO/BFO/MCX/CDS/BCD)", exch)
	}
	return InstrumentKey{Exchange: exch, Tradingsymbol: sym}, nil
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
