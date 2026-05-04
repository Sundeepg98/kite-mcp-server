package instruments

// InstrumentManagerInterface defines operations for looking up instrument
// metadata (symbols, tokens, ISIN, etc.).
//
// Anchor 5 PR 5.4 (per .research/anchor-5-prs-design.md): this interface
// was relocated from `kc/interfaces.go:508` to its owning package
// (kc/instruments) so that kc/ports/instrument.go can eventually drop
// its kc-parent import in PR 5.5 (Wave B-2). The legacy
// `kc.InstrumentManagerInterface` is preserved as a single-line type
// alias in kc/interfaces.go to keep the existing 10+ reverse-dep call
// sites compiling unchanged. Both names reference the SAME interface —
// Go type aliases are not new types — so satisfaction by *Manager
// (this package) is preserved at the alias site.
//
// Method set (12 methods, identical to the pre-move interface — only
// the type qualifier changes since we are now in the instruments
// package):
//   GetByID, GetByTradingsymbol, GetByISIN — symbol/ISIN lookup
//   GetByInstToken, GetByExchToken         — token lookup
//   Filter, GetAllByUnderlying             — predicate / F&O filter
//   Count                                  — total loaded count
//   GetUpdateStats, UpdateInstruments,
//   ForceUpdateInstruments                 — refresh lifecycle
//   Shutdown                               — graceful teardown
type InstrumentManagerInterface interface {
	// GetByID returns an instrument using the symbol (exchange:tradingsymbol).
	GetByID(id string) (Instrument, error)

	// GetByTradingsymbol returns an instrument using exchange and trading symbol.
	GetByTradingsymbol(exchange, tradingsymbol string) (Instrument, error)

	// GetByISIN returns instruments matching the given ISIN.
	GetByISIN(isin string) ([]Instrument, error)

	// GetByInstToken returns an instrument using its instrument token.
	GetByInstToken(token uint32) (Instrument, error)

	// GetByExchToken returns an instrument using exchange and exchange token.
	GetByExchToken(exch string, exchToken uint32) (Instrument, error)

	// Filter returns instruments matching the given filter function.
	Filter(filter func(Instrument) bool) []Instrument

	// GetAllByUnderlying returns F&O instruments for the given underlying.
	GetAllByUnderlying(exchange, underlying string) ([]Instrument, error)

	// Count returns the number of instruments loaded.
	Count() int

	// GetUpdateStats returns current update statistics.
	GetUpdateStats() UpdateStats

	// UpdateInstruments fetches and updates instrument data.
	UpdateInstruments() error

	// ForceUpdateInstruments forces an instrument update regardless of timing.
	ForceUpdateInstruments() error

	// Shutdown gracefully shuts down the instruments manager.
	Shutdown()
}
