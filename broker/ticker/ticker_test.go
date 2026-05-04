package ticker_test

// Package ticker_test (external _test package — kept separate from
// the ticker package itself so future contract suites can import
// concrete adapters without circular-import risk, mirroring the
// pattern from broker/contract_test.go at commit 55d1a17).
//
// These tests pin the SHAPE of the broker-agnostic ticker port:
//   - Mode constants exist with the expected names
//   - Tick DTO has the broker-agnostic fields callers depend on
//   - TickHandler is the canonical callback type
//   - Ticker interface enumerates the lifecycle + subscription
//     methods every broker adapter must satisfy
//
// They DO NOT exercise behaviour — that's the conformance harness
// (commit 4: broker/conformance/). Shape tests fail at compile time
// if a future refactor drops a method or renames a field; the
// runtime asserts here cover the rest.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	"github.com/zerodha/kite-mcp-server/broker/ticker"
)

// TestMode_ConstantsExist pins the broker-agnostic mode vocabulary.
// Adapter authors translate broker-specific mode codes (e.g. Zerodha
// kiteticker.ModeLTP) to these constants; consumers depend on the
// constants existing as an exhaustive set.
func TestMode_ConstantsExist(t *testing.T) {
	t.Parallel()
	assert.NotEmpty(t, string(ticker.ModeLTP), "ModeLTP must be a non-empty Mode value")
	assert.NotEmpty(t, string(ticker.ModeQuote), "ModeQuote must be a non-empty Mode value")
	assert.NotEmpty(t, string(ticker.ModeFull), "ModeFull must be a non-empty Mode value")
	// Distinct values — no two modes alias to the same string.
	assert.NotEqual(t, ticker.ModeLTP, ticker.ModeQuote)
	assert.NotEqual(t, ticker.ModeQuote, ticker.ModeFull)
	assert.NotEqual(t, ticker.ModeLTP, ticker.ModeFull)
}

// TestTick_FieldShape pins the broker-agnostic fields a Tick DTO
// must carry. Adapters fill these from broker-specific tick
// representations (e.g. kiteticker.models.Tick); consumers read
// only the canonical surface.
func TestTick_FieldShape(t *testing.T) {
	t.Parallel()
	tick := ticker.Tick{
		InstrumentToken: 408065,
		LastPrice:       1500.50,
		LastQuantity:    100,
		AverageTradePrice: 1499.75,
		Volume:          1_000_000,
		BuyQuantity:     500,
		SellQuantity:    750,
		OHLC: ticker.TickOHLC{
			Open:  1490.0,
			High:  1510.0,
			Low:   1485.0,
			Close: 1495.0,
		},
		ChangePercent: 0.37,
		Mode:          ticker.ModeFull,
	}
	assert.Equal(t, uint32(408065), tick.InstrumentToken)
	assert.InDelta(t, 1500.50, tick.LastPrice, 0.001)
	assert.Equal(t, uint32(100), tick.LastQuantity)
	assert.InDelta(t, 1499.75, tick.AverageTradePrice, 0.001)
	assert.Equal(t, uint32(1_000_000), tick.Volume)
	assert.Equal(t, uint32(500), tick.BuyQuantity)
	assert.Equal(t, uint32(750), tick.SellQuantity)
	assert.InDelta(t, 1490.0, tick.OHLC.Open, 0.001)
	assert.InDelta(t, 1510.0, tick.OHLC.High, 0.001)
	assert.InDelta(t, 1485.0, tick.OHLC.Low, 0.001)
	assert.InDelta(t, 1495.0, tick.OHLC.Close, 0.001)
	assert.InDelta(t, 0.37, tick.ChangePercent, 0.001)
	assert.Equal(t, ticker.ModeFull, tick.Mode)
}

// TestTickHandler_Signature pins the canonical callback type.
// Consumers register a handler via Ticker.OnTick(handler) — the
// handler signature must remain stable across broker adapters so
// downstream code (kc/ticker, alert evaluator, watchlist push)
// doesn't need per-broker adapter shims.
func TestTickHandler_Signature(t *testing.T) {
	t.Parallel()
	var calls int
	var lastTick ticker.Tick
	handler := ticker.TickHandler(func(tk ticker.Tick) {
		calls++
		lastTick = tk
	})
	handler(ticker.Tick{InstrumentToken: 99, LastPrice: 100.0, Mode: ticker.ModeLTP})
	assert.Equal(t, 1, calls)
	assert.Equal(t, uint32(99), lastTick.InstrumentToken)
	assert.InDelta(t, 100.0, lastTick.LastPrice, 0.001)
}

// TestTicker_InterfaceMethods asserts every method on the Ticker
// interface is reachable via a value of the interface type. If a
// future refactor drops a method, this test fails at compile time
// (the &fakeTicker{} assignment) before the assertion ever runs.
func TestTicker_InterfaceMethods(t *testing.T) {
	t.Parallel()
	var tk ticker.Ticker = &fakeTicker{}
	assert.NotNil(t, tk, "fakeTicker must satisfy ticker.Ticker")

	// Each method callable without panic on the interface value.
	assert.NotPanics(t, func() { _ = tk.Subscribe([]uint32{1}) })
	assert.NotPanics(t, func() { _ = tk.Unsubscribe([]uint32{1}) })
	assert.NotPanics(t, func() { _ = tk.SetMode(ticker.ModeLTP, []uint32{1}) })
	assert.NotPanics(t, func() { tk.OnTick(func(_ ticker.Tick) {}) })
	assert.NotPanics(t, func() { tk.OnConnect(func() {}) })
	assert.NotPanics(t, func() { tk.OnError(func(_ error) {}) })
	assert.NotPanics(t, func() { tk.OnClose(func(_ int, _ string) {}) })
	assert.NotPanics(t, func() { tk.OnReconnect(func(_ int, _ time.Duration) {}) })
	assert.NotPanics(t, func() { tk.OnNoReconnect(func(_ int) {}) })
	assert.NotPanics(t, func() { _ = tk.Close() })
}

// fakeTicker is a no-op implementation used purely to assert that
// the Ticker interface is satisfiable. Future broker adapters
// (Zerodha, Upstox, Dhan) ship their own real implementations.
type fakeTicker struct{}

func (*fakeTicker) Subscribe([]uint32) error                       { return nil }
func (*fakeTicker) Unsubscribe([]uint32) error                     { return nil }
func (*fakeTicker) SetMode(ticker.Mode, []uint32) error            { return nil }
func (*fakeTicker) OnTick(ticker.TickHandler)                      {}
func (*fakeTicker) OnConnect(func())                               {}
func (*fakeTicker) OnError(func(error))                            {}
func (*fakeTicker) OnClose(func(int, string))                      {}
func (*fakeTicker) OnReconnect(func(int, time.Duration))           {}
func (*fakeTicker) OnNoReconnect(func(int))                        {}
func (*fakeTicker) Close() error                                   { return nil }
