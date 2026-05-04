package zerodha

// ticker_adapter.go — wraps Zerodha's kiteticker websocket client to
// satisfy the broker-agnostic broker/ticker.Ticker port (commit
// eacaf2d). kc/ticker/service.go (after commit 3) depends on the
// port interface, NOT on this adapter's concrete type — when an
// Upstox / Dhan / Angel One ticker adapter ships, the only change in
// kc/ticker is a different factory call.
//
// Translation contract:
//   - kiteticker.Mode (typed string "ltp"/"quote"/"full") IS
//     byte-identical to broker/ticker.Mode, so SetMode is a trivial
//     pass-through cast.
//   - models.Tick → broker/ticker.Tick: field-rename mapping
//     (LastTradedQuantity→LastQuantity, VolumeTraded→Volume,
//     TotalBuyQuantity→BuyQuantity, etc.) plus NetChange→ChangePercent
//     plus OHLC nested struct extraction. NO information is dropped
//     except OI/OIDayHigh/OIDayLow (not in the broker-agnostic Tick
//     today; can be added if a non-Zerodha adapter needs them).
//   - Lifecycle callbacks (OnConnect / OnError / OnClose /
//     OnReconnect / OnNoReconnect) are pass-through; signatures
//     match.
//
// Production use: NewTickerAdapter(apiKey, accessToken) returns a
// *TickerAdapter ready for handler registration. Caller must
// register handlers BEFORE the underlying transport starts —
// matches existing kc/ticker/service.go contract.
//
// Test use: newTickerAdapterFromFake(fake) constructs the adapter
// around an in-process fake subscriber (no websocket). Used by
// ticker_adapter_test.go to verify translation without a live
// connection.

import (
	"context"
	"time"

	kiteticker "github.com/zerodha/gokiteconnect/v4/ticker"
	"github.com/zerodha/gokiteconnect/v4/models"

	brokerticker "github.com/zerodha/kite-mcp-server/broker/ticker"
)

// kiteSubscriber is the narrow surface of *kiteticker.Ticker the
// adapter uses for subscription mutation. The real *kiteticker.Ticker
// satisfies this implicitly via duck typing — but we don't reference
// kiteticker.Mode in the interface signature so tests can inject a
// fake without importing the kiteticker package.
type kiteSubscriber interface {
	Subscribe(tokens []uint32) error
	Unsubscribe(tokens []uint32) error
	SetMode(mode string, tokens []uint32) error
}

// kiteCallbackRegistrar is the narrow surface for registering
// websocket lifecycle callbacks on a kiteticker.Ticker. Real
// *kiteticker.Ticker satisfies this; tests inject a fake that
// captures the registered handlers for direct invocation.
type kiteCallbackRegistrar interface {
	OnConnect(f func())
	OnError(f func(err error))
	OnClose(f func(code int, reason string))
	OnReconnect(f func(attempt int, delay time.Duration))
	OnNoReconnect(f func(attempt int))
}

// kiteTickRegistrar is the OnTick registration. Separate from
// kiteCallbackRegistrar because the tick-handler signature varies
// across test fakes (real kiteticker uses func(models.Tick); tests
// use a parameterized fake-tick to avoid pulling in models).
type kiteTickRegistrar interface {
	OnTick(f func(tick models.Tick))
}

// TickerAdapter wraps a kiteticker subscriber to satisfy
// broker/ticker.Ticker. Construct via NewTickerAdapter for
// production; tests use newTickerAdapterFromFake.
//
// All exported methods are safe to call concurrently; lock
// discipline is delegated to the underlying *kiteticker.Ticker
// (which is internally locked) and the user-registered callbacks
// (which the adapter does not synchronize beyond write-once
// registration).
type TickerAdapter struct {
	sub kiteSubscriber
	cb  kiteCallbackRegistrar

	// serveFn is invoked by Serve. For real production
	// (*kiteticker.Ticker) it calls ServeWithContext on the
	// underlying ticker, blocking until ctx cancellation. Tests
	// inject a no-op or capturing fake.
	serveFn func(ctx context.Context)

	// closeFn is invoked by Close. For real production
	// (*kiteticker.Ticker) the underlying client doesn't expose
	// an explicit Close — Stop is via context cancellation in
	// the consumer (kc/ticker/service.go). We capture the
	// no-op behaviour here; tests can substitute a tracker.
	closeFn func() error

	// userTickHandler is the broker/ticker.TickHandler registered
	// by the consumer via OnTick. Adapter wraps it in a
	// kiteticker-shape callback (func(models.Tick)) and registers
	// that with the underlying subscriber during construction.
	// nil until OnTick is called; the wrapper checks nil before
	// dispatch so an unregistered handler is a no-op rather than a
	// panic.
	userTickHandler brokerticker.TickHandler
}

// NewTickerAdapter constructs a Zerodha ticker adapter wrapping a
// fresh *kiteticker.Ticker for the given Kite credentials. The
// underlying transport is NOT started by this constructor —
// consumers (kc/ticker/service.go) call ServeWithContext on the
// underlying ticker via type assertion, OR replace the
// orchestration with broker/ticker.Ticker-only methods.
//
// During the migration period (before kc/ticker swaps to use the
// port), production code paths constructing a *kiteticker.Ticker
// directly continue to work — the adapter is purely additive.
func NewTickerAdapter(apiKey, accessToken string) *TickerAdapter {
	t := kiteticker.New(apiKey, accessToken)
	t.SetAutoReconnect(true)
	t.SetReconnectMaxRetries(300)
	// Wrap the *kiteticker.Ticker in a tiny shim that adapts its
	// SetMode(kiteticker.Mode, ...) signature to the package-internal
	// kiteSubscriber interface's SetMode(string, ...). Tests inject a
	// fakeKiteSubscriber directly — the shim is production-only.
	shim := &kiteSubscriberShim{t: t}
	return newTickerAdapter(
		shim, t, t,
		func(ctx context.Context) { t.ServeWithContext(ctx) },
		func() error {
			// kiteticker has no Close; consumer drives lifecycle via
			// context cancellation. Return nil so Close stays idempotent.
			return nil
		},
	)
}

// kiteSubscriberShim adapts *kiteticker.Ticker's typed-Mode SetMode
// signature to the kiteSubscriber interface (which uses raw string
// to avoid leaking kiteticker.Mode into the test fake's type
// signature). Subscribe / Unsubscribe pass through unchanged.
type kiteSubscriberShim struct{ t *kiteticker.Ticker }

func (s *kiteSubscriberShim) Subscribe(tokens []uint32) error {
	return s.t.Subscribe(tokens)
}
func (s *kiteSubscriberShim) Unsubscribe(tokens []uint32) error {
	return s.t.Unsubscribe(tokens)
}
func (s *kiteSubscriberShim) SetMode(mode string, tokens []uint32) error {
	return s.t.SetMode(kiteticker.Mode(mode), tokens)
}

// newTickerAdapter is the package-internal constructor accepting
// every collaborator separately so tests can inject fakes per
// surface (subscriber / callback registrar / tick registrar).
// Production callers use NewTickerAdapter which wires all three to
// the same *kiteticker.Ticker.
func newTickerAdapter(
	sub kiteSubscriber,
	cb kiteCallbackRegistrar,
	tickReg kiteTickRegistrar,
	serveFn func(ctx context.Context),
	closeFn func() error,
) *TickerAdapter {
	a := &TickerAdapter{
		sub:     sub,
		serveFn: serveFn,
		closeFn: closeFn,
	}
	// Register a single OnTick hook on the underlying subscriber
	// during construction. The hook checks a.userTickHandler at
	// invocation time so consumers can register/replace handlers
	// after construction without re-wiring the underlying.
	tickReg.OnTick(func(raw models.Tick) {
		h := a.userTickHandler
		if h == nil {
			return
		}
		h(translateTick(raw))
	})
	// cb is captured for lifecycle pass-through; we don't pre-register
	// here because the consumer hasn't supplied handlers yet. The
	// adapter's OnConnect / OnError / etc. methods register against
	// cb on demand.
	a.cb = cb
	return a
}

// translateTick converts a Zerodha-side models.Tick to the
// broker-agnostic broker/ticker.Tick. Field renames are documented
// inline; missing values default to zero (broker/ticker.Tick fields
// are nullable-by-zero per the port contract).
func translateTick(raw models.Tick) brokerticker.Tick {
	return brokerticker.Tick{
		InstrumentToken:   raw.InstrumentToken,
		LastPrice:         raw.LastPrice,
		LastQuantity:      raw.LastTradedQuantity,
		AverageTradePrice: raw.AverageTradePrice,
		Volume:            raw.VolumeTraded,
		BuyQuantity:       raw.TotalBuyQuantity,
		SellQuantity:      raw.TotalSellQuantity,
		OHLC: brokerticker.TickOHLC{
			Open:  raw.OHLC.Open,
			High:  raw.OHLC.High,
			Low:   raw.OHLC.Low,
			Close: raw.OHLC.Close,
		},
		ChangePercent: raw.NetChange,
		Mode:          brokerticker.Mode(raw.Mode),
		Timestamp:     raw.Timestamp.Time,
	}
}

// Subscribe implements broker/ticker.Ticker.Subscribe.
func (a *TickerAdapter) Subscribe(tokens []uint32) error {
	return a.sub.Subscribe(tokens)
}

// Unsubscribe implements broker/ticker.Ticker.Unsubscribe.
func (a *TickerAdapter) Unsubscribe(tokens []uint32) error {
	return a.sub.Unsubscribe(tokens)
}

// SetMode implements broker/ticker.Ticker.SetMode. The Mode is a
// typed string with byte-identical values to kiteticker.Mode, so
// the cast is identity at runtime.
func (a *TickerAdapter) SetMode(mode brokerticker.Mode, tokens []uint32) error {
	return a.sub.SetMode(string(mode), tokens)
}

// OnTick implements broker/ticker.Ticker.OnTick. Stores the user
// handler on the adapter; the kiteticker-side hook installed at
// construction time dispatches to it on every incoming tick.
func (a *TickerAdapter) OnTick(handler brokerticker.TickHandler) {
	a.userTickHandler = handler
}

// OnConnect implements broker/ticker.Ticker.OnConnect.
func (a *TickerAdapter) OnConnect(handler func()) {
	a.cb.OnConnect(handler)
}

// OnError implements broker/ticker.Ticker.OnError.
func (a *TickerAdapter) OnError(handler func(error)) {
	a.cb.OnError(handler)
}

// OnClose implements broker/ticker.Ticker.OnClose.
func (a *TickerAdapter) OnClose(handler func(code int, reason string)) {
	a.cb.OnClose(handler)
}

// OnReconnect implements broker/ticker.Ticker.OnReconnect.
func (a *TickerAdapter) OnReconnect(handler func(attempt int, delay time.Duration)) {
	a.cb.OnReconnect(handler)
}

// OnNoReconnect implements broker/ticker.Ticker.OnNoReconnect.
func (a *TickerAdapter) OnNoReconnect(handler func(attempt int)) {
	a.cb.OnNoReconnect(handler)
}

// Serve implements broker/ticker.Ticker.Serve. Delegates to the
// underlying *kiteticker.Ticker's ServeWithContext, which blocks
// the calling goroutine until ctx is cancelled or the transport
// gives up reconnecting. Tests inject a fake server (via
// newTickerAdapter's serveFn) that returns immediately.
func (a *TickerAdapter) Serve(ctx context.Context) {
	if a.serveFn == nil {
		return
	}
	a.serveFn(ctx)
}

// Close implements broker/ticker.Ticker.Close. For Zerodha's
// kiteticker, the underlying transport is owned by the consumer's
// Serve goroutine; Close here is a no-op by default (returns nil).
// Future adapters with explicit close semantics can substitute a
// non-nil closeFn.
func (a *TickerAdapter) Close() error {
	if a.closeFn == nil {
		return nil
	}
	return a.closeFn()
}
