package zerodha

// ticker_adapter_test.go — pins the Zerodha ticker adapter's
// behavior at the public broker/ticker.Ticker boundary. We mock the
// underlying kiteticker subscriber so tests never touch a live
// websocket; the contract being verified here is purely the
// adapter's translation layer.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/gokiteconnect/v4/models"

	brokerticker "github.com/zerodha/kite-mcp-server/broker/ticker"
)

// newTickerAdapterFromFake is a test helper that builds a
// TickerAdapter around a fake kiteticker subscriber. The fake
// satisfies the package-internal kiteSubscriber + kiteCallbackRegistrar +
// kiteTickRegistrar interfaces; the helper passes it three times
// because in production *kiteticker.Ticker is the same value for
// all three roles. serveFn is a no-op (tests don't drive a real
// transport).
func newTickerAdapterFromFake(fake *fakeKiteSubscriber) *TickerAdapter {
	return newTickerAdapter(
		fake, fake, fake,
		func(context.Context) {},
		func() error { return nil },
	)
}

// OnConnect / OnError / OnClose / OnReconnect / OnNoReconnect on
// fakeKiteSubscriber capture the registered handler so tests can
// fire them directly. The OnTick method is similar but wraps the
// handler to translate through fakeTick → models.Tick before
// invoking the adapter's hook.
func (f *fakeKiteSubscriber) OnConnect(h func())      { f.onConnect = h }
func (f *fakeKiteSubscriber) OnError(h func(error))   { f.onError = h }
func (f *fakeKiteSubscriber) OnClose(h func(int, string)) {
	f.onClose = h
}
func (f *fakeKiteSubscriber) OnReconnect(h func(int, time.Duration)) {
	f.onReconnect = h
}
func (f *fakeKiteSubscriber) OnNoReconnect(h func(int)) {
	f.onNoReconnect = h
}

// OnTick on fakeKiteSubscriber accepts the kiteticker-shape callback
// (func(models.Tick)) installed by the adapter at construction
// time, then exposes a fakeTick → models.Tick wrapper as
// f.onTickRaw so tests can fire the chain via fake.onTickRaw(...).
func (f *fakeKiteSubscriber) OnTick(h func(tick models.Tick)) {
	f.onTickRaw = func(ft fakeTick) {
		h(models.Tick{
			InstrumentToken:    ft.InstrumentToken,
			LastPrice:          ft.LastPrice,
			LastTradedQuantity: ft.LastTradedQuantity,
			AverageTradePrice:  ft.AverageTradePrice,
			VolumeTraded:       ft.VolumeTraded,
			TotalBuyQuantity:   ft.TotalBuyQuantity,
			TotalSellQuantity:  ft.TotalSellQuantity,
			NetChange:          ft.NetChange,
			Mode:               ft.Mode,
			OHLC: models.OHLC{
				Open:  ft.OHLCOpen,
				High:  ft.OHLCHigh,
				Low:   ft.OHLCLow,
				Close: ft.OHLCClose,
			},
		})
	}
}

// fakeKiteSubscriber implements the narrow surface NewTickerAdapter
// uses for Subscribe / Unsubscribe / SetMode + the On* registration
// methods. Real production use injects *kiteticker.Ticker; tests
// inject this fake.
type fakeKiteSubscriber struct {
	subscribeTokens   []uint32
	subscribeErr      error
	unsubscribeTokens []uint32
	unsubscribeErr    error
	setModeTokens     []uint32
	setModeMode       string // captured raw mode string (kiteticker uses string-typed Mode)
	setModeErr        error

	// On* hooks captured by the adapter's wireCallbacks call.
	onConnect     func()
	onTickRaw     func(tick fakeTick)
	onError       func(error)
	onClose       func(int, string)
	onReconnect   func(int, time.Duration)
	onNoReconnect func(int)
}

// fakeTick mirrors models.Tick fields the adapter reads. Tests
// construct one and invoke onTickRaw to drive the adapter's
// translation path.
type fakeTick struct {
	InstrumentToken    uint32
	LastPrice          float64
	LastTradedQuantity uint32
	AverageTradePrice  float64
	VolumeTraded       uint32
	TotalBuyQuantity   uint32
	TotalSellQuantity  uint32
	NetChange          float64
	Mode               string
	OHLCOpen           float64
	OHLCHigh           float64
	OHLCLow            float64
	OHLCClose          float64
}

func (f *fakeKiteSubscriber) Subscribe(tokens []uint32) error {
	f.subscribeTokens = tokens
	return f.subscribeErr
}
func (f *fakeKiteSubscriber) Unsubscribe(tokens []uint32) error {
	f.unsubscribeTokens = tokens
	return f.unsubscribeErr
}
func (f *fakeKiteSubscriber) SetMode(mode string, tokens []uint32) error {
	f.setModeMode = mode
	f.setModeTokens = tokens
	return f.setModeErr
}

// TestTickerAdapter_Subscribe_HappyPath: Subscribe forwards tokens
// to the underlying kiteticker subscriber and returns its error
// transparently.
func TestTickerAdapter_Subscribe_HappyPath(t *testing.T) {
	t.Parallel()
	fake := &fakeKiteSubscriber{}
	adapter := newTickerAdapterFromFake(fake)

	err := adapter.Subscribe([]uint32{408065, 779521})
	require.NoError(t, err)
	assert.Equal(t, []uint32{408065, 779521}, fake.subscribeTokens)
}

// TestTickerAdapter_Subscribe_ErrorPath: Subscribe propagates errors
// from the underlying subscriber unchanged. Adapter must NOT swallow
// errors — kc/ticker/service.go's resubscribe-on-reconnect logic
// depends on knowing when the underlying call failed.
func TestTickerAdapter_Subscribe_ErrorPath(t *testing.T) {
	t.Parallel()
	want := errors.New("ws write failed")
	fake := &fakeKiteSubscriber{subscribeErr: want}
	adapter := newTickerAdapterFromFake(fake)

	err := adapter.Subscribe([]uint32{1})
	require.ErrorIs(t, err, want)
}

// TestTickerAdapter_Unsubscribe_HappyPath: Unsubscribe forwards
// tokens unchanged.
func TestTickerAdapter_Unsubscribe_HappyPath(t *testing.T) {
	t.Parallel()
	fake := &fakeKiteSubscriber{}
	adapter := newTickerAdapterFromFake(fake)

	err := adapter.Unsubscribe([]uint32{408065})
	require.NoError(t, err)
	assert.Equal(t, []uint32{408065}, fake.unsubscribeTokens)
}

// TestTickerAdapter_SetMode_TranslatesMode: SetMode translates
// broker/ticker.Mode (typed string "ltp"/"quote"/"full") to the
// kiteticker.Mode form. The translation is identity at the byte
// level (kiteticker.ModeLTP == "ltp"), but the adapter must still
// pass through correctly per Mode value.
func TestTickerAdapter_SetMode_TranslatesMode(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		mode    brokerticker.Mode
		wantRaw string
	}{
		{"ltp", brokerticker.ModeLTP, "ltp"},
		{"quote", brokerticker.ModeQuote, "quote"},
		{"full", brokerticker.ModeFull, "full"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			fake := &fakeKiteSubscriber{}
			adapter := newTickerAdapterFromFake(fake)
			err := adapter.SetMode(tc.mode, []uint32{42})
			require.NoError(t, err)
			assert.Equal(t, tc.wantRaw, fake.setModeMode)
			assert.Equal(t, []uint32{42}, fake.setModeTokens)
		})
	}
}

// TestTickerAdapter_SetMode_ErrorPath: SetMode propagates underlying
// errors unchanged.
func TestTickerAdapter_SetMode_ErrorPath(t *testing.T) {
	t.Parallel()
	want := errors.New("ws write fail")
	fake := &fakeKiteSubscriber{setModeErr: want}
	adapter := newTickerAdapterFromFake(fake)
	err := adapter.SetMode(brokerticker.ModeLTP, []uint32{1})
	require.ErrorIs(t, err, want)
}

// TestTickerAdapter_OnTick_TranslatesTick: when the underlying
// kiteticker fires a tick callback with a models.Tick-shaped
// payload, the adapter translates to broker/ticker.Tick and
// dispatches to the registered TickHandler. This is the headline
// translation contract.
func TestTickerAdapter_OnTick_TranslatesTick(t *testing.T) {
	t.Parallel()
	fake := &fakeKiteSubscriber{}
	adapter := newTickerAdapterFromFake(fake)

	var got brokerticker.Tick
	var calls int
	adapter.OnTick(func(tk brokerticker.Tick) {
		calls++
		got = tk
	})

	// Adapter installs the underlying kiteticker.OnTick handler
	// during construction. The fake captures it and lets the test
	// fire it directly.
	require.NotNil(t, fake.onTickRaw, "adapter must register OnTick on kiteticker")
	fake.onTickRaw(fakeTick{
		InstrumentToken:    408065,
		LastPrice:          1500.50,
		LastTradedQuantity: 100,
		AverageTradePrice:  1499.75,
		VolumeTraded:       1_000_000,
		TotalBuyQuantity:   500,
		TotalSellQuantity:  750,
		NetChange:          0.37,
		Mode:               "full",
		OHLCOpen:           1490.0,
		OHLCHigh:           1510.0,
		OHLCLow:            1485.0,
		OHLCClose:          1495.0,
	})

	assert.Equal(t, 1, calls)
	assert.Equal(t, uint32(408065), got.InstrumentToken)
	assert.InDelta(t, 1500.50, got.LastPrice, 0.001)
	assert.Equal(t, uint32(100), got.LastQuantity)
	assert.InDelta(t, 1499.75, got.AverageTradePrice, 0.001)
	assert.Equal(t, uint32(1_000_000), got.Volume)
	assert.Equal(t, uint32(500), got.BuyQuantity)
	assert.Equal(t, uint32(750), got.SellQuantity)
	assert.InDelta(t, 1490.0, got.OHLC.Open, 0.001)
	assert.InDelta(t, 1510.0, got.OHLC.High, 0.001)
	assert.InDelta(t, 1485.0, got.OHLC.Low, 0.001)
	assert.InDelta(t, 1495.0, got.OHLC.Close, 0.001)
	assert.InDelta(t, 0.37, got.ChangePercent, 0.001)
	assert.Equal(t, brokerticker.ModeFull, got.Mode)
}

// TestTickerAdapter_LifecycleHandlers_Forwarded: OnConnect / OnError
// / OnClose / OnReconnect / OnNoReconnect each register a callback
// on the underlying kiteticker, and firing the fake's stored hook
// invokes the adapter consumer's handler.
func TestTickerAdapter_LifecycleHandlers_Forwarded(t *testing.T) {
	t.Parallel()
	fake := &fakeKiteSubscriber{}
	adapter := newTickerAdapterFromFake(fake)

	var connectCalls int
	adapter.OnConnect(func() { connectCalls++ })
	require.NotNil(t, fake.onConnect)
	fake.onConnect()
	assert.Equal(t, 1, connectCalls)

	var lastErr error
	adapter.OnError(func(e error) { lastErr = e })
	require.NotNil(t, fake.onError)
	fake.onError(errors.New("boom"))
	assert.EqualError(t, lastErr, "boom")

	var closeCode int
	var closeReason string
	adapter.OnClose(func(c int, r string) { closeCode = c; closeReason = r })
	require.NotNil(t, fake.onClose)
	fake.onClose(1006, "abnormal closure")
	assert.Equal(t, 1006, closeCode)
	assert.Equal(t, "abnormal closure", closeReason)

	var reconnectAttempt int
	var reconnectDelay time.Duration
	adapter.OnReconnect(func(a int, d time.Duration) { reconnectAttempt = a; reconnectDelay = d })
	require.NotNil(t, fake.onReconnect)
	fake.onReconnect(3, 800*time.Millisecond)
	assert.Equal(t, 3, reconnectAttempt)
	assert.Equal(t, 800*time.Millisecond, reconnectDelay)

	var noReconnectAttempt int
	adapter.OnNoReconnect(func(a int) { noReconnectAttempt = a })
	require.NotNil(t, fake.onNoReconnect)
	fake.onNoReconnect(300)
	assert.Equal(t, 300, noReconnectAttempt)
}

// TestTickerAdapter_SatisfiesPort: compile-time + runtime
// confirmation that the adapter satisfies broker/ticker.Ticker.
func TestTickerAdapter_SatisfiesPort(t *testing.T) {
	t.Parallel()
	fake := &fakeKiteSubscriber{}
	adapter := newTickerAdapterFromFake(fake)
	var _ brokerticker.Ticker = adapter
	assert.NotNil(t, adapter)
}
