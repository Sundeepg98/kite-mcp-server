package ticker

import (
	"bytes"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteticker "github.com/zerodha/gokiteconnect/v4/ticker"
	"github.com/zerodha/gokiteconnect/v4/models"
)

// --- mockCallbackRegistrar captures closures registered by wireCallbacks ---

type mockCallbackRegistrar struct {
	mu            sync.Mutex
	onConnect     func()
	onTick        func(models.Tick)
	onError       func(error)
	onClose       func(int, string)
	onReconnect   func(int, time.Duration)
	onNoReconnect func(int)
}

func (m *mockCallbackRegistrar) OnConnect(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onConnect = f
}

func (m *mockCallbackRegistrar) OnTick(f func(models.Tick)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onTick = f
}

func (m *mockCallbackRegistrar) OnError(f func(error)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onError = f
}

func (m *mockCallbackRegistrar) OnClose(f func(int, string)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onClose = f
}

func (m *mockCallbackRegistrar) OnReconnect(f func(int, time.Duration)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onReconnect = f
}

func (m *mockCallbackRegistrar) OnNoReconnect(f func(int)) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onNoReconnect = f
}

// --- mockTickerConn implements tickerConn for Subscribe/Unsubscribe/SetMode ---

type mockTickerConn struct {
	mu             sync.Mutex
	subscribeCalls [][]uint32
	unsubCalls     [][]uint32
	modeCalls      []struct {
		mode   kiteticker.Mode
		tokens []uint32
	}
	subscribeErr error
	unsubErr     error
	setModeErr   error
}

func (m *mockTickerConn) Subscribe(tokens []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uint32, len(tokens))
	copy(cp, tokens)
	m.subscribeCalls = append(m.subscribeCalls, cp)
	return m.subscribeErr
}

func (m *mockTickerConn) Unsubscribe(tokens []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uint32, len(tokens))
	copy(cp, tokens)
	m.unsubCalls = append(m.unsubCalls, cp)
	return m.unsubErr
}

func (m *mockTickerConn) SetMode(mode kiteticker.Mode, tokens []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uint32, len(tokens))
	copy(cp, tokens)
	m.modeCalls = append(m.modeCalls, struct {
		mode   kiteticker.Mode
		tokens []uint32
	}{mode: mode, tokens: cp})
	return m.setModeErr
}

// newTestUserTickerWithMockConn creates a UserTicker backed by a mockTickerConn
// instead of a real kiteticker.Ticker, allowing connected-path testing.
func newTestUserTickerWithMockConn(email string, subs map[uint32]kiteticker.Mode, conn *mockTickerConn) *UserTicker {
	t := kiteticker.New("key", "tok")
	return &UserTicker{
		Email:       email,
		APIKey:      "key",
		AccessToken: "tok",
		Ticker:      t,
		conn:        conn,
		Cancel:      func() {},
		StartedAt:   time.Now(),
		Subscribed:  subs,
	}
}

func newEdgeTestService(onTick TickCallback) (*Service, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := New(Config{Logger: logger, OnTick: onTick})
	return svc, &buf
}

// ==========================================================================
// wireCallbacks closure body tests via mockCallbackRegistrar
// ==========================================================================

// TestWireCallbacksClosure_OnConnect invokes the closure registered by
// wireCallbacks and verifies it delegates to onConnect correctly.
func TestWireCallbacksClosure_OnConnect(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP}
	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("closure-connect@test.com", subs, mockConn)

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	// Invoke the captured closure
	reg.mu.Lock()
	fn := reg.onConnect
	reg.mu.Unlock()
	require.NotNil(t, fn, "OnConnect closure should be registered")

	fn()

	ut.mu.RLock()
	assert.True(t, ut.Connected, "closure should set Connected via onConnect")
	ut.mu.RUnlock()

	// Verify resubscription happened through the mock conn
	mockConn.mu.Lock()
	assert.Len(t, mockConn.subscribeCalls, 1)
	assert.Len(t, mockConn.modeCalls, 1)
	mockConn.mu.Unlock()
}

// TestWireCallbacksClosure_OnTick invokes the registered OnTick closure.
func TestWireCallbacksClosure_OnTick(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var gotEmail string
	var gotTick models.Tick

	svc, _ := newEdgeTestService(func(email string, tick models.Tick) {
		mu.Lock()
		gotEmail = email
		gotTick = tick
		mu.Unlock()
	})

	ut := newTestUserTickerWithMockConn("closure-tick@test.com", nil, &mockTickerConn{})

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onTick
	reg.mu.Unlock()
	require.NotNil(t, fn)

	tick := models.Tick{InstrumentToken: 999, LastPrice: 42.0}
	fn(tick)

	mu.Lock()
	assert.Equal(t, "closure-tick@test.com", gotEmail)
	assert.Equal(t, uint32(999), gotTick.InstrumentToken)
	assert.InDelta(t, 42.0, gotTick.LastPrice, 0.01)
	mu.Unlock()
}

// TestWireCallbacksClosure_OnError invokes the registered OnError closure.
func TestWireCallbacksClosure_OnError(t *testing.T) {
	t.Parallel()
	svc, buf := newEdgeTestService(nil)

	ut := newTestUserTickerWithMockConn("closure-error@test.com", nil, &mockTickerConn{})

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onError
	reg.mu.Unlock()
	require.NotNil(t, fn)

	fn(errors.New("test ws error"))

	assert.Contains(t, buf.String(), "Ticker error")
	assert.Contains(t, buf.String(), "test ws error")
}

// TestWireCallbacksClosure_OnClose invokes the registered OnClose closure.
func TestWireCallbacksClosure_OnClose(t *testing.T) {
	t.Parallel()
	svc, buf := newEdgeTestService(nil)

	ut := newTestUserTickerWithMockConn("closure-close@test.com", nil, &mockTickerConn{})
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onClose
	reg.mu.Unlock()
	require.NotNil(t, fn)

	fn(1006, "abnormal closure")

	ut.mu.RLock()
	assert.False(t, ut.Connected)
	ut.mu.RUnlock()
	assert.Contains(t, buf.String(), "Ticker closed")
}

// TestWireCallbacksClosure_OnReconnect invokes the registered OnReconnect closure.
func TestWireCallbacksClosure_OnReconnect(t *testing.T) {
	t.Parallel()
	svc, buf := newEdgeTestService(nil)

	ut := newTestUserTickerWithMockConn("closure-recon@test.com", nil, &mockTickerConn{})

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onReconnect
	reg.mu.Unlock()
	require.NotNil(t, fn)

	fn(5, 3*time.Second)

	assert.Contains(t, buf.String(), "Ticker reconnecting")
	assert.Contains(t, buf.String(), "closure-recon@test.com")
}

// TestWireCallbacksClosure_OnNoReconnect invokes the registered OnNoReconnect closure.
func TestWireCallbacksClosure_OnNoReconnect(t *testing.T) {
	t.Parallel()
	svc, buf := newEdgeTestService(nil)

	ut := newTestUserTickerWithMockConn("closure-norecon@test.com", nil, &mockTickerConn{})
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onNoReconnect
	reg.mu.Unlock()
	require.NotNil(t, fn)

	fn(300)

	ut.mu.RLock()
	assert.False(t, ut.Connected)
	ut.mu.RUnlock()
	assert.Contains(t, buf.String(), "Ticker gave up reconnecting")
}

// ==========================================================================
// Subscribe/Unsubscribe connected-path tests via mockTickerConn
// ==========================================================================

// TestSubscribe_Connected_Success exercises the connected path of Subscribe
// where ut.conn.Subscribe and ut.conn.SetMode are called.
func TestSubscribe_Connected_Success(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("sub-conn@test.com", make(map[uint32]kiteticker.Mode), mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Subscribe(ut.Email, []uint32{256265, 260105}, ModeFull)
	require.NoError(t, err)

	// Verify subscription stored
	ut.mu.RLock()
	assert.Equal(t, ModeFull, ut.Subscribed[256265])
	assert.Equal(t, ModeFull, ut.Subscribed[260105])
	ut.mu.RUnlock()

	// Verify conn.Subscribe was called
	mockConn.mu.Lock()
	require.Len(t, mockConn.subscribeCalls, 1)
	assert.ElementsMatch(t, []uint32{256265, 260105}, mockConn.subscribeCalls[0])
	// Verify conn.SetMode was called
	require.Len(t, mockConn.modeCalls, 1)
	assert.Equal(t, ModeFull, mockConn.modeCalls[0].mode)
	assert.ElementsMatch(t, []uint32{256265, 260105}, mockConn.modeCalls[0].tokens)
	mockConn.mu.Unlock()
}

// TestSubscribe_Connected_SubscribeError exercises the error path when
// ut.conn.Subscribe fails on a connected ticker.
func TestSubscribe_Connected_SubscribeError(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	mockConn := &mockTickerConn{subscribeErr: errors.New("ws write fail")}
	ut := newTestUserTickerWithMockConn("sub-conn-err@test.com", make(map[uint32]kiteticker.Mode), mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Subscribe(ut.Email, []uint32{256265}, ModeLTP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "subscribe failed")
	assert.Contains(t, err.Error(), "ws write fail")

	// Subscriptions should still be stored even though ws subscribe failed
	ut.mu.RLock()
	_, ok := ut.Subscribed[256265]
	ut.mu.RUnlock()
	assert.True(t, ok, "subscription should be stored even on ws error")
}

// TestSubscribe_Connected_SetModeError exercises the error path when
// ut.conn.SetMode fails (but Subscribe succeeded).
func TestSubscribe_Connected_SetModeError(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	mockConn := &mockTickerConn{setModeErr: errors.New("mode write fail")}
	ut := newTestUserTickerWithMockConn("sub-mode-err@test.com", make(map[uint32]kiteticker.Mode), mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Subscribe(ut.Email, []uint32{256265}, ModeQuote)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set mode failed")
	assert.Contains(t, err.Error(), "mode write fail")

	// Subscribe should have been called before SetMode failed
	mockConn.mu.Lock()
	assert.Len(t, mockConn.subscribeCalls, 1)
	mockConn.mu.Unlock()
}

// TestUnsubscribe_Connected_Success exercises the connected path of Unsubscribe
// where ut.conn.Unsubscribe is called.
func TestUnsubscribe_Connected_Success(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP, 260105: ModeQuote}
	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("unsub-conn@test.com", subs, mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Unsubscribe(ut.Email, []uint32{256265})
	require.NoError(t, err)

	// Verify subscription removed
	ut.mu.RLock()
	_, has256 := ut.Subscribed[256265]
	_, has260 := ut.Subscribed[260105]
	ut.mu.RUnlock()
	assert.False(t, has256)
	assert.True(t, has260)

	// Verify conn.Unsubscribe was called
	mockConn.mu.Lock()
	require.Len(t, mockConn.unsubCalls, 1)
	assert.Equal(t, []uint32{256265}, mockConn.unsubCalls[0])
	mockConn.mu.Unlock()
}

// TestUnsubscribe_Connected_Error exercises the error path when
// ut.conn.Unsubscribe fails on a connected ticker.
func TestUnsubscribe_Connected_Error(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP}
	mockConn := &mockTickerConn{unsubErr: errors.New("unsub write fail")}
	ut := newTestUserTickerWithMockConn("unsub-conn-err@test.com", subs, mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Unsubscribe(ut.Email, []uint32{256265})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unsubscribe failed")
	assert.Contains(t, err.Error(), "unsub write fail")

	// Subscription should still have been removed from the map
	ut.mu.RLock()
	_, has := ut.Subscribed[256265]
	ut.mu.RUnlock()
	assert.False(t, has, "subscription should be removed even on ws error")
}

// ==========================================================================
// Interface compliance checks
// ==========================================================================

func TestCallbackRegistrar_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	// Verify *kiteticker.Ticker satisfies callbackRegistrar
	var _ callbackRegistrar = kiteticker.New("k", "t")
	// Verify mock satisfies it too
	var _ callbackRegistrar = &mockCallbackRegistrar{}
}

func TestTickerConn_InterfaceCompliance(t *testing.T) {
	t.Parallel()
	// Verify *kiteticker.Ticker satisfies tickerConn
	var _ tickerConn = kiteticker.New("k", "t")
	// Verify mock satisfies it too
	var _ tickerConn = &mockTickerConn{}
}

// ==========================================================================
// Additional edge cases for full coverage
// ==========================================================================

// TestWireCallbacksClosure_OnTick_NilCallback ensures the closure doesn't
// panic when no OnTick callback is configured.
func TestWireCallbacksClosure_OnTick_NilCallback(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil) // no OnTick

	ut := newTestUserTickerWithMockConn("nil-tick@test.com", nil, &mockTickerConn{})

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onTick
	reg.mu.Unlock()
	require.NotNil(t, fn)

	// Should not panic
	assert.NotPanics(t, func() {
		fn(models.Tick{InstrumentToken: 1})
	})
}

// TestWireCallbacksClosure_OnConnect_NoSubs verifies the OnConnect closure
// works correctly when there are no subscriptions to restore.
func TestWireCallbacksClosure_OnConnect_NoSubs(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("no-subs@test.com", make(map[uint32]kiteticker.Mode), mockConn)

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onConnect
	reg.mu.Unlock()

	fn()

	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()

	mockConn.mu.Lock()
	assert.Empty(t, mockConn.subscribeCalls, "no subscribe calls when no subs")
	assert.Empty(t, mockConn.modeCalls, "no setMode calls when no subs")
	mockConn.mu.Unlock()
}

// TestSubscribe_Connected_MultipleTokensMultipleModes exercises subscribing
// different batches of tokens with different modes on a connected ticker.
func TestSubscribe_Connected_MultipleTokensMultipleModes(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("multi-mode@test.com", make(map[uint32]kiteticker.Mode), mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	// Subscribe first batch as LTP
	err := svc.Subscribe(ut.Email, []uint32{100, 200}, ModeLTP)
	require.NoError(t, err)

	// Subscribe second batch as Full
	err = svc.Subscribe(ut.Email, []uint32{300}, ModeFull)
	require.NoError(t, err)

	mockConn.mu.Lock()
	assert.Len(t, mockConn.subscribeCalls, 2)
	assert.Len(t, mockConn.modeCalls, 2)
	assert.Equal(t, ModeLTP, mockConn.modeCalls[0].mode)
	assert.Equal(t, ModeFull, mockConn.modeCalls[1].mode)
	mockConn.mu.Unlock()
}

// TestUnsubscribe_Connected_MultipleTokens exercises unsubscribing multiple
// tokens at once on a connected ticker.
func TestUnsubscribe_Connected_MultipleTokens(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{100: ModeLTP, 200: ModeQuote, 300: ModeFull}
	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("multi-unsub@test.com", subs, mockConn)
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.mu.Lock()
	svc.tickers[ut.Email] = ut
	svc.mu.Unlock()
	defer svc.Shutdown()

	err := svc.Unsubscribe(ut.Email, []uint32{100, 300})
	require.NoError(t, err)

	ut.mu.RLock()
	assert.Len(t, ut.Subscribed, 1)
	_, has200 := ut.Subscribed[200]
	ut.mu.RUnlock()
	assert.True(t, has200)

	mockConn.mu.Lock()
	require.Len(t, mockConn.unsubCalls, 1)
	assert.ElementsMatch(t, []uint32{100, 300}, mockConn.unsubCalls[0])
	mockConn.mu.Unlock()
}

// TestWireCallbacksClosure_OnConnect_WithSubscribeError verifies the closure
// handles subscribe errors gracefully (logs but doesn't panic).
func TestWireCallbacksClosure_OnConnect_WithSubscribeError(t *testing.T) {
	t.Parallel()
	svc, buf := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP}
	mockConn := &mockTickerConn{subscribeErr: errors.New("sub fail")}
	ut := newTestUserTickerWithMockConn("closure-sub-err@test.com", subs, mockConn)

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onConnect
	reg.mu.Unlock()

	fn()

	ut.mu.RLock()
	assert.True(t, ut.Connected, "should be connected despite sub error")
	ut.mu.RUnlock()
	assert.Contains(t, buf.String(), "Failed to resubscribe on connect")
}

// TestWireCallbacksClosure_OnConnect_MultiMode verifies the OnConnect closure
// correctly groups and restores multiple modes.
func TestWireCallbacksClosure_OnConnect_MultiMode(t *testing.T) {
	t.Parallel()
	svc, _ := newEdgeTestService(nil)

	subs := map[uint32]kiteticker.Mode{
		100: ModeLTP,
		200: ModeQuote,
		300: ModeFull,
		400: ModeLTP,
	}
	mockConn := &mockTickerConn{}
	ut := newTestUserTickerWithMockConn("closure-multi@test.com", subs, mockConn)

	reg := &mockCallbackRegistrar{}
	svc.wireCallbacks(ut, reg)

	reg.mu.Lock()
	fn := reg.onConnect
	reg.mu.Unlock()

	fn()

	mockConn.mu.Lock()
	defer mockConn.mu.Unlock()

	// One subscribe call with all 4 tokens
	require.Len(t, mockConn.subscribeCalls, 1)
	assert.Len(t, mockConn.subscribeCalls[0], 4)

	// 3 SetMode calls (LTP, Quote, Full)
	assert.Len(t, mockConn.modeCalls, 3)

	modeMap := make(map[kiteticker.Mode][]uint32)
	for _, mc := range mockConn.modeCalls {
		modeMap[mc.mode] = append(modeMap[mc.mode], mc.tokens...)
	}
	assert.ElementsMatch(t, []uint32{100, 400}, modeMap[ModeLTP])
	assert.ElementsMatch(t, []uint32{200}, modeMap[ModeQuote])
	assert.ElementsMatch(t, []uint32{300}, modeMap[ModeFull])
}
