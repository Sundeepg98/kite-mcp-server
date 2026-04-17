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

// --- mock tickerSubscriber ---

// mockSubscriber records Subscribe/SetMode calls for assertions.
type mockSubscriber struct {
	mu           sync.Mutex
	subscribed   [][]uint32
	modes        []modeCall
	subscribeErr error
	setModeErr   error
}

type modeCall struct {
	mode   kiteticker.Mode
	tokens []uint32
}

func (m *mockSubscriber) Subscribe(tokens []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uint32, len(tokens))
	copy(cp, tokens)
	m.subscribed = append(m.subscribed, cp)
	return m.subscribeErr
}

func (m *mockSubscriber) SetMode(mode kiteticker.Mode, tokens []uint32) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	cp := make([]uint32, len(tokens))
	copy(cp, tokens)
	m.modes = append(m.modes, modeCall{mode: mode, tokens: cp})
	return m.setModeErr
}

// newTestService creates a Service with an in-memory log buffer for assertions.
func newTestService(onTick TickCallback) (*Service, *bytes.Buffer) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, &slog.HandlerOptions{Level: slog.LevelDebug}))
	svc := New(Config{Logger: logger, OnTick: onTick})
	return svc, &buf
}

// --- onConnect tests ---

func TestOnConnect_SetsConnectedTrue(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("conn@test.com", "k", "t", make(map[uint32]kiteticker.Mode))

	assert.False(t, ut.Connected)
	svc.onConnect(ut, &mockSubscriber{})

	ut.mu.RLock()
	defer ut.mu.RUnlock()
	assert.True(t, ut.Connected)
}

func TestOnConnect_NoSubscriptions_NoResubscribe(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("empty@test.com", "k", "t", make(map[uint32]kiteticker.Mode))

	mock := &mockSubscriber{}
	svc.onConnect(ut, mock)

	mock.mu.Lock()
	defer mock.mu.Unlock()
	assert.Empty(t, mock.subscribed, "Subscribe should not be called when no tokens")
	assert.Empty(t, mock.modes, "SetMode should not be called when no tokens")
}

func TestOnConnect_ResubscribesTokens(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{
		256265: ModeLTP,
		260105: ModeQuote,
		738561: ModeFull,
	}
	ut := newTestUserTicker("resub@test.com", "k", "t", subs)

	mock := &mockSubscriber{}
	svc.onConnect(ut, mock)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// Subscribe should be called once with all tokens
	require.Len(t, mock.subscribed, 1)
	assert.Len(t, mock.subscribed[0], 3)

	// Collect all subscribed tokens
	subSet := make(map[uint32]bool)
	for _, tok := range mock.subscribed[0] {
		subSet[tok] = true
	}
	assert.True(t, subSet[256265])
	assert.True(t, subSet[260105])
	assert.True(t, subSet[738561])

	// SetMode should be called once per distinct mode (3 modes here)
	assert.Len(t, mock.modes, 3)

	// Collect modes -> tokens for verification
	modeMap := make(map[kiteticker.Mode][]uint32)
	for _, mc := range mock.modes {
		modeMap[mc.mode] = append(modeMap[mc.mode], mc.tokens...)
	}
	assert.Contains(t, modeMap, ModeLTP)
	assert.Contains(t, modeMap, ModeQuote)
	assert.Contains(t, modeMap, ModeFull)
	assert.Contains(t, modeMap[ModeLTP], uint32(256265))
	assert.Contains(t, modeMap[ModeQuote], uint32(260105))
	assert.Contains(t, modeMap[ModeFull], uint32(738561))
}

func TestOnConnect_SameModeGroupedTogether(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	// Multiple tokens with same mode
	subs := map[uint32]kiteticker.Mode{
		100: ModeLTP,
		200: ModeLTP,
		300: ModeLTP,
	}
	ut := newTestUserTicker("grouped@test.com", "k", "t", subs)

	mock := &mockSubscriber{}
	svc.onConnect(ut, mock)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	// Only one SetMode call for the single mode
	require.Len(t, mock.modes, 1)
	assert.Equal(t, ModeLTP, mock.modes[0].mode)
	assert.Len(t, mock.modes[0].tokens, 3)
}

func TestOnConnect_SubscribeError_LoggedAndContinues(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP}
	ut := newTestUserTicker("sub-err@test.com", "k", "t", subs)

	mock := &mockSubscriber{subscribeErr: errors.New("ws write failed")}
	svc.onConnect(ut, mock)

	// Should still be connected despite subscribe error
	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()

	// Error should be logged
	assert.Contains(t, buf.String(), "Failed to resubscribe on connect")

	// SetMode should still be called (errors don't abort the flow)
	mock.mu.Lock()
	assert.Len(t, mock.modes, 1)
	mock.mu.Unlock()
}

func TestOnConnect_SetModeError_LoggedAndContinues(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP, 260105: ModeQuote}
	ut := newTestUserTicker("mode-err@test.com", "k", "t", subs)

	mock := &mockSubscriber{setModeErr: errors.New("mode write failed")}
	svc.onConnect(ut, mock)

	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()

	assert.Contains(t, buf.String(), "Failed to restore mode on connect")
}

// --- onTickReceived tests ---

func TestOnTickReceived_CallsCallback(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	var gotEmail string
	var gotTick models.Tick

	svc, _ := newTestService(func(email string, tick models.Tick) {
		mu.Lock()
		gotEmail = email
		gotTick = tick
		mu.Unlock()
	})

	tick := models.Tick{InstrumentToken: 256265, LastPrice: 1500.50}
	svc.onTickReceived("tick@test.com", tick)

	mu.Lock()
	defer mu.Unlock()
	assert.Equal(t, "tick@test.com", gotEmail)
	assert.Equal(t, uint32(256265), gotTick.InstrumentToken)
	assert.InDelta(t, 1500.50, gotTick.LastPrice, 0.01)
}

func TestOnTickReceived_NilCallback_NoPanic(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil) // no OnTick callback

	assert.NotPanics(t, func() {
		svc.onTickReceived("noop@test.com", models.Tick{InstrumentToken: 100})
	})
}

// --- onError tests ---

func TestOnError_LogsError(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	svc.onError("err@test.com", errors.New("connection reset"))

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Ticker error")
	assert.Contains(t, logOutput, "err@test.com")
	assert.Contains(t, logOutput, "connection reset")
}

// --- onClose tests ---

func TestOnClose_SetsConnectedFalse(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	ut := newTestUserTicker("close@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.onClose(ut, 1000, "normal closure")

	ut.mu.RLock()
	defer ut.mu.RUnlock()
	assert.False(t, ut.Connected)
}

func TestOnClose_LogsCodeAndReason(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	ut := newTestUserTicker("close-log@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	svc.onClose(ut, 1006, "abnormal closure")

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Ticker closed")
	assert.Contains(t, logOutput, "close-log@test.com")
	assert.Contains(t, logOutput, "1006")
	assert.Contains(t, logOutput, "abnormal closure")
}

// --- onReconnect tests ---

func TestOnReconnect_Logs(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	svc.onReconnect("recon@test.com", 3, 5*time.Second)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Ticker reconnecting")
	assert.Contains(t, logOutput, "recon@test.com")
	assert.Contains(t, logOutput, "3")
}

// --- onNoReconnect tests ---

func TestOnNoReconnect_SetsConnectedFalse(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	ut := newTestUserTicker("norecon@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	svc.onNoReconnect(ut, 300)

	ut.mu.RLock()
	defer ut.mu.RUnlock()
	assert.False(t, ut.Connected)
}

func TestOnNoReconnect_LogsAttempts(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	ut := newTestUserTicker("norecon-log@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	svc.onNoReconnect(ut, 300)

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Ticker gave up reconnecting")
	assert.Contains(t, logOutput, "norecon-log@test.com")
	assert.Contains(t, logOutput, "300")
}

// --- wireCallbacks integration (verifies closures are wired) ---

// TestWireCallbacks_Integration verifies that wireCallbacks registers closures
// on the kiteticker.Ticker that delegate to the extracted methods. We confirm
// this indirectly: wireCallbacks should not panic and the service should
// remain functional after wiring.
func TestWireCallbacks_Integration(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	ut := newTestUserTicker("wire@test.com", "k", "t", map[uint32]kiteticker.Mode{
		256265: ModeLTP,
	})

	// Should not panic
	assert.NotPanics(t, func() {
		svc.wireCallbacks(ut, ut.Ticker)
	})
}

// --- Concurrent callback execution ---

func TestOnConnect_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{
		100: ModeLTP,
		200: ModeQuote,
	}
	ut := newTestUserTicker("concurrent@test.com", "k", "t", subs)
	mock := &mockSubscriber{}

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			svc.onConnect(ut, mock)
		})
	}
	wg.Wait()

	// Should be connected after all calls
	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()
}

func TestOnClose_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("conc-close@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()

	var wg sync.WaitGroup
	for code := range 10 {
		wg.Go(func() {
			svc.onClose(ut, code, "test")
		})
	}
	wg.Wait()

	ut.mu.RLock()
	assert.False(t, ut.Connected)
	ut.mu.RUnlock()
}

func TestOnTickReceived_ConcurrentSafe(t *testing.T) {
	t.Parallel()
	var mu sync.Mutex
	count := 0
	svc, _ := newTestService(func(email string, tick models.Tick) {
		mu.Lock()
		count++
		mu.Unlock()
	})

	var wg sync.WaitGroup
	for i := range 50 {
		wg.Go(func() {
			svc.onTickReceived("conc@test.com", models.Tick{InstrumentToken: uint32(i)})
		})
	}
	wg.Wait()

	mu.Lock()
	assert.Equal(t, 50, count)
	mu.Unlock()
}

// --- Edge cases ---

func TestOnConnect_EmptySubscriptions(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("empty-sub@test.com", "k", "t", make(map[uint32]kiteticker.Mode))

	mock := &mockSubscriber{}
	svc.onConnect(ut, mock)

	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()

	mock.mu.Lock()
	assert.Empty(t, mock.subscribed)
	assert.Empty(t, mock.modes)
	mock.mu.Unlock()
}

func TestOnConnect_SingleToken(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeFull}
	ut := newTestUserTicker("single@test.com", "k", "t", subs)

	mock := &mockSubscriber{}
	svc.onConnect(ut, mock)

	mock.mu.Lock()
	defer mock.mu.Unlock()

	require.Len(t, mock.subscribed, 1)
	assert.Equal(t, []uint32{256265}, mock.subscribed[0])

	require.Len(t, mock.modes, 1)
	assert.Equal(t, ModeFull, mock.modes[0].mode)
	assert.Equal(t, []uint32{256265}, mock.modes[0].tokens)
}

func TestOnClose_AlreadyDisconnected(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("already-dc@test.com", "k", "t", make(map[uint32]kiteticker.Mode))
	// Connected is already false

	// Should not panic
	assert.NotPanics(t, func() {
		svc.onClose(ut, 1000, "normal")
	})

	ut.mu.RLock()
	assert.False(t, ut.Connected)
	ut.mu.RUnlock()
}

func TestOnNoReconnect_AlreadyDisconnected(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)
	ut := newTestUserTicker("already-dc-norecon@test.com", "k", "t", make(map[uint32]kiteticker.Mode))

	assert.NotPanics(t, func() {
		svc.onNoReconnect(ut, 100)
	})

	ut.mu.RLock()
	assert.False(t, ut.Connected)
	ut.mu.RUnlock()
}

func TestOnConnect_BothSubscribeAndSetModeError(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	subs := map[uint32]kiteticker.Mode{256265: ModeLTP}
	ut := newTestUserTicker("both-err@test.com", "k", "t", subs)

	mock := &mockSubscriber{
		subscribeErr: errors.New("sub fail"),
		setModeErr:   errors.New("mode fail"),
	}
	svc.onConnect(ut, mock)

	// Still connected despite errors
	ut.mu.RLock()
	assert.True(t, ut.Connected)
	ut.mu.RUnlock()

	logOutput := buf.String()
	assert.Contains(t, logOutput, "Failed to resubscribe on connect")
	assert.Contains(t, logOutput, "Failed to restore mode on connect")
}

func TestOnError_NilError(t *testing.T) {
	t.Parallel()
	svc, _ := newTestService(nil)

	// Should not panic with nil error
	assert.NotPanics(t, func() {
		svc.onError("nil-err@test.com", nil)
	})
}

func TestOnReconnect_ZeroAttempt(t *testing.T) {
	t.Parallel()
	svc, buf := newTestService(nil)

	svc.onReconnect("zero@test.com", 0, 0)

	assert.Contains(t, buf.String(), "Ticker reconnecting")
}

// --- tickerSubscriber interface compliance ---

func TestMockSubscriber_ImplementsInterface(t *testing.T) {
	t.Parallel()
	var _ tickerSubscriber = &mockSubscriber{}
}
