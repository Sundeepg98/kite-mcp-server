package ticker

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteticker "github.com/zerodha/gokiteconnect/v4/ticker"
	"github.com/zerodha/gokiteconnect/v4/models"
)

func TestTickerService_New(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	require.NotNil(t, svc)
	assert.NotNil(t, svc.tickers)
	assert.NotNil(t, svc.logger)
}

func TestTickerService_NewWithCallback(t *testing.T) {
	t.Parallel()
	called := false
	svc := New(Config{
		OnTick: func(email string, tick models.Tick) {
			called = true
		},
	})
	require.NotNil(t, svc)
	// OnTick is stored but not invoked until a tick arrives
	assert.False(t, called)
}

func TestTickerService_GetStatus_NoTicker(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	status, err := svc.GetStatus("unknown@example.com")
	require.NoError(t, err)
	require.NotNil(t, status)
	assert.False(t, status.Running, "should report not running for unknown email")
	assert.False(t, status.Connected)
	assert.Empty(t, status.Subscriptions)
}

func TestTickerService_IsRunning_NoTicker(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	assert.False(t, svc.IsRunning("nobody@example.com"))
}

func TestTickerService_ListAll_Empty(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	list := svc.ListAll()
	assert.Empty(t, list)
	assert.NotNil(t, list, "should return empty slice, not nil")
}

func TestTickerService_StopNonExistent(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	err := svc.Stop("ghost@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ticker found")
}

func TestTickerService_StartEmptyEmail(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	err := svc.Start("", "apikey", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")

	// Verify nothing was registered
	assert.Empty(t, svc.ListAll())
}

func TestTickerService_SubscribeNoTicker(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	err := svc.Subscribe("missing@example.com", []uint32{256265}, ModeLTP)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ticker found")
}

func TestTickerService_UnsubscribeNoTicker(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	err := svc.Unsubscribe("missing@example.com", []uint32{256265})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ticker found")
}

func TestTickerService_Shutdown(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	// Shutdown on empty service should not panic
	assert.NotPanics(t, func() {
		svc.Shutdown()
	})

	// After shutdown, internal map should be empty
	assert.Empty(t, svc.ListAll())
}

func TestTickerService_UpdateTokenNoTicker(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	err := svc.UpdateToken("nobody@example.com", "key", "token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no ticker found")
}

// newTestUserTicker creates a UserTicker with a no-op cancel for testing.
// The Ticker field uses a real kiteticker.New (required for wireCallbacks)
// but we never call ServeWithContext so no WebSocket is opened.
// The conn field defaults to the real ticker (same as production Start).
func newTestUserTicker(email, apiKey, accessToken string, subs map[uint32]kiteticker.Mode) *UserTicker {
	_, cancel := context.WithCancel(context.Background())
	t := kiteticker.New(apiKey, accessToken)
	return &UserTicker{
		Email:       email,
		APIKey:      apiKey,
		AccessToken: accessToken,
		Ticker:      t,
		conn:        t,
		Cancel:      cancel,
		StartedAt:   time.Now(),
		Subscribed:  subs,
	}
}

// TestTickerService_StartCreatesEntry verifies that Start registers a ticker
// entry in the service. Even without a real WebSocket, the UserTicker is
// created and visible via IsRunning, GetStatus, and ListAll.
func TestTickerService_StartCreatesEntry(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "starter@example.com"

	err := svc.Start(email, "apikey", "token")
	require.NoError(t, err)
	// Cleanup: stop the ticker to cancel the goroutine
	defer svc.Stop(email)

	assert.True(t, svc.IsRunning(email), "ticker should be registered after Start")

	status, err := svc.GetStatus(email)
	require.NoError(t, err)
	assert.True(t, status.Running, "status.Running should be true")
	// Connected will be false because there's no real WebSocket server
	assert.False(t, status.Connected)

	list := svc.ListAll()
	require.Len(t, list, 1)
	assert.Equal(t, email, list[0].Email)
}

// TestTickerService_StartDuplicateDisconnected verifies that Start succeeds
// for an email that has an existing non-connected ticker (replaces it).
func TestTickerService_StartDuplicateDisconnected(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "dup@example.com"

	err := svc.Start(email, "key1", "tok1")
	require.NoError(t, err)
	defer svc.Shutdown()

	// The ticker is not connected (no real WebSocket), so starting again should succeed
	err = svc.Start(email, "key2", "tok2")
	require.NoError(t, err)

	assert.True(t, svc.IsRunning(email))
}

// TestTickerService_UpdateTokenPreservesSubscriptions injects a UserTicker
// with subscriptions directly into the service map, then calls UpdateToken
// and verifies the new ticker retains all subscriptions.
func TestTickerService_UpdateTokenPreservesSubscriptions(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "sub-test@example.com"

	// Inject a UserTicker with known subscriptions
	origSubs := map[uint32]kiteticker.Mode{
		256265: ModeLTP,
		260105: ModeQuote,
		738561: ModeFull,
	}
	ut := newTestUserTicker(email, "oldkey", "oldtoken", origSubs)

	svc.mu.Lock()
	svc.tickers[email] = ut
	svc.mu.Unlock()

	// UpdateToken should preserve subscriptions
	err := svc.UpdateToken(email, "newkey", "newtoken")
	require.NoError(t, err)
	defer svc.Shutdown()

	// Verify the ticker is still running
	assert.True(t, svc.IsRunning(email))

	// Verify subscriptions are preserved via GetStatus
	status, err := svc.GetStatus(email)
	require.NoError(t, err)
	assert.True(t, status.Running)
	require.Len(t, status.Subscriptions, len(origSubs), "subscription count should match")

	// Build a map from status subscriptions for easy comparison
	gotSubs := make(map[uint32]string, len(status.Subscriptions))
	for _, si := range status.Subscriptions {
		gotSubs[si.InstrumentToken] = si.Mode
	}

	for token, mode := range origSubs {
		got, ok := gotSubs[token]
		assert.True(t, ok, "token %d should be preserved", token)
		assert.Equal(t, string(mode), got, "mode for token %d should match", token)
	}
}

// TestTickerService_UpdateTokenNewCredentials verifies that after UpdateToken,
// the new ticker has the updated API key and access token.
func TestTickerService_UpdateTokenNewCredentials(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "cred-test@example.com"

	ut := newTestUserTicker(email, "oldkey", "oldtoken", make(map[uint32]kiteticker.Mode))
	svc.mu.Lock()
	svc.tickers[email] = ut
	svc.mu.Unlock()

	err := svc.UpdateToken(email, "newkey", "newtoken")
	require.NoError(t, err)
	defer svc.Shutdown()

	// Access the new UserTicker directly to check credentials
	svc.mu.RLock()
	newUT := svc.tickers[email]
	svc.mu.RUnlock()

	require.NotNil(t, newUT)
	assert.Equal(t, "newkey", newUT.APIKey)
	assert.Equal(t, "newtoken", newUT.AccessToken)
	assert.NotSame(t, ut, newUT, "should be a different UserTicker instance")
}

// TestTickerService_StopInjected verifies Stop works on an injected ticker.
func TestTickerService_StopInjected(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "stopper@example.com"

	ut := newTestUserTicker(email, "key", "tok", make(map[uint32]kiteticker.Mode))
	svc.mu.Lock()
	svc.tickers[email] = ut
	svc.mu.Unlock()

	assert.True(t, svc.IsRunning(email))
	err := svc.Stop(email)
	require.NoError(t, err)
	assert.False(t, svc.IsRunning(email))
}

// TestTickerService_ShutdownWithTickers verifies Shutdown stops all injected tickers.
func TestTickerService_ShutdownWithTickers(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	emails := []string{"a@test.com", "b@test.com", "c@test.com"}
	svc.mu.Lock()
	for _, email := range emails {
		svc.tickers[email] = newTestUserTicker(email, "key", "tok", make(map[uint32]kiteticker.Mode))
	}
	svc.mu.Unlock()

	require.Len(t, svc.ListAll(), 3)

	svc.Shutdown()

	assert.Empty(t, svc.ListAll())
	for _, email := range emails {
		assert.False(t, svc.IsRunning(email))
	}
}

// TestTickerService_GetStatusWithSubscriptions verifies GetStatus returns
// correct subscription info for injected tickers.
func TestTickerService_GetStatusWithSubscriptions(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "status@example.com"

	subs := map[uint32]kiteticker.Mode{
		256265: ModeLTP,
		260105: ModeQuote,
	}
	ut := newTestUserTicker(email, "key", "tok", subs)
	ut.Connected = true // simulate connected state

	svc.mu.Lock()
	svc.tickers[email] = ut
	svc.mu.Unlock()

	status, err := svc.GetStatus(email)
	require.NoError(t, err)
	assert.True(t, status.Running)
	assert.True(t, status.Connected)
	assert.Len(t, status.Subscriptions, 2)
	assert.NotEmpty(t, status.Uptime)
}

// TestTickerService_ListAllWithTickers verifies ListAll returns info for all
// injected tickers with correct subscription counts.
func TestTickerService_ListAllWithTickers(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	svc.mu.Lock()
	svc.tickers["a@test.com"] = newTestUserTicker("a@test.com", "k", "t", map[uint32]kiteticker.Mode{
		256265: ModeLTP,
	})
	svc.tickers["b@test.com"] = newTestUserTicker("b@test.com", "k", "t", map[uint32]kiteticker.Mode{
		256265: ModeLTP,
		260105: ModeQuote,
		738561: ModeFull,
	})
	svc.mu.Unlock()

	list := svc.ListAll()
	require.Len(t, list, 2)

	subCounts := make(map[string]int)
	for _, info := range list {
		subCounts[info.Email] = info.Subscriptions
	}
	assert.Equal(t, 1, subCounts["a@test.com"])
	assert.Equal(t, 3, subCounts["b@test.com"])
}

// TestTickerService_ConcurrentAccess verifies that concurrent reads and writes
// to the service do not trigger the race detector. This version exercises
// populated state rather than only empty-service error paths.
func TestTickerService_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	emails := []string{"a@test.com", "b@test.com", "c@test.com"}

	// Pre-populate with injected tickers so concurrent ops hit real state
	svc.mu.Lock()
	for _, email := range emails {
		svc.tickers[email] = newTestUserTicker(email, "key", "tok", map[uint32]kiteticker.Mode{
			256265: ModeLTP,
			260105: ModeQuote,
		})
	}
	svc.mu.Unlock()

	var wg sync.WaitGroup

	// Concurrent reads on populated state (exercises s.mu.RLock and ut.mu.RLock)
	for i := range 30 {
		email := emails[i%len(emails)]
		wg.Go(func() {
			svc.IsRunning(email)
			svc.GetStatus(email)
			svc.ListAll()
		})
	}

	// Concurrent writes that exercise Subscribe/Unsubscribe on populated tickers
	// (these write to ut.Subscribed under ut.mu.Lock)
	for i := range 15 {
		email := emails[i%len(emails)]
		token := uint32(300000 + i)
		wg.Go(func() {
			_ = svc.Subscribe(email, []uint32{token}, ModeLTP)
			_ = svc.Unsubscribe(email, []uint32{token})
		})
	}

	// Concurrent error-path writes (no ticker for these emails)
	for i := range 10 {
		email := emails[i%len(emails)] + ".missing"
		wg.Go(func() {
			_ = svc.Stop(email)
			_ = svc.Subscribe(email, []uint32{100}, ModeLTP)
			_ = svc.Unsubscribe(email, []uint32{100})
			_ = svc.UpdateToken(email, "k", "t")
		})
	}

	wg.Wait()

	// Cleanup
	svc.Shutdown()
}

// TestTickerService_ConcurrentAccessWithUpdateToken exercises concurrent
// UpdateToken calls alongside reads, verifying no races on the
// stop-and-restart path with populated subscriptions.
func TestTickerService_ConcurrentAccessWithUpdateToken(t *testing.T) {
	t.Parallel()
	svc := New(Config{})
	email := "concurrent-update@test.com"

	// Inject initial ticker with subscriptions
	svc.mu.Lock()
	svc.tickers[email] = newTestUserTicker(email, "key", "tok", map[uint32]kiteticker.Mode{
		256265: ModeLTP,
		260105: ModeQuote,
	})
	svc.mu.Unlock()

	var wg sync.WaitGroup

	// Concurrent reads while UpdateToken might be running
	for range 20 {
		wg.Go(func() {
			svc.IsRunning(email)
			svc.GetStatus(email)
			svc.ListAll()
		})
	}

	// Sequential UpdateToken calls (each needs exclusive lock, so only one
	// runs at a time, but they race with the concurrent reads above)
	for range 5 {
		wg.Go(func() {
			_ = svc.UpdateToken(email, "key", "newtok")
		})
	}

	wg.Wait()

	// Verify the ticker still exists and has subscriptions preserved
	assert.True(t, svc.IsRunning(email))
	status, err := svc.GetStatus(email)
	require.NoError(t, err)
	assert.True(t, status.Running)
	// Subscriptions should be preserved through all the UpdateToken calls
	assert.Len(t, status.Subscriptions, 2)

	svc.Shutdown()
}

// TestTickerService_ShutdownConcurrent verifies shutdown is safe under concurrent access.
func TestTickerService_ShutdownConcurrent(t *testing.T) {
	t.Parallel()
	svc := New(Config{})

	// Pre-populate with tickers so Shutdown has work to do
	svc.mu.Lock()
	for _, email := range []string{"x@test.com", "y@test.com"} {
		svc.tickers[email] = newTestUserTicker(email, "key", "tok", map[uint32]kiteticker.Mode{
			256265: ModeLTP,
		})
	}
	svc.mu.Unlock()

	var wg sync.WaitGroup
	// Multiple goroutines calling Shutdown concurrently
	for range 5 {
		wg.Go(func() {
			svc.Shutdown()
		})
	}
	// Concurrent reads during shutdown
	for range 10 {
		wg.Go(func() {
			svc.IsRunning("x@test.com")
			svc.ListAll()
		})
	}
	wg.Wait()

	assert.Empty(t, svc.ListAll())
}
