package mcp

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ===========================================================================
// IsTokenExpiredFn override — verify token refresh path
// ===========================================================================

// mockBrokerForRefresh implements broker.Client with controllable GetProfile.
type mockBrokerForRefresh struct {
	profileErr error
}

func (m *mockBrokerForRefresh) BrokerName() broker.Name                    { return "mock" }
func (m *mockBrokerForRefresh) GetProfile() (broker.Profile, error)        { return broker.Profile{UserID: "TST"}, m.profileErr }
func (m *mockBrokerForRefresh) GetMargins() (broker.Margins, error)        { return broker.Margins{}, nil }
func (m *mockBrokerForRefresh) GetHoldings() ([]broker.Holding, error)     { return nil, nil }
func (m *mockBrokerForRefresh) GetPositions() (broker.Positions, error)    { return broker.Positions{}, nil }
func (m *mockBrokerForRefresh) GetOrders() ([]broker.Order, error)         { return nil, nil }
func (m *mockBrokerForRefresh) GetOrderHistory(string) ([]broker.Order, error) { return nil, nil }
func (m *mockBrokerForRefresh) GetTrades() ([]broker.Trade, error)         { return nil, nil }
func (m *mockBrokerForRefresh) PlaceOrder(broker.OrderParams) (broker.OrderResponse, error) { return broker.OrderResponse{}, nil }
func (m *mockBrokerForRefresh) ModifyOrder(string, broker.OrderParams) (broker.OrderResponse, error) { return broker.OrderResponse{}, nil }
func (m *mockBrokerForRefresh) CancelOrder(string, string) (broker.OrderResponse, error) { return broker.OrderResponse{}, nil }
func (m *mockBrokerForRefresh) GetLTP(...string) (map[string]broker.LTP, error)   { return nil, nil }
func (m *mockBrokerForRefresh) GetOHLC(...string) (map[string]broker.OHLC, error) { return nil, nil }
func (m *mockBrokerForRefresh) GetHistoricalData(int, string, time.Time, time.Time) ([]broker.HistoricalCandle, error) { return nil, nil }
func (m *mockBrokerForRefresh) GetQuotes(...string) (map[string]broker.Quote, error) { return nil, nil }
func (m *mockBrokerForRefresh) GetOrderTrades(string) ([]broker.Trade, error)      { return nil, nil }
func (m *mockBrokerForRefresh) GetGTTs() ([]broker.GTTOrder, error)                { return nil, nil }
func (m *mockBrokerForRefresh) PlaceGTT(broker.GTTParams) (broker.GTTResponse, error) { return broker.GTTResponse{}, nil }
func (m *mockBrokerForRefresh) ModifyGTT(int, broker.GTTParams) (broker.GTTResponse, error) { return broker.GTTResponse{}, nil }
func (m *mockBrokerForRefresh) DeleteGTT(int) (broker.GTTResponse, error)          { return broker.GTTResponse{}, nil }
func (m *mockBrokerForRefresh) ConvertPosition(broker.ConvertPositionParams) (bool, error) { return true, nil }
func (m *mockBrokerForRefresh) GetMFOrders() ([]broker.MFOrder, error)             { return nil, nil }
func (m *mockBrokerForRefresh) GetMFSIPs() ([]broker.MFSIP, error)                { return nil, nil }
func (m *mockBrokerForRefresh) GetMFHoldings() ([]broker.MFHolding, error)         { return nil, nil }
func (m *mockBrokerForRefresh) PlaceMFOrder(broker.MFOrderParams) (broker.MFOrderResponse, error) { return broker.MFOrderResponse{}, nil }
func (m *mockBrokerForRefresh) CancelMFOrder(string) (broker.MFOrderResponse, error)              { return broker.MFOrderResponse{}, nil }
func (m *mockBrokerForRefresh) PlaceMFSIP(broker.MFSIPParams) (broker.MFSIPResponse, error)       { return broker.MFSIPResponse{}, nil }
func (m *mockBrokerForRefresh) CancelMFSIP(string) (broker.MFSIPResponse, error)                  { return broker.MFSIPResponse{}, nil }
func (m *mockBrokerForRefresh) GetOrderMargins([]broker.OrderMarginParam) (any, error)             { return nil, nil }
func (m *mockBrokerForRefresh) GetBasketMargins([]broker.OrderMarginParam, bool) (any, error)      { return nil, nil }
func (m *mockBrokerForRefresh) GetOrderCharges([]broker.OrderChargesParam) (any, error)            { return nil, nil }

// newTokenRefreshManager creates a kc.Manager in dev mode for token refresh tests.
func newTokenRefreshManager(t *testing.T) *kc.Manager {
	t.Helper()
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   logger,
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	mgr, err := kc.New(kc.Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		Logger:             logger,
		DevMode:            true,
		InstrumentsManager: instrMgr,
		AlertDBPath:        ":memory:",
	})
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)
	return mgr
}

func TestWithTokenRefresh_AlwaysExpired_ProfileOK(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	// Override IsTokenExpiredFn to always report expired
	handler.IsTokenExpiredFn = func(storedAt time.Time) bool {
		return true
	}

	// Store a token so TokenStore().Get() returns an entry
	mgr.TokenStore().Set("test@example.com", &kc.KiteTokenEntry{
		AccessToken: "token123",
		UserID:      "TST",
		StoredAt:    time.Now(),
	})

	// Create a session with a broker whose GetProfile succeeds
	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{profileErr: nil},
		Email:  "test@example.com",
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "test@example.com")

	// GetProfile succeeded → token is still valid → no error result
	assert.Nil(t, result, "WithTokenRefresh should return nil when GetProfile succeeds")

	// Token should still be in the store (not deleted)
	_, ok := mgr.TokenStore().Get("test@example.com")
	assert.True(t, ok, "token should remain in store when profile call succeeds")
}

func TestWithTokenRefresh_AlwaysExpired_ProfileFails(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	// Override to always report expired
	handler.IsTokenExpiredFn = func(storedAt time.Time) bool {
		return true
	}

	// Store a token
	mgr.TokenStore().Set("test@example.com", &kc.KiteTokenEntry{
		AccessToken: "token123",
		UserID:      "TST",
		StoredAt:    time.Now(),
	})

	// Broker GetProfile fails → token truly expired
	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{profileErr: errors.New("session expired")},
		Email:  "test@example.com",
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "test@example.com")

	// Should return an error result asking user to re-authenticate
	require.NotNil(t, result, "WithTokenRefresh should return error result when profile fails")
	assert.True(t, result.IsError)

	// Token should be deleted from store
	_, ok := mgr.TokenStore().Get("test@example.com")
	assert.False(t, ok, "token should be deleted from store when profile call fails")
}

func TestWithTokenRefresh_NeverExpired(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	// Override to never report expired
	handler.IsTokenExpiredFn = func(storedAt time.Time) bool {
		return false
	}

	// Store a token
	mgr.TokenStore().Set("test@example.com", &kc.KiteTokenEntry{
		AccessToken: "token123",
		UserID:      "TST",
		StoredAt:    time.Now(),
	})

	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{profileErr: errors.New("should not be called")},
		Email:  "test@example.com",
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "test@example.com")

	// Not expired → should return nil immediately (GetProfile never called)
	assert.Nil(t, result, "should return nil when token is not expired")
}

func TestWithTokenRefresh_EmptyEmail(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	handler.IsTokenExpiredFn = func(storedAt time.Time) bool {
		return true // shouldn't matter
	}

	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{},
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "")

	// Empty email → early return nil
	assert.Nil(t, result)
}

func TestWithTokenRefresh_NoTokenInStore(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	handler.IsTokenExpiredFn = func(storedAt time.Time) bool {
		return true
	}

	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{},
		Email:  "notoken@example.com",
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "notoken@example.com")

	// No token in store → TokenStore().Get() returns !ok → early return nil
	assert.Nil(t, result)
}

func TestWithTokenRefresh_DefaultFn(t *testing.T) {
	mgr := newTokenRefreshManager(t)
	handler := NewToolHandler(mgr)

	// Don't set IsTokenExpiredFn — uses default kc.IsKiteTokenExpired
	assert.Nil(t, handler.IsTokenExpiredFn)

	// Store a very recent token — IsKiteTokenExpired should return false
	mgr.TokenStore().Set("test@example.com", &kc.KiteTokenEntry{
		AccessToken: "token123",
		UserID:      "TST",
		StoredAt:    time.Now(),
	})

	session := &kc.KiteSessionData{
		Broker: &mockBrokerForRefresh{profileErr: errors.New("should not be called")},
		Email:  "test@example.com",
	}

	ctx := context.Background()
	result := handler.WithTokenRefresh(ctx, "test_tool", session, "session-1", "test@example.com")

	// Token just stored → not expired → nil
	assert.Nil(t, result)
}
