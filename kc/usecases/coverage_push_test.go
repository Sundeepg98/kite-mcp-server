package usecases

// coverage_push_test.go — tests for all uncovered use cases:
// MF, margins, convert position, paper trading, ticker, trailing stops, watchlist, P&L journal

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// --- Enhanced mock broker with configurable MF/margin/convert returns ---

type mfMockBrokerClient struct {
	mockBrokerClient

	mfOrders       []broker.MFOrder
	mfOrdersErr    error
	mfSIPs         []broker.MFSIP
	mfSIPsErr      error
	mfHoldings     []broker.MFHolding
	mfHoldingsErr  error
	placeMFResp    broker.MFOrderResponse
	placeMFErr     error
	cancelMFResp   broker.MFOrderResponse
	cancelMFErr    error
	placeSIPResp   broker.MFSIPResponse
	placeSIPErr    error
	cancelSIPResp  broker.MFSIPResponse
	cancelSIPErr   error
	orderMargins   any
	orderMarginsErr error
	basketMargins  any
	basketMarginsErr error
	orderCharges   any
	orderChargesErr error
	convertOK      bool
	convertErr     error
}

func (m *mfMockBrokerClient) GetMFOrders() ([]broker.MFOrder, error) {
	return m.mfOrders, m.mfOrdersErr
}
func (m *mfMockBrokerClient) GetMFSIPs() ([]broker.MFSIP, error) {
	return m.mfSIPs, m.mfSIPsErr
}
func (m *mfMockBrokerClient) GetMFHoldings() ([]broker.MFHolding, error) {
	return m.mfHoldings, m.mfHoldingsErr
}
func (m *mfMockBrokerClient) PlaceMFOrder(p broker.MFOrderParams) (broker.MFOrderResponse, error) {
	return m.placeMFResp, m.placeMFErr
}
func (m *mfMockBrokerClient) CancelMFOrder(orderID string) (broker.MFOrderResponse, error) {
	return m.cancelMFResp, m.cancelMFErr
}
func (m *mfMockBrokerClient) PlaceMFSIP(p broker.MFSIPParams) (broker.MFSIPResponse, error) {
	return m.placeSIPResp, m.placeSIPErr
}
func (m *mfMockBrokerClient) CancelMFSIP(sipID string) (broker.MFSIPResponse, error) {
	return m.cancelSIPResp, m.cancelSIPErr
}
func (m *mfMockBrokerClient) GetOrderMargins(p []broker.OrderMarginParam) (any, error) {
	return m.orderMargins, m.orderMarginsErr
}
func (m *mfMockBrokerClient) GetBasketMargins(p []broker.OrderMarginParam, considerPositions bool) (any, error) {
	return m.basketMargins, m.basketMarginsErr
}
func (m *mfMockBrokerClient) GetOrderCharges(p []broker.OrderChargesParam) (any, error) {
	return m.orderCharges, m.orderChargesErr
}
func (m *mfMockBrokerClient) ConvertPosition(p broker.ConvertPositionParams) (bool, error) {
	return m.convertOK, m.convertErr
}

// --- Mock paper engine ---

type mockPaperEngine struct {
	enableErr  error
	disableErr error
	resetErr   error
	statusMap  map[string]any
	statusErr  error
}

func (m *mockPaperEngine) Enable(email string, cash float64) error  { return m.enableErr }
func (m *mockPaperEngine) Disable(email string) error               { return m.disableErr }
func (m *mockPaperEngine) Reset(email string) error                 { return m.resetErr }
func (m *mockPaperEngine) Status(email string) (map[string]any, error) {
	return m.statusMap, m.statusErr
}

// --- Mock ticker service ---

type mockTickerService struct {
	startErr       error
	stopErr        error
	subscribeErr   error
	unsubscribeErr error
	status         *ticker.Status
	statusErr      error
	running        bool
}

func (m *mockTickerService) Start(email, apiKey, accessToken string) error { return m.startErr }
func (m *mockTickerService) Stop(email string) error                       { return m.stopErr }
func (m *mockTickerService) Subscribe(email string, tokens []uint32, mode ticker.Mode) error {
	return m.subscribeErr
}
func (m *mockTickerService) Unsubscribe(email string, tokens []uint32) error {
	return m.unsubscribeErr
}
func (m *mockTickerService) GetStatus(email string) (*ticker.Status, error) {
	return m.status, m.statusErr
}
func (m *mockTickerService) IsRunning(email string) bool { return m.running }

// --- Mock trailing stop manager ---

type mockTrailingStopManager struct {
	addID     string
	addErr    error
	list      []*alerts.TrailingStop
	cancelErr error
}

func (m *mockTrailingStopManager) Add(ts *alerts.TrailingStop) (string, error) {
	return m.addID, m.addErr
}
func (m *mockTrailingStopManager) List(email string) []*alerts.TrailingStop { return m.list }
func (m *mockTrailingStopManager) Cancel(email, id string) error           { return m.cancelErr }
func (m *mockTrailingStopManager) CancelByEmail(email string)              {}

// --- Mock watchlist store ---

type mockWatchlistStore struct {
	createID       string
	createErr      error
	deleteErr      error
	watchlists     []*watchlist.Watchlist
	findByName     *watchlist.Watchlist
	itemCounts     map[string]int
	addItemErr     error
	removeItemErr  error
	items          []*watchlist.WatchlistItem
	findBySymbol   *watchlist.WatchlistItem
}

func (m *mockWatchlistStore) CreateWatchlist(email, name string) (string, error) {
	return m.createID, m.createErr
}
func (m *mockWatchlistStore) DeleteWatchlist(email, wlID string) error { return m.deleteErr }
func (m *mockWatchlistStore) DeleteByEmail(email string)               {}
func (m *mockWatchlistStore) ListWatchlists(email string) []*watchlist.Watchlist {
	return m.watchlists
}
func (m *mockWatchlistStore) FindWatchlistByName(email, name string) *watchlist.Watchlist {
	return m.findByName
}
func (m *mockWatchlistStore) ItemCount(wlID string) int {
	if m.itemCounts != nil {
		return m.itemCounts[wlID]
	}
	return 0
}
func (m *mockWatchlistStore) AddItem(email, wlID string, item *watchlist.WatchlistItem) error {
	return m.addItemErr
}
func (m *mockWatchlistStore) RemoveItem(email, wlID, itemID string) error { return m.removeItemErr }
func (m *mockWatchlistStore) GetItems(wlID string) []*watchlist.WatchlistItem { return m.items }
func (m *mockWatchlistStore) FindItemBySymbol(wlID, exchange, ts string) *watchlist.WatchlistItem {
	return m.findBySymbol
}

// --- Mock PnL service ---

type mockPnLService struct {
	result *alerts.PnLJournalResult
	err    error
}

func (m *mockPnLService) GetJournal(email, from, to string) (*alerts.PnLJournalResult, error) {
	return m.result, m.err
}

// ===========================================================================
// MF Orders Tests
// ===========================================================================

func TestGetMFOrders_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfOrders: []broker.MFOrder{{OrderID: "MF1"}}}
	uc := NewGetMFOrdersUseCase(&mockBrokerResolver{client: client}, testLogger())

	result, err := uc.Execute(context.Background(), cqrs.GetMFOrdersQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "MF1", result[0].OrderID)
}

func TestGetMFOrders_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMFOrdersUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFOrdersQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetMFOrders_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetMFOrdersUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFOrdersQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetMFOrders_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfOrdersErr: errors.New("api fail")}
	uc := NewGetMFOrdersUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFOrdersQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "get mf orders")
}

// ===========================================================================
// MF SIPs Tests
// ===========================================================================

func TestGetMFSIPs_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfSIPs: []broker.MFSIP{{SIPID: "SIP1"}}}
	uc := NewGetMFSIPsUseCase(&mockBrokerResolver{client: client}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetMFSIPsQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestGetMFSIPs_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMFSIPsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFSIPsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetMFSIPs_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetMFSIPsUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFSIPsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetMFSIPs_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfSIPsErr: errors.New("api fail")}
	uc := NewGetMFSIPsUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFSIPsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "get mf sips")
}

// ===========================================================================
// MF Holdings Tests
// ===========================================================================

func TestGetMFHoldings_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfHoldings: []broker.MFHolding{{Folio: "F1"}}}
	uc := NewGetMFHoldingsUseCase(&mockBrokerResolver{client: client}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetMFHoldingsQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestGetMFHoldings_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetMFHoldingsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFHoldingsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetMFHoldings_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetMFHoldingsUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFHoldingsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetMFHoldings_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{mfHoldingsErr: errors.New("api fail")}
	uc := NewGetMFHoldingsUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetMFHoldingsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "get mf holdings")
}

// ===========================================================================
// Place MF Order Tests
// ===========================================================================

func TestPlaceMFOrder_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{placeMFResp: broker.MFOrderResponse{OrderID: "MFO1"}}
	uc := NewPlaceMFOrderUseCase(&mockBrokerResolver{client: client}, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.PlaceMFOrderCommand{
		Email: "u@test.com", Tradingsymbol: "INF123", TransactionType: "BUY", Amount: 1000,
	})
	require.NoError(t, err)
	assert.Equal(t, "MFO1", resp.OrderID)
}

func TestPlaceMFOrder_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFOrderUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFOrderCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPlaceMFOrder_EmptySymbol(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFOrderUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFOrderCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "tradingsymbol is required")
}

func TestPlaceMFOrder_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFOrderUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFOrderCommand{Email: "u@test.com", Tradingsymbol: "INF123"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestPlaceMFOrder_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{placeMFErr: errors.New("api fail")}
	uc := NewPlaceMFOrderUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFOrderCommand{
		Email: "u@test.com", Tradingsymbol: "INF123",
	})
	assert.ErrorContains(t, err, "place mf order")
}

// ===========================================================================
// Cancel MF Order Tests
// ===========================================================================

func TestCancelMFOrder_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{cancelMFResp: broker.MFOrderResponse{OrderID: "MFO1"}}
	uc := NewCancelMFOrderUseCase(&mockBrokerResolver{client: client}, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.CancelMFOrderCommand{Email: "u@test.com", OrderID: "MFO1"})
	require.NoError(t, err)
	assert.Equal(t, "MFO1", resp.OrderID)
}

func TestCancelMFOrder_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFOrderUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFOrderCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestCancelMFOrder_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFOrderUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFOrderCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

func TestCancelMFOrder_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFOrderUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFOrderCommand{Email: "u@test.com", OrderID: "MFO1"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestCancelMFOrder_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{cancelMFErr: errors.New("api fail")}
	uc := NewCancelMFOrderUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFOrderCommand{Email: "u@test.com", OrderID: "MFO1"})
	assert.ErrorContains(t, err, "cancel mf order")
}

// ===========================================================================
// Place MF SIP Tests
// ===========================================================================

func TestPlaceMFSIP_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{placeSIPResp: broker.MFSIPResponse{SIPID: "SIP1"}}
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{client: client}, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{
		Email: "u@test.com", Tradingsymbol: "INF123", Amount: 500, Frequency: "monthly",
	})
	require.NoError(t, err)
	assert.Equal(t, "SIP1", resp.SIPID)
}

func TestPlaceMFSIP_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPlaceMFSIP_EmptySymbol(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "tradingsymbol is required")
}

func TestPlaceMFSIP_ZeroAmount(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{
		Email: "u@test.com", Tradingsymbol: "INF123", Amount: 0,
	})
	assert.ErrorContains(t, err, "amount must be positive")
}

func TestPlaceMFSIP_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{
		Email: "u@test.com", Tradingsymbol: "INF123", Amount: 500,
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestPlaceMFSIP_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{placeSIPErr: errors.New("api fail")}
	uc := NewPlaceMFSIPUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PlaceMFSIPCommand{
		Email: "u@test.com", Tradingsymbol: "INF123", Amount: 500,
	})
	assert.ErrorContains(t, err, "place mf sip")
}

// ===========================================================================
// Cancel MF SIP Tests
// ===========================================================================

func TestCancelMFSIP_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{cancelSIPResp: broker.MFSIPResponse{SIPID: "SIP1"}}
	uc := NewCancelMFSIPUseCase(&mockBrokerResolver{client: client}, testLogger())
	resp, err := uc.Execute(context.Background(), cqrs.CancelMFSIPCommand{Email: "u@test.com", SIPID: "SIP1"})
	require.NoError(t, err)
	assert.Equal(t, "SIP1", resp.SIPID)
}

func TestCancelMFSIP_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFSIPUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFSIPCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestCancelMFSIP_EmptySIPID(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFSIPUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFSIPCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "sip_id is required")
}

func TestCancelMFSIP_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewCancelMFSIPUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFSIPCommand{Email: "u@test.com", SIPID: "SIP1"})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestCancelMFSIP_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{cancelSIPErr: errors.New("api fail")}
	uc := NewCancelMFSIPUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CancelMFSIPCommand{Email: "u@test.com", SIPID: "SIP1"})
	assert.ErrorContains(t, err, "cancel mf sip")
}

// ===========================================================================
// Order Margins Tests
// ===========================================================================

func TestGetOrderMargins_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{orderMargins: map[string]float64{"total": 1000}}
	uc := NewGetOrderMarginsUseCase(&mockBrokerResolver{client: client}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetOrderMarginsQuery{
		Email: "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE", Tradingsymbol: "INFY", TransactionType: "BUY", Quantity: 1}},
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetOrderMargins_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderMarginsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetOrderMargins_NoOrders(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderMarginsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "at least one order")
}

func TestGetOrderMargins_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderMarginsUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderMarginsQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE"}},
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetOrderMargins_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{orderMarginsErr: errors.New("api fail")}
	uc := NewGetOrderMarginsUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderMarginsQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE"}},
	})
	assert.ErrorContains(t, err, "get order margins")
}

// ===========================================================================
// Basket Margins Tests
// ===========================================================================

func TestGetBasketMargins_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{basketMargins: map[string]float64{"total": 2000}}
	uc := NewGetBasketMarginsUseCase(&mockBrokerResolver{client: client}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetBasketMarginsQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE"}},
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetBasketMargins_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetBasketMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetBasketMarginsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetBasketMargins_NoOrders(t *testing.T) {
	t.Parallel()
	uc := NewGetBasketMarginsUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetBasketMarginsQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "at least one order")
}

func TestGetBasketMargins_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetBasketMarginsUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetBasketMarginsQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE"}},
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetBasketMargins_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{basketMarginsErr: errors.New("api fail")}
	uc := NewGetBasketMarginsUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetBasketMarginsQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderMarginQueryParam{{Exchange: "NSE"}},
	})
	assert.ErrorContains(t, err, "get basket margins")
}

// ===========================================================================
// Order Charges Tests
// ===========================================================================

func TestGetOrderCharges_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{orderCharges: map[string]float64{"brokerage": 20}}
	uc := NewGetOrderChargesUseCase(&mockBrokerResolver{client: client}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetOrderChargesQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderChargesQueryParam{{OrderID: "O1", Exchange: "NSE"}},
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetOrderCharges_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderChargesUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderChargesQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetOrderCharges_NoOrders(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderChargesUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderChargesQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "at least one order")
}

func TestGetOrderCharges_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewGetOrderChargesUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderChargesQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderChargesQueryParam{{OrderID: "O1"}},
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestGetOrderCharges_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{orderChargesErr: errors.New("api fail")}
	uc := NewGetOrderChargesUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetOrderChargesQuery{
		Email:  "u@test.com",
		Orders: []cqrs.OrderChargesQueryParam{{OrderID: "O1"}},
	})
	assert.ErrorContains(t, err, "get order charges")
}

// ===========================================================================
// Convert Position Tests
// ===========================================================================

func TestConvertPosition_Success(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{convertOK: true}
	uc := NewConvertPositionUseCase(&mockBrokerResolver{client: client}, testLogger())
	ok, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{
		Email: "u@test.com", Tradingsymbol: "INFY", Quantity: 10,
		OldProduct: "CNC", NewProduct: "MIS",
	})
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestConvertPosition_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewConvertPositionUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestConvertPosition_EmptySymbol(t *testing.T) {
	t.Parallel()
	uc := NewConvertPositionUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "tradingsymbol is required")
}

func TestConvertPosition_ZeroQuantity(t *testing.T) {
	t.Parallel()
	uc := NewConvertPositionUseCase(&mockBrokerResolver{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{
		Email: "u@test.com", Tradingsymbol: "INFY", Quantity: 0,
	})
	assert.ErrorContains(t, err, "quantity must be positive")
}

func TestConvertPosition_ResolveError(t *testing.T) {
	t.Parallel()
	uc := NewConvertPositionUseCase(&mockBrokerResolver{resolveErr: errors.New("no broker")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{
		Email: "u@test.com", Tradingsymbol: "INFY", Quantity: 10,
	})
	assert.ErrorContains(t, err, "resolve broker")
}

func TestConvertPosition_BrokerError(t *testing.T) {
	t.Parallel()
	client := &mfMockBrokerClient{convertErr: errors.New("api fail")}
	uc := NewConvertPositionUseCase(&mockBrokerResolver{client: client}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ConvertPositionCommand{
		Email: "u@test.com", Tradingsymbol: "INFY", Quantity: 10,
	})
	assert.ErrorContains(t, err, "convert position")
}

// ===========================================================================
// Paper Trading Toggle Tests
// ===========================================================================

func TestPaperTradingToggle_Enable(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{}, testLogger())
	msg, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{
		Email: "u@test.com", Enable: true, InitialCash: 500000,
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "ENABLED")
}

func TestPaperTradingToggle_EnableDefaultCash(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{}, testLogger())
	msg, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{
		Email: "u@test.com", Enable: true, InitialCash: 0,
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "10000000")
}

func TestPaperTradingToggle_Disable(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{}, testLogger())
	msg, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{
		Email: "u@test.com", Enable: false,
	})
	require.NoError(t, err)
	assert.Contains(t, msg, "DISABLED")
}

func TestPaperTradingToggle_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPaperTradingToggle_EnableError(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{enableErr: errors.New("fail")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{
		Email: "u@test.com", Enable: true, InitialCash: 500000,
	})
	assert.ErrorContains(t, err, "enable paper trading")
}

func TestPaperTradingToggle_DisableError(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingToggleUseCase(&mockPaperEngine{disableErr: errors.New("fail")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PaperTradingToggleCommand{
		Email: "u@test.com", Enable: false,
	})
	assert.ErrorContains(t, err, "disable paper trading")
}

// ===========================================================================
// Paper Trading Status Tests
// ===========================================================================

func TestPaperTradingStatus_Success(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingStatusUseCase(&mockPaperEngine{statusMap: map[string]any{"enabled": true}}, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.PaperTradingStatusQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Equal(t, true, result["enabled"])
}

func TestPaperTradingStatus_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingStatusUseCase(&mockPaperEngine{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PaperTradingStatusQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPaperTradingStatus_Error(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingStatusUseCase(&mockPaperEngine{statusErr: errors.New("fail")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.PaperTradingStatusQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "paper trading status")
}

// ===========================================================================
// Paper Trading Reset Tests
// ===========================================================================

func TestPaperTradingReset_Success(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingResetUseCase(&mockPaperEngine{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.PaperTradingResetCommand{Email: "u@test.com"})
	require.NoError(t, err)
}

func TestPaperTradingReset_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingResetUseCase(&mockPaperEngine{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.PaperTradingResetCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestPaperTradingReset_Error(t *testing.T) {
	t.Parallel()
	uc := NewPaperTradingResetUseCase(&mockPaperEngine{resetErr: errors.New("fail")}, testLogger())
	err := uc.Execute(context.Background(), cqrs.PaperTradingResetCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "reset paper trading")
}

// ===========================================================================
// PnL Journal Tests
// ===========================================================================

func TestGetPnLJournal_Success(t *testing.T) {
	t.Parallel()
	svc := &mockPnLService{result: &alerts.PnLJournalResult{}}
	uc := NewGetPnLJournalUseCase(svc, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.GetPnLJournalQuery{
		Email: "u@test.com", FromDate: "2026-01-01", ToDate: "2026-01-31",
	})
	require.NoError(t, err)
	assert.NotNil(t, result)
}

func TestGetPnLJournal_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewGetPnLJournalUseCase(&mockPnLService{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPnLJournalQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestGetPnLJournal_EmptyFromDate(t *testing.T) {
	t.Parallel()
	uc := NewGetPnLJournalUseCase(&mockPnLService{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPnLJournalQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "from_date is required")
}

func TestGetPnLJournal_EmptyToDate(t *testing.T) {
	t.Parallel()
	uc := NewGetPnLJournalUseCase(&mockPnLService{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPnLJournalQuery{Email: "u@test.com", FromDate: "2026-01-01"})
	assert.ErrorContains(t, err, "to_date is required")
}

func TestGetPnLJournal_ServiceError(t *testing.T) {
	t.Parallel()
	svc := &mockPnLService{err: errors.New("db fail")}
	uc := NewGetPnLJournalUseCase(svc, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.GetPnLJournalQuery{
		Email: "u@test.com", FromDate: "2026-01-01", ToDate: "2026-01-31",
	})
	assert.ErrorContains(t, err, "get pnl journal")
}

// ===========================================================================
// Start Ticker Tests
// ===========================================================================

func TestStartTicker_Success(t *testing.T) {
	t.Parallel()
	uc := NewStartTickerUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StartTickerCommand{
		Email: "u@test.com", APIKey: "key", AccessToken: "tok",
	})
	require.NoError(t, err)
}

func TestStartTicker_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewStartTickerUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StartTickerCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestStartTicker_EmptyToken(t *testing.T) {
	t.Parallel()
	uc := NewStartTickerUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StartTickerCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "access_token is required")
}

func TestStartTicker_Error(t *testing.T) {
	t.Parallel()
	uc := NewStartTickerUseCase(&mockTickerService{startErr: errors.New("fail")}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StartTickerCommand{
		Email: "u@test.com", AccessToken: "tok",
	})
	assert.ErrorContains(t, err, "start ticker")
}

// ===========================================================================
// Stop Ticker Tests
// ===========================================================================

func TestStopTicker_Success(t *testing.T) {
	t.Parallel()
	uc := NewStopTickerUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StopTickerCommand{Email: "u@test.com"})
	require.NoError(t, err)
}

func TestStopTicker_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewStopTickerUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StopTickerCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestStopTicker_Error(t *testing.T) {
	t.Parallel()
	uc := NewStopTickerUseCase(&mockTickerService{stopErr: errors.New("fail")}, testLogger())
	err := uc.Execute(context.Background(), cqrs.StopTickerCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "stop ticker")
}

// ===========================================================================
// Ticker Status Tests
// ===========================================================================

func TestTickerStatus_Success(t *testing.T) {
	t.Parallel()
	uc := NewTickerStatusUseCase(&mockTickerService{status: &ticker.Status{Running: true}}, testLogger())
	status, err := uc.Execute(context.Background(), cqrs.TickerStatusQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.True(t, status.Running)
}

func TestTickerStatus_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewTickerStatusUseCase(&mockTickerService{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TickerStatusQuery{})
	assert.ErrorContains(t, err, "email is required")
}

func TestTickerStatus_Error(t *testing.T) {
	t.Parallel()
	uc := NewTickerStatusUseCase(&mockTickerService{statusErr: errors.New("fail")}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.TickerStatusQuery{Email: "u@test.com"})
	assert.ErrorContains(t, err, "get ticker status")
}

// ===========================================================================
// Subscribe Instruments Tests
// ===========================================================================

func TestSubscribeInstruments_Success(t *testing.T) {
	t.Parallel()
	uc := NewSubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SubscribeInstrumentsCommand{
		Email: "u@test.com", Tokens: []uint32{256265}, Mode: "ltp",
	})
	require.NoError(t, err)
}

func TestSubscribeInstruments_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewSubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SubscribeInstrumentsCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestSubscribeInstruments_NoTokens(t *testing.T) {
	t.Parallel()
	uc := NewSubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SubscribeInstrumentsCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "at least one token")
}

func TestSubscribeInstruments_Error(t *testing.T) {
	t.Parallel()
	uc := NewSubscribeInstrumentsUseCase(&mockTickerService{subscribeErr: errors.New("fail")}, testLogger())
	err := uc.Execute(context.Background(), cqrs.SubscribeInstrumentsCommand{
		Email: "u@test.com", Tokens: []uint32{256265},
	})
	assert.ErrorContains(t, err, "subscribe instruments")
}

// ===========================================================================
// Unsubscribe Instruments Tests
// ===========================================================================

func TestUnsubscribeInstruments_Success(t *testing.T) {
	t.Parallel()
	uc := NewUnsubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UnsubscribeInstrumentsCommand{
		Email: "u@test.com", Tokens: []uint32{256265},
	})
	require.NoError(t, err)
}

func TestUnsubscribeInstruments_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewUnsubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UnsubscribeInstrumentsCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestUnsubscribeInstruments_NoTokens(t *testing.T) {
	t.Parallel()
	uc := NewUnsubscribeInstrumentsUseCase(&mockTickerService{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UnsubscribeInstrumentsCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "at least one token")
}

func TestUnsubscribeInstruments_Error(t *testing.T) {
	t.Parallel()
	uc := NewUnsubscribeInstrumentsUseCase(&mockTickerService{unsubscribeErr: errors.New("fail")}, testLogger())
	err := uc.Execute(context.Background(), cqrs.UnsubscribeInstrumentsCommand{
		Email: "u@test.com", Tokens: []uint32{256265},
	})
	assert.ErrorContains(t, err, "unsubscribe instruments")
}

// ===========================================================================
// resolveMode Tests
// ===========================================================================

func TestResolveMode(t *testing.T) {
	t.Parallel()
	assert.Equal(t, ticker.ModeLTP, resolveMode("ltp"))
	assert.Equal(t, ticker.ModeQuote, resolveMode("quote"))
	assert.Equal(t, ticker.ModeFull, resolveMode("full"))
	assert.Equal(t, ticker.ModeFull, resolveMode("unknown"))
	assert.Equal(t, ticker.ModeFull, resolveMode(""))
}

// ===========================================================================
// Set Trailing Stop Tests
// ===========================================================================

func TestSetTrailingStop_Success(t *testing.T) {
	t.Parallel()
	mgr := &mockTrailingStopManager{addID: "TS1"}
	uc := NewSetTrailingStopUseCase(mgr, testLogger())
	id, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{
		Email: "u@test.com", OrderID: "ORD1", CurrentStop: 100, ReferencePrice: 110,
	})
	require.NoError(t, err)
	assert.Equal(t, "TS1", id)
}

func TestSetTrailingStop_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewSetTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestSetTrailingStop_EmptyOrderID(t *testing.T) {
	t.Parallel()
	uc := NewSetTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "order_id is required")
}

func TestSetTrailingStop_ZeroCurrentStop(t *testing.T) {
	t.Parallel()
	uc := NewSetTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{
		Email: "u@test.com", OrderID: "ORD1", CurrentStop: 0,
	})
	assert.ErrorContains(t, err, "current_stop must be positive")
}

func TestSetTrailingStop_ZeroRefPrice(t *testing.T) {
	t.Parallel()
	uc := NewSetTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{
		Email: "u@test.com", OrderID: "ORD1", CurrentStop: 100,
	})
	assert.ErrorContains(t, err, "reference_price must be positive")
}

func TestSetTrailingStop_ManagerError(t *testing.T) {
	t.Parallel()
	mgr := &mockTrailingStopManager{addErr: errors.New("fail")}
	uc := NewSetTrailingStopUseCase(mgr, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.SetTrailingStopCommand{
		Email: "u@test.com", OrderID: "ORD1", CurrentStop: 100, ReferencePrice: 110,
	})
	assert.ErrorContains(t, err, "set trailing stop")
}

// ===========================================================================
// List Trailing Stops Tests
// ===========================================================================

func TestListTrailingStops_Success(t *testing.T) {
	t.Parallel()
	mgr := &mockTrailingStopManager{list: []*alerts.TrailingStop{{OrderID: "ORD1"}}}
	uc := NewListTrailingStopsUseCase(mgr, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ListTrailingStopsQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

func TestListTrailingStops_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListTrailingStopsUseCase(&mockTrailingStopManager{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ListTrailingStopsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

// ===========================================================================
// Cancel Trailing Stop Tests
// ===========================================================================

func TestCancelTrailingStop_Success(t *testing.T) {
	t.Parallel()
	uc := NewCancelTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.CancelTrailingStopCommand{
		Email: "u@test.com", TrailingStopID: "TS1",
	})
	require.NoError(t, err)
}

func TestCancelTrailingStop_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCancelTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.CancelTrailingStopCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestCancelTrailingStop_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewCancelTrailingStopUseCase(&mockTrailingStopManager{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.CancelTrailingStopCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "trailing_stop_id is required")
}

func TestCancelTrailingStop_Error(t *testing.T) {
	t.Parallel()
	mgr := &mockTrailingStopManager{cancelErr: errors.New("fail")}
	uc := NewCancelTrailingStopUseCase(mgr, testLogger())
	err := uc.Execute(context.Background(), cqrs.CancelTrailingStopCommand{
		Email: "u@test.com", TrailingStopID: "TS1",
	})
	assert.ErrorContains(t, err, "cancel trailing stop")
}

// ===========================================================================
// Create Watchlist Tests
// ===========================================================================

func TestCreateWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createID: "WL1"}
	uc := NewCreateWatchlistUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "u@test.com", Name: "My List",
	})
	require.NoError(t, err)
	assert.Equal(t, "WL1", result.ID)
	assert.Equal(t, "My List", result.Name)
}

func TestCreateWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewCreateWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestCreateWatchlist_EmptyName(t *testing.T) {
	t.Parallel()
	uc := NewCreateWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "watchlist name is required")
}

func TestCreateWatchlist_Duplicate(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{findByName: &watchlist.Watchlist{ID: "WL1", Name: "My List"}}
	uc := NewCreateWatchlistUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "u@test.com", Name: "My List",
	})
	assert.ErrorContains(t, err, "already exists")
}

func TestCreateWatchlist_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{createErr: errors.New("db fail")}
	uc := NewCreateWatchlistUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.CreateWatchlistCommand{
		Email: "u@test.com", Name: "My List",
	})
	assert.ErrorContains(t, err, "create watchlist")
}

// ===========================================================================
// Delete Watchlist Tests
// ===========================================================================

func TestDeleteWatchlist_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		watchlists: []*watchlist.Watchlist{{ID: "WL1", Name: "My List"}},
		itemCounts: map[string]int{"WL1": 3},
	}
	uc := NewDeleteWatchlistUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{
		Email: "u@test.com", WatchlistID: "WL1",
	})
	require.NoError(t, err)
	assert.Equal(t, "My List", result.Name)
	assert.Equal(t, 3, result.ItemCount)
}

func TestDeleteWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewDeleteWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestDeleteWatchlist_EmptyID(t *testing.T) {
	t.Parallel()
	uc := NewDeleteWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}

func TestDeleteWatchlist_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{deleteErr: errors.New("db fail")}
	uc := NewDeleteWatchlistUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.DeleteWatchlistCommand{
		Email: "u@test.com", WatchlistID: "WL1",
	})
	assert.ErrorContains(t, err, "delete watchlist")
}

// ===========================================================================
// List Watchlists Tests
// ===========================================================================

func TestListWatchlists_Success(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{
		watchlists: []*watchlist.Watchlist{
			{ID: "WL1", Name: "Tech", UpdatedAt: time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)},
			{ID: "WL2", Name: "Banks", UpdatedAt: time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC)},
		},
		itemCounts: map[string]int{"WL1": 5, "WL2": 3},
	}
	uc := NewListWatchlistsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ListWatchlistsQuery{Email: "u@test.com"})
	require.NoError(t, err)
	assert.Len(t, result, 2)
	assert.Equal(t, 5, result[0].ItemCount)
	assert.Equal(t, "Banks", result[1].Name)
}

func TestListWatchlists_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewListWatchlistsUseCase(&mockWatchlistStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ListWatchlistsQuery{})
	assert.ErrorContains(t, err, "email is required")
}

// ===========================================================================
// Remove From Watchlist Tests
// ===========================================================================

func TestRemoveFromWatchlist_Success(t *testing.T) {
	t.Parallel()
	uc := NewRemoveFromWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{
		Email: "u@test.com", WatchlistID: "WL1", ItemID: "IT1",
	})
	require.NoError(t, err)
}

func TestRemoveFromWatchlist_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewRemoveFromWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{})
	assert.ErrorContains(t, err, "email is required")
}

func TestRemoveFromWatchlist_EmptyWatchlistID(t *testing.T) {
	t.Parallel()
	uc := NewRemoveFromWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{Email: "u@test.com"})
	assert.ErrorContains(t, err, "watchlist_id is required")
}

func TestRemoveFromWatchlist_EmptyItemID(t *testing.T) {
	t.Parallel()
	uc := NewRemoveFromWatchlistUseCase(&mockWatchlistStore{}, testLogger())
	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{
		Email: "u@test.com", WatchlistID: "WL1",
	})
	assert.ErrorContains(t, err, "item_id is required")
}

func TestRemoveFromWatchlist_StoreError(t *testing.T) {
	t.Parallel()
	store := &mockWatchlistStore{removeItemErr: errors.New("db fail")}
	uc := NewRemoveFromWatchlistUseCase(store, testLogger())
	err := uc.Execute(context.Background(), cqrs.RemoveFromWatchlistCommand{
		Email: "u@test.com", WatchlistID: "WL1", ItemID: "IT1",
	})
	assert.ErrorContains(t, err, "remove from watchlist")
}
