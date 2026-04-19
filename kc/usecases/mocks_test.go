package usecases

// Shared mock infrastructure for kc/usecases tests.
//
// This file is the single source of truth for mock types used across
// multiple *_test.go files in this package. File-local mocks (used in
// only one test file) remain beside the tests that use them.
//
// When adding a new mock, decide:
//   - Used in only one test file  -> leave it next to those tests
//   - Used in 2+ test files       -> put it here
//   - Duplicates an existing mock -> reuse the canonical one from here

import (
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// =============================================================================
// Test helpers
// =============================================================================

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
}

// testPlaceCmd builds a PlaceOrderCommand from raw values for test convenience.
// Confirmed defaults to true because production callers (mcp/post_tools.go)
// always set it true after elicitation — tests that assert downstream
// riskguard checks (value, dedup, count, etc.) need to pass the
// RequireConfirmAllOrders gate first. Tests that specifically exercise the
// confirmation gate should build a PlaceOrderCommand inline with
// `Confirmed: false`.
func testPlaceCmd(email, exchange, symbol, txnType, orderType, product string, qty int, price float64) cqrs.PlaceOrderCommand {
	q, _ := domain.NewQuantity(qty)
	return cqrs.PlaceOrderCommand{
		Email:           email,
		Instrument:      domain.NewInstrumentKey(exchange, symbol),
		TransactionType: txnType,
		Qty:             q,
		Price:           domain.NewINR(price),
		OrderType:       orderType,
		Product:         product,
		Confirmed:       true,
	}
}

// =============================================================================
// Broker resolver / client
// =============================================================================

// mockBrokerResolver resolves a mock broker client.
type mockBrokerResolver struct {
	client     broker.Client
	resolveErr error
}

func (m *mockBrokerResolver) GetBrokerForEmail(email string) (broker.Client, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	return m.client, nil
}

// mockBrokerClient is a minimal in-memory broker for testing.
type mockBrokerClient struct {
	placedOrders []broker.OrderParams
	orders       []broker.Order
	holdings     []broker.Holding
	positions    broker.Positions
	placeErr     error

	// Configurable return values for all broker methods.
	profile         broker.Profile
	profileErr      error
	margins         broker.Margins
	marginsErr      error
	trades          []broker.Trade
	tradesErr       error
	orderHistory    []broker.Order
	orderHistoryErr error
	positionsErr    error
	ltpMap          map[string]broker.LTP
	ltpErr          error
	ohlcMap         map[string]broker.OHLC
	ohlcErr         error
	historicalData  []broker.HistoricalCandle
	historicalErr   error
	modifyResp      broker.OrderResponse
	modifyErr       error
	cancelResp      broker.OrderResponse
	cancelErr       error
	quotesMap       map[string]broker.Quote
	quotesErr       error
	orderTrades     []broker.Trade
	orderTradesErr  error
	gtts            []broker.GTTOrder
	gttsErr         error
	placeGTTResp    broker.GTTResponse
	placeGTTErr     error
	modifyGTTResp   broker.GTTResponse
	modifyGTTErr    error
	deleteGTTResp   broker.GTTResponse
	deleteGTTErr    error

	// Capture arguments for assertions.
	lastModifyOrderID string
	lastModifyParams  broker.OrderParams
	lastCancelOrderID string
	lastCancelVariety string
	lastOrderTradesID string
	lastGTTParams     broker.GTTParams
	lastModifyGTTID   int
	lastDeleteGTTID   int
}

func (m *mockBrokerClient) BrokerName() broker.Name { return "mock" }
func (m *mockBrokerClient) GetProfile() (broker.Profile, error) {
	return m.profile, m.profileErr
}
func (m *mockBrokerClient) GetMargins() (broker.Margins, error) {
	return m.margins, m.marginsErr
}
func (m *mockBrokerClient) GetHoldings() ([]broker.Holding, error) { return m.holdings, nil }
func (m *mockBrokerClient) GetPositions() (broker.Positions, error) {
	if m.positionsErr != nil {
		return broker.Positions{}, m.positionsErr
	}
	return m.positions, nil
}
func (m *mockBrokerClient) GetOrders() ([]broker.Order, error) { return m.orders, nil }
func (m *mockBrokerClient) GetOrderHistory(orderID string) ([]broker.Order, error) {
	return m.orderHistory, m.orderHistoryErr
}
func (m *mockBrokerClient) GetTrades() ([]broker.Trade, error) {
	return m.trades, m.tradesErr
}
func (m *mockBrokerClient) PlaceOrder(params broker.OrderParams) (broker.OrderResponse, error) {
	if m.placeErr != nil {
		return broker.OrderResponse{}, m.placeErr
	}
	m.placedOrders = append(m.placedOrders, params)
	return broker.OrderResponse{OrderID: fmt.Sprintf("ORD-%d", len(m.placedOrders))}, nil
}
func (m *mockBrokerClient) ModifyOrder(orderID string, params broker.OrderParams) (broker.OrderResponse, error) {
	m.lastModifyOrderID = orderID
	m.lastModifyParams = params
	return m.modifyResp, m.modifyErr
}
func (m *mockBrokerClient) CancelOrder(orderID string, variety string) (broker.OrderResponse, error) {
	m.lastCancelOrderID = orderID
	m.lastCancelVariety = variety
	return m.cancelResp, m.cancelErr
}
func (m *mockBrokerClient) GetLTP(instruments ...string) (map[string]broker.LTP, error) {
	return m.ltpMap, m.ltpErr
}
func (m *mockBrokerClient) GetOHLC(instruments ...string) (map[string]broker.OHLC, error) {
	return m.ohlcMap, m.ohlcErr
}
func (m *mockBrokerClient) GetHistoricalData(instrumentToken int, interval string, from, to time.Time) ([]broker.HistoricalCandle, error) {
	return m.historicalData, m.historicalErr
}
func (m *mockBrokerClient) GetQuotes(instruments ...string) (map[string]broker.Quote, error) {
	return m.quotesMap, m.quotesErr
}
func (m *mockBrokerClient) GetOrderTrades(orderID string) ([]broker.Trade, error) {
	m.lastOrderTradesID = orderID
	return m.orderTrades, m.orderTradesErr
}
func (m *mockBrokerClient) GetGTTs() ([]broker.GTTOrder, error) {
	return m.gtts, m.gttsErr
}
func (m *mockBrokerClient) PlaceGTT(params broker.GTTParams) (broker.GTTResponse, error) {
	m.lastGTTParams = params
	return m.placeGTTResp, m.placeGTTErr
}
func (m *mockBrokerClient) ModifyGTT(triggerID int, params broker.GTTParams) (broker.GTTResponse, error) {
	m.lastModifyGTTID = triggerID
	m.lastGTTParams = params
	return m.modifyGTTResp, m.modifyGTTErr
}
func (m *mockBrokerClient) DeleteGTT(triggerID int) (broker.GTTResponse, error) {
	m.lastDeleteGTTID = triggerID
	return m.deleteGTTResp, m.deleteGTTErr
}
func (m *mockBrokerClient) ConvertPosition(_ broker.ConvertPositionParams) (bool, error) {
	return true, nil
}
func (m *mockBrokerClient) GetMFOrders() ([]broker.MFOrder, error)     { return nil, nil }
func (m *mockBrokerClient) GetMFSIPs() ([]broker.MFSIP, error)         { return nil, nil }
func (m *mockBrokerClient) GetMFHoldings() ([]broker.MFHolding, error) { return nil, nil }
func (m *mockBrokerClient) PlaceMFOrder(_ broker.MFOrderParams) (broker.MFOrderResponse, error) {
	return broker.MFOrderResponse{}, nil
}
func (m *mockBrokerClient) CancelMFOrder(_ string) (broker.MFOrderResponse, error) {
	return broker.MFOrderResponse{}, nil
}
func (m *mockBrokerClient) PlaceMFSIP(_ broker.MFSIPParams) (broker.MFSIPResponse, error) {
	return broker.MFSIPResponse{}, nil
}
func (m *mockBrokerClient) CancelMFSIP(_ string) (broker.MFSIPResponse, error) {
	return broker.MFSIPResponse{}, nil
}
func (m *mockBrokerClient) GetOrderMargins(_ []broker.OrderMarginParam) (any, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetBasketMargins(_ []broker.OrderMarginParam, _ bool) (any, error) {
	return nil, nil
}
func (m *mockBrokerClient) GetOrderCharges(_ []broker.OrderChargesParam) (any, error) {
	return nil, nil
}

// holdingsErrClient is a broker client that returns an error on GetHoldings.
type holdingsErrClient struct {
	mockBrokerClient
}

func (c *holdingsErrClient) GetHoldings() ([]broker.Holding, error) {
	return nil, fmt.Errorf("holdings API error")
}

// =============================================================================
// Alert / instrument stores (shared)
// =============================================================================

// mockAlertStore is a minimal in-memory alert store.
type mockAlertStore struct {
	alerts map[string]string // alertID -> tradingsymbol
	addErr error
}

func (m *mockAlertStore) Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction) (string, error) {
	if m.addErr != nil {
		return "", m.addErr
	}
	id := fmt.Sprintf("ALT-%d", len(m.alerts)+1)
	m.alerts[id] = tradingsymbol
	return id, nil
}

func (m *mockAlertStore) AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction alerts.Direction, referencePrice float64) (string, error) {
	return m.Add(email, tradingsymbol, exchange, instrumentToken, targetPrice, direction)
}

// mockInstrumentResolver returns a fixed token.
type mockInstrumentResolver struct {
	token uint32
	err   error
}

func (m *mockInstrumentResolver) GetInstrumentToken(exchange, tradingsymbol string) (uint32, error) {
	if m.err != nil {
		return 0, m.err
	}
	return m.token, nil
}

// =============================================================================
// Account lifecycle mocks (credential / token / alert deletion)
//
// These were previously duplicated under a second set of names
// (mockCredUpdater / mockTokenStr / mockAlertDel) in usecases_edge_test.go.
// The canonical types live here.
// =============================================================================

type mockCredentialStore struct{ deleted bool }

func (m *mockCredentialStore) Delete(email string) { m.deleted = true }

type mockTokenStore struct{ deleted bool }

func (m *mockTokenStore) Delete(email string) { m.deleted = true }

type mockAlertDeleterStore struct{ deleted bool }

func (m *mockAlertDeleterStore) DeleteByEmail(email string) { m.deleted = true }

// =============================================================================
// Paper engine / ticker / trailing stop / watchlist / PnL
// (used by mf_usecases_test.go and usecases_edge_test.go)
// =============================================================================

type mockPaperEngine struct {
	enableErr  error
	disableErr error
	resetErr   error
	statusMap  map[string]any
	statusErr  error
}

func (m *mockPaperEngine) Enable(email string, cash float64) error { return m.enableErr }
func (m *mockPaperEngine) Disable(email string) error              { return m.disableErr }
func (m *mockPaperEngine) Reset(email string) error                { return m.resetErr }
func (m *mockPaperEngine) Status(email string) (map[string]any, error) {
	return m.statusMap, m.statusErr
}

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
func (m *mockTrailingStopManager) Cancel(email, id string) error            { return m.cancelErr }
func (m *mockTrailingStopManager) CancelByEmail(email string)               {}

type mockWatchlistStore struct {
	createID      string
	createErr     error
	deleteErr     error
	watchlists    []*watchlist.Watchlist
	findByName    *watchlist.Watchlist
	itemCounts    map[string]int
	addItemErr    error
	removeItemErr error
	items         []*watchlist.WatchlistItem
	findBySymbol  *watchlist.WatchlistItem
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
func (m *mockWatchlistStore) RemoveItem(email, wlID, itemID string) error     { return m.removeItemErr }
func (m *mockWatchlistStore) GetItems(wlID string) []*watchlist.WatchlistItem { return m.items }
func (m *mockWatchlistStore) FindItemBySymbol(wlID, exchange, ts string) *watchlist.WatchlistItem {
	return m.findBySymbol
}

type mockPnLService struct {
	result *alerts.PnLJournalResult
	err    error
}

func (m *mockPnLService) GetJournal(email, from, to string) (*alerts.PnLJournalResult, error) {
	return m.result, m.err
}
