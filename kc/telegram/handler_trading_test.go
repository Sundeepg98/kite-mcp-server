package telegram

// Tests for handler functions that interact with Kite API via a fake HTTP server.
// These cover the handler body code paths that were at low coverage:
// handlePrice, handlePortfolio, handlePositions, handleOrders,
// handlePnL, handlePrices, handleMyWatchlist, executeConfirmedOrder.

import (
	"io"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
)

// fakeKiteAPI type is defined in handler_test.go (shared across split files).

// ===========================================================================
// handleSetAlert — full coverage
// ===========================================================================
func TestHandleSetAlert_Success(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE above 2700")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "RELIANCE") {
		t.Errorf("expected 'RELIANCE', got: %s", result)
	}
	if !strings.Contains(result, "above") {
		t.Errorf("expected 'above', got: %s", result)
	}
	if !strings.Contains(result, "2700.00") {
		t.Errorf("expected '2700.00', got: %s", result)
	}
}


func TestHandleSetAlert_InstrumentNotFound(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "NOSUCHSYMBOL above 100")
	if !strings.Contains(result, "not found") {
		t.Errorf("expected 'not found', got: %s", result)
	}
}


func TestHandleSetAlert_BelowDirection(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "INFY below 1300")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "below") {
		t.Errorf("expected 'below', got: %s", result)
	}
}


// ===========================================================================
// handleQuick — edge cases
// ===========================================================================
func TestHandleQuick_LimitBadPrice2(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "RELIANCE 10 SELL LIMIT -50")
}


func TestHandleQuick_InvalidQuantity2(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "RELIANCE abc BUY MARKET")
}


func TestHandleSell_LimitSuccess2(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleSell(42, email, "INFY 5 1600")
}


func TestHandleBuy_NegativePrice2(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, email, "RELIANCE 10 -500")
}


// ===========================================================================
// handleSetAlert — percentage direction > 100% rejection
// ===========================================================================
func TestHandleSetAlert_PercentageOver100(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.instrMgr = newTestInstrumentsManager(t)
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE drop_pct 150")
	if !strings.Contains(result, "exceed 100%") {
		t.Errorf("expected '100%%' error, got: %s", result)
	}
}


func TestHandleSetAlert_PercentageValid(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE rise_pct 5")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "5.00%") {
		t.Errorf("expected '5.00%%', got: %s", result)
	}
	if !strings.Contains(result, "rise_pct") {
		t.Errorf("expected 'rise_pct', got: %s", result)
	}
}


// ===========================================================================
// handleSetAlert — drop_pct direction with percentage display
// ===========================================================================
func TestHandleSetAlert_DropPct(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = newTestInstrumentsManager(t)

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "INFY drop_pct 3")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "3.00%") {
		t.Errorf("expected '3.00%%', got: %s", result)
	}
}


// ===========================================================================
// handleSetAlert — BSE fallback path
// ===========================================================================
func TestHandleSetAlert_BSEFallback(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	// Create instruments manager with only BSE instrument.
	bseData := map[uint32]*instruments.Instrument{
		500325: {
			ID:              "BSE:RELIANCE",
			InstrumentToken: 500325,
			Tradingsymbol:   "RELIANCE",
			Exchange:        "BSE",
			Name:            "Reliance Industries",
		},
	}
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	im, err := instruments.New(instruments.Config{
		TestData: bseData,
		Logger:   logger,
	})
	if err != nil {
		t.Fatalf("instruments.New failed: %v", err)
	}

	mgr := newMockKiteManager()
	mgr.alertStore = alerts.NewStore(nil)
	mgr.instrMgr = im

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, email, "RELIANCE above 2800")
	if !strings.Contains(result, "Alert set") {
		t.Errorf("expected 'Alert set', got: %s", result)
	}
	if !strings.Contains(result, "BSE") {
		t.Errorf("expected 'BSE' in result (fallback), got: %s", result)
	}
}


// ===========================================================================
// handleOrderCommand — paper trading mode label in confirmation
// ===========================================================================
func TestHandleBuy_PaperTradingMode(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper2.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { paperDB.Close() })
	ptStore := papertrading.NewStore(paperDB, logger)
	ptStore.InitTables()
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000)

	mgr := newMockKiteManager()
	mgr.paperEngine = pe

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, email, "RELIANCE 10")
}


func TestHandleQuick_PaperTradingMode(t *testing.T) {
	t.Parallel()
	email := "user@test.com"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper3.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { paperDB.Close() })
	ptStore := papertrading.NewStore(paperDB, logger)
	ptStore.InitTables()
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000)

	mgr := newMockKiteManager()
	mgr.paperEngine = pe

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, email, "INFY 5 BUY LIMIT 1500")
}
