package telegram

// push100_test.go — tests targeting remaining uncovered lines in kc/telegram.

import (
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
)

// ===========================================================================
// trading_commands.go:229-231 — paper trading PlaceOrder error
//
// This path fires when PaperEngineConcrete().IsEnabled(email) is true but
// PlaceOrder returns an error. We trigger this by closing the paper DB
// after enabling paper trading.
// ===========================================================================

func TestExecuteConfirmedOrder_PaperTradingError(t *testing.T) {
	email := "user@test.com"
	mgr := newMockKiteManager()
	mgr.apiKeys[email] = "test-api-key"
	mgr.accessTokens[email] = "test-access-token"
	mgr.tokenValid[email] = true
	mgr.tgStore.(*mockTelegramLookup).emails[42] = email

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()

	// Set up paper engine with a DB that will be closed.
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	dbPath := filepath.Join(t.TempDir(), "paper_err.db")
	paperDB, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	ptStore := papertrading.NewStore(paperDB, logger)
	if err := ptStore.InitTables(); err != nil {
		t.Fatalf("InitTables failed: %v", err)
	}
	pe := papertrading.NewEngine(ptStore, logger)
	pe.Enable(email, 10_00_000) // Enable paper trading
	t.Cleanup(func() { paperDB.Close() })

	mgr.paperEngine = pe

	// Set up a pending order.
	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        1,
		Price:           1500,
		OrderType:       "LIMIT",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	// Block order inserts via trigger so PlaceOrder fails.
	_ = paperDB.ExecDDL(`CREATE TRIGGER block_paper_orders BEFORE INSERT ON paper_orders BEGIN SELECT RAISE(FAIL, 'blocked for test'); END`)
	// Also block updates to paper_accounts so fillOrder fails.
	_ = paperDB.ExecDDL(`CREATE TRIGGER block_paper_accounts BEFORE UPDATE ON paper_accounts BEGIN SELECT RAISE(FAIL, 'blocked for test'); END`)

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-paper-err",
		Message: &tgbotapi.Message{
			MessageID: 400,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}

	// This should exercise the error path on line 229-231.
	h.executeConfirmedOrder(42, email, cq)
}
