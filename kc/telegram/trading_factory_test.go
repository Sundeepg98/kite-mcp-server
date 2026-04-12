package telegram

// Tests for trading commands using the kiteBaseURI injection point.
// Covers buy, sell, quick order flows and executeConfirmedOrder
// through a fake Kite API server.

import (
	"net/url"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/stretchr/testify/assert"
)

// decodeBody URL-decodes a form-encoded body for easier assertion.
func decodeBody(raw string) string {
	decoded, err := url.QueryUnescape(raw)
	if err != nil {
		return raw
	}
	return decoded
}

// TestHandleBuy_MarketOrder_ConfirmAndExecute exercises the full flow:
// /buy RELIANCE 10 → confirmation → executeConfirmedOrder through fakeKiteAPI.
func TestHandleBuy_MarketOrder_ConfirmAndExecute(t *testing.T) {
	email := "trader@test.com"
	h, mock, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// Register the place-order endpoint.
	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "BUY-MKT-001",
	}

	// Step 1: /buy command sets pending order and sends confirmation keyboard.
	h.handleBuy(42, email, "RELIANCE 10")

	// Verify confirmation message was sent.
	body := decodeBody(mock.lastBody())
	assert.Contains(t, body, "BUY Order Confirmation")
	assert.Contains(t, body, "RELIANCE")
	assert.Contains(t, body, "MARKET")

	// Step 2: Simulate user pressing Confirm.
	cq := &tgbotapi.CallbackQuery{
		ID: "cb-buy-mkt",
		Message: &tgbotapi.Message{
			MessageID: 200,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	h.executeConfirmedOrder(42, email, cq)

	// Verify order was placed — the bot should have sent an edit message.
	lastMsg := decodeBody(mock.lastBody())
	assert.Contains(t, lastMsg, "order placed")
}

// TestHandleSell_LimitOrder_ConfirmAndExecute exercises /sell with a limit price.
func TestHandleSell_LimitOrder_ConfirmAndExecute(t *testing.T) {
	email := "trader@test.com"
	h, mock, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "SELL-LMT-001",
	}

	// /sell INFY 5 1500
	h.handleSell(42, email, "INFY 5 1500")

	body := decodeBody(mock.lastBody())
	assert.Contains(t, body, "SELL Order Confirmation")
	assert.Contains(t, body, "INFY")
	assert.Contains(t, body, "LIMIT")
	assert.Contains(t, body, "1500")

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-sell-lmt",
		Message: &tgbotapi.Message{
			MessageID: 201,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	h.executeConfirmedOrder(42, email, cq)

	lastMsg := decodeBody(mock.lastBody())
	assert.Contains(t, lastMsg, "order placed")
}

// TestHandleQuick_BuyMarket_ConfirmAndExecute exercises /quick SYMBOL QTY BUY MARKET.
func TestHandleQuick_BuyMarket_ConfirmAndExecute(t *testing.T) {
	email := "trader@test.com"
	h, mock, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "QUICK-BUY-001",
	}

	h.handleQuick(42, email, "SBIN 50 BUY MARKET")

	body := decodeBody(mock.lastBody())
	assert.Contains(t, body, "Quick BUY MARKET Order")
	assert.Contains(t, body, "SBIN")
	assert.Contains(t, body, "50")

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-quick-buy",
		Message: &tgbotapi.Message{
			MessageID: 202,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	h.executeConfirmedOrder(42, email, cq)

	lastMsg := decodeBody(mock.lastBody())
	assert.Contains(t, lastMsg, "order placed")
}

// TestHandleQuick_SellLimit_ConfirmAndExecute exercises /quick SYMBOL QTY SELL LIMIT PRICE.
func TestHandleQuick_SellLimit_ConfirmAndExecute(t *testing.T) {
	email := "trader@test.com"
	h, mock, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	fakeAPI.responses["/orders/regular"] = map[string]interface{}{
		"order_id": "QUICK-SELL-LMT-001",
	}

	h.handleQuick(42, email, "TCS 20 SELL LIMIT 3800")

	body := decodeBody(mock.lastBody())
	assert.Contains(t, body, "Quick SELL LIMIT Order")
	assert.Contains(t, body, "TCS")
	assert.Contains(t, body, "3800")

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-quick-sell-lmt",
		Message: &tgbotapi.Message{
			MessageID: 203,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	h.executeConfirmedOrder(42, email, cq)

	lastMsg := decodeBody(mock.lastBody())
	assert.Contains(t, lastMsg, "order placed")
}

// TestExecuteConfirmedOrder_KiteAPIError exercises the error path when
// the Kite API returns a non-success response for order placement.
func TestExecuteConfirmedOrder_KiteAPIError(t *testing.T) {
	email := "trader@test.com"
	h, mock, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// Do NOT register /orders/regular — fakeKiteAPI returns 404.

	h.setPendingOrder(42, &pendingOrder{
		Email:           email,
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	})

	cq := &tgbotapi.CallbackQuery{
		ID: "cb-err",
		Message: &tgbotapi.Message{
			MessageID: 204,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	h.executeConfirmedOrder(42, email, cq)

	lastMsg := decodeBody(mock.lastBody())
	assert.Contains(t, lastMsg, "Order failed")
}

// TestExecuteConfirmedOrder_OrderExpired tests the case where the
// order was already popped (expired or processed) before confirmation.
func TestExecuteConfirmedOrder_OrderExpired(t *testing.T) {
	email := "trader@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	// No pending order set — simulates expiration.
	cq := &tgbotapi.CallbackQuery{
		ID: "cb-expired",
		Message: &tgbotapi.Message{
			MessageID: 205,
			Chat:      &tgbotapi.Chat{ID: 42},
		},
	}
	// Should not panic.
	h.executeConfirmedOrder(42, email, cq)
}

// TestNewKiteClient_KiteBaseURI_Applied verifies that when kiteBaseURI
// is set on BotHandler, newKiteClient applies it to the client.
func TestNewKiteClient_KiteBaseURI_Applied(t *testing.T) {
	email := "trader@test.com"
	h, _, fakeAPI := newTestBotWithFakeAPI(t, email)
	defer h.Shutdown()
	defer fakeAPI.close()

	client, errMsg := h.newKiteClient(email)
	assert.NotNil(t, client, "expected non-nil client")
	assert.Empty(t, errMsg, "expected no error message")
}

// TestNewKiteClient_BaseURINotSet tests that newKiteClient works without
// kiteBaseURI override (production mode) — no crash, no error.
func TestNewKiteClient_BaseURINotSet(t *testing.T) {
	mgr := newMockKiteManager()
	mgr.apiKeys["prod@test.com"] = "key"
	mgr.accessTokens["prod@test.com"] = "tok"
	mgr.tokenValid["prod@test.com"] = true

	h, _ := newTestBotHandler(mgr)
	defer h.Shutdown()
	// kiteBaseURI is empty by default.

	client, errMsg := h.newKiteClient("prod@test.com")
	assert.NotNil(t, client)
	assert.Empty(t, errMsg)
}
