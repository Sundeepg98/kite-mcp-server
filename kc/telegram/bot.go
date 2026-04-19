// Package telegram implements a Telegram bot webhook handler that provides
// read-only commands (/price, /portfolio, /positions, /orders, /pnl, /alerts,
// /prices, /mywatchlist, /status, /help) and trading commands (/buy, /sell,
// /quick, /setalert) with inline-keyboard confirmation for registered users.
package telegram

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/papertrading"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
	"github.com/zerodha/kite-mcp-server/kc/ticker"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// TelegramLookup abstracts the Telegram chat-ID-to-email mapping needed by the bot.
// Separated from alerts per Single Responsibility Principle.
type TelegramLookup interface {
	GetEmailByChatID(chatID int64) (string, bool)
}

// KiteClientFactory creates Kite API clients. Mirrors kc.KiteClientFactory
// to avoid a circular import between kc and kc/telegram. Returns the
// hexagonal zerodha.KiteSDK port rather than the concrete SDK client so
// trading commands can be exercised off-HTTP with zerodha.MockKiteSDK.
type KiteClientFactory interface {
	NewClient(apiKey string) zerodha.KiteSDK
	NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK
}

// KiteManager abstracts the kc.Manager methods needed by the bot handler.
// Using an interface avoids a circular import between kc and kc/telegram.
type KiteManager interface {
	TelegramStore() TelegramLookup
	AlertStoreConcrete() *alerts.Store
	WatchlistStoreConcrete() *watchlist.Store
	GetAPIKeyForEmail(email string) string
	GetAccessTokenForEmail(email string) string
	TelegramNotifier() *alerts.TelegramNotifier
	InstrumentsManagerConcrete() *instruments.Manager
	IsTokenValid(email string) bool

	// Trading support — riskguard, paper trading, ticker.
	RiskGuard() *riskguard.Guard
	PaperEngineConcrete() *papertrading.PaperEngine
	TickerServiceConcrete() *ticker.Service
}

// pendingOrder holds an order awaiting user confirmation via inline keyboard.
type pendingOrder struct {
	Email           string
	Exchange        string
	Tradingsymbol   string
	TransactionType string // BUY or SELL
	Quantity        int
	Price           float64 // 0 for MARKET
	OrderType       string  // MARKET or LIMIT
	Product         string  // CNC or MIS
	CreatedAt       time.Time
}

const (
	pendingOrderTTL = 60 * time.Second // auto-expire pending orders after 60s
)

// BotHandler handles incoming Telegram webhook updates and routes them
// to the appropriate command handler. It enforces that only private chats
// from registered users are served, with per-chat rate limiting.
type BotHandler struct {
	bot           alerts.BotAPI
	webhookSecret string
	manager       KiteManager
	logger        *slog.Logger

	// Per-chat rate limiting: 10 commands/minute
	rateMu     sync.Mutex
	rateWindow map[int64][]time.Time

	// Pending orders awaiting confirmation, keyed by chat ID.
	pendingMu     sync.Mutex
	pendingOrders map[int64]*pendingOrder

	// cleanupCancel stops the background cleanup goroutine.
	cleanupCancel context.CancelFunc

	// kiteBaseURI overrides the Kite API base URL (for testing).
	kiteBaseURI string

	// kiteClientFactory creates zerodha.KiteSDK instances. Required for trading.
	kiteClientFactory KiteClientFactory

	// tradingEnabled mirrors app.Config.EnableTrading. When false the
	// /buy, /sell, /quick commands return a polite "disabled in this
	// deployment" message instead of actually sending an order. The
	// zero value is *false*, so the hosted Fly.io path (which never
	// calls SetTradingEnabled) is safe by default; the constructor
	// initializes to true so local-dev tests and older call sites
	// retain the trading-on behaviour they relied on before Path 2.
	tradingEnabled bool
}

// NewBotHandler creates a new BotHandler and starts a background goroutine
// that periodically prunes stale rate-limit and pending-order entries.
// A nil factory disables trading commands (getClient returns an error).
//
// tradingEnabled defaults to *true* for back-compat with local/single-user
// builds and the existing test suite. The hosted multi-user server
// constructs this and then calls SetTradingEnabled(false) from
// app.Config.EnableTrading so /buy, /sell, /quick are gated consistently
// with the MCP tool gating.
func NewBotHandler(bot alerts.BotAPI, webhookSecret string, manager KiteManager, logger *slog.Logger, factory KiteClientFactory) *BotHandler {
	ctx, cancel := context.WithCancel(context.Background())
	h := &BotHandler{
		bot:               bot,
		webhookSecret:     webhookSecret,
		manager:           manager,
		logger:            logger,
		rateWindow:        make(map[int64][]time.Time),
		pendingOrders:     make(map[int64]*pendingOrder),
		cleanupCancel:     cancel,
		kiteClientFactory: factory,
		tradingEnabled:    true,
	}
	go h.runCleanup(ctx)
	return h
}

// SetTradingEnabled toggles the /buy, /sell, /quick Telegram commands on
// or off. Called once at wire-up from app.Config.EnableTrading so the
// Telegram surface matches the MCP tool gating (Path 2 compliance —
// NSE/INVG/69255 Annexure I Para 2.8 Algo Provider classification).
func (h *BotHandler) SetTradingEnabled(enabled bool) {
	h.tradingEnabled = enabled
}

// TradingEnabled reports the current trading-gate state. Exported so
// tests and admin tools can read it without reaching into unexported
// fields.
func (h *BotHandler) TradingEnabled() bool {
	return h.tradingEnabled
}

// tradingDisabledMessage is the polite refusal shown to users who run
// /buy, /sell, or /quick on a deployment where trading is gated off.
const tradingDisabledMessage = "\u26A0\uFE0F Trading commands are disabled in this deployment.\n\n" +
	"You can still use read-only commands: /portfolio, /positions, /orders, /pnl, /alerts, /prices, /status. " +
	"For order placement, run the server locally with <code>ENABLE_TRADING=true</code>."

const (
	maxCommandsPerMinute = 10
	maxBodyBytes         = 1 << 20 // 1 MB — Telegram updates are small
	cleanupInterval      = 2 * time.Minute
)

// runCleanup periodically prunes stale entries from rateWindow and pendingOrders
// to prevent unbounded memory growth from inactive chats.
func (h *BotHandler) runCleanup(ctx context.Context) {
	ticker := time.NewTicker(cleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C: // COVERAGE: unreachable in tests — requires 2-minute ticker wait; cleanupStaleEntries is tested directly
			h.cleanupStaleEntries()
		}
	}
}

// cleanupStaleEntries removes rate-limit entries where ALL timestamps are older
// than 2 minutes (no longer relevant for rate limiting) and pending orders that
// have exceeded the TTL.
func (h *BotHandler) cleanupStaleEntries() {
	now := time.Now()
	cutoff := now.Add(-cleanupInterval)

	// Prune stale rate-limit windows.
	h.rateMu.Lock()
	for chatID, times := range h.rateWindow {
		allStale := true
		for _, t := range times {
			if !t.Before(cutoff) {
				allStale = false
				break
			}
		}
		if allStale {
			delete(h.rateWindow, chatID)
		}
	}
	h.rateMu.Unlock()

	// Prune expired pending orders.
	h.pendingMu.Lock()
	for chatID, order := range h.pendingOrders {
		if now.Sub(order.CreatedAt) > pendingOrderTTL {
			delete(h.pendingOrders, chatID)
		}
	}
	h.pendingMu.Unlock()
}

// CleanupNow triggers an immediate cleanup of stale rate-limit and
// pending-order entries. Exposed for testing the cleanup logic without
// waiting for the background ticker.
func (h *BotHandler) CleanupNow() { h.cleanupStaleEntries() }

// Shutdown stops the background cleanup goroutine. It is safe to call
// multiple times.
func (h *BotHandler) Shutdown() {
	if h.cleanupCancel != nil {
		h.cleanupCancel()
	}
}

// ServeHTTP implements http.Handler. It validates the request, parses the
// Telegram update, and dispatches to the appropriate command handler.
func (h *BotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		h.logger.Error("Telegram webhook: failed to read body", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	var update tgbotapi.Update
	if err := json.Unmarshal(body, &update); err != nil {
		h.logger.Error("Telegram webhook: failed to parse update", "error", err)
		http.Error(w, "Bad request", http.StatusBadRequest)
		return
	}

	// Handle callback queries (inline keyboard button presses).
	if update.CallbackQuery != nil {
		h.handleCallbackQuery(update.CallbackQuery)
		w.WriteHeader(http.StatusOK)
		return
	}

	// Only handle text messages in private chats.
	if update.Message == nil || update.Message.Chat == nil {
		w.WriteHeader(http.StatusOK)
		return
	}
	if update.Message.Chat.Type != "private" {
		w.WriteHeader(http.StatusOK)
		return
	}

	chatID := update.Message.Chat.ID

	// Authentication: only respond to registered chat IDs.
	tgStore := h.manager.TelegramStore()
	email, ok := tgStore.GetEmailByChatID(chatID)
	if !ok {
		h.sendHTML(chatID, "You are not registered. Use the <code>/setup_telegram</code> MCP tool first.")
		w.WriteHeader(http.StatusOK)
		return
	}

	// Rate limit: 10 commands per minute per chat.
	if !h.allowCommand(chatID) {
		h.sendHTML(chatID, "Rate limit exceeded. Please wait a minute.")
		w.WriteHeader(http.StatusOK)
		return
	}

	text := strings.TrimSpace(update.Message.Text)
	if text == "" {
		w.WriteHeader(http.StatusOK)
		return
	}

	// Parse command and args.
	cmd, args := parseCommand(text)

	// isMeta captures commands whose reply is not a financial output
	// (help, disclaimer itself, unknown-command banner). Meta
	// messages MUST NOT carry the short disclaimer banner — see
	// disclaimer.go for the rationale.
	var (
		reply  string
		isMeta bool
	)
	switch cmd {
	case "/price":
		reply = h.handlePrice(chatID, email, args)
	case "/portfolio":
		reply = h.handlePortfolio(chatID, email)
	case "/positions":
		reply = h.handlePositions(chatID, email)
	case "/orders":
		reply = h.handleOrders(chatID, email)
	case "/pnl":
		reply = h.handlePnL(chatID, email)
	case "/alerts":
		reply = h.handleAlerts(chatID, email)
	case "/prices":
		reply = h.handlePrices(chatID, email, args)
	case "/mywatchlist":
		reply = h.handleMyWatchlist(chatID, email)
	case "/watchlist":
		// Backward compatibility: redirect to /prices
		reply = h.handlePrices(chatID, email, args)
	case "/status":
		reply = h.handleStatus(chatID, email)
	case "/help", "/start":
		reply = h.handleHelp(chatID)
		isMeta = true
	case "/disclaimer":
		reply = h.handleDisclaimer(chatID)
		isMeta = true
	// Trading commands — these write their own confirmation card
	// directly via sendFinancialHTMLWithKeyboard, so leave reply
	// empty.
	case "/buy":
		h.handleBuy(chatID, email, args)
	case "/sell":
		h.handleSell(chatID, email, args)
	case "/quick":
		h.handleQuick(chatID, email, args)
	case "/setalert":
		reply = h.handleSetAlert(chatID, email, args)
	default:
		reply = fmt.Sprintf("Unknown command: <code>%s</code>\nType /help for available commands.", escapeHTML(cmd))
		isMeta = true
	}

	if reply != "" {
		if isMeta {
			h.sendHTML(chatID, reply)
		} else {
			h.sendFinancialHTML(chatID, reply)
		}
	}

	w.WriteHeader(http.StatusOK)
}

// sendHTML sends an HTML-formatted message to the given chat.
// Callers MUST use this only for meta/system messages (help, rate
// limits, unregistered users, unknown commands). Financial replies
// must go through sendFinancialHTML so the SEBI classification
// banner is always present.
func (h *BotHandler) sendHTML(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	msg.DisableWebPagePreview = true
	if _, err := h.bot.Send(msg); err != nil {
		h.logger.Error("Telegram bot: failed to send message",
			"chat_id", chatID, "error", err)
	}
}

// sendFinancialHTML sends an HTML-formatted message prefixed with
// DisclaimerPrefix. Use this for any outbound message whose content
// touches prices, P&L, holdings, positions, orders, alerts, or order
// confirmations / errors. This is the SEBI classification-drift
// guardrail described in disclaimer.go.
func (h *BotHandler) sendFinancialHTML(chatID int64, text string) {
	h.sendHTML(chatID, withDisclaimer(text))
}

// sendFinancialHTMLWithKeyboard is the inline-keyboard counterpart
// for trading confirmations (/buy, /sell, /quick). Same disclaimer
// contract as sendFinancialHTML.
func (h *BotHandler) sendFinancialHTMLWithKeyboard(chatID int64, text string, keyboard tgbotapi.InlineKeyboardMarkup) {
	h.sendHTMLWithKeyboard(chatID, withDisclaimer(text), keyboard)
}

// allowCommand enforces the per-chat rate limit.
func (h *BotHandler) allowCommand(chatID int64) bool {
	h.rateMu.Lock()
	defer h.rateMu.Unlock()

	now := time.Now()
	cutoff := now.Add(-time.Minute)

	// Trim old entries.
	times := h.rateWindow[chatID]
	start := 0
	for start < len(times) && times[start].Before(cutoff) {
		start++
	}
	times = times[start:]

	if len(times) >= maxCommandsPerMinute {
		h.rateWindow[chatID] = times
		return false
	}

	h.rateWindow[chatID] = append(times, now)
	return true
}

// newKiteClient creates a Kite SDK client for the given email using
// stored credentials and token. Returns nil and an error message if
// credentials are missing or the token is expired. The return type is
// the zerodha.KiteSDK port so command handlers depend on the broker
// interface rather than the concrete gokiteconnect client — test
// builds can swap in zerodha.MockKiteSDK via the factory without
// standing up an httptest server.
func (h *BotHandler) newKiteClient(email string) (zerodha.KiteSDK, string) {
	apiKey := h.manager.GetAPIKeyForEmail(email)
	if apiKey == "" {
		return nil, "No API key found. Please re-login via MCP."
	}
	accessToken := h.manager.GetAccessTokenForEmail(email)
	if accessToken == "" {
		return nil, "No access token found. Please re-login via MCP."
	}
	if !h.manager.IsTokenValid(email) {
		return nil, "Kite token expired. Please re-login via MCP."
	}
	if h.kiteClientFactory == nil {
		return nil, "Internal error: Kite client factory not configured."
	}
	client := h.kiteClientFactory.NewClientWithToken(apiKey, accessToken)
	if h.kiteBaseURI != "" {
		client.SetBaseURI(h.kiteBaseURI)
	}
	return client, ""
}

// sendHTMLWithKeyboard sends an HTML-formatted message with an inline keyboard.
func (h *BotHandler) sendHTMLWithKeyboard(chatID int64, text string, keyboard tgbotapi.InlineKeyboardMarkup) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	msg.DisableWebPagePreview = true
	msg.ReplyMarkup = keyboard
	if _, err := h.bot.Send(msg); err != nil {
		h.logger.Error("Telegram bot: failed to send message with keyboard",
			"chat_id", chatID, "error", err)
	}
}

// handleCallbackQuery processes inline keyboard button presses for order confirmation.
func (h *BotHandler) handleCallbackQuery(cq *tgbotapi.CallbackQuery) {
	if cq.Message == nil || cq.Message.Chat == nil {
		return
	}
	chatID := cq.Message.Chat.ID

	// Authenticate the callback sender.
	tgStore := h.manager.TelegramStore()
	email, ok := tgStore.GetEmailByChatID(chatID)
	if !ok {
		h.answerCallback(cq.ID, "Not registered.")
		return
	}

	data := cq.Data
	switch data {
	case "confirm_order":
		h.executeConfirmedOrder(chatID, email, cq)
	case "cancel_order":
		h.cancelPendingOrder(chatID, cq)
	default:
		h.answerCallback(cq.ID, "Unknown action.")
	}
}

// answerCallback acknowledges a callback query with an optional toast message.
func (h *BotHandler) answerCallback(callbackID, text string) {
	callback := tgbotapi.NewCallback(callbackID, text)
	if _, err := h.bot.Request(callback); err != nil {
		h.logger.Error("Telegram bot: failed to answer callback", "error", err)
	}
}

// editMessage replaces the text (and removes the keyboard) of an existing message.
// Callers should use editFinancialMessage for any content that touches
// orders, P&L, holdings, or alerts. This raw variant is for meta
// text like "order cancelled" that doesn't contain financial data.
func (h *BotHandler) editMessage(chatID int64, messageID int, newText string) {
	edit := tgbotapi.NewEditMessageText(chatID, messageID, newText)
	edit.ParseMode = tgbotapi.ModeHTML
	if _, err := h.bot.Send(edit); err != nil {
		h.logger.Error("Telegram bot: failed to edit message",
			"chat_id", chatID, "message_id", messageID, "error", err)
	}
}

// editFinancialMessage edits an existing message, prepending the
// disclaimer banner. Used by order-result updates after the user
// taps Confirm / Cancel on a pending trade card.
func (h *BotHandler) editFinancialMessage(chatID int64, messageID int, newText string) {
	h.editMessage(chatID, messageID, withDisclaimer(newText))
}

// setPendingOrder stores a pending order for the given chat, replacing any previous one.
func (h *BotHandler) setPendingOrder(chatID int64, order *pendingOrder) {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	h.pendingOrders[chatID] = order
}

// popPendingOrder retrieves and removes the pending order for the given chat.
// Returns nil if no pending order exists or if it has expired.
func (h *BotHandler) popPendingOrder(chatID int64) *pendingOrder {
	h.pendingMu.Lock()
	defer h.pendingMu.Unlock()
	order, ok := h.pendingOrders[chatID]
	if !ok {
		return nil
	}
	delete(h.pendingOrders, chatID)
	if time.Since(order.CreatedAt) > pendingOrderTTL {
		return nil // expired
	}
	return order
}

// parseCommand splits "/cmd args" into (cmd, args).
func parseCommand(text string) (string, string) {
	// Strip @botname suffix from commands like /price@MyBot
	parts := strings.SplitN(text, " ", 2)
	cmd := strings.ToLower(parts[0])
	if before, _, ok := strings.Cut(cmd, "@"); ok && before != "" {
		cmd = before
	}
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}
	return cmd, args
}
