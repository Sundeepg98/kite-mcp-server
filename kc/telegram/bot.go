// Package telegram implements a Telegram bot webhook handler that provides
// read-only commands (/price, /portfolio, /positions, /orders, /pnl, /alerts,
// /prices, /mywatchlist, /status, /help) for registered users.
package telegram

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// KiteManager abstracts the kc.Manager methods needed by the bot handler.
// Using an interface avoids a circular import between kc and kc/telegram.
type KiteManager interface {
	AlertStore() *alerts.Store
	WatchlistStore() *watchlist.Store
	GetAPIKeyForEmail(email string) string
	GetAccessTokenForEmail(email string) string
	TelegramNotifier() *alerts.TelegramNotifier
	InstrumentsManager() *instruments.Manager
	IsTokenValid(email string) bool
}

// BotHandler handles incoming Telegram webhook updates and routes them
// to the appropriate command handler. It enforces that only private chats
// from registered users are served, with per-chat rate limiting.
type BotHandler struct {
	bot           *tgbotapi.BotAPI
	webhookSecret string
	manager       KiteManager
	logger        *slog.Logger

	// Per-chat rate limiting: 10 commands/minute
	rateMu     sync.Mutex
	rateWindow map[int64][]time.Time
}

// NewBotHandler creates a new BotHandler.
func NewBotHandler(bot *tgbotapi.BotAPI, webhookSecret string, manager KiteManager, logger *slog.Logger) *BotHandler {
	return &BotHandler{
		bot:           bot,
		webhookSecret: webhookSecret,
		manager:       manager,
		logger:        logger,
		rateWindow:    make(map[int64][]time.Time),
	}
}

const (
	maxCommandsPerMinute = 10
	maxBodyBytes         = 1 << 20 // 1 MB — Telegram updates are small
)

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
	store := h.manager.AlertStore()
	email, ok := store.GetEmailByChatID(chatID)
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

	var reply string
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
	default:
		reply = fmt.Sprintf("Unknown command: <code>%s</code>\nType /help for available commands.", escapeHTML(cmd))
	}

	if reply != "" {
		h.sendHTML(chatID, reply)
	}

	w.WriteHeader(http.StatusOK)
}

// sendHTML sends an HTML-formatted message to the given chat.
func (h *BotHandler) sendHTML(chatID int64, text string) {
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	msg.DisableWebPagePreview = true
	if _, err := h.bot.Send(msg); err != nil {
		h.logger.Error("Telegram bot: failed to send message",
			"chat_id", chatID, "error", err)
	}
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

// newKiteClient creates a Kite Connect client for the given email using
// stored credentials and token. Returns nil and an error message if
// credentials are missing or the token is expired.
func (h *BotHandler) newKiteClient(email string) (*kiteconnect.Client, string) {
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
	client := kiteconnect.New(apiKey)
	client.SetAccessToken(accessToken)
	return client, ""
}

// parseCommand splits "/cmd args" into (cmd, args).
func parseCommand(text string) (string, string) {
	// Strip @botname suffix from commands like /price@MyBot
	parts := strings.SplitN(text, " ", 2)
	cmd := strings.ToLower(parts[0])
	if i := strings.Index(cmd, "@"); i > 0 {
		cmd = cmd[:i]
	}
	args := ""
	if len(parts) > 1 {
		args = strings.TrimSpace(parts[1])
	}
	return cmd, args
}
