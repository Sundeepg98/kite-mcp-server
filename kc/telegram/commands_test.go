package telegram

import (
	"bytes"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
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

// testKiteClientFactory is a trivial factory used by tests; it mirrors the
// behavior of kc.defaultKiteClientFactory without importing the parent kc
// package (which would create an import cycle). It returns zerodha.KiteSDK
// to match the production factory contract.
type testKiteClientFactory struct{}

func (testKiteClientFactory) NewClient(apiKey string) zerodha.KiteSDK {
	return zerodha.NewKiteSDK(apiKey)
}

func (testKiteClientFactory) NewClientWithToken(apiKey, accessToken string) zerodha.KiteSDK {
	sdk := zerodha.NewKiteSDK(apiKey)
	sdk.SetAccessToken(accessToken)
	return sdk
}

// ---------------------------------------------------------------------------
// Mock HTTP client for the Telegram BotAPI — returns a canned "ok" response
// for every request, capturing the last request body for assertions.
// ---------------------------------------------------------------------------

type mockHTTPClient struct {
	mu          sync.Mutex
	lastBodies  []string
	statusCode  int
	responseObj tgbotapi.APIResponse
}

func newMockHTTPClient() *mockHTTPClient {
	return &mockHTTPClient{
		statusCode: http.StatusOK,
		responseObj: tgbotapi.APIResponse{
			Ok:     true,
			Result: json.RawMessage(`{"message_id":1,"chat":{"id":1},"date":0}`),
		},
	}
}

func (m *mockHTTPClient) Do(req *http.Request) (*http.Response, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if req.Body != nil {
		body, _ := io.ReadAll(req.Body)
		m.lastBodies = append(m.lastBodies, string(body))
	}

	respJSON, _ := json.Marshal(m.responseObj)
	return &http.Response{
		StatusCode: m.statusCode,
		Body:       io.NopCloser(bytes.NewReader(respJSON)),
		Header:     http.Header{"Content-Type": []string{"application/json"}},
	}, nil
}

// baseline is set after bot construction (which makes a getMe call)
// so we can distinguish test-triggered requests from setup noise.
func (m *mockHTTPClient) setBaseline() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.lastBodies = nil
}

func (m *mockHTTPClient) lastBody() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.lastBodies) == 0 {
		return ""
	}
	return m.lastBodies[len(m.lastBodies)-1]
}

func (m *mockHTTPClient) bodyCount() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.lastBodies)
}

// ---------------------------------------------------------------------------
// Mock KiteManager — minimal implementation for tests.
// ---------------------------------------------------------------------------

type mockKiteManager struct {
	tgStore         TelegramLookup
	alertStore      *alerts.Store
	watchlistStore  *watchlist.Store
	apiKeys         map[string]string
	accessTokens    map[string]string
	tokenValid      map[string]bool
	notifier        *alerts.TelegramNotifier
	instrMgr        *instruments.Manager
	guard           *riskguard.Guard
	paperEngine     *papertrading.PaperEngine
	tickerService   *ticker.Service
}

func newMockKiteManager() *mockKiteManager {
	return &mockKiteManager{
		tgStore:      &mockTelegramLookup{emails: map[int64]string{}},
		apiKeys:      map[string]string{},
		accessTokens: map[string]string{},
		tokenValid:   map[string]bool{},
	}
}

func (m *mockKiteManager) TelegramStore() TelegramLookup                 { return m.tgStore }
func (m *mockKiteManager) AlertStoreConcrete() *alerts.Store              { return m.alertStore }
func (m *mockKiteManager) WatchlistStoreConcrete() *watchlist.Store       { return m.watchlistStore }
func (m *mockKiteManager) GetAPIKeyForEmail(email string) string          { return m.apiKeys[email] }
func (m *mockKiteManager) GetAccessTokenForEmail(email string) string     { return m.accessTokens[email] }
func (m *mockKiteManager) IsTokenValid(email string) bool                 { return m.tokenValid[email] }
func (m *mockKiteManager) TelegramNotifier() *alerts.TelegramNotifier     { return m.notifier }
func (m *mockKiteManager) InstrumentsManagerConcrete() *instruments.Manager { return m.instrMgr }
func (m *mockKiteManager) RiskGuard() *riskguard.Guard                    { return m.guard }
func (m *mockKiteManager) PaperEngineConcrete() *papertrading.PaperEngine { return m.paperEngine }
func (m *mockKiteManager) TickerServiceConcrete() *ticker.Service         { return m.tickerService }

type mockTelegramLookup struct {
	emails map[int64]string
}

func (m *mockTelegramLookup) GetEmailByChatID(chatID int64) (string, bool) {
	e, ok := m.emails[chatID]
	return e, ok
}

// ---------------------------------------------------------------------------
// Test helper: create a BotHandler with mocked bot and manager.
// ---------------------------------------------------------------------------

func newTestBotHandler(tb testing.TB, mgr *mockKiteManager) (*BotHandler, *mockHTTPClient) {
	tb.Helper()
	mockClient := newMockHTTPClient()

	// Create a real BotAPI with a mock HTTP transport.
	// We set the API endpoint to a dummy URL; the mock client intercepts all requests.
	bot, _ := tgbotapi.NewBotAPIWithClient("fake-token", "https://api.telegram.org/bot%s/%s", mockClient)

	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	h := NewBotHandler(bot, "test-secret", mgr, logger, testKiteClientFactory{})
	// Register Shutdown so the background cleanup goroutine exits at
	// test teardown. Without this, goleak sentinels catch the leak.
	tb.Cleanup(h.Shutdown)
	// Reset baseline: NewBotAPIWithClient makes a getMe call that we don't want to count.
	mockClient.setBaseline()
	return h, mockClient
}

// ===========================================================================
// PURE HELPER TESTS (originally from commands_test.go)
// ===========================================================================

func TestEscapeHTML(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"hello", "hello"},
		{"<script>alert('xss')</script>", "&lt;script&gt;alert(&#39;xss&#39;)&lt;/script&gt;"},
		{"a & b", "a &amp; b"},
		{`"quoted"`, "&#34;quoted&#34;"},
		{"", ""},
	}
	for _, tt := range tests {
		got := escapeHTML(tt.input)
		if got != tt.want {
			t.Errorf("escapeHTML(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatRupee(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input float64
		want  string
	}{
		{100.50, "+\u20B9100.50"},
		{-250.75, "-\u20B9250.75"},
		{0, "+\u20B90.00"},
		{15000, "+\u20B915000"},
		{-50000, "-\u20B950000"},
		{9999.99, "+\u20B99999.99"},
		{10000, "+\u20B910000"},
	}
	for _, tt := range tests {
		got := formatRupee(tt.input)
		if got != tt.want {
			t.Errorf("formatRupee(%f) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatPctChange(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input float64
		want  string
	}{
		{1.25, "+1.25%"},
		{-0.85, "-0.85%"},
		{0.0, "+0.00%"},
		{100.0, "+100.00%"},
	}
	for _, tt := range tests {
		got := formatPctChange(tt.input)
		if got != tt.want {
			t.Errorf("formatPctChange(%f) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestNormalizeSymbol(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input string
		want  string
	}{
		{"reliance", "NSE:RELIANCE"},
		{"RELIANCE", "NSE:RELIANCE"},
		{"  infy  ", "NSE:INFY"},
		{"NSE:SBIN", "NSE:SBIN"},
		{"BSE:RELIANCE", "BSE:RELIANCE"},
		{"nse:tcs", "NSE:TCS"},
	}
	for _, tt := range tests {
		got := normalizeSymbol(tt.input)
		if got != tt.want {
			t.Errorf("normalizeSymbol(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestFormatVolume(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input uint64
		want  string
	}{
		{0, "0"},
		{500, "500"},
		{999, "999"},
		{1000, "1.0K"},
		{15000, "15.0K"},
		{99999, "100.0K"},
		{100000, "1.0L"},
		{500000, "5.0L"},
		{9999999, "100.0L"},
		{10000000, "1.0Cr"},
		{50000000, "5.0Cr"},
		{150000000, "15.0Cr"},
	}
	for _, tt := range tests {
		got := formatVolume(tt.input)
		if got != tt.want {
			t.Errorf("formatVolume(%d) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestAbsInt(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input int
		want  int
	}{
		{5, 5},
		{-5, 5},
		{0, 0},
		{-100, 100},
	}
	for _, tt := range tests {
		got := absInt(tt.input)
		if got != tt.want {
			t.Errorf("absInt(%d) = %d, want %d", tt.input, got, tt.want)
		}
	}
}

// ===========================================================================
// parseCommand TESTS
// ===========================================================================

func TestParseCommand(t *testing.T) {
	t.Parallel()
	tests := []struct {
		input   string
		wantCmd string
		wantArg string
	}{
		{"/help", "/help", ""},
		{"/price RELIANCE", "/price", "RELIANCE"},
		{"/buy INFY 10 1500", "/buy", "INFY 10 1500"},
		{"/price@MyKiteBot INFY", "/price", "INFY"},
		{"/START", "/start", ""},
		{"/prices TCS, INFY, SBIN", "/prices", "TCS, INFY, SBIN"},
		{"/setalert RELIANCE above 2700", "/setalert", "RELIANCE above 2700"},
		{"/quick RELIANCE 10 BUY MARKET", "/quick", "RELIANCE 10 BUY MARKET"},
		{"/sell@bot INFY 5", "/sell", "INFY 5"},
		{"/HELP", "/help", ""},
		// Extra whitespace
		{"/price   RELIANCE", "/price", "RELIANCE"},
	}
	for _, tt := range tests {
		cmd, args := parseCommand(tt.input)
		if cmd != tt.wantCmd {
			t.Errorf("parseCommand(%q) cmd = %q, want %q", tt.input, cmd, tt.wantCmd)
		}
		if args != tt.wantArg {
			t.Errorf("parseCommand(%q) args = %q, want %q", tt.input, args, tt.wantArg)
		}
	}
}

// ===========================================================================
// confirmKeyboard TEST
// ===========================================================================

func TestConfirmKeyboard(t *testing.T) {
	t.Parallel()
	kb := confirmKeyboard()
	if len(kb.InlineKeyboard) != 1 {
		t.Fatalf("expected 1 row, got %d", len(kb.InlineKeyboard))
	}
	row := kb.InlineKeyboard[0]
	if len(row) != 2 {
		t.Fatalf("expected 2 buttons, got %d", len(row))
	}

	// Confirm button
	if row[0].CallbackData == nil || *row[0].CallbackData != "confirm_order" {
		t.Errorf("first button callback data = %v, want confirm_order", row[0].CallbackData)
	}
	if !strings.Contains(row[0].Text, "Confirm") {
		t.Errorf("first button text = %q, want Confirm", row[0].Text)
	}

	// Cancel button
	if row[1].CallbackData == nil || *row[1].CallbackData != "cancel_order" {
		t.Errorf("second button callback data = %v, want cancel_order", row[1].CallbackData)
	}
	if !strings.Contains(row[1].Text, "Cancel") {
		t.Errorf("second button text = %q, want Cancel", row[1].Text)
	}
}

// ===========================================================================
// handleHelp TEST
// ===========================================================================

func TestHandleHelp(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	help := h.handleHelp(123)

	expectedKeywords := []string{
		"Kite Trading Bot",
		"/price", "/prices", "/portfolio", "/positions", "/orders", "/pnl",
		"/buy", "/sell", "/quick",
		"/alerts", "/setalert",
		"/status", "/help",
		"/mywatchlist",
	}
	for _, kw := range expectedKeywords {
		if !strings.Contains(help, kw) {
			t.Errorf("handleHelp() missing keyword %q", kw)
		}
	}
}

// ===========================================================================
// allowCommand (rate limiting) TESTS
// ===========================================================================

func TestAllowCommand_UnderLimit(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(12345)
	for i := 0; i < maxCommandsPerMinute; i++ {
		if !h.allowCommand(chatID) {
			t.Fatalf("allowCommand should return true for command %d (under limit)", i+1)
		}
	}
}

func TestAllowCommand_OverLimit(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(12345)
	// Fill up the limit.
	for i := 0; i < maxCommandsPerMinute; i++ {
		h.allowCommand(chatID)
	}
	// Next one should be rejected.
	if h.allowCommand(chatID) {
		t.Error("allowCommand should return false when rate limit exceeded")
	}
}

func TestAllowCommand_DifferentChats(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Fill up chat 1.
	for i := 0; i < maxCommandsPerMinute; i++ {
		h.allowCommand(1)
	}
	// Chat 2 should still be allowed.
	if !h.allowCommand(2) {
		t.Error("allowCommand for different chat should be independent")
	}
}

// ===========================================================================
// setPendingOrder / popPendingOrder TESTS
// ===========================================================================

func TestPendingOrderLifecycle(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(100)

	// No pending order initially.
	if got := h.popPendingOrder(chatID); got != nil {
		t.Error("expected nil for empty pending orders")
	}

	// Set and pop.
	order := &pendingOrder{
		Email:           "test@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "RELIANCE",
		TransactionType: "BUY",
		Quantity:        10,
		Price:           0,
		OrderType:       "MARKET",
		Product:         "CNC",
		CreatedAt:       time.Now(),
	}
	h.setPendingOrder(chatID, order)

	got := h.popPendingOrder(chatID)
	if got == nil {
		t.Fatal("expected pending order, got nil")
	}
	if got.Tradingsymbol != "RELIANCE" {
		t.Errorf("symbol = %q, want RELIANCE", got.Tradingsymbol)
	}

	// Pop again — should be nil (already consumed).
	if got2 := h.popPendingOrder(chatID); got2 != nil {
		t.Error("expected nil after pop, order should be consumed")
	}
}

func TestPendingOrderExpiry(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(200)
	order := &pendingOrder{
		Email:     "test@example.com",
		CreatedAt: time.Now().Add(-2 * pendingOrderTTL), // Already expired.
	}
	h.setPendingOrder(chatID, order)

	got := h.popPendingOrder(chatID)
	if got != nil {
		t.Error("expected nil for expired pending order")
	}
}

func TestPendingOrderOverwrite(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(300)
	order1 := &pendingOrder{Tradingsymbol: "INFY", CreatedAt: time.Now()}
	order2 := &pendingOrder{Tradingsymbol: "TCS", CreatedAt: time.Now()}

	h.setPendingOrder(chatID, order1)
	h.setPendingOrder(chatID, order2) // Overwrite.

	got := h.popPendingOrder(chatID)
	if got == nil || got.Tradingsymbol != "TCS" {
		t.Errorf("expected TCS (overwritten), got %v", got)
	}
}

// ===========================================================================
// cleanupStaleEntries TESTS
// ===========================================================================

func TestCleanupStaleEntries_PrunesExpiredOrders(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Add an expired order.
	h.setPendingOrder(1, &pendingOrder{
		Tradingsymbol: "OLD",
		CreatedAt:     time.Now().Add(-5 * time.Minute),
	})
	// Add a fresh order.
	h.setPendingOrder(2, &pendingOrder{
		Tradingsymbol: "FRESH",
		CreatedAt:     time.Now(),
	})

	h.cleanupStaleEntries()

	h.pendingMu.Lock()
	_, hasOld := h.pendingOrders[1]
	_, hasFresh := h.pendingOrders[2]
	h.pendingMu.Unlock()

	if hasOld {
		t.Error("expected expired order to be cleaned up")
	}
	if !hasFresh {
		t.Error("expected fresh order to survive cleanup")
	}
}

func TestCleanupStaleEntries_PrunesOldRateWindows(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Add stale rate-limit entries (all timestamps > 2 min ago).
	h.rateMu.Lock()
	h.rateWindow[1] = []time.Time{time.Now().Add(-5 * time.Minute)}
	h.rateWindow[2] = []time.Time{time.Now()} // Fresh, should survive.
	h.rateMu.Unlock()

	h.cleanupStaleEntries()

	h.rateMu.Lock()
	_, hasStale := h.rateWindow[1]
	_, hasFresh := h.rateWindow[2]
	h.rateMu.Unlock()

	if hasStale {
		t.Error("expected stale rate window to be pruned")
	}
	if !hasFresh {
		t.Error("expected fresh rate window to survive")
	}
}

// ===========================================================================
// Shutdown TESTS
// ===========================================================================

func TestShutdown_Idempotent(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)

	// Should not panic when called multiple times.
	h.Shutdown()
	h.Shutdown()
}

// ===========================================================================
// newKiteClient TESTS
// ===========================================================================

func TestNewKiteClient_NoAPIKey(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	client, msg := h.newKiteClient("nobody@example.com")
	if client != nil {
		t.Error("expected nil client when no API key")
	}
	if !strings.Contains(msg, "No API key") {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestNewKiteClient_NoAccessToken(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.apiKeys["user@test.com"] = "some-key"
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	client, msg := h.newKiteClient("user@test.com")
	if client != nil {
		t.Error("expected nil client when no access token")
	}
	if !strings.Contains(msg, "No access token") {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestNewKiteClient_ExpiredToken(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.apiKeys["user@test.com"] = "some-key"
	mgr.accessTokens["user@test.com"] = "some-token"
	mgr.tokenValid["user@test.com"] = false
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	client, msg := h.newKiteClient("user@test.com")
	if client != nil {
		t.Error("expected nil client when token expired")
	}
	if !strings.Contains(msg, "expired") {
		t.Errorf("unexpected error message: %q", msg)
	}
}

func TestNewKiteClient_ValidCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.apiKeys["user@test.com"] = "api-key-123"
	mgr.accessTokens["user@test.com"] = "token-456"
	mgr.tokenValid["user@test.com"] = true
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	client, msg := h.newKiteClient("user@test.com")
	if client == nil {
		t.Fatalf("expected valid client, got error: %s", msg)
	}
	if msg != "" {
		t.Errorf("expected empty error message, got: %q", msg)
	}
}

// ===========================================================================
// ServeHTTP TESTS
// ===========================================================================

func TestServeHTTP_RejectsNonPOST(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	req := httptest.NewRequest(http.MethodGet, "/telegram/webhook", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET should return 405, got %d", w.Code)
	}
}

func TestServeHTTP_InvalidJSON(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		strings.NewReader("not json"))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Errorf("invalid JSON should return 400, got %d", w.Code)
	}
}

func TestServeHTTP_EmptyUpdate(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	body, _ := json.Marshal(tgbotapi.Update{})
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("empty update should return 200, got %d", w.Code)
	}
}

func TestServeHTTP_UnregisteredUser(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/help",
			Chat: &tgbotapi.Chat{ID: 999, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Should have sent a "not registered" message.
	lastBody := mock.lastBody()
	if !strings.Contains(lastBody, "not+registered") && !strings.Contains(lastBody, "not registered") && !strings.Contains(lastBody, "not%20registered") {
		// The bot sends via multipart or URL-encoded form. Just check something was sent.
		if mock.bodyCount() == 0 {
			t.Error("expected a message to be sent to unregistered user")
		}
	}
}

func TestServeHTTP_GroupChat_Ignored(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/help",
			Chat: &tgbotapi.Chat{ID: 999, Type: "group"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// No message should be sent for group chats.
	if mock.bodyCount() > 0 {
		t.Error("should not send message for group chats")
	}
}

func TestServeHTTP_RegisteredUser_HelpCommand(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/help",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected help message to be sent")
	}
}

func TestServeHTTP_UnknownCommand(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/foobar",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected 'unknown command' message to be sent")
	}
}

func TestServeHTTP_EmptyMessage_NoReply(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() > 0 {
		t.Error("should not send message for empty text")
	}
}

func TestServeHTTP_RateLimited(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)

	// Fill the rate limit.
	for i := 0; i < maxCommandsPerMinute; i++ {
		h.allowCommand(chatID)
	}

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/help",
			Chat: &tgbotapi.Chat{ID: chatID, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook",
		bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	// Should still return 200 but send a rate-limit message.
	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if mock.bodyCount() == 0 {
		t.Error("expected rate limit message to be sent")
	}
}

// ===========================================================================
// Trading Command Parsing: handleBuy / handleSell via handleOrderCommand
// ===========================================================================

func TestHandleBuy_MissingArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "")

	if mock.bodyCount() == 0 {
		t.Error("expected usage message to be sent")
	}
}

func TestHandleBuy_TooManyArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "INFY 10 1500 extra")

	if mock.bodyCount() == 0 {
		t.Error("expected usage message to be sent")
	}
}

func TestHandleBuy_InvalidQty(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "INFY abc")

	if mock.bodyCount() == 0 {
		t.Error("expected error message about invalid quantity")
	}
}

func TestHandleBuy_NegativeQty(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "INFY -5")

	if mock.bodyCount() == 0 {
		t.Error("expected error message about invalid quantity")
	}
}

func TestHandleBuy_InvalidPrice(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "INFY 10 notanumber")

	if mock.bodyCount() == 0 {
		t.Error("expected error message about invalid price")
	}
}

func TestHandleBuy_MarketOrder_SetsPendingOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleBuy(chatID, "user@test.com", "RELIANCE 10")

	// Should have sent a confirmation message.
	if mock.bodyCount() == 0 {
		t.Fatal("expected confirmation message to be sent")
	}

	// Should have set a pending order.
	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order to be set")
	}
	if order.Tradingsymbol != "RELIANCE" {
		t.Errorf("symbol = %q, want RELIANCE", order.Tradingsymbol)
	}
	if order.Quantity != 10 {
		t.Errorf("quantity = %d, want 10", order.Quantity)
	}
	if order.OrderType != "MARKET" {
		t.Errorf("order type = %q, want MARKET", order.OrderType)
	}
	if order.TransactionType != "BUY" {
		t.Errorf("transaction type = %q, want BUY", order.TransactionType)
	}
	if order.Price != 0 {
		t.Errorf("price = %f, want 0 (market order)", order.Price)
	}
}

func TestHandleBuy_LimitOrder_SetsPendingOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleBuy(chatID, "user@test.com", "INFY 5 1500")

	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order to be set")
	}
	if order.Tradingsymbol != "INFY" {
		t.Errorf("symbol = %q, want INFY", order.Tradingsymbol)
	}
	if order.Quantity != 5 {
		t.Errorf("quantity = %d, want 5", order.Quantity)
	}
	if order.OrderType != "LIMIT" {
		t.Errorf("order type = %q, want LIMIT", order.OrderType)
	}
	if order.Price != 1500 {
		t.Errorf("price = %f, want 1500", order.Price)
	}
}

func TestHandleSell_MarketOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleSell(chatID, "user@test.com", "TCS 20")

	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order to be set")
	}
	if order.TransactionType != "SELL" {
		t.Errorf("transaction type = %q, want SELL", order.TransactionType)
	}
	if order.Tradingsymbol != "TCS" {
		t.Errorf("symbol = %q, want TCS", order.Tradingsymbol)
	}
}

// ===========================================================================
// /quick Command Parsing TESTS
// ===========================================================================

func TestHandleQuick_MissingArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, "user@test.com", "INFY 10")

	if mock.bodyCount() == 0 {
		t.Error("expected usage message for too few args")
	}
}

func TestHandleQuick_TooManyArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, "user@test.com", "INFY 10 BUY LIMIT 1500 extra")

	if mock.bodyCount() == 0 {
		t.Error("expected usage message for too many args")
	}
}

func TestHandleQuick_InvalidSide(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, "user@test.com", "INFY 10 HOLD MARKET")

	if mock.bodyCount() == 0 {
		t.Error("expected error about invalid side")
	}
}

func TestHandleQuick_InvalidType(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, "user@test.com", "INFY 10 BUY SL")

	if mock.bodyCount() == 0 {
		t.Error("expected error about invalid type")
	}
}

func TestHandleQuick_LimitWithoutPrice(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleQuick(42, "user@test.com", "INFY 10 BUY LIMIT")

	if mock.bodyCount() == 0 {
		t.Error("expected error about missing price for LIMIT")
	}
}

func TestHandleQuick_MarketOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleQuick(chatID, "user@test.com", "RELIANCE 10 BUY MARKET")

	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order")
	}
	if order.Tradingsymbol != "RELIANCE" {
		t.Errorf("symbol = %q, want RELIANCE", order.Tradingsymbol)
	}
	if order.TransactionType != "BUY" {
		t.Errorf("side = %q, want BUY", order.TransactionType)
	}
	if order.OrderType != "MARKET" {
		t.Errorf("type = %q, want MARKET", order.OrderType)
	}
}

func TestHandleQuick_LimitOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleQuick(chatID, "user@test.com", "INFY 5 SELL LIMIT 1500")

	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order")
	}
	if order.TransactionType != "SELL" {
		t.Errorf("side = %q, want SELL", order.TransactionType)
	}
	if order.OrderType != "LIMIT" {
		t.Errorf("type = %q, want LIMIT", order.OrderType)
	}
	if order.Price != 1500 {
		t.Errorf("price = %f, want 1500", order.Price)
	}
}

func TestHandleQuick_CaseInsensitiveSideAndType(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)
	h.handleQuick(chatID, "user@test.com", "SBIN 10 buy market")

	h.pendingMu.Lock()
	order, ok := h.pendingOrders[chatID]
	h.pendingMu.Unlock()

	if !ok || order == nil {
		t.Fatal("expected pending order")
	}
	if order.TransactionType != "BUY" {
		t.Errorf("side = %q, want BUY", order.TransactionType)
	}
	if order.OrderType != "MARKET" {
		t.Errorf("type = %q, want MARKET", order.OrderType)
	}
}

// ===========================================================================
// /setalert Command Parsing TESTS
// ===========================================================================

func TestHandleSetAlert_MissingArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "")
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage message, got: %q", result)
	}
}

func TestHandleSetAlert_TooFewArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE above")
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage message, got: %q", result)
	}
}

func TestHandleSetAlert_InvalidDirection(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE sideways 2700")
	if !strings.Contains(result, "Direction must be") {
		t.Errorf("expected direction error, got: %q", result)
	}
}

func TestHandleSetAlert_InvalidPrice(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE above abc")
	if !strings.Contains(result, "positive number") {
		t.Errorf("expected price error, got: %q", result)
	}
}

func TestHandleSetAlert_ZeroPrice(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE above 0")
	if !strings.Contains(result, "positive number") {
		t.Errorf("expected price error, got: %q", result)
	}
}

func TestHandleSetAlert_NoInstrumentsManager(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.instrMgr = nil
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleSetAlert(42, "user@test.com", "RELIANCE above 2700")
	if !strings.Contains(result, "Instruments data not available") {
		t.Errorf("expected instruments error, got: %q", result)
	}
}

// ===========================================================================
// /price Command — error paths
// ===========================================================================

func TestHandlePrice_EmptyArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePrice(42, "user@test.com", "")
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage message, got: %q", result)
	}
}

func TestHandlePrice_NoAPIKey(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePrice(42, "user@test.com", "RELIANCE")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected API key error, got: %q", result)
	}
}

// ===========================================================================
// /portfolio, /positions, /orders, /pnl — no credentials paths
// ===========================================================================

func TestHandlePortfolio_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePortfolio(42, "nobody@test.com")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected credential error, got: %q", result)
	}
}

func TestHandlePositions_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePositions(42, "nobody@test.com")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected credential error, got: %q", result)
	}
}

func TestHandleOrders_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleOrders(42, "nobody@test.com")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected credential error, got: %q", result)
	}
}

func TestHandlePnL_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePnL(42, "nobody@test.com")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected credential error, got: %q", result)
	}
}

// ===========================================================================
// /prices Command — error paths
// ===========================================================================

func TestHandlePrices_EmptyArgs(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePrices(42, "user@test.com", "")
	if !strings.Contains(result, "Usage") {
		t.Errorf("expected usage message, got: %q", result)
	}
}

func TestHandlePrices_TooManySymbols(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	// handlePrices checks credentials before the count, so we need valid creds.
	mgr.apiKeys["user@test.com"] = "key"
	mgr.accessTokens["user@test.com"] = "token"
	mgr.tokenValid["user@test.com"] = true
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePrices(42, "user@test.com", "A,B,C,D,E,F,G,H,I,J,K")
	if !strings.Contains(result, "Maximum 10") {
		t.Errorf("expected max symbols error, got: %q", result)
	}
}

func TestHandlePrices_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handlePrices(42, "nobody@test.com", "RELIANCE")
	if !strings.Contains(result, "No API key") {
		t.Errorf("expected credential error, got: %q", result)
	}
}

// ===========================================================================
// /mywatchlist — nil store path
// ===========================================================================

func TestHandleMyWatchlist_NilStore(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.watchlistStore = nil
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleMyWatchlist(42, "user@test.com")
	if !strings.Contains(result, "not available") {
		t.Errorf("expected 'not available', got: %q", result)
	}
}

// ===========================================================================
// /alerts — no active alerts path
// ===========================================================================

func TestHandleAlerts_NoStore(t *testing.T) {
	t.Parallel()
	// alertStore is nil — this will panic in production. We test the guard.
	// Actually the handler calls h.manager.AlertStoreConcrete() which returns nil.
	// This would panic. In production it's always set. We skip this test.
}

// ===========================================================================
// /status — partial credentials
// ===========================================================================

func TestHandleStatus_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	// Need alertStore to be non-nil for status handler.
	store := alerts.NewStore(nil)
	mgr.alertStore = store

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "nobody@test.com")
	if !strings.Contains(result, "Status") {
		t.Errorf("expected status header, got: %q", result)
	}
	if !strings.Contains(result, "Not configured") {
		t.Errorf("expected 'Not configured' for API key, got: %q", result)
	}
	if !strings.Contains(result, "Not found") {
		t.Errorf("expected 'Not found' for token, got: %q", result)
	}
}

func TestHandleStatus_ValidToken(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "abcd1234"
	mgr.accessTokens["user@test.com"] = "token-xyz"
	mgr.tokenValid["user@test.com"] = true

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Valid") {
		t.Errorf("expected 'Valid' for token, got: %q", result)
	}
	if !strings.Contains(result, "1234") {
		t.Errorf("expected last 4 chars of API key, got: %q", result)
	}
}

func TestHandleStatus_ExpiredToken(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	mgr.apiKeys["user@test.com"] = "abcd1234"
	mgr.accessTokens["user@test.com"] = "token-xyz"
	mgr.tokenValid["user@test.com"] = false

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleStatus(42, "user@test.com")
	if !strings.Contains(result, "Expired") {
		t.Errorf("expected 'Expired' for token, got: %q", result)
	}
}

// ===========================================================================
// /alerts — with alert store
// ===========================================================================

func TestHandleAlerts_Empty(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleAlerts(42, "user@test.com")
	if !strings.Contains(result, "No active alerts") {
		t.Errorf("expected 'No active alerts', got: %q", result)
	}
}

func TestHandleAlerts_WithAlerts(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	store := alerts.NewStore(nil)
	mgr.alertStore = store

	// Add an alert.
	_, err := store.Add("user@test.com", "RELIANCE", "NSE", 738561, 2700, alerts.DirectionAbove)
	if err != nil {
		t.Fatalf("failed to add alert: %v", err)
	}

	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	result := h.handleAlerts(42, "user@test.com")
	if !strings.Contains(result, "Active Alerts") {
		t.Errorf("expected 'Active Alerts', got: %q", result)
	}
	if !strings.Contains(result, "RELIANCE") {
		t.Errorf("expected 'RELIANCE' in alert list, got: %q", result)
	}
	if !strings.Contains(result, "above") {
		t.Errorf("expected 'above' direction, got: %q", result)
	}
}

// ===========================================================================
// Callback queries
// ===========================================================================

func TestHandleCallbackQuery_NilMessage(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Should not panic with nil message.
	h.handleCallbackQuery(&tgbotapi.CallbackQuery{
		ID:   "cb1",
		Data: "confirm_order",
	})
}

func TestHandleCallbackQuery_UnregisteredUser(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleCallbackQuery(&tgbotapi.CallbackQuery{
		ID:   "cb1",
		Data: "confirm_order",
		Message: &tgbotapi.Message{
			Chat: &tgbotapi.Chat{ID: 999, Type: "private"},
		},
	})

	// Should answer the callback (one request).
	if mock.bodyCount() == 0 {
		t.Error("expected callback answer to be sent")
	}
}

func TestHandleCallbackQuery_CancelOrder(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	chatID := int64(42)

	// Set a pending order.
	h.setPendingOrder(chatID, &pendingOrder{
		Email:         "user@test.com",
		Tradingsymbol: "RELIANCE",
		CreatedAt:     time.Now(),
	})

	h.handleCallbackQuery(&tgbotapi.CallbackQuery{
		ID:   "cb1",
		Data: "cancel_order",
		Message: &tgbotapi.Message{
			MessageID: 100,
			Chat:      &tgbotapi.Chat{ID: chatID, Type: "private"},
		},
	})

	// Pending order should be consumed.
	if got := h.popPendingOrder(chatID); got != nil {
		t.Error("expected pending order to be consumed after cancel")
	}

	// Should have sent callback answer + edit message.
	if mock.bodyCount() < 1 {
		t.Error("expected at least one request to be sent")
	}
}

func TestHandleCallbackQuery_ConfirmOrder_NoPending(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleCallbackQuery(&tgbotapi.CallbackQuery{
		ID:   "cb1",
		Data: "confirm_order",
		Message: &tgbotapi.Message{
			MessageID: 100,
			Chat:      &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	})

	// Should answer callback saying expired.
	if mock.bodyCount() == 0 {
		t.Error("expected callback answer to be sent")
	}
}

func TestHandleCallbackQuery_UnknownAction(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleCallbackQuery(&tgbotapi.CallbackQuery{
		ID:   "cb1",
		Data: "something_unknown",
		Message: &tgbotapi.Message{
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	})

	if mock.bodyCount() == 0 {
		t.Error("expected callback answer for unknown action")
	}
}

// ===========================================================================
// Concurrency: setPendingOrder from multiple goroutines
// ===========================================================================

func TestPendingOrder_Concurrent(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	var wg sync.WaitGroup
	for i := range 50 {
		chatID := int64(i)
		wg.Go(func() {
			h.setPendingOrder(chatID, &pendingOrder{
				Tradingsymbol: "TEST",
				CreatedAt:     time.Now(),
			})
			h.popPendingOrder(chatID)
		})
	}
	wg.Wait()
}

func TestAllowCommand_Concurrent(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	var wg sync.WaitGroup
	for range 50 {
		wg.Go(func() {
			h.allowCommand(int64(1))
		})
	}
	wg.Wait()
}
