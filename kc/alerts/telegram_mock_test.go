package alerts

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeTelegramServer creates a httptest.Server that mimics the Telegram Bot API.
// It handles getMe and sendMessage endpoints. The returned server URL can be used
// with tgbotapi.NewBotAPIWithClient to create a bot that doesn't hit real Telegram.
//
// If failSend is true, the server returns an error response for sendMessage calls.
func fakeTelegramServer(failSend bool) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		// The URL pattern is /bot<token>/<method>
		path := r.URL.Path
		if strings.HasSuffix(path, "/getMe") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"id":         12345,
					"is_bot":     true,
					"first_name": "TestBot",
					"username":   "test_bot",
				},
			})
			return
		}

		if strings.HasSuffix(path, "/sendMessage") {
			if failSend {
				json.NewEncoder(w).Encode(map[string]interface{}{
					"ok":          false,
					"error_code":  400,
					"description": "Bad Request: chat not found",
				})
				return
			}
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"message_id": 1,
					"date":       1234567890,
					"chat": map[string]interface{}{
						"id":   12345,
						"type": "private",
					},
					"text": "ok",
				},
			})
			return
		}

		// Default: unknown method
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":          false,
			"error_code":  404,
			"description": "Not Found",
		})
	}))
}

// newMockBot creates a BotAPI connected to the given httptest server.
func newMockBot(t *testing.T, serverURL string) *tgbotapi.BotAPI {
	t.Helper()
	apiEndpoint := serverURL + "/bot%s/%s"
	bot, err := tgbotapi.NewBotAPIWithClient("fake_token", apiEndpoint, &http.Client{})
	require.NoError(t, err)
	return bot
}

// newTestNotifier creates a TelegramNotifier backed by a fake Telegram server.
// If failSend is true, sendMessage calls will return errors.
func newTestNotifier(t *testing.T, failSend bool) (*TelegramNotifier, *httptest.Server) {
	t.Helper()
	server := fakeTelegramServer(failSend)
	bot := newMockBot(t, server.URL)
	store := newTestStore()
	logger := slog.Default()
	notifier := &TelegramNotifier{
		bot:    bot,
		store:  store,
		logger: logger,
	}
	return notifier, server
}

// --- NewTelegramNotifier tests ---

func TestMock_NewTelegramNotifier_EmptyToken(t *testing.T) {
	store := newTestStore()
	logger := slog.Default()
	notifier, err := NewTelegramNotifier("", store, logger)
	assert.NoError(t, err)
	assert.Nil(t, notifier, "should return nil when token is empty")
}

func TestNewTelegramNotifier_WithMockServer(t *testing.T) {
	server := fakeTelegramServer(false)
	defer server.Close()

	// Override newBotFunc to route through our mock server.
	apiEndpoint := server.URL + "/bot%s/%s"
	origBotFunc := newBotFunc
	newBotFunc = func(token string) (*tgbotapi.BotAPI, error) {
		return tgbotapi.NewBotAPIWithClient(token, apiEndpoint, &http.Client{})
	}
	defer func() { newBotFunc = origBotFunc }()

	store := newTestStore()
	logger := slog.Default()
	notifier, err := NewTelegramNotifier("fake_token", store, logger)
	require.NoError(t, err)
	require.NotNil(t, notifier)
	assert.Equal(t, "test_bot", notifier.Bot().Self.UserName)
	assert.Equal(t, store, notifier.Store())
	assert.Equal(t, logger, notifier.Logger())
}

func TestNewTelegramNotifier_InvalidToken(t *testing.T) {
	// Create a server that returns an error for getMe
	errServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":          false,
			"error_code":  401,
			"description": "Unauthorized",
		})
	}))
	defer errServer.Close()

	// Override newBotFunc to route through our error server.
	apiEndpoint := errServer.URL + "/bot%s/%s"
	origBotFunc := newBotFunc
	newBotFunc = func(token string) (*tgbotapi.BotAPI, error) {
		return tgbotapi.NewBotAPIWithClient(token, apiEndpoint, &http.Client{})
	}
	defer func() { newBotFunc = origBotFunc }()

	store := newTestStore()
	logger := slog.Default()
	notifier, err := NewTelegramNotifier("bad_token", store, logger)
	assert.Error(t, err)
	assert.Nil(t, notifier)
	assert.Contains(t, err.Error(), "failed to create Telegram bot")
}

// --- SendMessage tests ---

func TestSendMessage_Success(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	err := notifier.SendMessage(12345, "Hello, world\\!")
	assert.NoError(t, err)
}

func TestSendMessage_Error(t *testing.T) {
	notifier, server := newTestNotifier(t, true)
	defer server.Close()

	err := notifier.SendMessage(12345, "Hello, world\\!")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chat not found")
}

func TestSendMessage_NilNotifier(t *testing.T) {
	var notifier *TelegramNotifier
	err := notifier.SendMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSendMessage_NilBot(t *testing.T) {
	notifier := &TelegramNotifier{bot: nil}
	err := notifier.SendMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// --- SendHTMLMessage tests ---

func TestSendHTMLMessage_Success(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	err := notifier.SendHTMLMessage(12345, "<b>Hello</b>")
	assert.NoError(t, err)
}

func TestSendHTMLMessage_Error(t *testing.T) {
	notifier, server := newTestNotifier(t, true)
	defer server.Close()

	err := notifier.SendHTMLMessage(12345, "<b>Hello</b>")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "chat not found")
}

func TestSendHTMLMessage_NilNotifier(t *testing.T) {
	var notifier *TelegramNotifier
	err := notifier.SendHTMLMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

func TestSendHTMLMessage_NilBot(t *testing.T) {
	notifier := &TelegramNotifier{bot: nil}
	err := notifier.SendHTMLMessage(12345, "test")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not initialized")
}

// --- Notify tests ---

func TestNotify_DirectionAbove(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	id, err := notifier.store.Add("user@test.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	require.Len(t, alerts, 1)

	notifier.Notify(alerts[0], 2510.0)

	// Verify notification was marked as sent
	alerts = notifier.store.List("user@test.com")
	assert.False(t, alerts[0].NotificationSentAt.IsZero(), "notification_sent_at should be set")
	_ = id
}

func TestNotify_DirectionBelow(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	_, err := notifier.store.Add("user@test.com", "INFY", "NSE", 408065, 1400.0, DirectionBelow)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	notifier.Notify(alerts[0], 1390.0)

	alerts = notifier.store.List("user@test.com")
	assert.False(t, alerts[0].NotificationSentAt.IsZero())
}

func TestNotify_DirectionDropPct(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	_, err := notifier.store.AddWithReferencePrice("user@test.com", "TCS", "NSE", 2953217, 5.0, DirectionDropPct, 3500.0)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	notifier.Notify(alerts[0], 3300.0) // dropped ~5.7% from 3500

	alerts = notifier.store.List("user@test.com")
	assert.False(t, alerts[0].NotificationSentAt.IsZero())
}

func TestNotify_DirectionRisePct(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	_, err := notifier.store.AddWithReferencePrice("user@test.com", "HDFCBANK", "NSE", 341249, 10.0, DirectionRisePct, 1500.0)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	notifier.Notify(alerts[0], 1660.0) // risen ~10.7% from 1500

	alerts = notifier.store.List("user@test.com")
	assert.False(t, alerts[0].NotificationSentAt.IsZero())
}

func TestNotify_SendFailure(t *testing.T) {
	notifier, server := newTestNotifier(t, true)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	_, err := notifier.store.Add("user@test.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	notifier.Notify(alerts[0], 2510.0)

	// On send failure, notification_sent_at should NOT be set
	alerts = notifier.store.List("user@test.com")
	assert.True(t, alerts[0].NotificationSentAt.IsZero(), "notification_sent_at should not be set on failure")
}

func TestNotify_NoChatID(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	// Don't set any chat ID for this user
	_, err := notifier.store.Add("nochat@test.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)
	require.NoError(t, err)

	alerts := notifier.store.List("nochat@test.com")
	// Should not panic; just log a warning and return
	notifier.Notify(alerts[0], 2510.0)

	alerts = notifier.store.List("nochat@test.com")
	assert.True(t, alerts[0].NotificationSentAt.IsZero())
}

func TestNotify_NilNotifier(t *testing.T) {
	var notifier *TelegramNotifier
	alert := &Alert{
		Email:         "user@test.com",
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		TargetPrice:   2500.0,
		Direction:     DirectionAbove,
	}
	// Should not panic
	notifier.Notify(alert, 2510.0)
}

func TestNotify_NilBot(t *testing.T) {
	notifier := &TelegramNotifier{bot: nil, store: newTestStore(), logger: slog.Default()}
	alert := &Alert{
		Email:         "user@test.com",
		Tradingsymbol: "RELIANCE",
		Exchange:      "NSE",
		TargetPrice:   2500.0,
		Direction:     DirectionAbove,
	}
	// Should not panic
	notifier.Notify(alert, 2510.0)
}

// --- Verify request content reaches the mock server ---

func TestSendMessage_VerifiesParseMode(t *testing.T) {
	var mu sync.Mutex
	var receivedParseMode string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"id": 12345, "is_bot": true, "first_name": "TestBot", "username": "test_bot",
				},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			_ = r.ParseForm()
			mu.Lock()
			receivedParseMode = r.FormValue("parse_mode")
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"message_id": 1, "date": 1234567890,
					"chat": map[string]interface{}{"id": 12345, "type": "private"},
					"text": "ok",
				},
			})
			return
		}
	}))
	defer server.Close()

	bot := newMockBot(t, server.URL)
	notifier := &TelegramNotifier{bot: bot, store: newTestStore(), logger: slog.Default()}

	err := notifier.SendMessage(12345, "test")
	require.NoError(t, err)

	mu.Lock()
	assert.Equal(t, "MarkdownV2", receivedParseMode)
	mu.Unlock()
}

func TestSendHTMLMessage_VerifiesParseMode(t *testing.T) {
	var mu sync.Mutex
	var receivedParseMode string

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.HasSuffix(r.URL.Path, "/getMe") {
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"id": 12345, "is_bot": true, "first_name": "TestBot", "username": "test_bot",
				},
			})
			return
		}
		if strings.HasSuffix(r.URL.Path, "/sendMessage") {
			_ = r.ParseForm()
			mu.Lock()
			receivedParseMode = r.FormValue("parse_mode")
			mu.Unlock()
			json.NewEncoder(w).Encode(map[string]interface{}{
				"ok": true,
				"result": map[string]interface{}{
					"message_id": 1, "date": 1234567890,
					"chat": map[string]interface{}{"id": 12345, "type": "private"},
					"text": "ok",
				},
			})
			return
		}
	}))
	defer server.Close()

	bot := newMockBot(t, server.URL)
	notifier := &TelegramNotifier{bot: bot, store: newTestStore(), logger: slog.Default()}

	err := notifier.SendHTMLMessage(12345, "<b>test</b>")
	require.NoError(t, err)

	mu.Lock()
	assert.Equal(t, "HTML", receivedParseMode)
	mu.Unlock()
}

// --- Accessor method tests ---

func TestTelegramNotifier_Bot(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	assert.NotNil(t, notifier.Bot())
}

func TestTelegramNotifier_Bot_Nil(t *testing.T) {
	var notifier *TelegramNotifier
	assert.Nil(t, notifier.Bot())
}

func TestTelegramNotifier_Store(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	assert.NotNil(t, notifier.Store())
}

func TestTelegramNotifier_Logger(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	assert.NotNil(t, notifier.Logger())
}

// --- EscapeMarkdown test ---

func TestEscapeMarkdown(t *testing.T) {
	input := "Hello_World *bold* [link](url) ~strike~ `code`"
	escaped := EscapeMarkdown(input)
	assert.Contains(t, escaped, "\\_")
	assert.Contains(t, escaped, "\\*")
	assert.Contains(t, escaped, "\\[")
	assert.Contains(t, escaped, "\\]")
	assert.Contains(t, escaped, "\\(")
	assert.Contains(t, escaped, "\\)")
	assert.Contains(t, escaped, "\\~")
	assert.Contains(t, escaped, "\\`")
}

func TestEscapeMarkdown_AllSpecialChars(t *testing.T) {
	specials := []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"}
	for _, ch := range specials {
		escaped := EscapeMarkdown(ch)
		assert.Equal(t, "\\"+ch, escaped, "should escape %q", ch)
	}
}

func TestEscapeMarkdown_NoSpecialChars(t *testing.T) {
	input := "Hello World 123"
	assert.Equal(t, input, EscapeMarkdown(input))
}

// --- Notify with ReferencePrice zero (edge case for percentage direction) ---

func TestNotify_DropPct_ZeroReferencePrice(t *testing.T) {
	notifier, server := newTestNotifier(t, false)
	defer server.Close()

	notifier.store.SetTelegramChatID("user@test.com", 12345)
	// Add with zero reference price — actualPct will be 0
	_, err := notifier.store.AddWithReferencePrice("user@test.com", "SBIN", "NSE", 779521, 5.0, DirectionDropPct, 0.0)
	require.NoError(t, err)

	alerts := notifier.store.List("user@test.com")
	notifier.Notify(alerts[0], 100.0)

	alerts = notifier.store.List("user@test.com")
	assert.False(t, alerts[0].NotificationSentAt.IsZero())
}
