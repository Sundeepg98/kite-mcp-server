package app

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/instruments"
)

// ===========================================================================
// mockBotAPI — implements alerts.BotAPI for testing registerTelegramWebhook
// ===========================================================================

type mockBotAPI struct {
	sentMessages   []tgbotapi.Chattable
	requestCalls   []tgbotapi.Chattable
}

func (m *mockBotAPI) Send(c tgbotapi.Chattable) (tgbotapi.Message, error) {
	m.sentMessages = append(m.sentMessages, c)
	return tgbotapi.Message{}, nil
}

func (m *mockBotAPI) Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error) {
	m.requestCalls = append(m.requestCalls, c)
	return &tgbotapi.APIResponse{Ok: true}, nil
}

// fakeTelegramAPIServer returns a test server that responds to Telegram bot API
// methods: getMe, setWebhook, setMyCommands — enough for registerTelegramWebhook.
func fakeTelegramAPIServer() *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
			"result": map[string]interface{}{
				"id":         12345,
				"is_bot":     true,
				"first_name": "TestBot",
				"username":   "test_bot",
			},
		})
	}))
}

// newTelegramTestManager creates a kc.Manager with a TelegramNotifier that uses
// a fake Telegram API server, bypassing real network calls.
//
// Uses kc.WithBotFactory for per-Manager bot injection — does NOT touch the
// kc/alerts package-level newBotFunc global, so multiple parallel tests can
// each carry their own factory without racing on the global mutex.
func newTelegramTestManager(t *testing.T, tgServerURL string) *kc.Manager {
	t.Helper()
	endpoint := tgServerURL + "/bot%s/%s"
	factory := func(token string) (alerts.BotAPI, error) {
		return tgbotapi.NewBotAPIWithClient(token, endpoint, &http.Client{})
	}

	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		kc.WithAlertDBPath(":memory:"),
		kc.WithTelegramBotToken("fake-telegram-token"),
		kc.WithBotFactory(factory),
	)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)
	return mgr
}

// ===========================================================================
// registerTelegramWebhook — success path: webhook + commands registered
// ===========================================================================

func TestRegisterTelegramWebhook_Success(t *testing.T) {
	t.Parallel()
	tgServer := fakeTelegramAPIServer()
	defer tgServer.Close()

	mgr := newTelegramTestManager(t, tgServer.URL)
	// Verify notifier is wired
	require.NotNil(t, mgr.TelegramNotifier(), "TelegramNotifier must be non-nil")
	require.NotNil(t, mgr.TelegramNotifier().Bot(), "Bot must be non-nil")

	app := newTestApp(t)
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-characters-long"
	app.Config.ExternalURL = tgServer.URL

	mux := http.NewServeMux()
	app.registerTelegramWebhook(mux, mgr)

	// After registerTelegramWebhook, app.telegramBot should be set
	assert.NotNil(t, app.telegramBot, "telegramBot handler should be wired after successful registration")
	// Close the BotHandler background cleanup goroutine when the test ends.
	// registerTelegramWebhook spawns one on success; without Shutdown() it
	// lingers past test teardown and trips the package goleak sentinel.
	t.Cleanup(func() {
		if app.telegramBot != nil {
			app.telegramBot.Shutdown()
		}
	})
}

// ===========================================================================
// registerTelegramWebhook — nil notifier early exit
// ===========================================================================

func TestRegisterTelegramWebhook_NilNotifier_Inject(t *testing.T) {
	t.Parallel()
	instrMgr, err := instruments.New(instruments.Config{
		Logger:   testLogger(),
		TestData: map[uint32]*instruments.Instrument{},
	})
	require.NoError(t, err)
	t.Cleanup(instrMgr.Shutdown)

	mgr, err := kc.NewWithOptions(context.Background(),
		kc.WithLogger(testLogger()),
		kc.WithKiteCredentials("test_key", "test_secret"),
		kc.WithDevMode(true),
		kc.WithInstrumentsManager(instrMgr),
		// No WithTelegramBotToken → TelegramNotifier() is nil
	)
	require.NoError(t, err)
	t.Cleanup(mgr.Shutdown)

	app := newTestApp(t)
	app.Config.OAuthJWTSecret = "test-jwt-secret-at-least-32-characters-long"
	app.Config.ExternalURL = "https://example.com"

	mux := http.NewServeMux()
	app.registerTelegramWebhook(mux, mgr)

	// Should exit early — telegramBot not set
	assert.Nil(t, app.telegramBot)
}
