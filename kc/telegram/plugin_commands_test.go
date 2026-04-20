package telegram

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// TestRegisterCommand_FiresOnMatch covers the happy path of the new
// plugin command registry: a plugin registers /echo, the user sends
// "/echo hello", and the registered handler runs with the raw args.
func TestRegisterCommand_FiresOnMatch(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	var gotEmail, gotArgs string
	var gotChatID int64
	err := h.RegisterCommand("/echo", func(ctx PluginCommandContext) string {
		gotEmail = ctx.Email
		gotArgs = ctx.Args
		gotChatID = ctx.ChatID
		return "pong: " + ctx.Args
	})
	if err != nil {
		t.Fatalf("RegisterCommand returned unexpected error: %v", err)
	}

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/echo hello world",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	if gotEmail != "user@test.com" {
		t.Errorf("expected email user@test.com; got %q", gotEmail)
	}
	if gotArgs != "hello world" {
		t.Errorf("expected args 'hello world'; got %q", gotArgs)
	}
	if gotChatID != 42 {
		t.Errorf("expected chatID 42; got %d", gotChatID)
	}
	// Response body should be sent to Telegram with our reply text.
	// BotAPI posts to /sendMessage with form-encoded body containing text.
	last := mock.lastBody()
	if last == "" {
		t.Fatal("expected at least one outbound Telegram message")
	}
	// Form-encoded bodies are %-escaped; decode to check the payload text.
	decoded := urlDecodeForm(last)
	if !strings.Contains(decoded, "pong: hello world") {
		t.Errorf("expected outbound body to contain response text; got %q", last)
	}
}

// TestRegisterCommand_DoesNotOverrideBuiltin confirms that a plugin
// attempting to register a built-in command (e.g. /price) is rejected
// with a clear error. Built-ins MUST win — a malicious plugin cannot
// hijack the /buy or /sell routing.
func TestRegisterCommand_DoesNotOverrideBuiltin(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	builtins := []string{
		"/price", "/portfolio", "/positions", "/orders", "/pnl",
		"/alerts", "/prices", "/mywatchlist", "/watchlist", "/status",
		"/help", "/start", "/disclaimer", "/buy", "/sell", "/quick", "/setalert",
	}
	for _, b := range builtins {
		err := h.RegisterCommand(b, func(ctx PluginCommandContext) string { return "hijacked" })
		if err == nil {
			t.Errorf("RegisterCommand(%q) should fail — built-in must not be overridable", b)
		}
	}
}

// TestRegisterCommand_RejectsInvalidName catches several malformed names:
// empty, missing leading slash, containing whitespace. The bot's
// parseCommand lowercases and trims, so registration validation should
// match the same shape.
func TestRegisterCommand_RejectsInvalidName(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	cases := []string{
		"",             // empty
		"echo",         // missing leading slash
		"/",            // slash only
		"/echo bar",    // embedded space
		"/echo\nbar",   // embedded newline
	}
	for _, name := range cases {
		err := h.RegisterCommand(name, func(ctx PluginCommandContext) string { return "" })
		if err == nil {
			t.Errorf("RegisterCommand(%q) should have rejected; got nil err", name)
		}
	}
}

// TestRegisterCommand_UnknownCommandStillEmitsDefault confirms that when
// no plugin handles a command, the pre-existing "Unknown command" banner
// still fires. Plugin registration is additive — it must NOT shadow the
// default-else path.
func TestRegisterCommand_UnknownCommandStillEmitsDefault(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Register /echo but send /nonexistent.
	_ = h.RegisterCommand("/echo", func(ctx PluginCommandContext) string { return "ignored" })

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/nonexistent",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if mock.bodyCount() == 0 {
		t.Fatal("expected outbound message")
	}
	decoded := urlDecodeForm(mock.lastBody())
	if !strings.Contains(decoded, "Unknown command") {
		t.Errorf("expected 'Unknown command' banner for unregistered commands; got %q", decoded)
	}
}

// TestRegisterCommand_LastWinsOnDuplicate — registering /echo twice
// replaces the first handler. Simple last-wins semantics mirror a
// typical singleton plugin lifecycle where a restart re-registers.
func TestRegisterCommand_LastWinsOnDuplicate(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	var firstCalls, secondCalls atomic.Int32
	_ = h.RegisterCommand("/echo", func(ctx PluginCommandContext) string {
		firstCalls.Add(1)
		return "first"
	})
	_ = h.RegisterCommand("/echo", func(ctx PluginCommandContext) string {
		secondCalls.Add(1)
		return "second"
	})

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/echo x",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if firstCalls.Load() != 0 {
		t.Errorf("first handler should be replaced; got %d calls", firstCalls.Load())
	}
	if secondCalls.Load() != 1 {
		t.Errorf("second handler should have run once; got %d calls", secondCalls.Load())
	}
	if !strings.Contains(urlDecodeForm(mock.lastBody()), "second") {
		t.Errorf("expected second reply; got %q", mock.lastBody())
	}
}

// TestRegisterCommand_PanicRecovered — a panicking plugin handler must
// not crash the webhook; the user should see an error message instead.
func TestRegisterCommand_PanicRecovered(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	_ = h.RegisterCommand("/boom", func(ctx PluginCommandContext) string {
		panic("kaboom")
	})

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/boom",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()

	// Must not panic. httptest recorder catches any panic the handler
	// propagates; our middleware must recover.
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("ServeHTTP propagated a panic to the outer scope: %v", r)
		}
	}()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", w.Code)
	}
	// Should still send a message (the error notice).
	if mock.bodyCount() == 0 {
		t.Fatal("expected an outbound error message after panic")
	}
}

// urlDecodeForm percent-decodes a form-encoded body so tests can match
// on the human-readable payload. BotAPI posts to sendMessage with
// `application/x-www-form-urlencoded`, so the body is `text=...`.
// Fallback: if parsing fails, return the raw string so the caller's
// Contains checks still have SOMETHING to match against.
func urlDecodeForm(body string) string {
	v, err := url.ParseQuery(body)
	if err != nil {
		return body
	}
	return v.Get("text")
}
