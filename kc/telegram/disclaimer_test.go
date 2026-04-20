package telegram

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// TestDisclaimerPrefix_Constants verifies both constants carry the
// core "Not investment advice" language so grep-based compliance
// audits keep working if the constants are later renamed.
func TestDisclaimerPrefix_Constants(t *testing.T) {
	t.Parallel()
	if !strings.Contains(DisclaimerPrefix, "Not investment advice") {
		t.Errorf("DisclaimerPrefix missing 'Not investment advice': %q", DisclaimerPrefix)
	}
	if !strings.Contains(DisclaimerFullText, "SEBI-registered Investment Adviser") {
		t.Errorf("DisclaimerFullText missing SEBI-IA statement: %q", DisclaimerFullText)
	}
	if !strings.Contains(DisclaimerFullText, "SEBI-registered Research Analyst") {
		t.Errorf("DisclaimerFullText missing SEBI-RA statement: %q", DisclaimerFullText)
	}
	if !strings.Contains(DisclaimerFullText, "user-initiated") {
		t.Errorf("DisclaimerFullText missing user-initiated clause: %q", DisclaimerFullText)
	}
}

// TestWithDisclaimer_PrependsPrefix verifies the helper prepends the
// short banner verbatim.
func TestWithDisclaimer_PrependsPrefix(t *testing.T) {
	t.Parallel()
	body := "Your portfolio is up 2%."
	got := withDisclaimer(body)

	if !strings.HasPrefix(got, DisclaimerPrefix) {
		t.Errorf("withDisclaimer did not prepend prefix; got: %q", got)
	}
	if !strings.Contains(got, body) {
		t.Errorf("withDisclaimer dropped the body; got: %q", got)
	}
}

// decodeFormBody unwraps a url-encoded form body (which is how the
// Telegram SDK serialises a sendMessage call) and returns the "text"
// field. Used by tests below to assert on the actual wire payload.
func decodeFormBody(t *testing.T, body string) string {
	t.Helper()
	v, err := url.ParseQuery(body)
	if err != nil {
		return body // multipart or non-form — return raw
	}
	return v.Get("text")
}

// TestDisclaimerPrefix_OnFinancialMessage verifies that when a
// financial command (/portfolio) is dispatched the outbound text on
// the wire carries the disclaimer banner.
func TestDisclaimerPrefix_OnFinancialMessage(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// /portfolio goes through newKiteClient first, so with no creds
	// we see the credential-error branch — which is also a
	// financial message and MUST be prefixed.
	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/portfolio",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if mock.bodyCount() == 0 {
		t.Fatal("expected a message to be sent")
	}
	text := decodeFormBody(t, mock.lastBody())
	if !strings.Contains(text, "Not investment advice") {
		t.Errorf("expected financial reply to carry disclaimer banner; got: %q", text)
	}
}

// TestHelpCommandNotPrefixed verifies /help does NOT carry the
// disclaimer banner — the help screen is a meta-command, not a
// financial output, and prefixing it adds noise without legal value.
func TestHelpCommandNotPrefixed(t *testing.T) {
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
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if mock.bodyCount() == 0 {
		t.Fatal("expected help message to be sent")
	}
	text := decodeFormBody(t, mock.lastBody())
	if strings.Contains(text, "Not investment advice") {
		t.Errorf("/help should NOT carry disclaimer banner; got: %q", text)
	}
	// Sanity — it's the real help screen.
	if !strings.Contains(text, "Kite Trading Bot") {
		t.Errorf("expected help content; got: %q", text)
	}
}

// TestDisclaimerCommand verifies /disclaimer returns the long
// classification statement.
func TestDisclaimerCommand(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/disclaimer",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if mock.bodyCount() == 0 {
		t.Fatal("expected disclaimer message to be sent")
	}
	text := decodeFormBody(t, mock.lastBody())
	if !strings.Contains(text, "SEBI-registered Investment Adviser") {
		t.Errorf("/disclaimer should contain SEBI-IA statement; got: %q", text)
	}
	if !strings.Contains(text, "SEBI-registered Research Analyst") {
		t.Errorf("/disclaimer should contain SEBI-RA statement; got: %q", text)
	}
	// /disclaimer itself is meta — no banner on the classification
	// statement, otherwise we'd double up the wording.
	if strings.Contains(text, DisclaimerPrefix) {
		t.Errorf("/disclaimer output should not duplicate prefix banner; got: %q", text)
	}
}

// TestHandleDisclaimer_ReturnsFullText is a unit-level check that
// doesn't need the HTTP round-trip.
func TestHandleDisclaimer_ReturnsFullText(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	h, _ := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	got := h.handleDisclaimer(42)
	if got != DisclaimerFullText {
		t.Errorf("handleDisclaimer should return DisclaimerFullText verbatim; got: %q", got)
	}
}

// TestDisclaimerPrefix_OnTradingConfirmation verifies that /buy's
// confirmation card carries the disclaimer banner — trading
// confirmations are high-salience financial messages.
func TestDisclaimerPrefix_OnTradingConfirmation(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	h.handleBuy(42, "user@test.com", "RELIANCE 10 1500")

	if mock.bodyCount() == 0 {
		t.Fatal("expected confirmation message")
	}
	text := decodeFormBody(t, mock.lastBody())
	if !strings.Contains(text, "Not investment advice") {
		t.Errorf("/buy confirmation should carry disclaimer banner; got: %q", text)
	}
}

// TestDisclaimerPrefix_OnRateLimit verifies rate-limit messages are
// NOT prefixed — they're system errors, not financial messages.
// (This documents the intended scope; adjust if policy widens.)
func TestDisclaimerPrefix_NotOnRateLimit(t *testing.T) {
	t.Parallel()
	mgr := newMockKiteManager()
	mgr.tgStore = &mockTelegramLookup{emails: map[int64]string{42: "user@test.com"}}
	h, mock := newTestBotHandler(t, mgr)
	defer h.Shutdown()

	// Burn through the rate limit so the next call is rejected.
	for range maxCommandsPerMinute {
		h.allowCommand(42)
	}

	update := tgbotapi.Update{
		Message: &tgbotapi.Message{
			Text: "/portfolio",
			Chat: &tgbotapi.Chat{ID: 42, Type: "private"},
		},
	}
	body, _ := json.Marshal(update)
	req := httptest.NewRequest(http.MethodPost, "/telegram/webhook", bytes.NewReader(body))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if mock.bodyCount() == 0 {
		t.Fatal("expected rate-limit message")
	}
	text := decodeFormBody(t, mock.lastBody())
	if !strings.Contains(text, "Rate limit exceeded") {
		t.Errorf("expected rate-limit message, got: %q", text)
	}
	if strings.Contains(text, "Not investment advice") {
		t.Errorf("rate-limit message should not carry disclaimer banner; got: %q", text)
	}
}

// Compile-time guard: keep the helper exported for downstream code
// (e.g. briefing.go, future alerts) and make sure its signature is
// stable.
var _ = withDisclaimer
var _ = time.Now // keep import stable (may be used by future tests)
