package telegramnotify

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// --- test doubles ---

type fakeUserLookup struct {
	byEmail map[string]*users.User
}

func (f *fakeUserLookup) Get(email string) (*users.User, bool) {
	u, ok := f.byEmail[email]
	return u, ok
}

type fakeChatIDs struct {
	byEmail map[string]int64
}

func (f *fakeChatIDs) GetTelegramChatID(email string) (int64, bool) {
	id, ok := f.byEmail[email]
	return id, ok
}

type recordSender struct {
	mu   sync.Mutex
	sent []sentMsg
	err  error
}

type sentMsg struct {
	chatID int64
	text   string
}

func (r *recordSender) SendMessage(chatID int64, text string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sent = append(r.sent, sentMsg{chatID: chatID, text: text})
	return r.err
}

func (r *recordSender) calls() []sentMsg {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]sentMsg, len(r.sent))
	copy(out, r.sent)
	return out
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// --- fixtures ---

func familyFixture() (*fakeUserLookup, *fakeChatIDs) {
	lookup := &fakeUserLookup{
		byEmail: map[string]*users.User{
			"admin@family.test": {
				Email:       "admin@family.test",
				Role:        "admin",
				Status:      "active",
				DisplayName: "Dad",
				// admin is not a family member (no AdminEmail)
			},
			"son@family.test": {
				Email:       "son@family.test",
				Role:        "trader",
				Status:      "active",
				DisplayName: "Son",
				AdminEmail:  "admin@family.test",
			},
			"unrelated@example.com": {
				Email:  "unrelated@example.com",
				Role:   "trader",
				Status: "active",
				// no AdminEmail — solo user
			},
		},
	}
	// Only admin has Telegram connected (typical setup — family members
	// don't need their own Telegram linkage for notifications to work).
	chatIDs := &fakeChatIDs{
		byEmail: map[string]int64{
			"admin@family.test": 12345,
		},
	}
	return lookup, chatIDs
}

// --- tests ---

func TestTelegramNotify_FamilyMemberTradeNotifiesAdmin(t *testing.T) {
	u, c := familyFixture()
	sender := &recordSender{}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "son@family.test")
	err := hook(ctx, "place_order", map[string]interface{}{
		"tradingsymbol":    "RELIANCE",
		"transaction_type": "BUY",
		"quantity":         float64(10),
		"price":            float64(2500.50),
	})
	require.NoError(t, err)

	calls := sender.calls()
	require.Len(t, calls, 1)
	assert.Equal(t, int64(12345), calls[0].chatID)
	assert.Contains(t, calls[0].text, "Son")
	assert.Contains(t, calls[0].text, "place_order")
	assert.Contains(t, calls[0].text, "RELIANCE")
	assert.Contains(t, calls[0].text, "BUY")
	assert.Contains(t, calls[0].text, "qty=10")
	assert.Contains(t, calls[0].text, "2500.50")
}

func TestTelegramNotify_AdminSelfCallNotNotified(t *testing.T) {
	u, c := familyFixture()
	sender := &recordSender{}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "admin@family.test")
	// Admin is not IsFamilyMember (no AdminEmail), so they don't self-notify.
	err := hook(ctx, "place_order", map[string]interface{}{"tradingsymbol": "INFY"})
	require.NoError(t, err)
	assert.Empty(t, sender.calls(), "admin's own trade must not fire a DM")
}

func TestTelegramNotify_SoloUserNotNotified(t *testing.T) {
	u, c := familyFixture()
	sender := &recordSender{}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "unrelated@example.com")
	err := hook(ctx, "place_order", nil)
	require.NoError(t, err)
	assert.Empty(t, sender.calls(), "solo user's trade must not fire any DM")
}

func TestTelegramNotify_ReadToolNotNotified(t *testing.T) {
	u, c := familyFixture()
	sender := &recordSender{}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "son@family.test")
	readTools := []string{"get_holdings", "get_orders", "list_alerts", "get_profile"}
	for _, tool := range readTools {
		err := hook(ctx, tool, nil)
		require.NoError(t, err)
	}
	assert.Empty(t, sender.calls(), "read tools must never fire notifications")
}

func TestTelegramNotify_AdminWithoutTelegramSilent(t *testing.T) {
	u, _ := familyFixture()
	// Empty chat store — admin hasn't connected Telegram.
	c := &fakeChatIDs{byEmail: map[string]int64{}}
	sender := &recordSender{}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "son@family.test")
	err := hook(ctx, "place_order", nil)
	require.NoError(t, err)
	assert.Empty(t, sender.calls())
}

func TestTelegramNotify_NotifyPrefixes(t *testing.T) {
	cases := map[string]bool{
		// notify on these
		"place_order":          true,
		"place_order_basket":   true, // place_order + underscore extension
		"modify_order":         true,
		"cancel_order":         true,
		"place_gtt_order":      true,
		"convert_position":     true,
		"close_position":       true,
		"close_all_positions":  true,
		"place_mf_order":       true,
		// don't notify on these
		"get_holdings":         false,
		"list_alerts":          false,
		"update_my_credentials": false, // write but not a trade
		"delete_my_account":    false,
		"create_alert":         false,
		"start_ticker":         false,
	}
	for tool, want := range cases {
		t.Run(tool, func(t *testing.T) {
			assert.Equal(t, want, isNotifyTool(tool))
		})
	}
}

func TestTelegramNotify_SenderErrorDoesNotPropagate(t *testing.T) {
	u, c := familyFixture()
	sender := &recordSender{err: assert.AnError}
	hook := Hook(Deps{Users: u, ChatIDs: c, Sender: sender, Logger: testLogger()})

	ctx := oauth.ContextWithEmail(context.Background(), "son@family.test")
	// After-hooks can't cancel completed tools. Sender error must be
	// swallowed (logged) so the user's original tool call isn't affected.
	err := hook(ctx, "place_order", nil)
	assert.NoError(t, err, "after-hooks must not propagate sender errors")
	assert.Len(t, sender.calls(), 1, "sender was still called")
}

func TestTelegramNotify_NilDepsDisable(t *testing.T) {
	sender := &recordSender{}
	// All combinations of nil deps should fail-open.
	hooks := []Deps{
		{Users: nil, ChatIDs: &fakeChatIDs{}, Sender: sender},
		{Users: &fakeUserLookup{}, ChatIDs: nil, Sender: sender},
		{Users: &fakeUserLookup{}, ChatIDs: &fakeChatIDs{}, Sender: nil},
	}
	for i, d := range hooks {
		t.Run(string(rune('a'+i)), func(t *testing.T) {
			h := Hook(d)
			ctx := oauth.ContextWithEmail(context.Background(), "son@family.test")
			err := h(ctx, "place_order", nil)
			assert.NoError(t, err)
		})
	}
	assert.Empty(t, sender.calls())
}

func TestTelegramNotify_SanitizeStripsMarkdown(t *testing.T) {
	// Underscores are stripped because Telegram MarkdownV2 treats them as
	// italic markers. "RELIANCE_BE" becomes "RELIANCEBE".
	assert.Equal(t, "RELIANCEBE", sanitize("RELIANCE_BE"))
	// Asterisks (bold markers) stripped.
	assert.Equal(t, "normal", sanitize("*normal*"))
	// Square brackets (link markers) rewritten to parens.
	assert.Equal(t, "(code)", sanitize("[code]"))
	// Backticks (code fences) stripped.
	assert.Equal(t, "inline", sanitize("`inline`"))
	// Normal strings pass through.
	assert.Equal(t, "plain text 123", sanitize("plain text 123"))
}
