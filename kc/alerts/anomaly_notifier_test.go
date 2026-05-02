package alerts

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// newAnomalyTestSetup builds a per-test TelegramNotifier backed by a
// fresh httptest server, returning the notifier + per-server counter
// state. t.Parallel-safe.
func newAnomalyTestSetup(t *testing.T) (*TelegramNotifier, *fakeTelegramState) {
	t.Helper()
	server, st := newFakeTelegramServerWithCounter(false)
	t.Cleanup(server.Close)
	bot := newMockBot(t, server.URL)
	store := newTestStore()
	notifier := &TelegramNotifier{
		bot:    bot,
		store:  store,
		logger: logport.NewSlog(testLogger()),
	}
	return notifier, st
}

// waitFor polls fn until it returns true or the timeout expires.
func waitFor(t *testing.T, fn func() bool, timeout time.Duration, msg string) {
	t.Helper()
	deadline := time.After(timeout)
	for {
		select {
		case <-deadline:
			t.Fatalf("timeout: %s", msg)
			return
		default:
			if fn() {
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
}

// TestAnomalyNotifier_HandleEvent_BasicNotify verifies the happy path:
// a RiskguardRejectionEvent for a known admin produces an HTML telegram
// message via the notifier.
func TestAnomalyNotifier_HandleEvent_BasicNotify(t *testing.T) {
	t.Parallel()

	notifier, st := newAnomalyTestSetup(t)
	store := notifier.store
	const adminEmail = "admin@example.com"
	store.SetTelegramChatID(adminEmail, 12345)

	an := NewAnomalyNotifier(notifier, store, []string{adminEmail}, testLogger())

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	})

	waitFor(t, func() bool { return st.Count() >= 1 }, 2*time.Second,
		"expected at least 1 send within 2s")
}

// TestAnomalyNotifier_HandleEvent_NoAdminChatID: when no admin has set
// a Telegram chat ID, the notifier should silently skip. No panic, no
// send attempts.
func TestAnomalyNotifier_HandleEvent_NoAdminChatID(t *testing.T) {
	t.Parallel()

	notifier, st := newAnomalyTestSetup(t)

	an := NewAnomalyNotifier(notifier, notifier.store, []string{"admin@example.com"}, testLogger())

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	})

	// Wait briefly to confirm no async send happens on this server.
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int64(0), st.Count(), "no send expected when admin has no chat ID")
}

// TestAnomalyNotifier_HandleEvent_NilSafe: nil notifier or nil store
// must not panic.
func TestAnomalyNotifier_HandleEvent_NilSafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		notifier *TelegramNotifier
		store    *Store
	}{
		{"nil notifier", nil, nil},
		{"nil store", &TelegramNotifier{}, nil},
		{"empty admin list", &TelegramNotifier{}, NewStore(nil)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var admins []string
			if tc.name != "empty admin list" {
				admins = []string{"admin@example.com"}
			}
			an := NewAnomalyNotifier(tc.notifier, tc.store, admins, testLogger())
			an.HandleEvent(domain.RiskguardRejectionEvent{
				UserEmail: "trader@example.com",
				Reason:    "anomaly_high",
				Timestamp: time.Now(),
			})
		})
	}
}

// TestAnomalyNotifier_Dedup: same (user_email, reason) within the dedup
// TTL window produces only one notification. After TTL expires, a new
// event triggers a fresh notification.
func TestAnomalyNotifier_Dedup(t *testing.T) {
	t.Parallel()

	notifier, st := newAnomalyTestSetup(t)
	store := notifier.store
	const adminEmail = "admin@example.com"
	store.SetTelegramChatID(adminEmail, 12345)

	// Tight TTL so test is fast.
	an := newAnomalyNotifierWithTTL(notifier, store, []string{adminEmail}, testLogger(), 100*time.Millisecond)

	evt := domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	}

	an.HandleEvent(evt)
	waitFor(t, func() bool { return st.Count() >= 1 }, 2*time.Second, "first send")
	afterFirst := st.Count()

	// Second identical event — should be deduped (no new send).
	an.HandleEvent(evt)
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, afterFirst, st.Count(), "duplicate event within TTL must be deduped")

	// Wait past TTL.
	time.Sleep(120 * time.Millisecond)

	// Third identical event — TTL elapsed, should send again.
	an.HandleEvent(evt)
	waitFor(t, func() bool { return st.Count() >= afterFirst+1 }, 2*time.Second,
		"send after TTL expiry")
}

// TestAnomalyNotifier_DifferentReasonNotDeduped: same user + different
// reason should NOT be deduped — each reason class deserves its own
// alert.
func TestAnomalyNotifier_DifferentReasonNotDeduped(t *testing.T) {
	t.Parallel()

	notifier, st := newAnomalyTestSetup(t)
	store := notifier.store
	const adminEmail = "admin@example.com"
	store.SetTelegramChatID(adminEmail, 12345)

	an := NewAnomalyNotifier(notifier, store, []string{adminEmail}, testLogger())

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	})
	waitFor(t, func() bool { return st.Count() >= 1 }, 2*time.Second, "first reason")

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "kill_switch_global",
		Timestamp: time.Now(),
	})
	waitFor(t, func() bool { return st.Count() >= 2 }, 2*time.Second, "second reason")
}

// TestAnomalyNotifier_MultipleAdmins: every admin in the list receives
// a notification (multi-admin operations team support).
func TestAnomalyNotifier_MultipleAdmins(t *testing.T) {
	t.Parallel()

	notifier, st := newAnomalyTestSetup(t)
	store := notifier.store
	store.SetTelegramChatID("admin1@example.com", 11111)
	store.SetTelegramChatID("admin2@example.com", 22222)
	// admin3 has no chat-id; should be skipped silently.

	an := NewAnomalyNotifier(notifier, store, []string{"admin1@example.com", "admin2@example.com", "admin3@example.com"}, testLogger())

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: "trader@example.com",
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	})

	waitFor(t, func() bool { return st.Count() >= 2 }, 2*time.Second,
		"2 sends expected (admin1 + admin2)")

	// Confirm a third send doesn't appear.
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int64(2), st.Count(), "exactly 2 sends; admin3 has no chat-id")
}

// TestAnomalyNotifier_PIIRedaction: the message MUST hash the trader's
// email rather than embedding plaintext. Defends against operator-side
// log leakage of user emails.
func TestAnomalyNotifier_PIIRedaction(t *testing.T) {
	t.Parallel()

	const traderEmail = "secret-trader@example.com"

	notifier, st := newAnomalyTestSetup(t)
	store := notifier.store
	store.SetTelegramChatID("admin@example.com", 12345)

	an := NewAnomalyNotifier(notifier, store, []string{"admin@example.com"}, testLogger())

	an.HandleEvent(domain.RiskguardRejectionEvent{
		UserEmail: traderEmail,
		Reason:    "anomaly_high",
		Timestamp: time.Now(),
	})

	waitFor(t, func() bool { return st.Count() >= 1 }, 2*time.Second, "send")

	msg := st.LastMessage()
	assert.NotContains(t, msg, traderEmail, "plaintext trader email must NOT appear in alert body")
	assert.True(t, strings.Contains(msg, "anomaly_high"),
		"alert body should contain rejection reason; got: %q", msg)
}
