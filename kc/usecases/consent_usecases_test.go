package usecases

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// stubConsentWithdrawer captures MarkWithdrawnByEmailHash arguments so
// tests can verify the use case forwards them faithfully.
type stubConsentWithdrawer struct {
	mu sync.Mutex

	// Inputs captured per call.
	emailHash     string
	withdrawnAt   time.Time
	noticeVersion string
	reason        string
	ipAddress     string
	userAgent     string
	calls         int

	// Configurable outputs.
	rows int64
	err  error
}

func (s *stubConsentWithdrawer) MarkWithdrawnByEmailHash(
	emailHash string, withdrawnAt time.Time,
	noticeVersion, reason, ipAddress, userAgent string,
) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.emailHash = emailHash
	s.withdrawnAt = withdrawnAt
	s.noticeVersion = noticeVersion
	s.reason = reason
	s.ipAddress = ipAddress
	s.userAgent = userAgent
	s.calls++
	return s.rows, s.err
}

// stubHasher is a deterministic hasher for tests — just lowercases the
// input and prefixes "h:" so we can verify the use case routes the
// hashed value (not the plaintext) into the port.
type stubHasher struct{}

func (stubHasher) HashEmail(email string) string {
	if email == "" {
		return ""
	}
	return "h:" + strings.ToLower(email)
}

// stubDispatcher captures dispatched events.
type stubDispatcher struct {
	mu     sync.Mutex
	events []domain.Event
}

func (s *stubDispatcher) Dispatch(event domain.Event) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.events = append(s.events, event)
}

func discardLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestWithdrawConsent_HappyPath(t *testing.T) {
	t.Parallel()
	w := &stubConsentWithdrawer{rows: 1}
	d := &stubDispatcher{}
	uc := NewWithdrawConsentUseCase(w, stubHasher{}, d, discardLogger())

	fixed := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	uc.SetClock(func() time.Time { return fixed })

	res, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{
		Email:         "Alice@Example.com",
		Reason:        "user request via dashboard",
		NoticeVersion: "v1.2",
		IPAddress:     "10.0.0.5",
		UserAgent:     "Mozilla",
	})
	require.NoError(t, err)
	require.NotNil(t, res)

	// Hashed value passed to port — plaintext never leaks downstream.
	assert.Equal(t, "h:alice@example.com", res.EmailHash)
	assert.Equal(t, "h:alice@example.com", w.emailHash)
	assert.Equal(t, fixed, w.withdrawnAt)
	assert.Equal(t, "v1.2", w.noticeVersion)
	assert.Equal(t, "user request via dashboard", w.reason)
	assert.Equal(t, "10.0.0.5", w.ipAddress)
	assert.Equal(t, "Mozilla", w.userAgent)
	assert.Equal(t, int64(1), res.GrantsWithdrawn)

	// Event dispatched with both plaintext + hash so all downstream
	// consumers can serve their need without re-hashing.
	require.Len(t, d.events, 1)
	evt, ok := d.events[0].(domain.ConsentWithdrawnEvent)
	require.True(t, ok)
	assert.Equal(t, "alice@example.com", evt.Email)
	assert.Equal(t, "h:alice@example.com", evt.EmailHash)
	assert.Equal(t, "user request via dashboard", evt.Reason)
	assert.Equal(t, fixed, evt.Timestamp)
	assert.Equal(t, "consent.withdrawn", evt.EventType())
}

func TestWithdrawConsent_NoActiveGrants(t *testing.T) {
	t.Parallel()
	// Withdrawer reports zero updates — the use case still succeeds; the
	// caller decides whether to surface "nothing to withdraw" as an error.
	w := &stubConsentWithdrawer{rows: 0}
	uc := NewWithdrawConsentUseCase(w, stubHasher{}, nil, discardLogger())
	res, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{
		Email: "alice@example.com",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(0), res.GrantsWithdrawn)
}

func TestWithdrawConsent_EmptyEmail(t *testing.T) {
	t.Parallel()
	w := &stubConsentWithdrawer{}
	uc := NewWithdrawConsentUseCase(w, stubHasher{}, nil, discardLogger())
	_, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{Email: "  "})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
	assert.Equal(t, 0, w.calls, "withdrawer must not be called on empty input")
}

func TestWithdrawConsent_NilWithdrawer(t *testing.T) {
	t.Parallel()
	uc := NewWithdrawConsentUseCase(nil, stubHasher{}, nil, discardLogger())
	_, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{Email: "a@b.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no consent store")
}

func TestWithdrawConsent_PortError(t *testing.T) {
	t.Parallel()
	w := &stubConsentWithdrawer{err: errors.New("db disk full")}
	d := &stubDispatcher{}
	uc := NewWithdrawConsentUseCase(w, stubHasher{}, d, discardLogger())
	_, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{
		Email: "a@b.com",
	})
	require.Error(t, err)
	// Event must NOT be dispatched on a failed write — otherwise
	// listeners would see "consent withdrawn" while the persistent
	// log still shows it active.
	assert.Empty(t, d.events, "dispatcher must not fire on storage error")
}

func TestWithdrawConsent_NilDispatcherIsOk(t *testing.T) {
	t.Parallel()
	// Dev-mode wiring (no dispatcher) succeeds silently.
	w := &stubConsentWithdrawer{rows: 1}
	uc := NewWithdrawConsentUseCase(w, stubHasher{}, nil, discardLogger())
	res, err := uc.Execute(context.Background(), cqrs.WithdrawConsentCommand{
		Email: "a@b.com",
	})
	require.NoError(t, err)
	assert.Equal(t, int64(1), res.GrantsWithdrawn)
}
