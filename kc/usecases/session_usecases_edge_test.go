package usecases

import (
	"context"
	"errors"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/eventsourcing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockEventAppender captures StoredEvents appended by a use case so tests
// can assert that the audit-log write happened with the right event type
// and payload. appendErr forces the append to fail so the use case can be
// verified to surface store errors (wrapped) rather than swallow them.
type mockEventAppender struct {
	appended   []eventsourcing.StoredEvent
	nextSeqErr error
	appendErr  error
}

func (m *mockEventAppender) Append(events ...eventsourcing.StoredEvent) error {
	if m.appendErr != nil {
		return m.appendErr
	}
	m.appended = append(m.appended, events...)
	return nil
}

func (m *mockEventAppender) NextSequence(aggregateID string) (int64, error) {
	if m.nextSeqErr != nil {
		return 0, m.nextSeqErr
	}
	return int64(len(m.appended) + 1), nil
}

// mockSessionDataClearer is a stub SessionDataClearer that records the
// session ID it was asked to clear and optionally returns a preset error.
type mockSessionDataClearer struct {
	cleared  bool
	lastID   string
	errToRet error
}

func (m *mockSessionDataClearer) ClearSessionData(sessionID string) error {
	m.lastID = sessionID
	if m.errToRet != nil {
		return m.errToRet
	}
	m.cleared = true
	return nil
}

// TestClearSessionData_Success verifies the new command clears a session's
// Kite data and fires the narrow SessionDataClearer port exactly once.
func TestClearSessionData_Success(t *testing.T) {
	t.Parallel()
	sessions := &mockSessionDataClearer{}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{
		SessionID: "mcp-sess-123",
		Reason:    "post_credential_register",
	})
	require.NoError(t, err)
	assert.True(t, sessions.cleared, "session clearer must fire on success path")
	assert.Equal(t, "mcp-sess-123", sessions.lastID, "session ID must be forwarded verbatim")
}

// TestClearSessionData_EmptySessionID rejects empty-session-id requests —
// the session manager is keyed by ID and an empty key has no valid target.
func TestClearSessionData_EmptySessionID(t *testing.T) {
	t.Parallel()
	sessions := &mockSessionDataClearer{}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{SessionID: ""})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "session_id is required")
	assert.False(t, sessions.cleared, "empty session ID must NOT trigger a clear")
}

// TestClearSessionData_NilClearer: defensive guard — manager wiring may
// hand a nil SessionService during partial bootstrap. Must not panic and
// must surface a configuration error.
func TestClearSessionData_NilClearer(t *testing.T) {
	t.Parallel()
	uc := NewClearSessionDataUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{SessionID: "mcp-sess-123"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not configured")
}

// TestClearSessionData_ClearerError: errors from the underlying session
// service propagate (wrapped) to the caller so the login flow can log and
// return to the client rather than silently advancing.
func TestClearSessionData_ClearerError(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("session not found")
	sessions := &mockSessionDataClearer{errToRet: sentinel}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{SessionID: "mcp-sess-123"})
	require.Error(t, err)
	assert.ErrorIs(t, err, sentinel, "underlying clearer error must be wrapped, not swallowed")
}

// TestClearSessionData_EmitsEventOnSuccess verifies the use case appends
// a session.cleared event to the audit log after the SQL write lands. The
// aggregate ID is the SessionID; payload carries the reason verbatim.
func TestClearSessionData_EmitsEventOnSuccess(t *testing.T) {
	t.Parallel()
	sessions := &mockSessionDataClearer{}
	events := &mockEventAppender{}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	uc.SetEventStore(events)
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{
		SessionID: "mcp-sess-42",
		Reason:    "post_credential_register",
	})
	require.NoError(t, err)
	require.Len(t, events.appended, 1, "exactly one session.cleared event must be appended")
	got := events.appended[0]
	assert.Equal(t, "mcp-sess-42", got.AggregateID, "aggregate ID must be the session ID")
	assert.Equal(t, "Session", got.AggregateType)
	assert.Equal(t, "session.cleared", got.EventType)
	assert.Contains(t, string(got.Payload), "post_credential_register")
}

// TestClearSessionData_EventStoreFailureDoesNotRollback: the SQL write
// is the source of truth; if the audit-log append fails, the clear has
// already happened and must not be rolled back. The append failure is
// logged, not surfaced, to avoid breaking the login flow on a best-effort
// audit-log write.
func TestClearSessionData_EventStoreFailureDoesNotRollback(t *testing.T) {
	t.Parallel()
	sessions := &mockSessionDataClearer{}
	events := &mockEventAppender{appendErr: errors.New("disk full")}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	uc.SetEventStore(events)
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{
		SessionID: "mcp-sess-43",
		Reason:    "profile_check_failed",
	})
	require.NoError(t, err, "audit-log failure must not fail the command")
	assert.True(t, sessions.cleared, "the SQL clear must still have happened")
}

// TestClearSessionData_NilEventStoreNoOp confirms that when no event
// store is wired (partial bootstrap, tests), the use case completes
// successfully without attempting to append.
func TestClearSessionData_NilEventStoreNoOp(t *testing.T) {
	t.Parallel()
	sessions := &mockSessionDataClearer{}
	uc := NewClearSessionDataUseCase(sessions, testLogger())
	// Intentionally do NOT call SetEventStore.
	err := uc.Execute(context.Background(), cqrs.ClearSessionDataCommand{
		SessionID: "mcp-sess-44",
		Reason:    "admin_action",
	})
	require.NoError(t, err)
	assert.True(t, sessions.cleared)
}
