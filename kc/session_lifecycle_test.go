package kc

// session_lifecycle_test.go — coverage close-out for the session
// lifecycle surface that existing tests in kc/session_test.go and
// kc/session_edge_test.go don't cover. Targets:
//
//   1. SessionLifecycleService accessor (was 0%)
//   2. SessionService.SetBrokerFactory + HasBrokerFactory (both 0%)
//   3. SessionRegistry.cleanupRoutine parent-context-cancel branch
//      (75% — only the internal-cancel branch was covered)
//   4. SessionRegistry.LoadFromDB skipped-stale-entries branch
//      (94.4% — the happy-path was covered, stale-skip wasn't fully)
//   5. SessionRegistry.GenerateWithDataAndHint persistence-error
//      branch (93.3% — DB-error path)
//   6. SessionService.ClearSessionData error-return branches
//
// Sub-commit B of Wave B option 2 (kc/ root Manager boot + lifecycle).
//
// File-scope: deliberately new file kc/session_lifecycle_test.go,
// separate from existing kc/session_test.go + kc/session_edge_test.go
// so concurrent Wave D BrokerResolver work that may rename helpers in
// those files does not collide.

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/broker"
)

// quietLifecycleLogger discards log output to keep test output clean.
// Local helper rather than reusing helpers from session_test.go, which
// peer agents may rename during concurrent work.
func quietLifecycleLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// ===========================================================================
// SessionLifecycle accessor — was 0%
// ===========================================================================

// TestManager_SessionLifecycle_AccessorReturnsService verifies the
// Manager-level accessor at session_lifecycle_service.go:73 surfaces
// the same SessionLifecycleService that initFocusedServices wires
// during Manager construction.
func TestManager_SessionLifecycle_AccessorReturnsService(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	svc := mgr.SessionLifecycle()
	require.NotNil(t, svc, "SessionLifecycle() must return a non-nil facade")
	// Same-pointer round-trip — the accessor reads the field, doesn't
	// rebuild on every call.
	assert.Same(t, svc, mgr.SessionLifecycle(),
		"accessor must be a stable pointer, not a fresh build per call")
}

// TestSessionLifecycleService_DelegatesGenerate verifies the facade's
// GenerateSession method delegates to the underlying SessionService.
// Pins the contract that Manager-level callers and the facade-level
// callers see identical behaviour.
func TestSessionLifecycleService_DelegatesGenerate(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithDevMode(true),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	id := mgr.SessionLifecycle().GenerateSession()
	assert.NotEmpty(t, id)
	// Facade and Manager-level methods produce equivalent behaviour.
	count := mgr.SessionLifecycle().GetActiveSessionCount()
	assert.Equal(t, count, mgr.GetActiveSessionCount(),
		"facade and Manager accessor return the same active count")
}

// ===========================================================================
// SetBrokerFactory + HasBrokerFactory — both 0%
// ===========================================================================

// stubBrokerFactory is a minimal broker.Factory for testing — it
// returns nil clients but satisfies the interface so SessionService
// can hold it.
type stubBrokerFactory struct{}

func (s *stubBrokerFactory) Create(apiKey string) (broker.Client, error) {
	return nil, errors.New("stub: no client")
}

func (s *stubBrokerFactory) CreateWithToken(apiKey, accessToken string) (broker.Client, error) {
	return nil, errors.New("stub: no client")
}

func (s *stubBrokerFactory) BrokerName() broker.Name {
	return broker.Name("stub")
}

// TestSessionService_HasBrokerFactory_NilByDefault verifies fresh
// Manager construction has no broker.Factory wired (initFocusedServices
// doesn't auto-wire one — production wiring in app/wire.go does that
// via SetBrokerFactory).
func TestSessionService_HasBrokerFactory_NilByDefault(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)
	assert.False(t, mgr.SessionSvc().HasBrokerFactory(),
		"fresh Manager must not have a broker.Factory wired")
}

// TestSessionService_SetBrokerFactory_WiresFactory verifies the
// setter mutates the field so HasBrokerFactory flips to true.
// Production code calls SetBrokerFactory once in app/wire.go startup.
func TestSessionService_SetBrokerFactory_WiresFactory(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	mgr.SessionSvc().SetBrokerFactory(&stubBrokerFactory{})
	assert.True(t, mgr.SessionSvc().HasBrokerFactory(),
		"after SetBrokerFactory the service must report a wired factory")
}

// TestSessionService_SetBrokerFactory_NilUnwires verifies passing nil
// flips HasBrokerFactory back to false. Defensive: production never
// calls this with nil but the contract should hold.
func TestSessionService_SetBrokerFactory_NilUnwires(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	mgr.SessionSvc().SetBrokerFactory(&stubBrokerFactory{})
	require.True(t, mgr.SessionSvc().HasBrokerFactory())

	// Now flip back to nil.
	mgr.SessionSvc().SetBrokerFactory(nil)
	assert.False(t, mgr.SessionSvc().HasBrokerFactory())
}

// ===========================================================================
// cleanupRoutine — parent-context-cancel branch (was 75%)
// ===========================================================================

// TestSessionRegistry_CleanupRoutine_ParentContextCancel verifies the
// branch at session.go:473-475: when the caller's context is
// cancelled, the routine logs "stopped" and exits cleanly. The
// existing TestCleanupRoutine in session_test.go covers the
// internal-cancel path (StopCleanupRoutine); this covers the
// parent-cancel path.
func TestSessionRegistry_CleanupRoutine_ParentContextCancel(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(quietLifecycleLogger())

	parentCtx, cancel := context.WithCancel(context.Background())
	reg.StartCleanupRoutine(parentCtx)

	// Cancel the parent context — the routine's <-ctx.Done() branch
	// should fire and the goroutine should exit. We then call
	// StopCleanupRoutine which will Wait on cleanupWG; the Wait must
	// return promptly because the goroutine has already exited.
	cancel()

	done := make(chan struct{})
	go func() {
		reg.StopCleanupRoutine()
		close(done)
	}()

	select {
	case <-done:
		// Goroutine exited and StopCleanupRoutine returned.
	case <-time.After(2 * time.Second):
		t.Fatal("cleanupRoutine did not exit within 2s of parent context cancel")
	}
}

// TestSessionRegistry_StopCleanupRoutine_DoubleCallSafe verifies the
// stopOnce guard: calling StopCleanupRoutine twice does not panic.
// The second call's Wait must also return (because the routine has
// already exited).
func TestSessionRegistry_StopCleanupRoutine_DoubleCallSafe(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.StartCleanupRoutine(context.Background())

	// First Stop — routine exits cleanly.
	reg.StopCleanupRoutine()
	// Second Stop — must not panic, must return promptly.
	done := make(chan struct{})
	go func() {
		reg.StopCleanupRoutine()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(1 * time.Second):
		t.Fatal("second StopCleanupRoutine did not return within 1s")
	}
}

// TestSessionRegistry_StopCleanupRoutine_BeforeStart verifies calling
// Stop on a never-started registry does not panic. The cleanupWG is
// only Add'd inside StartCleanupRoutine, so Wait is a no-op when the
// routine was never started — this branch isn't covered by the
// existing test suite.
func TestSessionRegistry_StopCleanupRoutine_BeforeStart(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(quietLifecycleLogger())
	// Never called StartCleanupRoutine. Stop should be a no-op.
	reg.StopCleanupRoutine()
}

// ===========================================================================
// LoadFromDB — stale-entry skip branch
// ===========================================================================

// stubSessionDB is a SessionDB that returns canned LoadSessions data
// and records DeleteSession calls. Used to exercise the stale-skip
// branch at session.go:131-137.
type stubSessionDB struct {
	mu              sync.Mutex
	loadEntries     []*SessionLoadEntry
	loadErr         error
	saveErr         error
	deletedSessions []string
}

func (s *stubSessionDB) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	return s.saveErr
}

func (s *stubSessionDB) LoadSessions() ([]*SessionLoadEntry, error) {
	return s.loadEntries, s.loadErr
}

func (s *stubSessionDB) DeleteSession(sessionID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletedSessions = append(s.deletedSessions, sessionID)
	return nil
}

// TestSessionRegistry_LoadFromDB_SkipsExpiredAndTerminated verifies
// the stale-skip branch: when LoadSessions returns entries that are
// either Terminated or past ExpiresAt, the registry deletes them
// from the DB and skips loading them into memory.
func TestSessionRegistry_LoadFromDB_SkipsExpiredAndTerminated(t *testing.T) {
	t.Parallel()

	now := time.Now()
	stub := &stubSessionDB{
		loadEntries: []*SessionLoadEntry{
			{
				SessionID:  "kitemcp-stale-expired",
				Email:      "u@t.com",
				CreatedAt:  now.Add(-2 * time.Hour),
				ExpiresAt:  now.Add(-1 * time.Hour), // expired
				Terminated: false,
			},
			{
				SessionID:  "kitemcp-stale-terminated",
				Email:      "u@t.com",
				CreatedAt:  now.Add(-30 * time.Minute),
				ExpiresAt:  now.Add(1 * time.Hour),
				Terminated: true, // terminated
			},
			{
				SessionID:  "kitemcp-fresh",
				Email:      "u@t.com",
				CreatedAt:  now.Add(-1 * time.Minute),
				ExpiresAt:  now.Add(1 * time.Hour),
				Terminated: false,
			},
		},
	}

	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.SetDB(stub)
	require.NoError(t, reg.LoadFromDB())

	// Both stale entries must have been deleted from the DB.
	stub.mu.Lock()
	deleted := make([]string, len(stub.deletedSessions))
	copy(deleted, stub.deletedSessions)
	stub.mu.Unlock()
	assert.ElementsMatch(t, []string{
		"kitemcp-stale-expired",
		"kitemcp-stale-terminated",
	}, deleted, "both stale entries must have been deleted from the DB")

	// Only the fresh entry survives in memory.
	active := reg.ListActiveSessions()
	require.Len(t, active, 1)
	assert.Equal(t, "kitemcp-fresh", active[0].ID)
}

// TestSessionRegistry_LoadFromDB_NilDBIsNoop verifies the early-
// return guard: SetDB has not been called, LoadFromDB returns nil
// without touching anything.
func TestSessionRegistry_LoadFromDB_NilDBIsNoop(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistry(quietLifecycleLogger())
	// No SetDB call.
	require.NoError(t, reg.LoadFromDB())
	assert.Empty(t, reg.ListActiveSessions(),
		"LoadFromDB on nil-DB registry must leave session map empty")
}

// TestSessionRegistry_LoadFromDB_LoadErrorBubbles verifies the
// load-error branch: when LoadSessions itself returns an error, the
// caller sees that error and the in-memory registry is left empty.
func TestSessionRegistry_LoadFromDB_LoadErrorBubbles(t *testing.T) {
	t.Parallel()

	stub := &stubSessionDB{loadErr: errors.New("disk corrupt")}
	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.SetDB(stub)

	err := reg.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "disk corrupt")
	assert.Empty(t, reg.ListActiveSessions())
}

// ===========================================================================
// GenerateWithDataAndHint — DB persistence-error branch
// ===========================================================================

// TestSessionRegistry_Generate_DBErrorLoggedNotReturned verifies that
// when SaveSession fails the registry still returns the new sessionID
// (the error is logged but doesn't bubble — sessions live in memory,
// persistence is a "best effort" durability win). Pins the existing
// production behaviour at session.go:194-198.
func TestSessionRegistry_Generate_DBErrorLoggedNotReturned(t *testing.T) {
	t.Parallel()

	stub := &stubSessionDB{saveErr: errors.New("write failed")}
	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.SetDB(stub)

	// Generate should succeed even though the persistence write fails.
	id := reg.GenerateWithDataAndHint(&KiteSessionData{Email: "u@t.com"}, "test-client")
	assert.NotEmpty(t, id)
	// The session is still in memory.
	session, err := reg.GetSession(id)
	require.NoError(t, err)
	assert.Equal(t, "test-client", session.ClientHint,
		"client hint must round-trip through GenerateWithDataAndHint")
}

// TestSessionRegistry_Generate_NilDataNoEmail verifies the
// nil-Data branch in the persistence path (session.go:191-194):
// when Data is nil OR not a *KiteSessionData, the persisted email
// is empty rather than panicking on a nil-deref.
func TestSessionRegistry_Generate_NilDataNoEmail(t *testing.T) {
	t.Parallel()

	stub := &stubSessionDB{}
	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.SetDB(stub)

	// Generate with nil data — persistence path should still run with email="".
	id := reg.Generate()
	assert.NotEmpty(t, id)
	// Session exists in memory with nil Data.
	session, err := reg.GetSession(id)
	require.NoError(t, err)
	assert.Nil(t, session.Data)
}

// TestSessionRegistry_Generate_NonKiteDataNoEmail covers the type-
// assertion negative branch: Data is non-nil but not a
// *KiteSessionData. The email passed to SaveSession should be empty.
func TestSessionRegistry_Generate_NonKiteDataNoEmail(t *testing.T) {
	t.Parallel()

	stub := &stubSessionDB{}
	reg := NewSessionRegistry(quietLifecycleLogger())
	reg.SetDB(stub)

	type otherData struct{ X string }
	id := reg.GenerateWithData(&otherData{X: "not-kite"})
	assert.NotEmpty(t, id)

	// Session exists, but the saved email is empty (not panicked).
	session, err := reg.GetSession(id)
	require.NoError(t, err)
	require.NotNil(t, session.Data)
}

// ===========================================================================
// SessionRegistry.NewSessionRegistryWithDuration — coverage of the
// alternate constructor
// ===========================================================================

// TestNewSessionRegistryWithDuration_RespectsDuration verifies the
// alt-constructor sets the session duration that controls expiry.
// Pins that GenerateWithData uses the registry's configured duration
// (not DefaultSessionDuration as a fallback).
func TestNewSessionRegistryWithDuration_RespectsDuration(t *testing.T) {
	t.Parallel()

	customDuration := 5 * time.Minute
	reg := NewSessionRegistryWithDuration(customDuration, quietLifecycleLogger())
	assert.Equal(t, customDuration, reg.GetSessionDuration())

	id := reg.Generate()
	session, err := reg.GetSession(id)
	require.NoError(t, err)
	// ExpiresAt - CreatedAt should approximate customDuration.
	delta := session.ExpiresAt.Sub(session.CreatedAt)
	assert.InDelta(t, customDuration.Seconds(), delta.Seconds(), 1.0,
		"session duration should match the registry's configured duration")
}

// TestSessionRegistry_SetSessionDuration_AffectsNewSessions verifies
// that mutating duration mid-life affects only sessions generated
// AFTER the change (existing sessions keep their original ExpiresAt).
func TestSessionRegistry_SetSessionDuration_AffectsNewSessions(t *testing.T) {
	t.Parallel()

	reg := NewSessionRegistryWithDuration(1*time.Hour, quietLifecycleLogger())

	// First session uses 1h duration.
	idOld := reg.Generate()
	oldSession, err := reg.GetSession(idOld)
	require.NoError(t, err)
	oldDelta := oldSession.ExpiresAt.Sub(oldSession.CreatedAt)
	assert.InDelta(t, time.Hour.Seconds(), oldDelta.Seconds(), 1.0)

	// Mutate to 10m.
	reg.SetSessionDuration(10 * time.Minute)
	assert.Equal(t, 10*time.Minute, reg.GetSessionDuration())

	// New session uses 10m.
	idNew := reg.Generate()
	newSession, err := reg.GetSession(idNew)
	require.NoError(t, err)
	newDelta := newSession.ExpiresAt.Sub(newSession.CreatedAt)
	assert.InDelta(t, (10 * time.Minute).Seconds(), newDelta.Seconds(), 1.0)

	// Old session's ExpiresAt is unchanged.
	oldAgain, err := reg.GetSession(idOld)
	require.NoError(t, err)
	assert.True(t, oldAgain.ExpiresAt.Equal(oldSession.ExpiresAt),
		"existing session's ExpiresAt must not change when duration is mutated")
}

// ===========================================================================
// ClearSessionData — error branches
// ===========================================================================

// TestSessionService_ClearSessionData_InvalidIDReturnsError verifies
// the validateSessionID guard at session_service.go:342-344: a
// malformed session ID returns the validation error without touching
// the registry.
func TestSessionService_ClearSessionData_InvalidIDReturnsError(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	err = mgr.SessionSvc().ClearSessionData("not-a-uuid-not-a-prefix")
	require.Error(t, err)
}

// TestSessionService_ClearSessionData_UnknownSessionReturnsError
// verifies the not-found branch: a well-formed but non-existent
// session ID returns errSessionNotFound.
func TestSessionService_ClearSessionData_UnknownSessionReturnsError(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	// Well-formed but unknown — the kitemcp- prefix + a fresh UUID
	// shape passes validation but the registry has no entry.
	err = mgr.SessionSvc().ClearSessionData("kitemcp-00000000-0000-0000-0000-000000000000")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

// TestSessionService_ClearSessionData_NoDataIsNoop verifies the
// nil-Data branch: an existing session with no Data set runs the
// clear without invoking the cleanup hook (which would deref the
// nil Kite pointer).
func TestSessionService_ClearSessionData_NoDataIsNoop(t *testing.T) {
	t.Parallel()

	mgr, err := NewWithOptions(context.Background(),
		WithLogger(quietLifecycleLogger()),
		WithDevMode(true),
		WithInstrumentsSkipFetch(true),
	)
	require.NoError(t, err)

	// Generate a session without populating Data.
	id := mgr.GenerateSession()
	require.NoError(t, mgr.SessionSvc().ClearSessionData(id),
		"clearing a session with nil Data must succeed without invoking the hook")
}
