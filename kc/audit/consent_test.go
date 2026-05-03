package audit

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// openTestConsentStore creates an in-memory SQLite DB, initialises the consent
// log table, and returns a ready-to-use *ConsentStore.
func openTestConsentStore(t *testing.T) *ConsentStore {
	t.Helper()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cs := NewConsentStore(db)
	require.NoError(t, cs.InitTable())
	return cs
}

// TestHashEmail verifies the exported HashEmail helper matches SHA-256 of the
// lowercased input. This is the contract callers (OAuth callback, dashboard
// toggle) rely on to produce user_email_hash values.
func TestHashEmail(t *testing.T) {
	t.Parallel()
	// Same hash for same normalized input.
	assert.Equal(t, HashEmail("alice@example.com"), HashEmail("ALICE@example.com"),
		"email hash must be case-insensitive")

	// Known-vector check: SHA-256 of the lowercased email.
	want := sha256Hex([]byte("alice@example.com"))
	assert.Equal(t, want, HashEmail("alice@example.com"))
	assert.Equal(t, want, HashEmail("Alice@Example.com"))

	// Empty input produces empty hash (callers should never pass empty email,
	// but we prefer returning "" over a hash of "" which would leak).
	assert.Equal(t, "", HashEmail(""))
}

// TestComputeProofHash verifies stability: same inputs => same output, and
// the hash is sensitive to every input field.
func TestComputeProofHash(t *testing.T) {
	t.Parallel()

	// Same inputs produce the same hash.
	a := ComputeProofHash("notice v1.0 bytes", "grant:trading,analytics")
	b := ComputeProofHash("notice v1.0 bytes", "grant:trading,analytics")
	assert.Equal(t, a, b, "proof hash must be stable for identical input")

	// Any field change must change the hash.
	c := ComputeProofHash("notice v1.1 bytes", "grant:trading,analytics")
	assert.NotEqual(t, a, c, "hash must change when notice bytes change")

	d := ComputeProofHash("notice v1.0 bytes", "withdraw:trading")
	assert.NotEqual(t, a, d, "hash must change when user action changes")

	// Hash is hex-encoded 64 chars (SHA-256 = 32 bytes = 64 hex chars).
	assert.Len(t, a, 64, "proof hash must be hex-encoded SHA-256 (64 chars)")
}

// TestConsentStore_Insert verifies a grant row round-trips through the store.
func TestConsentStore_Insert(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	emailHash := HashEmail("alice@example.com")
	scopeJSON, err := json.Marshal([]string{"trading", "analytics"})
	require.NoError(t, err)
	proof := ComputeProofHash("DPDP notice v1.0", "grant oauth_callback")

	entry := &ConsentLogEntry{
		UserEmailHash:  emailHash,
		TimestampUTC:   time.Now().UTC().Truncate(time.Second),
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-agent/1.0",
		NoticeVersion:  "1.0",
		ConsentAction:  ConsentActionGrant,
		Scope:          string(scopeJSON),
		Method:         ConsentMethodOAuthCallback,
		ProofHash:      proof,
	}
	require.NoError(t, cs.Insert(entry))
	assert.True(t, entry.ID > 0, "auto-increment ID should be positive after insert")

	// List by email hash returns the row.
	rows, err := cs.ListByEmailHash(emailHash, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)
	got := rows[0]
	assert.Equal(t, emailHash, got.UserEmailHash)
	assert.Equal(t, "127.0.0.1", got.IPAddress)
	assert.Equal(t, "test-agent/1.0", got.UserAgent)
	assert.Equal(t, "1.0", got.NoticeVersion)
	assert.Equal(t, ConsentActionGrant, got.ConsentAction)
	assert.Equal(t, string(scopeJSON), got.Scope)
	assert.Equal(t, ConsentMethodOAuthCallback, got.Method)
	assert.Equal(t, proof, got.ProofHash)
	assert.Equal(t, entry.TimestampUTC, got.TimestampUTC)
}

// TestConsentStore_Withdraw verifies a grant followed by a withdraw are both
// persisted and returned in chronological order (oldest first).
func TestConsentStore_Withdraw(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	emailHash := HashEmail("bob@example.com")
	base := time.Date(2026, 4, 18, 10, 0, 0, 0, time.UTC)

	grant := &ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  base,
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `["trading","analytics","telegram"]`,
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("notice-v1.0", "grant"),
	}
	require.NoError(t, cs.Insert(grant))

	withdraw := &ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  base.Add(24 * time.Hour),
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionWithdraw,
		Scope:         `["telegram"]`,
		Method:        ConsentMethodDashboardToggle,
		ProofHash:     ComputeProofHash("notice-v1.0", "withdraw telegram"),
	}
	require.NoError(t, cs.Insert(withdraw))

	rows, err := cs.ListByEmailHash(emailHash, 10)
	require.NoError(t, err)
	require.Len(t, rows, 2, "both grant and withdraw must be retained")

	// Order is chronological (oldest first).
	assert.Equal(t, ConsentActionGrant, rows[0].ConsentAction)
	assert.Equal(t, ConsentMethodOAuthCallback, rows[0].Method)
	assert.Equal(t, base, rows[0].TimestampUTC)

	assert.Equal(t, ConsentActionWithdraw, rows[1].ConsentAction)
	assert.Equal(t, ConsentMethodDashboardToggle, rows[1].Method)
	assert.Equal(t, base.Add(24*time.Hour), rows[1].TimestampUTC)
}

// TestConsentStore_ScopeJSON verifies a JSON-encoded scope round-trips byte-exact
// through SQLite storage. Scope is stored as opaque JSON text for flexibility —
// callers can decode into any shape they prefer.
func TestConsentStore_ScopeJSON(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	emailHash := HashEmail("carol@example.com")

	// Object-shaped scope with nested structure.
	scope := map[string]any{
		"trading":   true,
		"analytics": true,
		"telegram":  false,
		"features":  []string{"alerts", "widgets"},
	}
	scopeJSON, err := json.Marshal(scope)
	require.NoError(t, err)

	entry := &ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  time.Now().UTC().Truncate(time.Second),
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         string(scopeJSON),
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("notice-v1.0", "grant"),
	}
	require.NoError(t, cs.Insert(entry))

	rows, err := cs.ListByEmailHash(emailHash, 10)
	require.NoError(t, err)
	require.Len(t, rows, 1)

	// Re-decode and verify structural equality.
	var decoded map[string]any
	require.NoError(t, json.Unmarshal([]byte(rows[0].Scope), &decoded))
	assert.Equal(t, true, decoded["trading"])
	assert.Equal(t, true, decoded["analytics"])
	assert.Equal(t, false, decoded["telegram"])
	feats, ok := decoded["features"].([]any)
	require.True(t, ok, "features must round-trip as a slice")
	assert.Equal(t, []any{"alerts", "widgets"}, feats)
}

// TestConsentStore_InvalidAction verifies the CHECK constraint rejects an
// unknown action value. This is our guard against typos and is the reason
// we prefer the ConsentAction* constants over ad-hoc strings.
func TestConsentStore_InvalidAction(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	entry := &ConsentLogEntry{
		UserEmailHash: HashEmail("dave@example.com"),
		TimestampUTC:  time.Now().UTC(),
		NoticeVersion: "1.0",
		ConsentAction: "approve", // not in ('grant','withdraw') — must be rejected
		Scope:         `["trading"]`,
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("notice-v1.0", "approve"),
	}
	err := cs.Insert(entry)
	require.Error(t, err, "invalid consent_action must be rejected by CHECK constraint")
}

// TestConsentStore_InvalidMethod verifies the CHECK constraint on method.
func TestConsentStore_InvalidMethod(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	entry := &ConsentLogEntry{
		UserEmailHash: HashEmail("eve@example.com"),
		TimestampUTC:  time.Now().UTC(),
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `["trading"]`,
		Method:        "cli", // not in ('oauth_callback','dashboard_toggle')
		ProofHash:     ComputeProofHash("notice-v1.0", "grant"),
	}
	err := cs.Insert(entry)
	require.Error(t, err, "invalid method must be rejected by CHECK constraint")
}

// TestConsentStore_IsolationByEmailHash verifies a query for user A does not
// return user B's consent rows. PII minimization relies on the hash being the
// only user-identifying field — never the raw email.
func TestConsentStore_IsolationByEmailHash(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	aHash := HashEmail("a@example.com")
	bHash := HashEmail("b@example.com")

	require.NoError(t, cs.Insert(&ConsentLogEntry{
		UserEmailHash: aHash,
		TimestampUTC:  time.Now().UTC(),
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `["trading"]`,
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("notice-v1.0", "grant A"),
	}))
	require.NoError(t, cs.Insert(&ConsentLogEntry{
		UserEmailHash: bHash,
		TimestampUTC:  time.Now().UTC(),
		NoticeVersion: "1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `["trading"]`,
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("notice-v1.0", "grant B"),
	}))

	rowsA, err := cs.ListByEmailHash(aHash, 10)
	require.NoError(t, err)
	require.Len(t, rowsA, 1)
	assert.Equal(t, aHash, rowsA[0].UserEmailHash)

	rowsB, err := cs.ListByEmailHash(bHash, 10)
	require.NoError(t, err)
	require.Len(t, rowsB, 1)
	assert.Equal(t, bHash, rowsB[0].UserEmailHash)

	// A query for an unknown hash returns an empty slice.
	rowsC, err := cs.ListByEmailHash(HashEmail("nobody@example.com"), 10)
	require.NoError(t, err)
	assert.Empty(t, rowsC)
}

// ===========================================================================
// PR-D Item 1: consent withdrawal (DPDP §6(4))
// ===========================================================================

// TestConsentStore_MarkWithdrawn_StampsActiveGrant verifies the canonical
// flow: a prior grant is stamped with withdrawn_at, AND a new "withdraw"
// row is appended. Both writes succeed so a downstream query sees the
// full history plus a fast-path "is consent active?" check.
func TestConsentStore_MarkWithdrawn_StampsActiveGrant(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)
	emailHash := HashEmail("withdraw-test@example.com")

	scope, _ := json.Marshal(map[string]any{"trading": true, "analytics": true})
	grant := &ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  time.Now().UTC().Add(-1 * time.Hour),
		IPAddress:     "10.0.0.1",
		UserAgent:     "Mozilla/5.0",
		NoticeVersion: "v1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         string(scope),
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     ComputeProofHash("v1.0", "grant:trading,analytics"),
	}
	require.NoError(t, cs.Insert(grant))

	// Active before withdrawal.
	active, err := cs.HasActiveGrant(emailHash)
	require.NoError(t, err)
	assert.True(t, active, "consent must be active immediately after grant")

	// Withdraw.
	withdrawnAt := time.Now().UTC()
	updated, err := cs.MarkWithdrawnByEmailHash(
		emailHash, withdrawnAt,
		"v1.0", "user requested deletion via dashboard",
		"10.0.0.1", "Mozilla/5.0",
	)
	require.NoError(t, err)
	assert.Equal(t, int64(1), updated, "exactly one grant row should be marked withdrawn")

	// No longer active.
	active2, err := cs.HasActiveGrant(emailHash)
	require.NoError(t, err)
	assert.False(t, active2, "consent must NOT be active after withdrawal")

	// History has BOTH the (now-stamped) grant AND the new withdraw row.
	rows, err := cs.ListByEmailHash(emailHash, 10)
	require.NoError(t, err)
	require.Len(t, rows, 2, "history must contain grant + withdraw rows")
	assert.Equal(t, ConsentActionGrant, rows[0].ConsentAction)
	assert.False(t, rows[0].WithdrawnAt.IsZero(), "grant row must be stamped withdrawn_at")
	assert.Equal(t, ConsentActionWithdraw, rows[1].ConsentAction)
	assert.True(t, rows[1].WithdrawnAt.IsZero(), "withdraw row itself has no withdrawn_at")
	assert.Contains(t, rows[1].Scope, "user requested",
		"withdraw row's scope captures the reason")
}

// TestConsentStore_MarkWithdrawn_NoActiveGrant returns 0 updates without
// erroring. DPDP §6(4) doesn't require a prior grant to exist; the call
// is idempotent and harmless.
func TestConsentStore_MarkWithdrawn_NoActiveGrant(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)

	updated, err := cs.MarkWithdrawnByEmailHash(
		HashEmail("never-granted@example.com"),
		time.Now().UTC(),
		"v1.0", "user request", "1.2.3.4", "ua",
	)
	require.NoError(t, err)
	assert.Equal(t, int64(0), updated)
}

// TestConsentStore_RegrantAfterWithdraw verifies the round-trip: after
// withdrawing, the user can grant fresh consent. The history retains the
// old grant (stamped withdrawn) plus the withdraw row plus the new grant.
func TestConsentStore_RegrantAfterWithdraw(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)
	emailHash := HashEmail("regrant@example.com")

	// Grant 1.
	require.NoError(t, cs.Insert(&ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  time.Now().UTC().Add(-2 * time.Hour),
		NoticeVersion: "v1.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `{"trading":true}`,
		Method:        ConsentMethodOAuthCallback,
		ProofHash:     "h1",
	}))

	// Withdraw.
	_, err := cs.MarkWithdrawnByEmailHash(
		emailHash, time.Now().UTC().Add(-1*time.Hour),
		"v1.0", "user request", "", "",
	)
	require.NoError(t, err)

	active, err := cs.HasActiveGrant(emailHash)
	require.NoError(t, err)
	assert.False(t, active)

	// Grant 2 (fresh consent under newer notice).
	require.NoError(t, cs.Insert(&ConsentLogEntry{
		UserEmailHash: emailHash,
		TimestampUTC:  time.Now().UTC(),
		NoticeVersion: "v2.0",
		ConsentAction: ConsentActionGrant,
		Scope:         `{"trading":true,"analytics":false}`,
		Method:        ConsentMethodDashboardToggle,
		ProofHash:     "h3",
	}))

	active2, err := cs.HasActiveGrant(emailHash)
	require.NoError(t, err)
	assert.True(t, active2, "fresh grant must be visible as active again")

	// Full history: grant1 (withdrawn) + withdraw + grant2 (active).
	rows, err := cs.ListByEmailHash(emailHash, 10)
	require.NoError(t, err)
	require.Len(t, rows, 3)
	assert.Equal(t, ConsentActionGrant, rows[0].ConsentAction)
	assert.False(t, rows[0].WithdrawnAt.IsZero(), "first grant withdrawn")
	assert.Equal(t, ConsentActionWithdraw, rows[1].ConsentAction)
	assert.Equal(t, ConsentActionGrant, rows[2].ConsentAction)
	assert.True(t, rows[2].WithdrawnAt.IsZero(), "fresh grant is active")
}

// TestConsentStore_HasActiveGrant_EmptyHash returns false without erroring.
// Defensive guard so callers that forget to hash before checking don't get
// a misleading "yes" from a SQL row matching empty string.
func TestConsentStore_HasActiveGrant_EmptyHash(t *testing.T) {
	t.Parallel()
	cs := openTestConsentStore(t)
	active, err := cs.HasActiveGrant("")
	require.NoError(t, err)
	assert.False(t, active)
}

// TestConsentStore_InitTable_Idempotent_FreshDB verifies InitTable can be
// called repeatedly on a fresh DB without erroring. This is the basic
// "fresh install" startup path — second InitTable call is what every server
// restart hits in steady state.
func TestConsentStore_InitTable_Idempotent_FreshDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	cs := NewConsentStore(db)
	require.NoError(t, cs.InitTable(), "first InitTable on fresh DB must succeed")
	require.NoError(t, cs.InitTable(), "second InitTable on populated DB must succeed (idempotent)")
	require.NoError(t, cs.InitTable(), "third InitTable must still succeed")
}

// TestConsentStore_InitTable_PreMigrationSchema is a regression test for the
// v181 production crashloop (commit 471b9e8 deploy, 2026-05-03). The bug:
// the original InitTable bundled CREATE TABLE, CREATE INDEX (with a partial
// index referencing withdrawn_at), and ALTER TABLE ADD COLUMN withdrawn_at
// into a single ExecDDL call. SQLite executed them in source order, so on
// existing v180 databases (which had consent_log WITHOUT withdrawn_at), the
// partial-index creation failed referencing a non-existent column BEFORE the
// ALTER TABLE could add it. This took down server startup.
//
// The fix splits the DDL into three phases: CREATE TABLE → ALTER ADD COLUMN
// → CREATE INDEX, ensuring the column exists before any partial index
// references it.
//
// This test simulates a v180 database by hand-rolling the pre-migration
// schema (no withdrawn_at column), then runs InitTable() and asserts it
// recovers cleanly. Without the fix, this test reproduces the production
// crash.
func TestConsentStore_InitTable_PreMigrationSchema(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })

	// Simulate the v180 schema: consent_log table WITHOUT withdrawn_at.
	v180DDL := `
CREATE TABLE consent_log (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    user_email_hash  TEXT NOT NULL,
    timestamp_utc    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    ip_address       TEXT,
    user_agent       TEXT,
    notice_version   TEXT NOT NULL,
    consent_action   TEXT NOT NULL CHECK(consent_action IN ('grant','withdraw')),
    scope            TEXT NOT NULL,
    method           TEXT NOT NULL CHECK(method IN ('oauth_callback','dashboard_toggle')),
    proof_hash       TEXT NOT NULL
);`
	require.NoError(t, db.ExecDDL(v180DDL), "set up pre-migration v180 schema")

	// Run InitTable() — this MUST migrate the table forward without erroring.
	cs := NewConsentStore(db)
	require.NoError(t, cs.InitTable(),
		"InitTable on v180 schema must add withdrawn_at column and create indexes")

	// Calling again should still work (idempotent).
	require.NoError(t, cs.InitTable(),
		"second InitTable after migration must succeed (idempotent)")

	// Verify the column was actually added by inserting a row that uses it.
	emailHash := HashEmail("alice@example.com")
	scopeJSON := `["trading"]`
	proof := ComputeProofHash("notice v1", "grant")
	entry := &ConsentLogEntry{
		UserEmailHash:  emailHash,
		TimestampUTC:   time.Now().UTC().Truncate(time.Second),
		IPAddress:      "127.0.0.1",
		UserAgent:      "test-agent/1.0",
		NoticeVersion:  "v1",
		ConsentAction:  ConsentActionGrant,
		Scope:          scopeJSON,
		Method:         ConsentMethodOAuthCallback,
		ProofHash:      proof,
	}
	require.NoError(t, cs.Insert(entry), "insert must succeed against migrated schema")

	// MarkWithdrawnByEmailHash exercises the withdrawn_at column directly —
	// proves both the migration AND the partial-index path function on a
	// previously pre-migration DB.
	count, err := cs.MarkWithdrawnByEmailHash(
		emailHash, time.Now().UTC(), "v1", "regression test", "127.0.0.1", "test/1",
	)
	require.NoError(t, err)
	assert.Equal(t, int64(1), count, "MarkWithdrawnByEmailHash must stamp the migrated grant row")
}
