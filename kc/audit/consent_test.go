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
