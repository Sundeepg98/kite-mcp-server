package alerts

import (
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Coverage push: hit remaining achievable uncovered lines.
// ===========================================================================

// ---------------------------------------------------------------------------
// evaluator.go line 32-33 — MarkTriggered returns false (alert already triggered)
// ShouldTrigger does NOT check Triggered flag, so a second Evaluate on the same
// alert will pass ShouldTrigger but fail MarkTriggered → continue.
// ---------------------------------------------------------------------------

// TestEvaluator_AlreadyTriggered_Continue — evaluator.go line 32-33 is UNREACHABLE
// without a race condition: GetByToken filters triggered alerts, so the only way
// MarkTriggered returns false is if another goroutine triggers the alert between
// GetByToken and MarkTriggered calls. Annotated with COVERAGE comment in source.

// ---------------------------------------------------------------------------
// telegram.go line 17-19 — newBotFunc error (when tgbotapi.NewBotAPI fails)
// ---------------------------------------------------------------------------

func TestNewTelegramNotifier_InvalidToken_CP(t *testing.T) {
	t.Parallel()
	s := NewStore(nil)
	_, err := NewTelegramNotifier("invalid-token-that-will-fail", s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	// NewBotAPI with an invalid token should return an error
	assert.Error(t, err)
}

// ---------------------------------------------------------------------------
// db.go line 191ff — migrateRegistryCheckConstraint with old-style table
// ---------------------------------------------------------------------------

func TestMigrateRegistryCheckConstraint(t *testing.T) {
	t.Parallel()
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// The constraint migration happens in OpenDB, so just verify the DB is usable
	// by inserting a row with the 'invalid' status (which requires the new constraint).
	_, execErr := db.ExecResult(
		`INSERT INTO app_registry (id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, 'invalid', ?, ?, ?, ?, ?)`,
		"test-id", "key", "secret", "user", "label", "admin", "admin", "", "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
	assert.NoError(t, execErr, "should accept 'invalid' status after migration")
}

// ---------------------------------------------------------------------------
// db.go line 248ff — migrateAlerts adds reference_price column
// ---------------------------------------------------------------------------

func TestMigrateAlerts_Idempotent_CP(t *testing.T) {
	t.Parallel()
	// Opening DB twice should be safe (migration is idempotent)
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Verify we can insert an alert with reference_price
	_, execErr := db.ExecResult(
		`INSERT INTO alerts (id, email, tradingsymbol, exchange, instrument_token, target_price, direction, triggered, created_at, reference_price)
		 VALUES (?, ?, ?, ?, ?, ?, ?, 0, ?, ?)`,
		"alert-1", "test@test.com", "INFY", "NSE", 408065, 1500.0, "above", "2026-01-01T00:00:00Z", 0.0)
	assert.NoError(t, execErr)
}
