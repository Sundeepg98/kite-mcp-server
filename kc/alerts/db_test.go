package alerts


import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/gokiteconnect/v4/models"
	_ "modernc.org/sqlite"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
)

func openTestDB(t *testing.T) *DB {
	t.Helper()
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	t.Cleanup(func() { db.Close() })
	return db
}

// TestSQLDB_DBSatisfiesInterface pins the Postgres-readiness contract:
// *alerts.DB must satisfy the SQLDB interface, which describes the
// SQL-driver-portable subset of the *alerts.DB API. Adding a Postgres
// adapter (kc/alerts/postgres.go or similar) becomes a 1-line proof of
// concept: `var _ SQLDB = (*PostgresDB)(nil)` and the interface
// guarantees the consumer-facing method signatures match.
//
// The interface is intentionally NARROW — it captures only the
// driver-level surface (ExecDDL/ExecInsert/ExecResult/QueryRow/RawQuery/
// Close/Ping/SetEncryptionKey), not the SQLite-specific helpers
// (GetConfig/SetConfig use INSERT OR REPLACE which is SQLite-only;
// those stay on *DB and would have a Postgres-flavored sibling on the
// hypothetical PostgresDB).
func TestSQLDB_DBSatisfiesInterface(t *testing.T) {
	t.Parallel()
	var _ SQLDB = (*DB)(nil) // compile-time assertion; runtime body is for documentation
	db := openTestDB(t)
	var iface SQLDB = db
	require.NotNil(t, iface, "*alerts.DB must satisfy SQLDB interface")
	require.NoError(t, iface.Ping(), "Ping through interface must work end-to-end")
}



// ===========================================================================
// SetConfig / GetConfig
// ===========================================================================
func TestSetConfig_Success(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.SetConfig("test_key", "test_value")
	require.NoError(t, err)

	val, err := db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)
}


func TestGetConfig_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	_, err := db.GetConfig("missing_key")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}


func TestSetConfig_Upsert(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SetConfig("k", "v1"))
	require.NoError(t, db.SetConfig("k", "v2"))
	val, err := db.GetConfig("k")
	require.NoError(t, err)
	assert.Equal(t, "v2", val)
}



// ===========================================================================
// SaveTrailingStop — all optional fields populated
// ===========================================================================
func TestSaveTrailingStop_AllFields(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	ts := &TrailingStop{
		ID: "ts-full", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "RELIANCE", InstrumentToken: 738561, OrderID: "ORD1",
		Variety: "regular", TrailAmount: 20, TrailPct: 1.5, Direction: "long",
		HighWaterMark: 2500, CurrentStop: 2480, Active: true,
		CreatedAt: now, DeactivatedAt: now.Add(time.Hour),
		ModifyCount: 3, LastModifiedAt: now.Add(30 * time.Minute),
	}

	err := db.SaveTrailingStop(ts)
	require.NoError(t, err)

	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.Equal(t, "ts-full", stops[0].ID)
	assert.Equal(t, 3, stops[0].ModifyCount)
}



// ===========================================================================
// LoadTrailingStops — empty
// ===========================================================================
func TestLoadTrailingStops_Empty(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	assert.Empty(t, stops)
}



// ===========================================================================
// LoadTrailingStops — only active stops returned
// ===========================================================================
func TestLoadTrailingStops_OnlyActive(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	activeStop := &TrailingStop{
		ID: "ts-active", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "INFY", InstrumentToken: 408065, OrderID: "ORD1",
		Variety: "regular", TrailAmount: 20, Direction: "long",
		HighWaterMark: 1500, CurrentStop: 1480, Active: true, CreatedAt: now,
	}
	inactiveStop := &TrailingStop{
		ID: "ts-inactive", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "TCS", InstrumentToken: 2953217, OrderID: "ORD2",
		Variety: "regular", TrailAmount: 10, Direction: "long",
		HighWaterMark: 4000, CurrentStop: 3990, Active: false, CreatedAt: now,
	}

	require.NoError(t, db.SaveTrailingStop(activeStop))
	require.NoError(t, db.SaveTrailingStop(inactiveStop))

	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.Equal(t, "ts-active", stops[0].ID)
}



// ===========================================================================
// DeactivateTrailingStop — non-existent
// ===========================================================================
func TestDeactivateTrailingStop_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.DeactivateTrailingStop("nonexistent")
	assert.NoError(t, err)
}



// ===========================================================================
// UpdateTrailingStop — non-existent
// ===========================================================================
func TestUpdateTrailingStop_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.UpdateTrailingStop("nonexistent", 100, 90, 1)
	assert.NoError(t, err)
}



// ===========================================================================
// SaveDailyPnL — duplicate key (upsert)
// ===========================================================================
func TestSaveDailyPnL_DuplicateKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	entry := &DailyPnLEntry{
		Date: "2026-04-01", Email: "user@example.com",
		HoldingsPnL: 100, PositionsPnL: 200, NetPnL: 300,
		HoldingsCount: 5, TradesCount: 3,
	}
	require.NoError(t, db.SaveDailyPnL(entry))

	// Upsert
	entry.NetPnL = 999
	require.NoError(t, db.SaveDailyPnL(entry))

	entries, err := db.LoadDailyPnL("user@example.com", "2026-04-01", "2026-04-01")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.InDelta(t, 999, entries[0].NetPnL, 0.01)
}



// ===========================================================================
// LoadDailyPnL — empty result
// ===========================================================================
func TestLoadDailyPnL_Empty(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	entries, err := db.LoadDailyPnL("user@example.com", "2026-01-01", "2026-12-31")
	require.NoError(t, err)
	assert.Empty(t, entries)
}



// ===========================================================================
// SaveRegistryEntry — all fields, duplicate key, encryption
// ===========================================================================
func TestSaveRegistryEntry_AllFields(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-time.Hour)

	entry := &RegistryDBEntry{
		ID: "reg1", APIKey: "key1", APISecret: "secret1",
		AssignedTo: "user@example.com", Label: "My App",
		Status: "active", RegisteredBy: "admin@example.com",
		Source: "admin", LastUsedAt: &lastUsed,
		CreatedAt: now, UpdatedAt: now,
	}

	err := db.SaveRegistryEntry(entry)
	require.NoError(t, err)

	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg1")
	loaded := entries["reg1"]
	assert.Equal(t, "key1", loaded.APIKey)
	assert.Equal(t, "secret1", loaded.APISecret)
	assert.Equal(t, "user@example.com", loaded.AssignedTo)
	assert.Equal(t, "My App", loaded.Label)
	assert.Equal(t, "active", loaded.Status)
	assert.Equal(t, "admin@example.com", loaded.RegisteredBy)
	assert.Equal(t, "admin", loaded.Source)
	assert.NotNil(t, loaded.LastUsedAt)
}


func TestSaveRegistryEntry_NilLastUsedAt(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	entry := &RegistryDBEntry{
		ID: "reg2", APIKey: "key2", APISecret: "secret2",
		Status: "active", Source: "admin",
		CreatedAt: now, UpdatedAt: now,
	}

	err := db.SaveRegistryEntry(entry)
	require.NoError(t, err)

	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg2")
	assert.Nil(t, entries["reg2"].LastUsedAt)
}


func TestSaveRegistryEntry_DuplicateKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	entry := &RegistryDBEntry{
		ID: "reg-dup", APIKey: "key1", APISecret: "secret1",
		Status: "active", Source: "admin", CreatedAt: now, UpdatedAt: now,
	}
	require.NoError(t, db.SaveRegistryEntry(entry))

	// Update via upsert
	entry.APIKey = "key-updated"
	entry.Status = "disabled"
	require.NoError(t, db.SaveRegistryEntry(entry))

	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg-dup")
	assert.Equal(t, "key-updated", entries["reg-dup"].APIKey)
	assert.Equal(t, "disabled", entries["reg-dup"].Status)
}


func TestSaveRegistryEntry_WithEncryption(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	entry := &RegistryDBEntry{
		ID: "reg-enc", APIKey: "mykey", APISecret: "mysecret",
		Status: "active", Source: "admin", CreatedAt: now, UpdatedAt: now,
	}

	require.NoError(t, db.SaveRegistryEntry(entry))

	// Verify raw values are encrypted
	var rawKey, rawSecret string
	row := db.db.QueryRow(`SELECT api_key, api_secret FROM app_registry WHERE id = ?`, "reg-enc")
	require.NoError(t, row.Scan(&rawKey, &rawSecret))
	assert.NotEqual(t, "mykey", rawKey)
	assert.NotEqual(t, "mysecret", rawSecret)

	// Load decrypts transparently
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg-enc")
	assert.Equal(t, "mykey", entries["reg-enc"].APIKey)
	assert.Equal(t, "mysecret", entries["reg-enc"].APISecret)
}



// ===========================================================================
// LoadRegistryEntries — empty
// ===========================================================================
func TestLoadRegistryEntries_Empty(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}



// ===========================================================================
// LoadRegistryEntries — bad timestamps (covers fallback branches)
// ===========================================================================
func TestLoadRegistryEntries_BadTimestamps(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO app_registry (id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at) VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		"reg-bad", "k1", "s1", "", "", "active", "", "admin", "bad-date", "bad-date", "bad-date")
	require.NoError(t, err)

	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg-bad")
	// Bad timestamps should result in zero time, not an error
	assert.True(t, entries["reg-bad"].CreatedAt.IsZero())
	assert.True(t, entries["reg-bad"].UpdatedAt.IsZero())
	assert.Nil(t, entries["reg-bad"].LastUsedAt) // bad date won't parse -> nil
}



// ===========================================================================
// DeleteRegistryEntry — non-existent
// ===========================================================================
func TestDeleteRegistryEntry_NonExistent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.DeleteRegistryEntry("nonexistent")
	assert.NoError(t, err)
}



// ===========================================================================
// migrateRegistryCheckConstraint — idempotency
// ===========================================================================
func TestMigrateRegistryCheckConstraint_Idempotent(t *testing.T) {
	t.Parallel()
	// First migration: OpenDB already ran it. Run it again — should be no-op.
	db := openTestDB(t)

	// The DDL in OpenDB already has 'invalid' in the CHECK constraint.
	// Running migrateRegistryCheckConstraint again should be safe.
	err := migrateRegistryCheckConstraint(db.db)
	assert.NoError(t, err)
}


func TestMigrateRegistryCheckConstraint_OldSchema(t *testing.T) {
	t.Parallel()
	// Create a raw DB with old schema (without 'invalid' in CHECK constraint)
	rawDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close()

	oldDDL := `CREATE TABLE app_registry (
		id            TEXT PRIMARY KEY,
		api_key       TEXT NOT NULL,
		api_secret    TEXT NOT NULL,
		assigned_to   TEXT NOT NULL DEFAULT '',
		label         TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled')),
		registered_by TEXT NOT NULL DEFAULT '',
		source        TEXT NOT NULL DEFAULT 'admin',
		last_used_at  TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL
	)`
	_, err = rawDB.Exec(oldDDL)
	require.NoError(t, err)

	// Insert data with old schema
	_, err = rawDB.Exec(`INSERT INTO app_registry (id, api_key, api_secret, status, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		"old1", "k1", "s1", "active", time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// Run migration
	err = migrateRegistryCheckConstraint(rawDB)
	require.NoError(t, err)

	// Verify data is preserved
	var apiKey string
	err = rawDB.QueryRow(`SELECT api_key FROM app_registry WHERE id = ?`, "old1").Scan(&apiKey)
	require.NoError(t, err)
	assert.Equal(t, "k1", apiKey)

	// Verify new status values are now accepted
	_, err = rawDB.Exec(`INSERT INTO app_registry (id, api_key, api_secret, status, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		"new1", "k2", "s2", "invalid", time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	_, err = rawDB.Exec(`INSERT INTO app_registry (id, api_key, api_secret, status, created_at, updated_at) VALUES (?,?,?,?,?,?)`,
		"new2", "k3", "s3", "replaced", time.Now().Format(time.RFC3339), time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// Run migration again — should be idempotent
	err = migrateRegistryCheckConstraint(rawDB)
	require.NoError(t, err)
}


func TestMigrateRegistryCheckConstraint_NoTable(t *testing.T) {
	t.Parallel()
	// If the table doesn't exist, migration should return nil
	rawDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close()

	err = migrateRegistryCheckConstraint(rawDB)
	assert.NoError(t, err) // should return nil (table doesn't exist)
}



// ===========================================================================
// migrateAlerts — idempotency and partial migration
// ===========================================================================
func TestMigrateAlerts_Idempotent(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	// The migration already ran in OpenDB. Run it again.
	err := migrateAlerts(db.db)
	assert.NoError(t, err)
}


func TestMigrateAlerts_AlreadyHasColumns(t *testing.T) {
	t.Parallel()
	// When reference_price and notification_sent_at already exist,
	// migration should be a no-op
	rawDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close()

	ddl := `CREATE TABLE alerts (
		id TEXT PRIMARY KEY,
		email TEXT NOT NULL,
		tradingsymbol TEXT NOT NULL,
		exchange TEXT NOT NULL,
		instrument_token INTEGER NOT NULL,
		target_price REAL NOT NULL,
		direction TEXT NOT NULL CHECK(direction IN ('above','below','drop_pct','rise_pct')),
		triggered INTEGER NOT NULL DEFAULT 0,
		created_at TEXT NOT NULL,
		triggered_at TEXT,
		triggered_price REAL,
		reference_price REAL,
		notification_sent_at TEXT
	)`
	_, err = rawDB.Exec(ddl)
	require.NoError(t, err)

	err = migrateAlerts(rawDB)
	assert.NoError(t, err)
}



// ===========================================================================
// EnsureEncryptionSalt — corrupt salt in config
// ===========================================================================
func TestEnsureEncryptionSalt_CorruptSalt(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Manually store a corrupt (non-hex) salt
	require.NoError(t, db.SetConfig(hkdfSaltConfigKey, "not-valid-hex!@#"))

	_, err := EnsureEncryptionSalt(db, "test-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "decode stored salt")
}



// ===========================================================================
// hashSessionID — without encryption key (fallback)
// ===========================================================================
func TestHashSessionID_NoKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	// No encryption key set
	result := db.hashSessionID("my-session-id")
	assert.Equal(t, "my-session-id", result)
}


func TestHashSessionID_WithKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	result := db.hashSessionID("my-session-id")
	assert.NotEqual(t, "my-session-id", result)
	assert.Len(t, result, 64) // HMAC-SHA256 hex
}



// ===========================================================================
// ExecDDL / ExecInsert / ExecResult / QueryRow / RawQuery / Close
// ===========================================================================
func TestExecDDL(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.ExecDDL(`CREATE TABLE test_ddl (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)

	// Verify table exists
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM test_ddl`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 0, count)
}


func TestExecInsert(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.ExecDDL(`CREATE TABLE test_insert (id TEXT, val TEXT)`))
	err := db.ExecInsert(`INSERT INTO test_insert (id, val) VALUES (?, ?)`, "1", "hello")
	require.NoError(t, err)

	var val string
	err = db.QueryRow(`SELECT val FROM test_insert WHERE id = ?`, "1").Scan(&val)
	require.NoError(t, err)
	assert.Equal(t, "hello", val)
}


func TestExecResult(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.ExecDDL(`CREATE TABLE test_result (id TEXT)`))
	require.NoError(t, db.ExecInsert(`INSERT INTO test_result (id) VALUES (?)`, "1"))

	result, err := db.ExecResult(`DELETE FROM test_result WHERE id = ?`, "1")
	require.NoError(t, err)
	affected, err := result.RowsAffected()
	require.NoError(t, err)
	assert.Equal(t, int64(1), affected)
}


func TestRawQuery(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("a@x.com", 111))
	require.NoError(t, db.SaveTelegramChatID("b@x.com", 222))

	rows, err := db.RawQuery(`SELECT email, chat_id FROM telegram_chat_ids ORDER BY email`)
	require.NoError(t, err)
	defer rows.Close()

	var count int
	for rows.Next() {
		count++
		var email string
		var chatID int64
		require.NoError(t, rows.Scan(&email, &chatID))
	}
	assert.Equal(t, 2, count)
}



// ===========================================================================
// Evaluator boundary conditions — exactly at target price
// ===========================================================================
func TestShouldTrigger_ExactlyAtAboveTarget(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionAbove, TargetPrice: 100}
	assert.True(t, a.ShouldTrigger( 100)) // >= target
}


func TestShouldTrigger_ExactlyAtBelowTarget(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionBelow, TargetPrice: 100}
	assert.True(t, a.ShouldTrigger( 100)) // <= target
}


func TestShouldTrigger_DropPctExactly(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: 1000}
	// Exactly 5% drop: (1000 - 950) / 1000 * 100 = 5.0
	assert.True(t, a.ShouldTrigger( 950))
}


func TestShouldTrigger_RisePctExactly(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 1000}
	// Exactly 10% rise: (1100 - 1000) / 1000 * 100 = 10.0
	assert.True(t, a.ShouldTrigger( 1100))
}


func TestShouldTrigger_DropPctJustUnder(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: 1000}
	// 4.9% drop: (1000 - 951) / 1000 * 100 = 4.9
	assert.False(t, a.ShouldTrigger( 951))
}


func TestShouldTrigger_RisePctJustUnder(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 1000}
	// 9.9% rise: (1099 - 1000) / 1000 * 100 = 9.9
	assert.False(t, a.ShouldTrigger( 1099))
}


func TestShouldTrigger_RisePctZeroReference(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 0}
	assert.False(t, a.ShouldTrigger( 1100))
}


func TestShouldTrigger_DropPctNegativeReference(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: -100}
	assert.False(t, a.ShouldTrigger( 50))
}


func TestShouldTrigger_AboveJustBelow(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionAbove, TargetPrice: 100}
	assert.False(t, a.ShouldTrigger( 99.99))
}


func TestShouldTrigger_BelowJustAbove(t *testing.T) {
	t.Parallel()
	a := &Alert{Direction: DirectionBelow, TargetPrice: 100}
	assert.False(t, a.ShouldTrigger( 100.01))
}



// ===========================================================================
// Store — non-existent paths for DB-backed operations
// ===========================================================================
func TestStore_MarkTriggered_NonExistentID_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	ok := s.MarkTriggered("nonexistent-id", 1600.0)
	assert.False(t, ok)
}


func TestStore_MarkTriggered_AlreadyTriggered_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	ok := s.MarkTriggered(id, 1600.0)
	assert.True(t, ok)

	// Second trigger should return false
	ok = s.MarkTriggered(id, 1700.0)
	assert.False(t, ok)
}


func TestStore_MarkNotificationSent_NonExistentID_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.MarkNotificationSent("nonexistent-id", time.Now())
}


func TestStore_DeleteByEmail_NoAlerts_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	// Should not panic
	s.DeleteByEmail("nobody@example.com")
}


func TestStore_GetByToken_NoMatch_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	matches := s.GetByToken(999999) // non-existent token
	assert.Empty(t, matches)
}


func TestStore_GetByToken_OnlyActive_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)

	// Trigger the alert
	s.MarkTriggered(id, 1600.0)

	// GetByToken should skip triggered alerts
	matches := s.GetByToken(408065)
	assert.Empty(t, matches)
}


func TestStore_ActiveCount_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	id2, _ := s.Add("user@example.com", "TCS", "NSE", 2953217, 4000.0, DirectionBelow)
	s.Add("user@example.com", "RELIANCE", "NSE", 738561, 2500.0, DirectionAbove)

	assert.Equal(t, 3, s.ActiveCount("user@example.com"))

	s.MarkTriggered(id2, 3900.0)
	assert.Equal(t, 2, s.ActiveCount("user@example.com"))

	assert.Equal(t, 0, s.ActiveCount("nobody@example.com"))
}


func TestStore_ListAll_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.Add("a@x.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	s.Add("b@x.com", "TCS", "NSE", 2953217, 4000.0, DirectionBelow)

	all := s.ListAll()
	assert.Len(t, all, 2)
	assert.Len(t, all["a@x.com"], 1)
	assert.Len(t, all["b@x.com"], 1)
}


func TestStore_ListAllTelegram_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.SetTelegramChatID("a@x.com", 111)
	s.SetTelegramChatID("b@x.com", 222)

	all := s.ListAllTelegram()
	assert.Len(t, all, 2)
	assert.Equal(t, int64(111), all["a@x.com"])
	assert.Equal(t, int64(222), all["b@x.com"])
}


func TestStore_GetEmailByChatID_DB(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	s.SetTelegramChatID("user@example.com", 12345)

	email, ok := s.GetEmailByChatID(12345)
	assert.True(t, ok)
	assert.Equal(t, "user@example.com", email)

	email, ok = s.GetEmailByChatID(99999)
	assert.False(t, ok)
	assert.Empty(t, email)
}


func TestStore_LoadFromDB_NilDB_DB(t *testing.T) {
	t.Parallel()
	s := NewStore(nil)
	// No DB set — should return nil
	err := s.LoadFromDB()
	assert.NoError(t, err)
}



// ===========================================================================
// DB Close
// ===========================================================================
func TestDB_Close(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	err := db.Close()
	assert.NoError(t, err)
}



// ===========================================================================
// Encrypt/Decrypt exported wrappers
// ===========================================================================
func TestEncryptDecrypt_Exported(t *testing.T) {
	t.Parallel()
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	ct, err := Encrypt(key, "hello-world")
	require.NoError(t, err)

	pt := Decrypt(key, ct)
	assert.Equal(t, "hello-world", pt)
}


func TestDecrypt_EmptyInput(t *testing.T) {
	t.Parallel()
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	result := Decrypt(key, "")
	assert.Equal(t, "", result)
}


func TestDecrypt_TruncatedHex(t *testing.T) {
	t.Parallel()
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	// Valid hex but too short for GCM nonce
	result := Decrypt(key, "aabb")
	assert.Equal(t, "aabb", result) // returned as-is (too short)
}



// ===========================================================================
// Error-path coverage: closed DB triggers error branches in every CRUD function
// ===========================================================================
func closedTestDB(t *testing.T) *DB {
	t.Helper()
	db := openTestDB(t)
	db.db.Close() // Close the underlying *sql.DB
	return db
}


func TestSetConfig_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.SetConfig("k", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set config")
}


func TestSaveTrailingStop_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	ts := &TrailingStop{
		ID: "ts-err", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "INFY", InstrumentToken: 408065, OrderID: "ORD1",
		Variety: "regular", TrailAmount: 20, Direction: "long",
		HighWaterMark: 1500, CurrentStop: 1480, Active: true, CreatedAt: time.Now(),
	}
	err := db.SaveTrailingStop(ts)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save trailing stop")
}


func TestLoadTrailingStops_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	_, err := db.LoadTrailingStops()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query trailing stops")
}


func TestDeactivateTrailingStop_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.DeactivateTrailingStop("ts1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deactivate trailing stop")
}


func TestUpdateTrailingStop_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.UpdateTrailingStop("ts1", 100, 90, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update trailing stop")
}


func TestSaveDailyPnL_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	entry := &DailyPnLEntry{Date: "2026-04-01", Email: "user@example.com"}
	err := db.SaveDailyPnL(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save daily pnl")
}


func TestLoadDailyPnL_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	_, err := db.LoadDailyPnL("user@example.com", "2026-01-01", "2026-12-31")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query daily pnl")
}


func TestLoadRegistryEntries_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	_, err := db.LoadRegistryEntries()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query app_registry")
}


func TestSaveRegistryEntry_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	entry := &RegistryDBEntry{
		ID: "reg-err", APIKey: "k1", APISecret: "s1",
		Status: "active", Source: "admin",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	err := db.SaveRegistryEntry(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save registry entry")
}


func TestDeleteRegistryEntry_ClosedDB(t *testing.T) {
	t.Parallel()
	db := closedTestDB(t)
	err := db.DeleteRegistryEntry("reg1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete registry entry")
}



// ===========================================================================
// migrateAlerts — error path: check reference_price fails
// ===========================================================================
func TestMigrateAlerts_ClosedDB(t *testing.T) {
	t.Parallel()
	rawDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	// Create alerts table first
	_, err = rawDB.Exec(`CREATE TABLE alerts (id TEXT PRIMARY KEY, email TEXT, tradingsymbol TEXT, exchange TEXT, instrument_token INTEGER, target_price REAL, direction TEXT, triggered INTEGER DEFAULT 0, created_at TEXT)`)
	require.NoError(t, err)
	rawDB.Close()

	err = migrateAlerts(rawDB)
	require.Error(t, err)
}



// ===========================================================================
// migrateRegistryCheckConstraint — error paths
// ===========================================================================
func TestMigrateRegistryCheckConstraint_WithData(t *testing.T) {
	t.Parallel()
	// Test that migration preserves multiple rows of data
	rawDB, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer rawDB.Close()

	_, err = rawDB.Exec(`CREATE TABLE app_registry (
		id TEXT PRIMARY KEY, api_key TEXT NOT NULL, api_secret TEXT NOT NULL,
		assigned_to TEXT DEFAULT '', label TEXT DEFAULT '',
		status TEXT DEFAULT 'active' CHECK(status IN ('active','disabled')),
		registered_by TEXT DEFAULT '', source TEXT DEFAULT 'admin',
		last_used_at TEXT DEFAULT '', created_at TEXT NOT NULL, updated_at TEXT NOT NULL
	)`)
	require.NoError(t, err)

	now := time.Now().Format(time.RFC3339)
	_, err = rawDB.Exec(`INSERT INTO app_registry (id, api_key, api_secret, status, created_at, updated_at) VALUES (?,?,?,?,?,?)`, "a1", "k1", "s1", "active", now, now)
	require.NoError(t, err)
	_, err = rawDB.Exec(`INSERT INTO app_registry (id, api_key, api_secret, status, created_at, updated_at) VALUES (?,?,?,?,?,?)`, "a2", "k2", "s2", "disabled", now, now)
	require.NoError(t, err)

	err = migrateRegistryCheckConstraint(rawDB)
	require.NoError(t, err)

	// Verify both rows survived
	var count int
	require.NoError(t, rawDB.QueryRow(`SELECT COUNT(*) FROM app_registry`).Scan(&count))
	assert.Equal(t, 2, count)

	// Verify old statuses are preserved
	var status string
	require.NoError(t, rawDB.QueryRow(`SELECT status FROM app_registry WHERE id = ?`, "a2").Scan(&status))
	assert.Equal(t, "disabled", status)
}



// ===========================================================================
// SaveRegistryEntry — encryption error-path coverage for both api_key and api_secret
// ===========================================================================
func TestSaveRegistryEntry_EncryptionBothFields(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-time.Hour)
	entry := &RegistryDBEntry{
		ID: "reg-enc2", APIKey: "mykey2", APISecret: "mysecret2",
		AssignedTo: "user@example.com", Label: "App2",
		Status: "active", RegisteredBy: "admin@example.com",
		Source: "admin", LastUsedAt: &lastUsed,
		CreatedAt: now, UpdatedAt: now,
	}

	require.NoError(t, db.SaveRegistryEntry(entry))

	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Contains(t, entries, "reg-enc2")
	assert.Equal(t, "mykey2", entries["reg-enc2"].APIKey)
	assert.Equal(t, "mysecret2", entries["reg-enc2"].APISecret)
}



// ===========================================================================
// GetConfig — covers the success path that was missing
// ===========================================================================
func TestGetConfig_Success(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SetConfig("mykey", "myvalue"))
	val, err := db.GetConfig("mykey")
	require.NoError(t, err)
	assert.Equal(t, "myvalue", val)
}



// ===========================================================================
// LoadTrailingStops — with deactivated_at and last_modified_at populated
// ===========================================================================
func TestLoadTrailingStops_WithOptionalDates(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	ts := &TrailingStop{
		ID: "ts-dates", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "INFY", InstrumentToken: 408065, OrderID: "ORD1",
		Variety: "regular", TrailAmount: 20, Direction: "long",
		HighWaterMark: 1500, CurrentStop: 1480, Active: true,
		CreatedAt: now, LastModifiedAt: now.Add(time.Minute),
	}
	require.NoError(t, db.SaveTrailingStop(ts))

	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.False(t, stops[0].LastModifiedAt.IsZero())
}



// ===========================================================================
// SaveTrailingStop — without optional dates (covers zero-value branches)
// ===========================================================================

// ===========================================================================
// Store — DB persistence: error logging paths with DB
// ===========================================================================
func TestStore_AddWithDB_Persistence(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, err := s.AddWithReferencePrice("user@example.com", "RELIANCE", "NSE", 738561, 5.0, DirectionDropPct, 2500.0)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// Verify stored in DB
	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alerts["user@example.com"], 1)
	assert.Equal(t, 2500.0, alerts["user@example.com"][0].ReferencePrice)
}


func TestStore_SetTelegramChatID_WithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	s.SetTelegramChatID("user@example.com", 99999)

	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(99999), ids["user@example.com"])
}


func TestStore_DeleteByEmail_WithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	s.SetTelegramChatID("user@example.com", 12345)

	s.DeleteByEmail("user@example.com")

	// Verify DB is cleaned
	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alerts["user@example.com"])

	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	_, ok := ids["user@example.com"]
	assert.False(t, ok)
}


func TestStore_MarkTriggered_WithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	ok := s.MarkTriggered(id, 1600.0)
	assert.True(t, ok)

	// Verify in DB
	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alerts["user@example.com"], 1)
	assert.True(t, alerts["user@example.com"][0].Triggered)
}


func TestStore_MarkNotificationSent_WithDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	now := time.Now().Truncate(time.Second)
	s.MarkNotificationSent(id, now)

	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alerts["user@example.com"], 1)
	assert.False(t, alerts["user@example.com"][0].NotificationSentAt.IsZero())
}



// ===========================================================================
// Evaluator — additional edge cases
// ===========================================================================
func TestEvaluator_AlreadyTriggered_NoDoubleNotify(t *testing.T) {
	t.Parallel()
	var notifyCount int
	s := NewStore(func(a *Alert, price float64) {
		notifyCount++
	})

	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 5.0, DirectionDropPct, 1000.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// First trigger at 5% drop
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 950})
	assert.Equal(t, 1, notifyCount)

	// Second tick at same level — already triggered, no double notify
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 940})
	assert.Equal(t, 1, notifyCount) // Still 1
}


func TestEvaluator_MultipleAlertsSameToken(t *testing.T) {
	t.Parallel()
	var notified []string
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a.ID)
	})

	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	s.Add("user@example.com", "INFY", "NSE", 408065, 1400.0, DirectionAbove)
	eval := NewEvaluator(s, defaultTestLogger())

	// Price at 1500 — should trigger both
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 1500})
	assert.Len(t, notified, 2)
}


func TestEvaluator_RisePctWithReference(t *testing.T) {
	t.Parallel()
	var notified []*Alert
	s := NewStore(func(a *Alert, price float64) {
		notified = append(notified, a)
	})

	s.AddWithReferencePrice("user@example.com", "INFY", "NSE", 408065, 10.0, DirectionRisePct, 500.0)
	eval := NewEvaluator(s, defaultTestLogger())

	// 10% rise from 500 = 550
	eval.Evaluate("user@example.com", models.Tick{InstrumentToken: 408065, LastPrice: 550})
	assert.Len(t, notified, 1)
}



// ===========================================================================
// ValidDirections
// ===========================================================================
func TestValidDirections_DBCoverage(t *testing.T) {
	t.Parallel()
	assert.True(t, ValidDirections[DirectionAbove])
	assert.True(t, ValidDirections[DirectionBelow])
	assert.True(t, ValidDirections[DirectionDropPct])
	assert.True(t, ValidDirections[DirectionRisePct])
	assert.False(t, ValidDirections[Direction("invalid")])
}



// ===========================================================================
// Store — DB error logging paths (closed DB triggers error -> logger.Error)
// ===========================================================================
func TestStore_LoadFromDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())
	db.db.Close() // close underlying connection

	err := s.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load alerts")
}


func TestStore_Add_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())
	db.db.Close()

	// Add should succeed (in-memory) but log error for DB persistence
	id, err := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	require.NoError(t, err) // Add itself doesn't fail
	assert.NotEmpty(t, id)
}


func TestStore_Delete_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	// First add while DB is open
	id, err := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	require.NoError(t, err)

	// Close DB, then delete — should succeed in-memory but log DB error
	db.db.Close()
	err = s.Delete("user@example.com", id)
	require.NoError(t, err) // Delete itself doesn't fail
}


func TestStore_DeleteByEmail_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	s.SetTelegramChatID("user@example.com", 12345)

	db.db.Close()
	// Should not panic, but logs errors
	s.DeleteByEmail("user@example.com")
}


func TestStore_MarkTriggered_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	db.db.Close()

	ok := s.MarkTriggered(id, 1600.0)
	assert.True(t, ok) // in-memory succeeds, DB error logged
}


func TestStore_MarkNotificationSent_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())

	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	db.db.Close()

	// Should not panic
	s.MarkNotificationSent(id, time.Now())
}


func TestStore_SetTelegramChatID_ClosedDB_LogsError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)
	s.SetLogger(defaultTestLogger())
	db.db.Close()

	// Should not panic
	s.SetTelegramChatID("user@example.com", 12345)
}



// ===========================================================================
// PnLSnapshotService — error paths
// ===========================================================================
func TestPnLSnapshotService_NilDB(t *testing.T) {
	t.Parallel()
	svc := NewPnLSnapshotService(nil, nil, nil, defaultTestLogger())
	assert.Nil(t, svc)
}


func TestPnLSnapshotService_SetBrokerProviderNil(t *testing.T) {
	t.Parallel()
	var svc *PnLSnapshotService
	// SetBrokerProvider on nil service should not panic
	svc.SetBrokerProvider(nil)
}


func TestPnLJournal_ClosedDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	db.db.Close()

	_, err := svc.GetJournal("user@example.com", "2026-01-01", "2026-12-31")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load daily pnl")
}


func TestPnLJournal_StreakTracking(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())

	// Win, Win, Loss, Loss, Loss, Win
	entries := []*DailyPnLEntry{
		{Date: "2026-01-01", Email: "user@example.com", NetPnL: 100},
		{Date: "2026-01-02", Email: "user@example.com", NetPnL: 200},
		{Date: "2026-01-03", Email: "user@example.com", NetPnL: -50},
		{Date: "2026-01-04", Email: "user@example.com", NetPnL: -100},
		{Date: "2026-01-05", Email: "user@example.com", NetPnL: -25},
		{Date: "2026-01-06", Email: "user@example.com", NetPnL: 300},
	}
	for _, e := range entries {
		require.NoError(t, db.SaveDailyPnL(e))
	}

	result, err := svc.GetJournal("user@example.com", "2026-01-01", "2026-01-06")
	require.NoError(t, err)
	assert.Equal(t, 6, result.TotalDays)
	assert.Equal(t, 3, result.WinDays)   // 100, 200, 300
	assert.Equal(t, 3, result.LossDays)  // -50, -100, -25
	assert.Equal(t, 2, result.BestStreak) // 2 wins in a row
	assert.Equal(t, -3, result.WorstStreak) // 3 losses in a row
	assert.Equal(t, 1, result.CurrentStreak) // ended with a win
}



// ===========================================================================
// PnLSnapshotService — TakeSnapshots with mocks
// ===========================================================================

type testCredentialGetter struct {
	keys map[string]string
}

func (g *testCredentialGetter) GetAPIKey(email string) string {
	return g.keys[email]
}
func TestTakeSnapshots_Success(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Set up a user with a telegram chat ID
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))
	require.NoError(t, db.SaveToken("user@example.com", "token1", "uid1", "User1", time.Now()))

	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "token1", storedAt: time.Now()},
		},
	}
	creds := &testCredentialGetter{keys: map[string]string{"user@example.com": "apikey1"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())

	mock := &mockBrokerData{
		holdings: []kiteconnect.Holding{{Tradingsymbol: "INFY", DayChange: 500}},
	}
	svc.SetBrokerProvider(mock)

	// Should not panic, should save a snapshot
	svc.TakeSnapshots()
}


func TestTakeSnapshots_ClosedDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	tokens := &mockTokenChecker{}
	creds := &testCredentialGetter{}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	db.db.Close()

	// Should not panic — logs error and returns
	svc.TakeSnapshots()
}


func TestTakeSnapshots_NoToken(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))

	tokens := &mockTokenChecker{} // no tokens
	creds := &testCredentialGetter{keys: map[string]string{"user@example.com": "apikey1"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	// Should skip user with no token
	svc.TakeSnapshots()
}


func TestTakeSnapshots_ExpiredToken(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))

	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "token1", storedAt: time.Now()},
		},
		expiredFunc: func(t time.Time) bool { return true }, // always expired
	}
	creds := &testCredentialGetter{keys: map[string]string{"user@example.com": "apikey1"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	// Should skip user with expired token
	svc.TakeSnapshots()
}


func TestTakeSnapshots_NoAPIKey(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))

	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "token1", storedAt: time.Now()},
		},
	}
	creds := &testCredentialGetter{} // no API keys

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	// Should skip user with no API key
	svc.TakeSnapshots()
}


func TestTakeSnapshots_BrokerError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))

	tokens := &mockTokenChecker{
		tokens: map[string]struct {
			accessToken string
			storedAt    time.Time
		}{
			"user@example.com": {accessToken: "token1", storedAt: time.Now()},
		},
	}
	creds := &testCredentialGetter{keys: map[string]string{"user@example.com": "apikey1"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	mock := &mockBrokerData{
		holdingsErr:  assert.AnError,
		positionsErr: assert.AnError,
	}
	svc.SetBrokerProvider(mock)

	// Should still save a snapshot (with zero values)
	svc.TakeSnapshots()
}



// ===========================================================================
// PnL buildPnLEntry edge cases
// ===========================================================================
func TestBuildPnLEntry_BothErrors_DBCov(t *testing.T) {
	t.Parallel()
	entry := buildPnLEntry("2026-04-01", "user@example.com", nil, assert.AnError,
		kiteconnect.Positions{}, assert.AnError)
	assert.Equal(t, "2026-04-01", entry.Date)
	assert.Equal(t, 0.0, entry.NetPnL)
	assert.Equal(t, 0, entry.HoldingsCount)
	assert.Equal(t, 0, entry.TradesCount)
}


func TestBuildPnLEntry_WithData(t *testing.T) {
	t.Parallel()
	holdings := []kiteconnect.Holding{
		{Tradingsymbol: "INFY", DayChange: 500},
		{Tradingsymbol: "TCS", DayChange: -200},
	}
	positions := kiteconnect.Positions{
		Day: []kiteconnect.Position{
			{Tradingsymbol: "RELIANCE", PnL: 300, Quantity: 10},
			{Tradingsymbol: "HDFCBANK", PnL: -100, DayBuyQuantity: 5},
		},
	}
	entry := buildPnLEntry("2026-04-01", "user@example.com", holdings, nil, positions, nil)
	assert.Equal(t, 2, entry.HoldingsCount)
	assert.InDelta(t, 300, entry.HoldingsPnL, 0.01)     // 500 + (-200)
	assert.InDelta(t, 200, entry.PositionsPnL, 0.01)     // 300 + (-100)
	assert.InDelta(t, 500, entry.NetPnL, 0.01)           // 300 + 200
	assert.Equal(t, 2, entry.TradesCount)                 // both have qty or day qty
}


func TestSaveTrailingStop_MinimalFields(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	ts := &TrailingStop{
		ID: "ts-min", Email: "user@example.com", Exchange: "NSE",
		Tradingsymbol: "INFY", InstrumentToken: 408065, OrderID: "ORD1",
		Variety: "regular", TrailAmount: 20, Direction: "long",
		HighWaterMark: 1500, CurrentStop: 1480, Active: true,
		CreatedAt: time.Now().Truncate(time.Second),
		// DeactivatedAt and LastModifiedAt are zero
	}
	require.NoError(t, db.SaveTrailingStop(ts))

	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.True(t, stops[0].DeactivatedAt.IsZero())
	assert.True(t, stops[0].LastModifiedAt.IsZero())
}


func TestSaveRegistryEntry_Error(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.Close()
	err := db.SaveRegistryEntry(&RegistryDBEntry{
		ID: "reg1", APIKey: "k", APISecret: "s",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.Error(t, err)
}
