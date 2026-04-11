package alerts


import (
	"database/sql"
	"os"
	"path/filepath"
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

func TestCredentialCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveCredential("user@example.com", "key123", "secret456", "key123", now)
	require.NoError(t, err)

	// Load
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "user@example.com", creds[0].Email)
	assert.Equal(t, "key123", creds[0].APIKey)
	assert.Equal(t, "secret456", creds[0].APISecret)
	assert.Equal(t, "key123", creds[0].AppID)

	// Update (upsert)
	err = db.SaveCredential("user@example.com", "newkey", "newsecret", "newkey", now)
	require.NoError(t, err)
	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "newkey", creds[0].APIKey)

	// Delete
	err = db.DeleteCredential("user@example.com")
	require.NoError(t, err)
	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestCredentialEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now()
	err = db.SaveCredential("enc@example.com", "mykey", "mysecret", "mykey", now)
	require.NoError(t, err)

	// Verify values are encrypted in DB (raw query)
	var rawKey, rawSecret string
	row := db.db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "enc@example.com")
	require.NoError(t, row.Scan(&rawKey, &rawSecret))
	assert.NotEqual(t, "mykey", rawKey, "api_key should be encrypted in DB")
	assert.NotEqual(t, "mysecret", rawSecret, "api_secret should be encrypted in DB")

	// Load decrypts transparently
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "mykey", creds[0].APIKey)
	assert.Equal(t, "mysecret", creds[0].APISecret)
}

func TestCredentialPlaintextMigration(t *testing.T) {
	db := openTestDB(t)

	// Save without encryption (simulates pre-encryption data)
	now := time.Now()
	err := db.SaveCredential("old@example.com", "plainkey", "plainsecret", "plainkey", now)
	require.NoError(t, err)

	// Now enable encryption and load — plaintext values should load fine
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "plainkey", creds[0].APIKey)
	assert.Equal(t, "plainsecret", creds[0].APISecret)
}

func TestTokenCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	err := db.SaveToken("user@example.com", "token123", "uid1", "UserName", now)
	require.NoError(t, err)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "user@example.com", tokens[0].Email)
	assert.Equal(t, "token123", tokens[0].AccessToken)
	assert.Equal(t, "uid1", tokens[0].UserID)
	assert.Equal(t, "UserName", tokens[0].UserName)

	err = db.DeleteToken("user@example.com")
	require.NoError(t, err)
	tokens, err = db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

func TestMultipleCredentials(t *testing.T) {
	db := openTestDB(t)
	now := time.Now()

	db.SaveCredential("a@x.com", "k1", "s1", "k1", now)
	db.SaveCredential("b@x.com", "k2", "s2", "k2", now)
	db.SaveCredential("c@x.com", "k3", "s3", "k3", now)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	assert.Len(t, creds, 3)
}

func TestSessionCRUD(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Save
	err := db.SaveSession("kitemcp-abc-123", "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Load
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "kitemcp-abc-123", sessions[0].SessionID)
	assert.Equal(t, "user@example.com", sessions[0].Email)
	assert.Equal(t, now.UTC(), sessions[0].CreatedAt.UTC())
	assert.Equal(t, expires.UTC(), sessions[0].ExpiresAt.UTC())
	assert.False(t, sessions[0].Terminated)

	// Update (upsert) — mark as terminated
	err = db.SaveSession("kitemcp-abc-123", "user@example.com", now, expires, true)
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].Terminated)

	// Delete
	err = db.DeleteSession("kitemcp-abc-123")
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionEmptyEmail(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Sessions can have empty email (local dev, pre-OAuth)
	err := db.SaveSession("kitemcp-no-email", "", now, expires, false)
	require.NoError(t, err)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "", sessions[0].Email)
}

func TestMultipleSessions(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	db.SaveSession("kitemcp-s1", "a@x.com", now, expires, false)
	db.SaveSession("kitemcp-s2", "b@x.com", now, expires, false)
	db.SaveSession("kitemcp-s3", "a@x.com", now, expires, true)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	assert.Len(t, sessions, 3)
}

func TestTokenEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	err = db.SaveToken("enc@example.com", "my-access-token", "uid1", "TestUser", now)
	require.NoError(t, err)

	// Verify the raw value in SQLite is NOT plaintext
	var rawToken string
	row := db.db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "enc@example.com")
	require.NoError(t, row.Scan(&rawToken))
	assert.NotEqual(t, "my-access-token", rawToken, "access_token should be encrypted in DB")

	// Load decrypts transparently
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "my-access-token", tokens[0].AccessToken)
	assert.Equal(t, "enc@example.com", tokens[0].Email)
	assert.Equal(t, "uid1", tokens[0].UserID)
	assert.Equal(t, "TestUser", tokens[0].UserName)
}

func TestTokenEncryptionMigration(t *testing.T) {
	db := openTestDB(t)

	// Insert a plaintext token directly (simulates pre-encryption data)
	now := time.Now().Truncate(time.Second)
	_, err := db.db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"old@example.com", "plaintext-token", "uid2", "OldUser", now.Format(time.RFC3339))
	require.NoError(t, err)

	// Now enable encryption and load — plaintext should be returned as-is
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "plaintext-token", tokens[0].AccessToken)
}

func TestClientSecretEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	err = db.SaveClient("client-id-1", "super-secret", `["http://localhost"]`, "TestApp", now, false)
	require.NoError(t, err)

	// Verify the raw value in SQLite is NOT plaintext
	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "client-id-1")
	require.NoError(t, row.Scan(&rawSecret))
	assert.NotEqual(t, "super-secret", rawSecret, "client_secret should be encrypted in DB")

	// Load decrypts transparently
	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "super-secret", clients[0].ClientSecret)
	assert.Equal(t, "client-id-1", clients[0].ClientID)
	assert.Equal(t, "TestApp", clients[0].ClientName)
	assert.False(t, clients[0].IsKiteAPIKey)
}

func TestClientSecretEncryptionEmptySecret(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	// Kite API key clients may have empty secret — encryption should be skipped
	err = db.SaveClient("kite-api-key", "", `["http://localhost"]`, "KiteApp", now, true)
	require.NoError(t, err)

	// Raw value should still be empty
	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "kite-api-key")
	require.NoError(t, row.Scan(&rawSecret))
	assert.Equal(t, "", rawSecret, "empty secret should remain empty")

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "", clients[0].ClientSecret)
	assert.True(t, clients[0].IsKiteAPIKey)
}

func TestAlertCRUD_WithReferencePrice(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "test1234",
		Email:           "user@example.com",
		Tradingsymbol:   "RELIANCE",
		Exchange:        "NSE",
		InstrumentToken: 738561,
		TargetPrice:     5.0,
		Direction:       DirectionDropPct,
		ReferencePrice:  2500.0,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	// Save
	err := db.SaveAlert(alert)
	require.NoError(t, err)

	// Load
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	assert.Equal(t, "test1234", loaded.ID)
	assert.Equal(t, DirectionDropPct, loaded.Direction)
	assert.Equal(t, 5.0, loaded.TargetPrice)
	assert.Equal(t, 2500.0, loaded.ReferencePrice)
	assert.False(t, loaded.Triggered)
}

func TestAlertCRUD_WithoutReferencePrice(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "test5678",
		Email:           "user@example.com",
		Tradingsymbol:   "INFY",
		Exchange:        "NSE",
		InstrumentToken: 408065,
		TargetPrice:     1500.0,
		Direction:       DirectionAbove,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	// Save (no reference price)
	err := db.SaveAlert(alert)
	require.NoError(t, err)

	// Load — reference_price should be 0
	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	assert.Equal(t, DirectionAbove, loaded.Direction)
	assert.Equal(t, 1500.0, loaded.TargetPrice)
	assert.Equal(t, 0.0, loaded.ReferencePrice)
}

func TestAlertCRUD_RisePct(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "test9012",
		Email:           "user@example.com",
		Tradingsymbol:   "TCS",
		Exchange:        "NSE",
		InstrumentToken: 2953217,
		TargetPrice:     10.0,
		Direction:       DirectionRisePct,
		ReferencePrice:  3500.0,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	err := db.SaveAlert(alert)
	require.NoError(t, err)

	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	assert.Equal(t, DirectionRisePct, loaded.Direction)
	assert.Equal(t, 10.0, loaded.TargetPrice)
	assert.Equal(t, 3500.0, loaded.ReferencePrice)
}

func TestAlertMigration_AddReferencePrice(t *testing.T) {
	// Simulate an old database without the reference_price column.
	// Create a DB with old schema, then open it with OpenDB which runs migration.
	db, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer db.Close()

	// Create old schema (without reference_price, old CHECK constraint)
	oldDDL := `
CREATE TABLE IF NOT EXISTS alerts (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    instrument_token INTEGER NOT NULL,
    target_price     REAL NOT NULL,
    direction        TEXT NOT NULL CHECK(direction IN ('above','below')),
    triggered        INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    triggered_at     TEXT,
    triggered_price  REAL
);`
	_, err = db.Exec(oldDDL)
	require.NoError(t, err)

	// Insert an old-style alert
	_, err = db.Exec(`INSERT INTO alerts (id, email, tradingsymbol, exchange, instrument_token, target_price, direction, triggered, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		"old123", "user@example.com", "RELIANCE", "NSE", 738561, 2500.0, "above", 0, time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// Run migration
	err = migrateAlerts(db)
	require.NoError(t, err)

	// Verify the column was added
	var count int
	err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('alerts') WHERE name = 'reference_price'`).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count)

	// Verify existing data is intact (reference_price should be NULL)
	var refPrice sql.NullFloat64
	err = db.QueryRow(`SELECT reference_price FROM alerts WHERE id = ?`, "old123").Scan(&refPrice)
	require.NoError(t, err)
	assert.False(t, refPrice.Valid, "reference_price should be NULL for old alerts")
}

func TestClientSecretEncryptionMigration(t *testing.T) {
	db := openTestDB(t)

	// Insert a plaintext client_secret directly (simulates pre-encryption data)
	now := time.Now().Truncate(time.Second)
	_, err := db.db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key) VALUES (?,?,?,?,?,?)`,
		"old-client", "plaintext-secret", `["http://localhost"]`, "OldApp", now.Format(time.RFC3339), 0)
	require.NoError(t, err)

	// Now enable encryption and load — plaintext should be returned as-is
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "plaintext-secret", clients[0].ClientSecret)
}

func TestSessionHashedID(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)
	sessionID := "kitemcp-abc-123-hashed"

	// Save
	err = db.SaveSession(sessionID, "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Verify the PK in DB is NOT the original session ID (it's an HMAC hash)
	var rawPK string
	row := db.db.QueryRow(`SELECT session_id FROM mcp_sessions LIMIT 1`)
	require.NoError(t, row.Scan(&rawPK))
	assert.NotEqual(t, sessionID, rawPK, "session_id PK should be HMAC-hashed, not plaintext")
	assert.Len(t, rawPK, 64, "HMAC-SHA256 hex output should be 64 chars")

	// Verify session_id_enc is populated and NOT the original
	var rawEnc string
	row = db.db.QueryRow(`SELECT session_id_enc FROM mcp_sessions LIMIT 1`)
	require.NoError(t, row.Scan(&rawEnc))
	assert.NotEqual(t, sessionID, rawEnc, "session_id_enc should be encrypted, not plaintext")
	assert.NotEmpty(t, rawEnc)

	// Load should recover the original session ID
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, sessionID, sessions[0].SessionID, "LoadSessions should decrypt and return original session ID")
	assert.Equal(t, "user@example.com", sessions[0].Email)

	// Delete by original session ID should work (hashes internally)
	err = db.DeleteSession(sessionID)
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestSessionHashedID_Deterministic(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	// hashSessionID should be deterministic for the same input
	h1 := db.hashSessionID("kitemcp-test-123")
	h2 := db.hashSessionID("kitemcp-test-123")
	assert.Equal(t, h1, h2, "HMAC hash should be deterministic")

	// Different inputs should produce different hashes
	h3 := db.hashSessionID("kitemcp-test-456")
	assert.NotEqual(t, h1, h3, "Different session IDs should hash differently")
}

func TestSessionHashedID_NoEncryptionKey(t *testing.T) {
	db := openTestDB(t)
	// No encryption key set — should fall back to storing session ID as-is

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)
	sessionID := "kitemcp-plain-fallback"

	err := db.SaveSession(sessionID, "user@example.com", now, expires, false)
	require.NoError(t, err)

	// PK should be the original session ID (no hashing)
	var rawPK string
	row := db.db.QueryRow(`SELECT session_id FROM mcp_sessions LIMIT 1`)
	require.NoError(t, row.Scan(&rawPK))
	assert.Equal(t, sessionID, rawPK, "without encryption key, session_id should be stored as-is")

	// Load should work normally
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, sessionID, sessions[0].SessionID)

	// Delete should work
	err = db.DeleteSession(sessionID)
	require.NoError(t, err)
	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

func TestDailyPnLCRUD(t *testing.T) {
	db := openTestDB(t)

	// Save
	entry := &DailyPnLEntry{
		Date:          "2026-04-01",
		Email:         "user@example.com",
		HoldingsPnL:   1500.50,
		PositionsPnL:  -200.25,
		NetPnL:        1300.25,
		HoldingsCount: 10,
		TradesCount:   3,
	}
	err := db.SaveDailyPnL(entry)
	require.NoError(t, err)

	// Save another day
	entry2 := &DailyPnLEntry{
		Date:          "2026-04-02",
		Email:         "user@example.com",
		HoldingsPnL:   -500.00,
		PositionsPnL:  800.00,
		NetPnL:        300.00,
		HoldingsCount: 10,
		TradesCount:   5,
	}
	err = db.SaveDailyPnL(entry2)
	require.NoError(t, err)

	// Load range
	entries, err := db.LoadDailyPnL("user@example.com", "2026-04-01", "2026-04-02")
	require.NoError(t, err)
	require.Len(t, entries, 2)
	assert.Equal(t, "2026-04-01", entries[0].Date)
	assert.InDelta(t, 1300.25, entries[0].NetPnL, 0.01)
	assert.Equal(t, "2026-04-02", entries[1].Date)
	assert.InDelta(t, 300.00, entries[1].NetPnL, 0.01)

	// Load single day
	entries, err = db.LoadDailyPnL("user@example.com", "2026-04-02", "2026-04-02")
	require.NoError(t, err)
	require.Len(t, entries, 1)

	// Load empty range
	entries, err = db.LoadDailyPnL("user@example.com", "2025-01-01", "2025-01-31")
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Upsert (replace)
	entry.NetPnL = 9999.99
	err = db.SaveDailyPnL(entry)
	require.NoError(t, err)
	entries, err = db.LoadDailyPnL("user@example.com", "2026-04-01", "2026-04-01")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.InDelta(t, 9999.99, entries[0].NetPnL, 0.01)

	// Different user
	entries, err = db.LoadDailyPnL("other@example.com", "2026-04-01", "2026-04-02")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestTrailingStopDBCRUD(t *testing.T) {
	db := openTestDB(t)

	ts := &TrailingStop{
		ID:              "ts001",
		Email:           "user@example.com",
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		InstrumentToken: 408065,
		OrderID:         "ORD001",
		Variety:         "regular",
		TrailAmount:     20,
		Direction:       "long",
		HighWaterMark:   1500,
		CurrentStop:     1480,
		Active:          true,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	// Save
	err := db.SaveTrailingStop(ts)
	require.NoError(t, err)

	// Load
	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.Equal(t, "ts001", stops[0].ID)
	assert.Equal(t, "ORD001", stops[0].OrderID)
	assert.InDelta(t, 1500, stops[0].HighWaterMark, 0.01)
	assert.InDelta(t, 1480, stops[0].CurrentStop, 0.01)

	// Update
	err = db.UpdateTrailingStop("ts001", 1550, 1530, 1)
	require.NoError(t, err)

	stops, err = db.LoadTrailingStops()
	require.NoError(t, err)
	require.Len(t, stops, 1)
	assert.InDelta(t, 1550, stops[0].HighWaterMark, 0.01)
	assert.InDelta(t, 1530, stops[0].CurrentStop, 0.01)
	assert.Equal(t, 1, stops[0].ModifyCount)

	// Deactivate
	err = db.DeactivateTrailingStop("ts001")
	require.NoError(t, err)

	// LoadTrailingStops only returns active
	stops, err = db.LoadTrailingStops()
	require.NoError(t, err)
	assert.Empty(t, stops)
}

func TestSessionHashedID_UpsertSameSession(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)
	sessionID := "kitemcp-upsert-test"

	// Save initial
	err = db.SaveSession(sessionID, "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Upsert with terminated=true
	err = db.SaveSession(sessionID, "user@example.com", now, expires, true)
	require.NoError(t, err)

	// Should have exactly one row (upsert, not duplicate)
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].Terminated)
	assert.Equal(t, sessionID, sessions[0].SessionID)
}


// ===========================================================================
// Merged from coverage_test.go
// ===========================================================================

func TestDB_RegistryCRUD_Extended(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-1 * time.Hour)

	entry := &RegistryDBEntry{
		ID:           "reg-001",
		APIKey:       "test-api-key",
		APISecret:    "test-api-secret",
		AssignedTo:   "user@example.com",
		Label:        "Test App",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "manual",
		LastUsedAt:   &lastUsed,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	// Save
	err := db.SaveRegistryEntry(entry)
	require.NoError(t, err)

	// Load
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "reg-001", entries["reg-001"].ID)
	assert.Equal(t, "test-api-key", entries["reg-001"].APIKey)
	assert.Equal(t, "user@example.com", entries["reg-001"].AssignedTo)
	assert.NotNil(t, entries["reg-001"].LastUsedAt)

	// Save without LastUsedAt
	entry2 := &RegistryDBEntry{
		ID:           "reg-002",
		APIKey:       "key2",
		APISecret:    "secret2",
		AssignedTo:   "user2@example.com",
		Label:        "App 2",
		Status:       "active",
		RegisteredBy: "admin@example.com",
		Source:       "api",
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	err = db.SaveRegistryEntry(entry2)
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 2)

	// Delete
	err = db.DeleteRegistryEntry("reg-001")
	require.NoError(t, err)

	entries, err = db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
}

// ===========================================================================
// DB — Config get/set
// ===========================================================================

func TestDB_Config(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Get nonexistent — returns error (sql.ErrNoRows)
	val, err := db.GetConfig("nonexistent")
	assert.Error(t, err)
	assert.Empty(t, val)

	// Set
	err = db.SetConfig("test_key", "test_value")
	require.NoError(t, err)

	// Get
	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)

	// Overwrite
	err = db.SetConfig("test_key", "new_value")
	require.NoError(t, err)

	val, err = db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "new_value", val)
}

// ===========================================================================
// DB — Session CRUD
// ===========================================================================

func TestDB_SessionCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(24 * time.Hour)

	// Save
	err := db.SaveSession("sess-001", "user@example.com", now, expires, false)
	require.NoError(t, err)

	// Load
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "user@example.com", sessions[0].Email)

	// Delete
	err = db.DeleteSession("sess-001")
	require.NoError(t, err)

	sessions, err = db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

// ===========================================================================
// DB — Token CRUD
// ===========================================================================

func TestDB_TokenCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveToken("user@example.com", "token_abc", "UID01", "Alice", now)
	require.NoError(t, err)

	// Load
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "token_abc", tokens[0].AccessToken)

	// Delete
	err = db.DeleteToken("user@example.com")
	require.NoError(t, err)

	tokens, err = db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ===========================================================================
// DB — Client CRUD
// ===========================================================================

func TestDB_ClientCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveClient("client-001", "secret-001", `["https://example.com/cb"]`, "Test App", now, true)
	require.NoError(t, err)

	// Load
	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "client-001", clients[0].ClientID)
	assert.Equal(t, "Test App", clients[0].ClientName)
	assert.True(t, clients[0].IsKiteAPIKey)

	// Delete
	err = db.DeleteClient("client-001")
	require.NoError(t, err)

	clients, err = db.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

// ===========================================================================
// DB — Credential CRUD
// ===========================================================================

func TestDB_CredentialCRUD(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	now := time.Now().Truncate(time.Second)

	// Save
	err := db.SaveCredential("user@example.com", "key_abc", "secret_xyz", "key_abc", now)
	require.NoError(t, err)

	// Load
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "key_abc", creds[0].APIKey)

	// Delete
	err = db.DeleteCredential("user@example.com")
	require.NoError(t, err)

	creds, err = db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// ===========================================================================
// TrailingStop — CancelByEmail with DB
// ===========================================================================

// ===========================================================================
// Merged from db_coverage_test.go
// ===========================================================================


// mockBrokerData implements BrokerDataProvider for testing.
type mockBrokerData struct {
	holdings     []kiteconnect.Holding
	holdingsErr  error
	positions    kiteconnect.Positions
	positionsErr error
	margins      kiteconnect.AllMargins
	marginsErr   error
	ltp          kiteconnect.QuoteLTP
	ltpErr       error
}

func (m *mockBrokerData) GetHoldings(apiKey, accessToken string) ([]kiteconnect.Holding, error) {
	return m.holdings, m.holdingsErr
}
func (m *mockBrokerData) GetPositions(apiKey, accessToken string) (kiteconnect.Positions, error) {
	return m.positions, m.positionsErr
}
func (m *mockBrokerData) GetUserMargins(apiKey, accessToken string) (kiteconnect.AllMargins, error) {
	return m.margins, m.marginsErr
}
func (m *mockBrokerData) GetLTP(apiKey, accessToken string, instruments ...string) (kiteconnect.QuoteLTP, error) {
	return m.ltp, m.ltpErr
}

// ===========================================================================
// OpenDB — test with temp directory (covers file-based path)
// ===========================================================================

func TestOpenDB_TempDir(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.db")

	db, err := OpenDB(path)
	require.NoError(t, err)
	defer db.Close()

	// Verify file was created
	_, err = os.Stat(path)
	require.NoError(t, err)

	// Verify tables exist by doing a basic operation
	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	assert.Empty(t, alerts)
}

func TestOpenDB_InvalidPath(t *testing.T) {
	// Invalid path that cannot be opened
	_, err := OpenDB("/nonexistent/deeply/nested/path/that/cannot/exist/test.db")
	require.Error(t, err)
}

func TestOpenDB_Idempotent(t *testing.T) {
	// Opening the same in-memory DB path twice should work (different connections)
	dir := t.TempDir()
	path := filepath.Join(dir, "idempotent.db")

	db1, err := OpenDB(path)
	require.NoError(t, err)
	db1.Close()

	// Open again — all migrations should be idempotent
	db2, err := OpenDB(path)
	require.NoError(t, err)
	db2.Close()
}

// ===========================================================================
// DeleteAlert — non-existent ID (SQL DELETE on missing row is no-op)
// ===========================================================================

func TestDeleteAlert_NonExistent(t *testing.T) {
	db := openTestDB(t)
	// Don't insert anything
	err := db.DeleteAlert("nonexistent@example.com", "nonexistent_id")
	// Should not error (SQL DELETE on missing row is a no-op)
	assert.NoError(t, err)
}

func TestDeleteAlertsByEmail_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteAlertsByEmail("nobody@example.com")
	assert.NoError(t, err)
}

// ===========================================================================
// LoadAlerts — empty result set
// ===========================================================================

func TestLoadAlerts_Empty(t *testing.T) {
	db := openTestDB(t)
	alerts, err := db.LoadAlerts()
	assert.NoError(t, err)
	assert.Empty(t, alerts)
}

// ===========================================================================
// LoadAlerts — corrupt data (bad timestamps)
// ===========================================================================

func TestLoadAlerts_BadCreatedAt(t *testing.T) {
	db := openTestDB(t)
	// Insert an alert with a bad created_at timestamp directly
	_, err := db.db.Exec(`INSERT INTO alerts (id, email, tradingsymbol, exchange, instrument_token,
		target_price, direction, triggered, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`,
		"bad1", "user@example.com", "INFY", "NSE", 408065, 1500.0, "above", 0, "not-a-date")
	require.NoError(t, err)

	_, err = db.LoadAlerts()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse created_at")
}

func TestLoadAlerts_BadTriggeredAt(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Format(time.RFC3339)
	_, err := db.db.Exec(`INSERT INTO alerts (id, email, tradingsymbol, exchange, instrument_token,
		target_price, direction, triggered, created_at, triggered_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`,
		"bad2", "user@example.com", "INFY", "NSE", 408065, 1500.0, "above", 1, now, "not-a-date")
	require.NoError(t, err)

	_, err = db.LoadAlerts()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse triggered_at")
}

// ===========================================================================
// SaveAlert — all optional fields populated (triggered, trigPrice, refPrice, notifSentAt)
// ===========================================================================

func TestSaveAlert_AllFieldsPopulated(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	alert := &Alert{
		ID:                 "full123",
		Email:              "user@example.com",
		Tradingsymbol:      "RELIANCE",
		Exchange:           "NSE",
		InstrumentToken:    738561,
		TargetPrice:        2500.0,
		Direction:          DirectionAbove,
		ReferencePrice:     2400.0,
		Triggered:          true,
		CreatedAt:          now,
		TriggeredAt:        now.Add(time.Hour),
		TriggeredPrice:     2550.0,
		NotificationSentAt: now.Add(2 * time.Hour),
	}

	err := db.SaveAlert(alert)
	require.NoError(t, err)

	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alerts["user@example.com"], 1)

	loaded := alerts["user@example.com"][0]
	assert.True(t, loaded.Triggered)
	assert.Equal(t, 2550.0, loaded.TriggeredPrice)
	assert.Equal(t, 2400.0, loaded.ReferencePrice)
	assert.False(t, loaded.NotificationSentAt.IsZero())
	assert.False(t, loaded.TriggeredAt.IsZero())
}

// ===========================================================================
// SaveAlert — duplicate key (INSERT OR REPLACE should upsert)
// ===========================================================================

func TestSaveAlert_DuplicateKey(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	alert := &Alert{
		ID: "dup1", Email: "user@example.com", Tradingsymbol: "INFY",
		Exchange: "NSE", InstrumentToken: 408065, TargetPrice: 1500.0,
		Direction: DirectionAbove, CreatedAt: now,
	}
	require.NoError(t, db.SaveAlert(alert))

	// Save again with modified target — should upsert
	alert.TargetPrice = 1600.0
	require.NoError(t, db.SaveAlert(alert))

	alerts, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alerts["user@example.com"], 1)
	assert.Equal(t, 1600.0, alerts["user@example.com"][0].TargetPrice)
}

// ===========================================================================
// UpdateAlertNotification — non-existent ID
// ===========================================================================

func TestUpdateAlertNotification_NonExistent(t *testing.T) {
	db := openTestDB(t)
	// Should not error (UPDATE on missing row affects 0 rows)
	err := db.UpdateAlertNotification("nonexistent", time.Now())
	assert.NoError(t, err)
}

// ===========================================================================
// UpdateTriggered — non-existent ID
// ===========================================================================

func TestUpdateTriggered_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.UpdateTriggered("nonexistent", 100.0, time.Now())
	assert.NoError(t, err)
}

// ===========================================================================
// DeleteTelegramChatID — non-existent
// ===========================================================================

func TestDeleteTelegramChatID_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteTelegramChatID("nobody@example.com")
	assert.NoError(t, err)
}

// ===========================================================================
// LoadTelegramChatIDs — empty
// ===========================================================================

func TestLoadTelegramChatIDs_Empty(t *testing.T) {
	db := openTestDB(t)
	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Empty(t, ids)
}

// ===========================================================================
// SaveTelegramChatID — duplicate key (upsert)
// ===========================================================================

func TestSaveTelegramChatID_DuplicateKey(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 111))
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 222))

	ids, err := db.LoadTelegramChatIDs()
	require.NoError(t, err)
	assert.Equal(t, int64(222), ids["user@example.com"])
}

// ===========================================================================
// LoadTokens — empty
// ===========================================================================

func TestLoadTokens_Empty(t *testing.T) {
	db := openTestDB(t)
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	assert.Empty(t, tokens)
}

// ===========================================================================
// LoadTokens — bad stored_at (covers fallback to zero time)
// ===========================================================================

func TestLoadTokens_BadStoredAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO kite_tokens (email, access_token, user_id, user_name, stored_at) VALUES (?,?,?,?,?)`,
		"user@example.com", "tok1", "uid1", "User1", "bad-date")
	require.NoError(t, err)

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.True(t, tokens[0].StoredAt.IsZero()) // fallback to zero time
}

// ===========================================================================
// SaveToken — duplicate key (upsert)
// ===========================================================================

func TestSaveToken_DuplicateKey(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	require.NoError(t, db.SaveToken("user@example.com", "token1", "uid1", "User1", now))
	require.NoError(t, db.SaveToken("user@example.com", "token2", "uid1", "User1", now))

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "token2", tokens[0].AccessToken)
}

// ===========================================================================
// DeleteToken — non-existent
// ===========================================================================

func TestDeleteToken_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteToken("nobody@example.com")
	assert.NoError(t, err)
}

// ===========================================================================
// LoadCredentials — empty
// ===========================================================================

func TestLoadCredentials_Empty(t *testing.T) {
	db := openTestDB(t)
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

// ===========================================================================
// LoadCredentials — bad stored_at (covers fallback to zero time)
// ===========================================================================

func TestLoadCredentials_BadStoredAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO kite_credentials (email, api_key, api_secret, stored_at) VALUES (?,?,?,?)`,
		"user@example.com", "key1", "secret1", "bad-date")
	require.NoError(t, err)

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.True(t, creds[0].StoredAt.IsZero()) // fallback to zero time
}

// ===========================================================================
// DeleteCredential — non-existent
// ===========================================================================

func TestDeleteCredential_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteCredential("nobody@example.com")
	assert.NoError(t, err)
}

// ===========================================================================
// LoadClients — empty
// ===========================================================================

func TestLoadClients_Empty(t *testing.T) {
	db := openTestDB(t)
	clients, err := db.LoadClients()
	require.NoError(t, err)
	assert.Empty(t, clients)
}

// ===========================================================================
// LoadClients — bad created_at (covers fallback to zero time)
// ===========================================================================

func TestLoadClients_BadCreatedAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO oauth_clients (client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key) VALUES (?,?,?,?,?,?)`,
		"c1", "secret1", `["http://localhost"]`, "App1", "bad-date", 0)
	require.NoError(t, err)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.True(t, clients[0].CreatedAt.IsZero())
}

// ===========================================================================
// SaveClient — with IsKiteAPIKey=true
// ===========================================================================

func TestSaveClient_IsKiteKey(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)

	err := db.SaveClient("kite-key-1", "secret", `["http://localhost"]`, "KiteApp", now, true)
	require.NoError(t, err)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.True(t, clients[0].IsKiteAPIKey)
}

// ===========================================================================
// DeleteClient — non-existent
// ===========================================================================

func TestDeleteClient_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteClient("nonexistent-client")
	assert.NoError(t, err)
}

// ===========================================================================
// LoadSessions — empty
// ===========================================================================

func TestLoadSessions_Empty(t *testing.T) {
	db := openTestDB(t)
	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	assert.Empty(t, sessions)
}

// ===========================================================================
// LoadSessions — skip stale encrypted row (bad session_id_enc)
// ===========================================================================

func TestLoadSessions_SkipCorruptEncryptedRow(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	// Insert a row with valid hex but bad ciphertext (decryption will fail -> decrypt returns "" -> skip)
	hashedID := db.hashSessionID("test-session")
	// This is valid hex (long enough for GCM nonce) but will fail AES-GCM authentication
	badHexCiphertext := "aabbccddee00112233445566778899aabbccddee00112233445566778899aabbccddee0011223344"
	_, err = db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		hashedID, "user@example.com", now.Format(time.RFC3339), expires.Format(time.RFC3339), 0, badHexCiphertext)
	require.NoError(t, err)

	// Also insert a good row
	err = db.SaveSession("good-session", "user2@example.com", now, expires, false)
	require.NoError(t, err)

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	// Only the good session should be loaded (corrupt one skipped)
	require.Len(t, sessions, 1)
	assert.Equal(t, "good-session", sessions[0].SessionID)
}

// ===========================================================================
// LoadSessions — bad created_at timestamp
// ===========================================================================

func TestLoadSessions_BadCreatedAt(t *testing.T) {
	db := openTestDB(t)
	// No encryption — session_id stored as-is
	_, err := db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		"sess1", "user@example.com", "not-a-date", time.Now().Add(time.Hour).Format(time.RFC3339), 0, "")
	require.NoError(t, err)

	_, err = db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse session created_at")
}

func TestLoadSessions_BadExpiresAt(t *testing.T) {
	db := openTestDB(t)
	_, err := db.db.Exec(`INSERT INTO mcp_sessions (session_id, email, created_at, expires_at, terminated, session_id_enc) VALUES (?,?,?,?,?,?)`,
		"sess2", "user@example.com", time.Now().Format(time.RFC3339), "not-a-date", 0, "")
	require.NoError(t, err)

	_, err = db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "parse session expires_at")
}

// ===========================================================================
// DeleteSession — non-existent
// ===========================================================================

func TestDeleteSession_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.DeleteSession("nonexistent-session")
	assert.NoError(t, err)
}

// ===========================================================================
// SetConfig / GetConfig
// ===========================================================================

func TestSetConfig_Success(t *testing.T) {
	db := openTestDB(t)
	err := db.SetConfig("test_key", "test_value")
	require.NoError(t, err)

	val, err := db.GetConfig("test_key")
	require.NoError(t, err)
	assert.Equal(t, "test_value", val)
}

func TestGetConfig_NonExistent(t *testing.T) {
	db := openTestDB(t)
	_, err := db.GetConfig("missing_key")
	assert.ErrorIs(t, err, sql.ErrNoRows)
}

func TestSetConfig_Upsert(t *testing.T) {
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
	db := openTestDB(t)
	stops, err := db.LoadTrailingStops()
	require.NoError(t, err)
	assert.Empty(t, stops)
}

// ===========================================================================
// LoadTrailingStops — only active stops returned
// ===========================================================================

func TestLoadTrailingStops_OnlyActive(t *testing.T) {
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
	db := openTestDB(t)
	err := db.DeactivateTrailingStop("nonexistent")
	assert.NoError(t, err)
}

// ===========================================================================
// UpdateTrailingStop — non-existent
// ===========================================================================

func TestUpdateTrailingStop_NonExistent(t *testing.T) {
	db := openTestDB(t)
	err := db.UpdateTrailingStop("nonexistent", 100, 90, 1)
	assert.NoError(t, err)
}

// ===========================================================================
// SaveDailyPnL — duplicate key (upsert)
// ===========================================================================

func TestSaveDailyPnL_DuplicateKey(t *testing.T) {
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
	db := openTestDB(t)
	entries, err := db.LoadDailyPnL("user@example.com", "2026-01-01", "2026-12-31")
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// ===========================================================================
// SaveRegistryEntry — all fields, duplicate key, encryption
// ===========================================================================

func TestSaveRegistryEntry_AllFields(t *testing.T) {
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
	db := openTestDB(t)
	entries, err := db.LoadRegistryEntries()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

// ===========================================================================
// LoadRegistryEntries — bad timestamps (covers fallback branches)
// ===========================================================================

func TestLoadRegistryEntries_BadTimestamps(t *testing.T) {
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
	db := openTestDB(t)
	err := db.DeleteRegistryEntry("nonexistent")
	assert.NoError(t, err)
}

// ===========================================================================
// migrateRegistryCheckConstraint — idempotency
// ===========================================================================

func TestMigrateRegistryCheckConstraint_Idempotent(t *testing.T) {
	// First migration: OpenDB already ran it. Run it again — should be no-op.
	db := openTestDB(t)

	// The DDL in OpenDB already has 'invalid' in the CHECK constraint.
	// Running migrateRegistryCheckConstraint again should be safe.
	err := migrateRegistryCheckConstraint(db.db)
	assert.NoError(t, err)
}

func TestMigrateRegistryCheckConstraint_OldSchema(t *testing.T) {
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
	db := openTestDB(t)
	// The migration already ran in OpenDB. Run it again.
	err := migrateAlerts(db.db)
	assert.NoError(t, err)
}

func TestMigrateAlerts_AlreadyHasColumns(t *testing.T) {
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
	db := openTestDB(t)
	// No encryption key set
	result := db.hashSessionID("my-session-id")
	assert.Equal(t, "my-session-id", result)
}

func TestHashSessionID_WithKey(t *testing.T) {
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
// SaveCredential — encryption of both api_key and api_secret
// ===========================================================================

func TestSaveCredential_EncryptionBothFields(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveCredential("user@example.com", "the-key", "the-secret", "app1", now))

	// Raw DB should have encrypted values
	var rawKey, rawSecret string
	row := db.db.QueryRow(`SELECT api_key, api_secret FROM kite_credentials WHERE email = ?`, "user@example.com")
	require.NoError(t, row.Scan(&rawKey, &rawSecret))
	assert.NotEqual(t, "the-key", rawKey)
	assert.NotEqual(t, "the-secret", rawSecret)

	// Load decrypts
	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "the-key", creds[0].APIKey)
	assert.Equal(t, "the-secret", creds[0].APISecret)
	assert.Equal(t, "app1", creds[0].AppID)
}

// ===========================================================================
// SaveToken — with encryption
// ===========================================================================

func TestSaveToken_WithEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveToken("user@example.com", "my-token", "uid1", "User1", now))

	// Verify token is encrypted in raw DB
	var rawToken string
	row := db.db.QueryRow(`SELECT access_token FROM kite_tokens WHERE email = ?`, "user@example.com")
	require.NoError(t, row.Scan(&rawToken))
	assert.NotEqual(t, "my-token", rawToken)

	// Load decrypts
	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "my-token", tokens[0].AccessToken)
}

// ===========================================================================
// SaveClient — with encryption
// ===========================================================================

func TestSaveClient_WithEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveClient("c1", "client-secret", `["http://localhost"]`, "App1", now, false))

	var rawSecret string
	row := db.db.QueryRow(`SELECT client_secret FROM oauth_clients WHERE client_id = ?`, "c1")
	require.NoError(t, row.Scan(&rawSecret))
	assert.NotEqual(t, "client-secret", rawSecret)

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "client-secret", clients[0].ClientSecret)
}

// ===========================================================================
// SaveSession — with encryption (covers encrypt path for session_id_enc)
// ===========================================================================

func TestSaveSession_WithEncryption(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)
	require.NoError(t, db.SaveSession("my-session", "user@example.com", now, expires, true))

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.Equal(t, "my-session", sessions[0].SessionID)
	assert.True(t, sessions[0].Terminated)
}

// ===========================================================================
// Evaluator boundary conditions — exactly at target price
// ===========================================================================

func TestShouldTrigger_ExactlyAtAboveTarget(t *testing.T) {
	a := &Alert{Direction: DirectionAbove, TargetPrice: 100}
	assert.True(t, a.ShouldTrigger( 100)) // >= target
}

func TestShouldTrigger_ExactlyAtBelowTarget(t *testing.T) {
	a := &Alert{Direction: DirectionBelow, TargetPrice: 100}
	assert.True(t, a.ShouldTrigger( 100)) // <= target
}

func TestShouldTrigger_DropPctExactly(t *testing.T) {
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: 1000}
	// Exactly 5% drop: (1000 - 950) / 1000 * 100 = 5.0
	assert.True(t, a.ShouldTrigger( 950))
}

func TestShouldTrigger_RisePctExactly(t *testing.T) {
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 1000}
	// Exactly 10% rise: (1100 - 1000) / 1000 * 100 = 10.0
	assert.True(t, a.ShouldTrigger( 1100))
}

func TestShouldTrigger_DropPctJustUnder(t *testing.T) {
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: 1000}
	// 4.9% drop: (1000 - 951) / 1000 * 100 = 4.9
	assert.False(t, a.ShouldTrigger( 951))
}

func TestShouldTrigger_RisePctJustUnder(t *testing.T) {
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 1000}
	// 9.9% rise: (1099 - 1000) / 1000 * 100 = 9.9
	assert.False(t, a.ShouldTrigger( 1099))
}

func TestShouldTrigger_RisePctZeroReference(t *testing.T) {
	a := &Alert{Direction: DirectionRisePct, TargetPrice: 10.0, ReferencePrice: 0}
	assert.False(t, a.ShouldTrigger( 1100))
}

func TestShouldTrigger_DropPctNegativeReference(t *testing.T) {
	a := &Alert{Direction: DirectionDropPct, TargetPrice: 5.0, ReferencePrice: -100}
	assert.False(t, a.ShouldTrigger( 50))
}

func TestShouldTrigger_AboveJustBelow(t *testing.T) {
	a := &Alert{Direction: DirectionAbove, TargetPrice: 100}
	assert.False(t, a.ShouldTrigger( 99.99))
}

func TestShouldTrigger_BelowJustAbove(t *testing.T) {
	a := &Alert{Direction: DirectionBelow, TargetPrice: 100}
	assert.False(t, a.ShouldTrigger( 100.01))
}

// ===========================================================================
// Store — non-existent paths for DB-backed operations
// ===========================================================================

func TestStore_MarkTriggered_NonExistentID_DB(t *testing.T) {
	s := newTestStore()
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	ok := s.MarkTriggered("nonexistent-id", 1600.0)
	assert.False(t, ok)
}

func TestStore_MarkTriggered_AlreadyTriggered_DB(t *testing.T) {
	s := newTestStore()
	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	ok := s.MarkTriggered(id, 1600.0)
	assert.True(t, ok)

	// Second trigger should return false
	ok = s.MarkTriggered(id, 1700.0)
	assert.False(t, ok)
}

func TestStore_MarkNotificationSent_NonExistentID_DB(t *testing.T) {
	s := newTestStore()
	// Should not panic
	s.MarkNotificationSent("nonexistent-id", time.Now())
}

func TestStore_DeleteByEmail_NoAlerts_DB(t *testing.T) {
	s := newTestStore()
	// Should not panic
	s.DeleteByEmail("nobody@example.com")
}

func TestStore_GetByToken_NoMatch_DB(t *testing.T) {
	s := newTestStore()
	s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	matches := s.GetByToken(999999) // non-existent token
	assert.Empty(t, matches)
}

func TestStore_GetByToken_OnlyActive_DB(t *testing.T) {
	s := newTestStore()
	id, _ := s.Add("user@example.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)

	// Trigger the alert
	s.MarkTriggered(id, 1600.0)

	// GetByToken should skip triggered alerts
	matches := s.GetByToken(408065)
	assert.Empty(t, matches)
}

func TestStore_ActiveCount_DB(t *testing.T) {
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
	s := newTestStore()
	s.Add("a@x.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	s.Add("b@x.com", "TCS", "NSE", 2953217, 4000.0, DirectionBelow)

	all := s.ListAll()
	assert.Len(t, all, 2)
	assert.Len(t, all["a@x.com"], 1)
	assert.Len(t, all["b@x.com"], 1)
}

func TestStore_ListAllTelegram_DB(t *testing.T) {
	s := newTestStore()
	s.SetTelegramChatID("a@x.com", 111)
	s.SetTelegramChatID("b@x.com", 222)

	all := s.ListAllTelegram()
	assert.Len(t, all, 2)
	assert.Equal(t, int64(111), all["a@x.com"])
	assert.Equal(t, int64(222), all["b@x.com"])
}

func TestStore_GetEmailByChatID_DB(t *testing.T) {
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
	s := NewStore(nil)
	// No DB set — should return nil
	err := s.LoadFromDB()
	assert.NoError(t, err)
}

// ===========================================================================
// DB Close
// ===========================================================================

func TestDB_Close(t *testing.T) {
	db := openTestDB(t)
	err := db.Close()
	assert.NoError(t, err)
}

// ===========================================================================
// Encrypt/Decrypt exported wrappers
// ===========================================================================

func TestEncryptDecrypt_Exported(t *testing.T) {
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	ct, err := Encrypt(key, "hello-world")
	require.NoError(t, err)

	pt := Decrypt(key, ct)
	assert.Equal(t, "hello-world", pt)
}

func TestDecrypt_EmptyInput(t *testing.T) {
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)

	result := Decrypt(key, "")
	assert.Equal(t, "", result)
}

func TestDecrypt_TruncatedHex(t *testing.T) {
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

func TestDeleteAlert_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteAlert("user@example.com", "id1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete alert")
}

func TestDeleteAlertsByEmail_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteAlertsByEmail("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete alerts by email")
}

func TestDeleteTelegramChatID_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteTelegramChatID("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete telegram chat id")
}

func TestUpdateAlertNotification_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.UpdateAlertNotification("id1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update notification_sent_at")
}

func TestUpdateTriggered_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.UpdateTriggered("id1", 100.0, time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update triggered")
}

func TestLoadAlerts_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadAlerts()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query alerts")
}

func TestLoadTelegramChatIDs_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadTelegramChatIDs()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query telegram chat ids")
}

func TestSaveTelegramChatID_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveTelegramChatID("user@example.com", 123)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save telegram chat id")
}

func TestSaveAlert_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	alert := &Alert{
		ID: "err1", Email: "user@example.com", Tradingsymbol: "INFY",
		Exchange: "NSE", InstrumentToken: 408065, TargetPrice: 1500.0,
		Direction: DirectionAbove, CreatedAt: time.Now(),
	}
	err := db.SaveAlert(alert)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save alert")
}

func TestLoadTokens_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadTokens()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query tokens")
}

func TestSaveToken_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveToken("user@example.com", "tok1", "uid1", "User1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save token")
}

func TestDeleteToken_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteToken("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete token")
}

func TestLoadCredentials_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadCredentials()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query credentials")
}

func TestSaveCredential_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveCredential("user@example.com", "k1", "s1", "k1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save credential")
}

func TestDeleteCredential_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteCredential("user@example.com")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete credential")
}

func TestLoadClients_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadClients()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query oauth clients")
}

func TestSaveClient_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveClient("c1", "secret", `["http://localhost"]`, "App1", time.Now(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save oauth client")
}

func TestDeleteClient_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteClient("c1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete oauth client")
}

func TestLoadSessions_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadSessions()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query sessions")
}

func TestSaveSession_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SaveSession("s1", "user@example.com", time.Now(), time.Now().Add(time.Hour), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save session")
}

func TestDeleteSession_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeleteSession("s1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete session")
}

func TestSetConfig_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.SetConfig("k", "v")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "set config")
}

func TestSaveTrailingStop_ClosedDB(t *testing.T) {
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
	db := closedTestDB(t)
	_, err := db.LoadTrailingStops()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query trailing stops")
}

func TestDeactivateTrailingStop_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.DeactivateTrailingStop("ts1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "deactivate trailing stop")
}

func TestUpdateTrailingStop_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.UpdateTrailingStop("ts1", 100, 90, 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update trailing stop")
}

func TestSaveDailyPnL_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	entry := &DailyPnLEntry{Date: "2026-04-01", Email: "user@example.com"}
	err := db.SaveDailyPnL(entry)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save daily pnl")
}

func TestLoadDailyPnL_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadDailyPnL("user@example.com", "2026-01-01", "2026-12-31")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query daily pnl")
}

func TestLoadRegistryEntries_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadRegistryEntries()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query app_registry")
}

func TestSaveRegistryEntry_ClosedDB(t *testing.T) {
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
	db := closedTestDB(t)
	err := db.DeleteRegistryEntry("reg1")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "delete registry entry")
}

// ===========================================================================
// OpenDB — error paths: ping fails, DDL fails
// ===========================================================================

func TestOpenDB_PingFail(t *testing.T) {
	// Use a path whose parent directory does not exist.
	// SQLite will not create intermediate directories, so Open/Ping fails
	// on both Windows and Linux.
	badPath := filepath.Join(t.TempDir(), "no_such_subdir", "deep", "test.db")
	_, err := OpenDB(badPath)
	require.Error(t, err)
}

// ===========================================================================
// migrateAlerts — error path: check reference_price fails
// ===========================================================================

func TestMigrateAlerts_ClosedDB(t *testing.T) {
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
// SaveToken with encryption — covers encryption error path
// We can't easily force encrypt to fail, but covering the normal enc path helps
// ===========================================================================

func TestSaveToken_EncryptionDuplicateKey(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveToken("user@example.com", "tok1", "uid1", "User1", now))
	// Upsert with encryption
	require.NoError(t, db.SaveToken("user@example.com", "tok2", "uid1", "User1", now))

	tokens, err := db.LoadTokens()
	require.NoError(t, err)
	require.Len(t, tokens, 1)
	assert.Equal(t, "tok2", tokens[0].AccessToken)
}

// ===========================================================================
// SaveCredential with encryption — duplicate key
// ===========================================================================

func TestSaveCredential_EncryptionDuplicateKey(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveCredential("user@example.com", "k1", "s1", "k1", now))
	require.NoError(t, db.SaveCredential("user@example.com", "k2", "s2", "k2", now))

	creds, err := db.LoadCredentials()
	require.NoError(t, err)
	require.Len(t, creds, 1)
	assert.Equal(t, "k2", creds[0].APIKey)
}

// ===========================================================================
// SaveClient with encryption — duplicate key (covers encrypt on non-empty)
// ===========================================================================

func TestSaveClient_EncryptionDuplicateKey(t *testing.T) {
	db := openTestDB(t)
	key, err := DeriveEncryptionKey("test-secret")
	require.NoError(t, err)
	db.SetEncryptionKey(key)

	now := time.Now().Truncate(time.Second)
	require.NoError(t, db.SaveClient("c1", "s1", `["http://localhost"]`, "App1", now, false))
	require.NoError(t, db.SaveClient("c1", "s2", `["http://localhost"]`, "App1", now, false))

	clients, err := db.LoadClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)
	assert.Equal(t, "s2", clients[0].ClientSecret)
}

// ===========================================================================
// SaveRegistryEntry — encryption error-path coverage for both api_key and api_secret
// ===========================================================================

func TestSaveRegistryEntry_EncryptionBothFields(t *testing.T) {
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
	db := openTestDB(t)
	require.NoError(t, db.SetConfig("mykey", "myvalue"))
	val, err := db.GetConfig("mykey")
	require.NoError(t, err)
	assert.Equal(t, "myvalue", val)
}

// ===========================================================================
// LoadSessions — cover session with terminated=1
// ===========================================================================

func TestLoadSessions_TerminatedSession(t *testing.T) {
	db := openTestDB(t)
	now := time.Now().Truncate(time.Second)
	expires := now.Add(12 * time.Hour)

	require.NoError(t, db.SaveSession("s-term", "user@example.com", now, expires, true))

	sessions, err := db.LoadSessions()
	require.NoError(t, err)
	require.Len(t, sessions, 1)
	assert.True(t, sessions[0].Terminated)
}

// ===========================================================================
// LoadTrailingStops — with deactivated_at and last_modified_at populated
// ===========================================================================

func TestLoadTrailingStops_WithOptionalDates(t *testing.T) {
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
	svc := NewPnLSnapshotService(nil, nil, nil, defaultTestLogger())
	assert.Nil(t, svc)
}

func TestPnLSnapshotService_SetBrokerProviderNil(t *testing.T) {
	var svc *PnLSnapshotService
	// SetBrokerProvider on nil service should not panic
	svc.SetBrokerProvider(nil)
}

func TestPnLJournal_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	svc := NewPnLSnapshotService(db, nil, nil, defaultTestLogger())
	db.db.Close()

	_, err := svc.GetJournal("user@example.com", "2026-01-01", "2026-12-31")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load daily pnl")
}

func TestPnLJournal_StreakTracking(t *testing.T) {
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
// TrailingStopManager — DB error logging paths
// ===========================================================================

func TestTrailingStopManager_LoadFromDB_NilDB(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	err := m.LoadFromDB()
	assert.NoError(t, err)
}

func TestTrailingStopManager_LoadFromDB_ClosedDB(t *testing.T) {
	db := openTestDB(t)
	m := NewTrailingStopManager(defaultTestLogger())
	m.SetDB(db)
	db.db.Close()

	err := m.LoadFromDB()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "load trailing stops")
}

func TestTrailingStopManager_Add_ClosedDB_LogsError(t *testing.T) {
	db := openTestDB(t)
	m := NewTrailingStopManager(defaultTestLogger())
	m.SetDB(db)
	db.db.Close()

	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "ORD1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	_, err := m.Add(ts)
	require.NoError(t, err) // in-memory succeeds, DB error logged
}

func TestTrailingStopManager_Cancel_ClosedDB_LogsError(t *testing.T) {
	db := openTestDB(t)
	m := NewTrailingStopManager(defaultTestLogger())
	m.SetDB(db)

	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "ORD1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, err := m.Add(ts)
	require.NoError(t, err)

	db.db.Close()
	err = m.Cancel("user@example.com", id)
	require.NoError(t, err) // in-memory succeeds, DB error logged
}

func TestTrailingStopManager_Cancel_NotFound(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	err := m.Cancel("user@example.com", "nonexistent")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTrailingStopManager_Cancel_WrongEmail(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "ORD1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, _ := m.Add(ts)

	err := m.Cancel("wrong@example.com", id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestTrailingStopManager_Cancel_AlreadyInactive(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "ORD1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	id, _ := m.Add(ts)

	// Cancel once
	require.NoError(t, m.Cancel("user@example.com", id))
	// Cancel again — already inactive
	err := m.Cancel("user@example.com", id)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "already inactive")
}

func TestTrailingStopManager_CancelByEmail_ClosedDB_LogsError(t *testing.T) {
	db := openTestDB(t)
	m := NewTrailingStopManager(defaultTestLogger())
	m.SetDB(db)

	ts := &TrailingStop{
		Email: "user@example.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "ORD1", TrailAmount: 20,
		Direction: "long", HighWaterMark: 1500, CurrentStop: 1480,
	}
	m.Add(ts)

	db.db.Close()
	// Should not panic
	m.CancelByEmail("user@example.com")
}

// ===========================================================================
// TrailingStopManager — Add validation
// ===========================================================================

func TestTrailingStopManager_Add_NoOrderID(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	_, err := m.Add(&TrailingStop{
		Email: "user@example.com", Direction: "long", TrailAmount: 20,
		HighWaterMark: 1500, CurrentStop: 1480,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "order_id")
}

func TestTrailingStopManager_Add_InvalidDirection(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	_, err := m.Add(&TrailingStop{
		Email: "user@example.com", OrderID: "ORD1", Direction: "invalid",
		TrailAmount: 20, HighWaterMark: 1500, CurrentStop: 1480,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "direction")
}

func TestTrailingStopManager_Add_NoTrail(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	_, err := m.Add(&TrailingStop{
		Email: "user@example.com", OrderID: "ORD1", Direction: "long",
		HighWaterMark: 1500, CurrentStop: 1480,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "trail_amount")
}

func TestTrailingStopManager_Add_ZeroCurrentStop(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	_, err := m.Add(&TrailingStop{
		Email: "user@example.com", OrderID: "ORD1", Direction: "long",
		TrailAmount: 20, HighWaterMark: 1500,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "current_stop")
}

func TestTrailingStopManager_Add_ZeroHWM(t *testing.T) {
	m := NewTrailingStopManager(defaultTestLogger())
	_, err := m.Add(&TrailingStop{
		Email: "user@example.com", OrderID: "ORD1", Direction: "long",
		TrailAmount: 20, CurrentStop: 1480,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "high_water_mark")
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
	db := openTestDB(t)
	tokens := &mockTokenChecker{}
	creds := &testCredentialGetter{}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	db.db.Close()

	// Should not panic — logs error and returns
	svc.TakeSnapshots()
}

func TestTakeSnapshots_NoToken(t *testing.T) {
	db := openTestDB(t)
	require.NoError(t, db.SaveTelegramChatID("user@example.com", 12345))

	tokens := &mockTokenChecker{} // no tokens
	creds := &testCredentialGetter{keys: map[string]string{"user@example.com": "apikey1"}}

	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())
	// Should skip user with no token
	svc.TakeSnapshots()
}

func TestTakeSnapshots_ExpiredToken(t *testing.T) {
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
	entry := buildPnLEntry("2026-04-01", "user@example.com", nil, assert.AnError,
		kiteconnect.Positions{}, assert.AnError)
	assert.Equal(t, "2026-04-01", entry.Date)
	assert.Equal(t, 0.0, entry.NetPnL)
	assert.Equal(t, 0, entry.HoldingsCount)
	assert.Equal(t, 0, entry.TradesCount)
}

func TestBuildPnLEntry_WithData(t *testing.T) {
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

// ===========================================================================
// Encryption-error paths in Save* functions (invalid key length).
// ===========================================================================

func TestSaveToken_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad")) // invalid AES key length
	err := db.SaveToken("u@t.com", "tok", "uid", "name", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt access_token")
}

func TestSaveCredential_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveCredential("u@t.com", "key", "secret", "app", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt api_key")
}

func TestSaveClient_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveClient("cid", "csecret", `["http://localhost"]`, "name", time.Now(), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt client_secret")
}

func TestSaveSession_EncryptError(t *testing.T) {
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("bad"))
	err := db.SaveSession("sid", "u@t.com", time.Now(), time.Now().Add(time.Hour), false)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "encrypt session_id")
}

func TestSaveRegistryEntry_Error(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	err := db.SaveRegistryEntry(&RegistryDBEntry{
		ID: "reg1", APIKey: "k", APISecret: "s",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	})
	require.Error(t, err)
}

func TestLoadTelegramChatIDs_ClosedDB_ErrorPath(t *testing.T) {
	db := openTestDB(t)
	db.Close()
	_, err := db.LoadTelegramChatIDs()
	require.Error(t, err)
}

func TestSaveCredential_EncryptSecretError(t *testing.T) {
	db := openTestDB(t)
	// Use a 16-byte key so aes.NewCipher succeeds for the first encrypt call
	// (api_key) but we can't easily make only the second fail. Instead test
	// the DB error path with a closed DB.
	key, _ := DeriveEncryptionKey("s")
	db.SetEncryptionKey(key)
	db.Close()
	err := db.SaveCredential("u@t.com", "key", "secret", "app", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "save credential")
}

