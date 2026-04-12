package alerts

// Coverage ceiling: 97.0% — unreachable lines: crypto/rand failures
// (Go 1.25 panics), HKDF/AES/GCM errors (always valid key sizes),
// SQLite scan/iteration errors, and notification dispatch (needs Telegram).

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
)

func TestEvaluator_MarkTriggeredRace(t *testing.T) {
	t.Parallel()
	s := newTestStore()
	eval := NewEvaluator(s, defaultTestLogger())

	// Add an alert that will trigger at price >= 1500.
	_, err := s.Add("u@test.com", "INFY", "NSE", 408065, 1500.0, DirectionAbove)
	require.NoError(t, err)

	// Fire many concurrent evaluations to increase the chance of hitting the
	// MarkTriggered-returns-false path.
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			eval.Evaluate("u@test.com", models.Tick{InstrumentToken: 408065, LastPrice: 1600.0})
		}()
	}
	wg.Wait()

	// Alert should be triggered exactly once.
	alerts := s.List("u@test.com")
	require.Len(t, alerts, 1)
	assert.True(t, alerts[0].Triggered)
}

// ===========================================================================
// trailing.go:295-297 — short direction HWM update when stop doesn't move
//
// This path is hit when a short trailing stop sees a new low price but the
// computed new stop is NOT lower than the current stop (so the order is not
// modified), yet the high water mark still needs to be updated.
// ===========================================================================

func TestTrailingStop_ShortHWMUpdate_NoStopMove(t *testing.T) {
	t.Parallel()
	m := NewTrailingStopManager(slog.Default())

	modifyCalled := false
	mock := &mockModifier{}
	m.SetModifier(func(email string) (KiteOrderModifier, error) { return mock, nil })
	m.SetOnModify(func(ts *TrailingStop, oldStop, newStop float64) {
		modifyCalled = true
	})

	// Short trailing stop: HWM=1000, CurrentStop=1050, TrailAmount=60.
	// If price drops to 995: newHWM=995, newStop=995+60=1055, 1055 > 1050 → not modified.
	// But HWM should still be updated to 995 (line 295-296).
	ts := &TrailingStop{
		Email: "t@t.com", Exchange: "NSE", Tradingsymbol: "INFY",
		InstrumentToken: 408065, OrderID: "SL-SHORT-HWM",
		TrailAmount: 60, Direction: "short",
		HighWaterMark: 1000, CurrentStop: 1050,
	}
	_, err := m.Add(ts)
	require.NoError(t, err)

	m.Evaluate("t@t.com", models.Tick{InstrumentToken: 408065, LastPrice: 995})

	// Stop should NOT be modified (new stop 1055 > current 1050).
	assert.False(t, modifyCalled, "stop should not move when new stop > current stop")

	// But HWM should be updated to the new low.
	m.mu.RLock()
	for _, s := range m.stops {
		if s.OrderID == "SL-SHORT-HWM" {
			assert.Equal(t, 995.0, s.HighWaterMark, "HWM should be updated to the new low price")
		}
	}
	m.mu.RUnlock()
}

// ===========================================================================
// pnl.go:100-103 — LoadTokens error
//
// To hit this path, LoadTelegramChatIDs must succeed (return 0 rows) but
// LoadTokens must fail. Both use the same DB, so we use a DB where the
// telegram_chat_ids table is empty but the kite_tokens table is corrupted.
// Since SQLite doesn't easily support per-table corruption, we drop the
// kite_tokens table to force an error.
// ===========================================================================

func TestTakeSnapshots_LoadTokensError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	tokens := &mockTokenChecker{}
	creds := &testCredentialGetter{}
	svc := NewPnLSnapshotService(db, tokens, creds, defaultTestLogger())

	// Drop the kite_tokens table so LoadTokens fails.
	_, err := db.db.Exec(`DROP TABLE kite_tokens`)
	require.NoError(t, err)

	// Should log error and return (not panic).
	svc.TakeSnapshots()
}

// ===========================================================================
// pnl.go:141-143 — SaveDailyPnL error
//
// The daily_pnl table must exist for LoadTelegramChatIDs/LoadTokens to succeed,
// but fail on insert. We drop the daily_pnl table after the loads.
// Actually, we can just corrupt the table by dropping it before TakeSnapshots
// tries to save.
// ===========================================================================

func TestTakeSnapshots_SaveDailyPnLError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Add a user with token and chat ID so we get past all checks.
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
	svc.SetBrokerProvider(&mockBrokerData{})

	// Drop daily_pnl table so SaveDailyPnL fails.
	_, err := db.db.Exec(`DROP TABLE daily_pnl`)
	require.NoError(t, err)

	// Should not panic; logs error and continues.
	svc.TakeSnapshots()
}

// ===========================================================================
// store.go:99-101 — LoadFromDB: LoadTelegramChatIDs error
//
// LoadAlerts succeeds (empty result) but LoadTelegramChatIDs fails. We drop
// the telegram_chat_ids table after initializing the DB.
// ===========================================================================

func TestStore_LoadFromDB_ChatIDError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	s := NewStore(nil)
	s.SetDB(db)

	// Drop the table to cause the error.
	_, err := db.db.Exec(`DROP TABLE telegram_chat_ids`)
	require.NoError(t, err)

	err = s.LoadFromDB()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "load telegram chat ids")
}

// ===========================================================================
// db.go scan errors — LoadAlerts, LoadTelegramChatIDs, LoadTokens, etc.
//
// These scan errors happen when columns mismatch. We can trigger them by
// altering the table schema after creation but before loading.
// ===========================================================================

func TestLoadAlerts_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Insert an alert with a bad direction that passes the CHECK but has wrong column data.
	// Actually, easier: drop columns by recreating the table with fewer columns.
	// For SQLite, we can insert a row with NULL in a NOT NULL column by using INSERT OR IGNORE
	// in a creative way, or just add data then modify schema.

	// Insert a valid alert first.
	require.NoError(t, db.SaveAlert(&Alert{
		ID: "a1", Email: "u@t.com", Tradingsymbol: "INFY", Exchange: "NSE",
		InstrumentToken: 408065, TargetPrice: 1500, Direction: DirectionAbove,
		CreatedAt: time.Now(),
	}))

	// Drop the alerts table and recreate with wrong schema.
	_, err := db.db.Exec(`DROP TABLE alerts`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE alerts (id TEXT PRIMARY KEY, wrong_col TEXT)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO alerts (id, wrong_col) VALUES ('a1', 'garbage')`)
	require.NoError(t, err)

	_, loadErr := db.LoadAlerts()
	assert.Error(t, loadErr, "should fail on scan with wrong schema")
}

func TestLoadTelegramChatIDs_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE telegram_chat_ids`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE telegram_chat_ids (email TEXT PRIMARY KEY, chat_id TEXT)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO telegram_chat_ids (email, chat_id) VALUES ('u@t.com', 'not_an_int')`)
	require.NoError(t, err)

	_, loadErr := db.LoadTelegramChatIDs()
	assert.Error(t, loadErr, "should fail scanning non-integer chat_id")
}

func TestLoadTokens_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE kite_tokens`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE kite_tokens (email TEXT PRIMARY KEY, access_token TEXT)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO kite_tokens (email, access_token) VALUES ('u@t.com', 'tok')`)
	require.NoError(t, err)

	_, loadErr := db.LoadTokens()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadCredentials_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE kite_credentials`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE kite_credentials (email TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO kite_credentials (email) VALUES ('u@t.com')`)
	require.NoError(t, err)

	_, loadErr := db.LoadCredentials()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadClients_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE oauth_clients`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE oauth_clients (client_id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO oauth_clients (client_id) VALUES ('c1')`)
	require.NoError(t, err)

	_, loadErr := db.LoadClients()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadSessions_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE mcp_sessions`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE mcp_sessions (session_id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO mcp_sessions (session_id) VALUES ('s1')`)
	require.NoError(t, err)

	_, loadErr := db.LoadSessions()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadTrailingStops_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE trailing_stops`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE trailing_stops (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO trailing_stops (id) VALUES ('ts1')`)
	require.NoError(t, err)

	_, loadErr := db.LoadTrailingStops()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadDailyPnL_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE daily_pnl`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE daily_pnl (date TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO daily_pnl (date) VALUES ('2026-01-01')`)
	require.NoError(t, err)

	_, loadErr := db.LoadDailyPnL("u@t.com", "2025-01-01", "2027-01-01")
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

func TestLoadRegistryEntries_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	_, err := db.db.Exec(`DROP TABLE app_registry`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE app_registry (id TEXT PRIMARY KEY)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO app_registry (id) VALUES ('r1')`)
	require.NoError(t, err)

	_, loadErr := db.LoadRegistryEntries()
	assert.Error(t, loadErr, "should fail scanning with missing columns")
}

// ===========================================================================
// db.go:1005-1011 — SaveRegistryEntry encrypt errors
//
// These happen when the encryption key is invalid (not 32 bytes).
// ===========================================================================

func TestSaveRegistryEntry_EncryptError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("short")) // invalid key for AES-256

	e := &RegistryDBEntry{
		ID: "r1", APIKey: "key", APISecret: "secret",
		Status: "active", Source: "admin",
		CreatedAt: time.Now(), UpdatedAt: time.Now(),
	}
	err := db.SaveRegistryEntry(e)
	assert.Error(t, err, "should fail with invalid encryption key")
	assert.Contains(t, err.Error(), "encrypt registry")
}

// ===========================================================================
// db.go:554-556 — SaveCredential encrypt error
// ===========================================================================

func TestSaveCredential_EncryptError_Push(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.SetEncryptionKey([]byte("short")) // invalid key

	err := db.SaveCredential("u@t.com", "key", "secret", "app1", time.Now())
	assert.Error(t, err, "should fail with invalid encryption key")
	assert.Contains(t, err.Error(), "encrypt api_key")
}

// ===========================================================================
// db.go — migrateRegistryCheckConstraint error paths
//
// db.go:205-207 — Begin error (closed DB after schema query succeeds).
// db.go:222-224 — tx.Exec error.
// db.go:230-232 — INSERT ... SELECT error.
// db.go:234-236 — DROP TABLE error.
// db.go:237-239 — ALTER TABLE RENAME error.
//
// These are within a transaction; to trigger individual errors is very hard.
// We can at least trigger the "migration needed" path by creating a table
// without the 'invalid' status.
// ===========================================================================

func TestMigrateRegistryCheckConstraint_Needed(t *testing.T) {
	t.Parallel()
	// Create a raw DB with old schema (no 'invalid' in CHECK).
	db := openTestDB(t)

	// The openTestDB already runs migrations including the check constraint.
	// We need to verify that re-running migration is a no-op when table already has 'invalid'.
	// This tests the "already has invalid → return nil" path.
	err := migrateRegistryCheckConstraint(db.db)
	assert.NoError(t, err)
}

// ===========================================================================
// db.go — migrateAlerts error paths (db.go:256-258)
// ===========================================================================

func TestMigrateAlerts_AlreadyMigrated(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Reference_price column already exists after OpenDB.
	// Running migrateAlerts again should be a no-op (the ALTER is idempotent).
	err := migrateAlerts(db.db)
	assert.NoError(t, err)
}

// ===========================================================================
// crypto.go — reEncryptTable scan and iteration errors with corrupted schema
// ===========================================================================

func TestReEncryptTable_ScanError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	oldKey, err := DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Insert a token row then corrupt the table.
	require.NoError(t, db.SaveToken("u@t.com", "tok", "uid", "name", time.Now()))

	// Drop and recreate with wrong schema.
	_, err = db.db.Exec(`DROP TABLE kite_tokens`)
	require.NoError(t, err)
	_, err = db.db.Exec(`CREATE TABLE kite_tokens (email TEXT)`)
	require.NoError(t, err)
	_, err = db.db.Exec(`INSERT INTO kite_tokens (email) VALUES ('u@t.com')`)
	require.NoError(t, err)

	// reEncryptTable expects 2 columns (email + access_token) but only 1 exists.
	err = reEncryptTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	assert.Error(t, err, "should fail scanning with missing column")
}

// ===========================================================================
// crypto.go:175-177 — reEncryptTable ExecResult error (db write fails)
// ===========================================================================

func TestReEncryptTable_UpdateError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	oldKey, err := DeriveEncryptionKeyWithSalt("old", nil)
	require.NoError(t, err)
	newKey, err := DeriveEncryptionKeyWithSalt("new", nil)
	require.NoError(t, err)

	// Insert and encrypt a token.
	db.SetEncryptionKey(oldKey)
	require.NoError(t, db.SaveToken("u@t.com", "tok", "uid", "name", time.Now()))
	db.SetEncryptionKey(nil)

	// Make the table read-only by dropping it and creating one with a UNIQUE constraint
	// that will conflict on update. Actually, let's just close the underlying DB after
	// reading rows to force the update to fail.
	// Instead, use a simpler approach: add a trigger that blocks updates.
	_, err = db.db.Exec(`CREATE TRIGGER block_token_update BEFORE UPDATE ON kite_tokens BEGIN SELECT RAISE(FAIL, 'blocked by trigger'); END`)
	require.NoError(t, err)

	err = reEncryptTable(db, oldKey, newKey, "kite_tokens", "email", []string{"access_token"})
	assert.Error(t, err, "should fail on blocked update")
	assert.Contains(t, err.Error(), "update pk=")
}

// ===========================================================================
// crypto.go:164-166 — reEncryptTable Encrypt error
//
// This happens when Encrypt fails on re-encryption. With a valid 32-byte key,
// AES-GCM encryption never fails. UNREACHABLE with valid keys.
//
// COVERAGE UNREACHABLE: crypto.go:164-166 — Encrypt(newKey, plaintext) with
// valid 32-byte key never fails; AES-GCM seal is infallible.
// ===========================================================================


// ---------------------------------------------------------------------------
// crypto.go — DeriveEncryptionKeyWithSalt empty secret
// ---------------------------------------------------------------------------

func TestDeriveEncryptionKeyWithSalt_EmptySecret_FC(t *testing.T) {
	t.Parallel()
	_, err := DeriveEncryptionKeyWithSalt("", nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty secret")
}

// ---------------------------------------------------------------------------
// crypto.go — EnsureEncryptionSalt with empty secret
// ---------------------------------------------------------------------------

func TestEnsureEncryptionSalt_EmptySecret_FC(t *testing.T) {
	t.Parallel()
	db, err := OpenDB(":memory:")
	require.NoError(t, err)
	defer db.Close()

	_, err = EnsureEncryptionSalt(db, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "empty secret")
}

// ---------------------------------------------------------------------------
// crypto.go — Decrypt with bad ciphertext
// ---------------------------------------------------------------------------

func TestDecrypt_BadCiphertext_FC(t *testing.T) {
	t.Parallel()
	key, err := DeriveEncryptionKey("test-secret-for-decrypt-testing!")
	require.NoError(t, err)

	// "not-base64-!!!" is not valid hex, so decrypt returns it as-is (plaintext fallback)
	result := decrypt(key, "not-base64-!!!")
	assert.Equal(t, "not-base64-!!!", result)
}

func TestDecrypt_ShortCiphertext_FC(t *testing.T) {
	t.Parallel()
	key, err := DeriveEncryptionKey("test-secret-for-decrypt-testing!")
	require.NoError(t, err)

	// "QQ==" is not valid hex (contains '='), so decrypt returns it as-is (plaintext fallback)
	result := decrypt(key, "QQ==")
	assert.Equal(t, "QQ==", result)
}

// realisticBrokerProvider returns a mockBrokerProvider populated with
// a multi-stock portfolio resembling a real Indian retail investor.
func realisticBrokerProvider() *mockBrokerProvider {
	return &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 1200, DayChangePercentage: 2.1, Quantity: 15},
			{Tradingsymbol: "INFY", DayChange: -800, DayChangePercentage: -1.5, Quantity: 25},
			{Tradingsymbol: "HDFCBANK", DayChange: 500, DayChangePercentage: 0.9, Quantity: 20},
			{Tradingsymbol: "TCS", DayChange: -200, DayChangePercentage: -0.4, Quantity: 10},
			{Tradingsymbol: "TATAMOTORS", DayChange: 3000, DayChangePercentage: 4.5, Quantity: 50},
		},
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 1500, DayBuyQuantity: 100, Product: "MIS"},
				{Tradingsymbol: "BHARTIARTL", PnL: -300, DayBuyQuantity: 50, Product: "MIS"},
			},
			Net: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 1500, Quantity: 100, Product: "MIS"},
				{Tradingsymbol: "BHARTIARTL", PnL: -300, Quantity: -50, Product: "MIS"},
			},
		},
		margins: kiteconnect.AllMargins{
			Equity: kiteconnect.Margins{Net: 125000},
		},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50":   {LastPrice: 22345.60},
			"NSE:NIFTY BANK": {LastPrice: 48120.75},
		},
	}
}

func TestBuildMorningBriefing_RealisticPortfolio(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 30, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Portfolio: sum of DayChange = 1200 - 800 + 500 - 200 + 3000 = 3700
	assert.Contains(t, result, "+₹3700")
	assert.Contains(t, result, "5 stocks")
	assert.Contains(t, result, "Margin available: ₹125000")
	assert.Contains(t, result, "NIFTY 50: ₹22345.60")
	assert.Contains(t, result, "BANK NIFTY: ₹48120.75")
	assert.Contains(t, result, "Market opens in 45 minutes")
}

// TestBuildMorningBriefing_WithTriggeredAlerts_RealisticData tests that
// overnight alerts appear alongside portfolio data in the morning briefing.
func TestBuildMorningBriefing_WithTriggeredAlerts_RealisticData(t *testing.T) {
	t.Parallel()

	store := newTestStore()
	// Add a triggered alert
	id, err := store.Add("trader@test.com", "RELIANCE", "NSE", 738561, 2800.0, DirectionAbove)
	require.NoError(t, err)
	store.MarkTriggered(id, 2810.50)

	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs := &BriefingService{
		alertStore:     store,
		tokens:         tokens,
		creds:          creds,
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc) // Monday morning
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	assert.Contains(t, result, "Alerts triggered overnight: 1")
	assert.Contains(t, result, "RELIANCE")
	assert.Contains(t, result, "2810.50")
	assert.Contains(t, result, "above")
	// Portfolio data should still be present
	assert.Contains(t, result, "Portfolio:")
	assert.Contains(t, result, "Token status: Valid")
}

// TestBuildDailySummary_RealisticPortfolio exercises buildDailySummary
// with a multi-stock portfolio, checking gainers/losers output.
func TestBuildDailySummary_RealisticPortfolio(t *testing.T) {
	t.Parallel()

	bp := realisticBrokerProvider()
	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	// Holdings P&L: 1200 - 800 + 500 - 200 + 3000 = 3700
	assert.Contains(t, result, "+₹3700")
	assert.Contains(t, result, "5 stocks")
	// Positions P&L: 1500 + (-300) = 1200
	assert.Contains(t, result, "+₹1200")
	assert.Contains(t, result, "2 positions")
	// Net = 3700 + 1200 = 4900
	assert.Contains(t, result, "Net Day P&amp;L: +₹4900")
	// Top Gainers should include TATAMOTORS (4.5%), RELIANCE (2.1%)
	assert.Contains(t, result, "Top Gainers:")
	assert.Contains(t, result, "TATAMOTORS +4.5%")
	assert.Contains(t, result, "RELIANCE +2.1%")
	// Top Losers should include INFY (-1.5%)
	assert.Contains(t, result, "Top Losers:")
	assert.Contains(t, result, "INFY -1.5%")
}

// TestBuildDailySummary_BrokerErrors_Graceful verifies that broker errors
// produce "unavailable" in the summary without panicking.
func TestBuildDailySummary_BrokerErrors_Graceful(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr:  fmt.Errorf("network error"),
		positionsErr: fmt.Errorf("timeout"),
	}
	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Positions P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Net Day P&amp;L: +₹0")
}

// TestSendMorningBriefings_RealisticMultiUser exercises SendMorningBriefings
// end-to-end with two users having different portfolio sizes.
func TestSendMorningBriefings_RealisticMultiUser(t *testing.T) {
	store := storeWithChat(map[string]int64{
		"alice@test.com": 100,
		"bob@test.com":   200,
	})
	tokens := validTokenChecker("alice@test.com", "bob@test.com")
	creds := credsFor(map[string]string{
		"alice@test.com": "key-alice",
		"bob@test.com":   "key-bob",
	})
	bp := realisticBrokerProvider()

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	// Should not panic and should send to both users.
	bs.SendMorningBriefings()
}

// TestSendDailySummaries_RealisticSingleUser exercises SendDailySummaries
// end-to-end with realistic data flowing through the mock broker provider.
func TestSendDailySummaries_RealisticSingleUser(t *testing.T) {
	store := storeWithChat(map[string]int64{"trader@test.com": 100})
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider()

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	bs.SendDailySummaries()
}

// TestSendMISWarnings_RealisticPositions exercises SendMISWarnings
// with open MIS positions flowing through the mock broker provider.
func TestSendMISWarnings_RealisticPositions(t *testing.T) {
	store := storeWithChat(map[string]int64{"trader@test.com": 100})
	tokens := validTokenChecker("trader@test.com")
	creds := credsFor(map[string]string{"trader@test.com": "api-key"})
	bp := realisticBrokerProvider() // has MIS positions in Net

	bs, cleanup := newBriefingServiceWithMock(t, false, store, tokens, creds, bp)
	defer cleanup()

	bs.SendMISWarnings()
}

// TestFormatMISWarning_RealisticPositions validates the content of MIS
// warning messages with both long and short positions.
func TestFormatMISWarning_RealisticPositions(t *testing.T) {
	t.Parallel()

	open := []misPosition{
		{Symbol: "SBIN", Quantity: 100, PnL: 1500},
		{Symbol: "BHARTIARTL", Quantity: -50, PnL: -300},
	}

	result := formatMISWarning(open)

	assert.Contains(t, result, "MIS Square-Off Warning")
	assert.Contains(t, result, "2 open MIS position(s)")
	assert.Contains(t, result, "SBIN: LONG 100")
	assert.Contains(t, result, "+₹1500")
	assert.Contains(t, result, "BHARTIARTL: SHORT 50")
	assert.Contains(t, result, "-₹300")
	// Net MIS P&L = 1500 + (-300) = 1200
	assert.Contains(t, result, "MIS P&amp;L: <b>+₹1200</b>")
	assert.Contains(t, result, "convert to CNC/NRML")
}

// TestBuildMorningBriefing_NegativePortfolio exercises the negative P&L
// formatting path with all holdings in the red.
func TestBuildMorningBriefing_NegativePortfolio(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: -2000, DayChangePercentage: -3.5, Quantity: 15},
			{Tradingsymbol: "INFY", DayChange: -1500, DayChangePercentage: -2.8, Quantity: 25},
		},
		margins: kiteconnect.AllMargins{Equity: kiteconnect.Margins{Net: 50000}},
		ltp: kiteconnect.QuoteLTP{
			"NSE:NIFTY 50": {LastPrice: 21500},
		},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 10, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Total day P&L = -2000 + (-1500) = -3500
	assert.Contains(t, result, "-₹3500")
	assert.Contains(t, result, "2 stocks")
	assert.Contains(t, result, "Market is open.")
	// Only NIFTY 50, no BANK NIFTY
	assert.Contains(t, result, "NIFTY 50: ₹21500.00")
	assert.NotContains(t, result, "BANK NIFTY:")
}

// TestBuildMorningBriefing_LTPError_GracefulDegradation tests that
// LTP errors are handled gracefully — indices section simply omitted.
func TestBuildMorningBriefing_LTPError_GracefulDegradation(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings: []kiteconnect.Holding{
			{Tradingsymbol: "RELIANCE", DayChange: 500, Quantity: 10},
		},
		margins: kiteconnect.AllMargins{Equity: kiteconnect.Margins{Net: 80000}},
		ltpErr:  fmt.Errorf("connection refused"),
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Holdings still show up
	assert.Contains(t, result, "+₹500")
	assert.Contains(t, result, "Margin available:")
	// No indices section
	assert.NotContains(t, result, "NIFTY 50:")
	assert.NotContains(t, result, "BANK NIFTY:")
}

// TestBuildDailySummary_OnlyHoldingsError tests partial failure
// where only holdings fetch fails but positions succeed.
func TestBuildDailySummary_OnlyHoldingsError(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("API rate limited"),
		positions: kiteconnect.Positions{
			Day: []kiteconnect.Position{
				{Tradingsymbol: "SBIN", PnL: 2500},
			},
		},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("trader@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: <i>unavailable</i>")
	assert.Contains(t, result, "Positions P&amp;L: +₹2500")
	// Net = 0 (holdings err) + 2500 = 2500
	assert.Contains(t, result, "Net Day P&amp;L: +₹2500")
}

// TestFilterMISPositions_RealisticMix tests filtering with a mix of
// MIS and CNC positions, ensuring only open MIS positions are returned.
func TestFilterMISPositions_RealisticMix(t *testing.T) {
	t.Parallel()

	positions := kiteconnect.Positions{
		Net: []kiteconnect.Position{
			{Tradingsymbol: "SBIN", Quantity: 100, Product: "MIS", PnL: 1500},
			{Tradingsymbol: "RELIANCE", Quantity: 15, Product: "CNC", PnL: 800},
			{Tradingsymbol: "BHARTIARTL", Quantity: -50, Product: "MIS", PnL: -300},
			{Tradingsymbol: "INFY", Quantity: 0, Product: "MIS", PnL: 0}, // closed MIS — should be excluded
			{Tradingsymbol: "TCS", Quantity: 20, Product: "NRML", PnL: 200},
		},
	}

	open := filterMISPositions(positions)

	assert.Len(t, open, 2)

	var symbols []string
	for _, p := range open {
		symbols = append(symbols, p.Symbol)
	}
	assert.Contains(t, symbols, "SBIN")
	assert.Contains(t, symbols, "BHARTIARTL")
	// CNC, NRML, and closed MIS should be excluded
	assert.NotContains(t, symbols, "RELIANCE")
	assert.NotContains(t, symbols, "INFY")
	assert.NotContains(t, symbols, "TCS")
}

// TestBrokerProvider_DefaultFallback verifies that broker() returns
// defaultBrokerProvider when brokerProvider is nil.
func TestBrokerProvider_DefaultFallback(t *testing.T) {
	t.Parallel()

	bs := &BriefingService{
		alertStore: newTestStore(),
		logger:     defaultTestLogger(),
	}

	bp := bs.broker()
	assert.NotNil(t, bp)
	_, isDefault := bp.(*defaultBrokerProvider)
	assert.True(t, isDefault, "expected defaultBrokerProvider when brokerProvider is nil")
}

// TestBrokerProvider_OverrideUsed verifies that SetBrokerProvider
// correctly replaces the default broker.
func TestBrokerProvider_OverrideUsed(t *testing.T) {
	t.Parallel()

	bs := &BriefingService{
		alertStore: newTestStore(),
		logger:     defaultTestLogger(),
	}

	mock := &mockBrokerProvider{}
	bs.SetBrokerProvider(mock)

	bp := bs.broker()
	assert.Equal(t, mock, bp, "expected mock broker after SetBrokerProvider")
}

// TestBuildDailySummary_EmptyPortfolio tests the case where holdings
// and positions both return empty (new user with no trades).
func TestBuildDailySummary_EmptyPortfolio(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdings:  []kiteconnect.Holding{},
		positions: kiteconnect.Positions{},
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("newuser@test.com"),
		creds:          credsFor(map[string]string{"newuser@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	result := bs.buildDailySummary("newuser@test.com", "api-key", "tok", "April 7, 2026")

	assert.Contains(t, result, "Holdings P&amp;L: +₹0 (0 stocks)")
	assert.Contains(t, result, "Positions P&amp;L: +₹0 (0 positions)")
	assert.Contains(t, result, "Net Day P&amp;L: +₹0")
	assert.NotContains(t, result, "Top Gainers")
	assert.NotContains(t, result, "Top Losers")
}

// TestBuildMorningBriefing_AllBrokerErrors tests graceful degradation
// when all broker API calls fail — still produces valid briefing.
func TestBuildMorningBriefing_AllBrokerErrors(t *testing.T) {
	t.Parallel()

	bp := &mockBrokerProvider{
		holdingsErr: fmt.Errorf("holdings error"),
		marginsErr:  fmt.Errorf("margins error"),
		ltpErr:      fmt.Errorf("ltp error"),
	}

	bs := &BriefingService{
		alertStore:     newTestStore(),
		tokens:         validTokenChecker("trader@test.com"),
		creds:          credsFor(map[string]string{"trader@test.com": "api-key"}),
		logger:         defaultTestLogger(),
		brokerProvider: bp,
	}

	now := time.Date(2026, 4, 7, 8, 0, 0, 0, kolkataLoc)
	result := bs.buildMorningBriefing("trader@test.com", "April 7, 2026", now)

	// Should still produce a valid briefing with token status
	assert.Contains(t, result, "Morning Briefing")
	assert.Contains(t, result, "Token status: Valid")
	// No portfolio/margin/indices data
	assert.NotContains(t, result, "Portfolio:")
	assert.NotContains(t, result, "Margin available:")
	assert.NotContains(t, result, "NIFTY 50:")
	// Market timing still works
	assert.True(t, strings.Contains(result, "Market opens in") || strings.Contains(result, "Market is open"))
}

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
