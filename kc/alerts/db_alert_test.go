package alerts


import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	_ "modernc.org/sqlite"
)


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


func TestUpdateAlertNotification_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	err := db.UpdateAlertNotification("id1", time.Now())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "update notification_sent_at")
}


func TestLoadAlerts_ClosedDB(t *testing.T) {
	db := closedTestDB(t)
	_, err := db.LoadAlerts()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "query alerts")
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
