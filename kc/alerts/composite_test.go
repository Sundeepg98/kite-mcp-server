package alerts

// composite_test.go — tests for composite alerts that fire when a group of
// per-instrument conditions are satisfied together (AND) or when any single
// leg fires (ANY). Composite alerts share the `alerts` table with
// single-leg alerts and are distinguished by alert_type='composite' with
// a JSON-encoded conditions payload.
//
// These tests exercise three layers:
//   1. DB persistence (SaveAlert/LoadAlerts round-trip with composite columns)
//   2. Store CRUD (AddComposite wires DB + in-memory state)
//   3. Migration (opening a DB that lacks composite columns adds them idempotently)

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	_ "modernc.org/sqlite"
)

// TestAlertDB_SaveAndLoadComposite_AND verifies that a composite alert with
// AND logic round-trips through SaveAlert -> LoadAlerts with every field
// (logic, conditions, name) intact.
func TestAlertDB_SaveAndLoadComposite_AND(t *testing.T) {
	db := openTestDB(t)

	conds := []domain.CompositeCondition{
		{
			Exchange:        "NSE",
			Tradingsymbol:   "NIFTY 50",
			InstrumentToken: 256265,
			Operator:        domain.DirectionDropPct,
			Value:           0.5,
			ReferencePrice:  22500.0,
		},
		{
			Exchange:        "NSE",
			Tradingsymbol:   "INDIA VIX",
			InstrumentToken: 264969,
			Operator:        domain.DirectionRisePct,
			Value:           15.0,
			ReferencePrice:  14.2,
		},
	}

	alert := &Alert{
		ID:              "cmp12345",
		Email:           "user@example.com",
		AlertType:       domain.AlertTypeComposite,
		CompositeName:   "nifty_vix_correlation",
		CompositeLogic:  domain.CompositeLogicAnd,
		Conditions:      conds,
		Tradingsymbol:   "NIFTY 50",
		Exchange:        "NSE",
		InstrumentToken: 256265,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	require.NoError(t, db.SaveAlert(alert))

	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	assert.Equal(t, "cmp12345", loaded.ID)
	assert.Equal(t, domain.AlertTypeComposite, loaded.AlertType)
	assert.Equal(t, "nifty_vix_correlation", loaded.CompositeName)
	assert.Equal(t, domain.CompositeLogicAnd, loaded.CompositeLogic)
	require.Len(t, loaded.Conditions, 2)
	assert.Equal(t, "NIFTY 50", loaded.Conditions[0].Tradingsymbol)
	assert.Equal(t, domain.DirectionDropPct, loaded.Conditions[0].Operator)
	assert.Equal(t, 0.5, loaded.Conditions[0].Value)
	assert.Equal(t, 22500.0, loaded.Conditions[0].ReferencePrice)
	assert.Equal(t, uint32(256265), loaded.Conditions[0].InstrumentToken)
	assert.Equal(t, "INDIA VIX", loaded.Conditions[1].Tradingsymbol)
	assert.Equal(t, domain.DirectionRisePct, loaded.Conditions[1].Operator)
}

// TestAlertDB_SaveAndLoadComposite_OR verifies an ANY-logic composite
// round-trips correctly and preserves leg ordering.
func TestAlertDB_SaveAndLoadComposite_OR(t *testing.T) {
	db := openTestDB(t)

	conds := []domain.CompositeCondition{
		{
			Exchange: "NSE", Tradingsymbol: "RELIANCE", InstrumentToken: 738561,
			Operator: domain.DirectionAbove, Value: 3000.0,
		},
		{
			Exchange: "NSE", Tradingsymbol: "TCS", InstrumentToken: 2953217,
			Operator: domain.DirectionBelow, Value: 3500.0,
		},
	}

	alert := &Alert{
		ID:              "cmpOR001",
		Email:           "user@example.com",
		AlertType:       domain.AlertTypeComposite,
		CompositeName:   "blue_chip_watcher",
		CompositeLogic:  domain.CompositeLogicAny,
		Conditions:      conds,
		Tradingsymbol:   "RELIANCE",
		Exchange:        "NSE",
		InstrumentToken: 738561,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	require.NoError(t, db.SaveAlert(alert))

	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	assert.Equal(t, domain.AlertTypeComposite, loaded.AlertType)
	assert.Equal(t, domain.CompositeLogicAny, loaded.CompositeLogic)
	require.Len(t, loaded.Conditions, 2)
	assert.Equal(t, "RELIANCE", loaded.Conditions[0].Tradingsymbol)
	assert.Equal(t, "TCS", loaded.Conditions[1].Tradingsymbol)
}

// TestAlertDB_SingleAlertHasNilCompositeFields verifies that saving a
// plain single-leg alert does NOT populate composite columns, preserving
// backwards compatibility. The DB returns alert_type='single' and NULL
// for the composite_* and conditions_json columns.
func TestAlertDB_SingleAlertHasNilCompositeFields(t *testing.T) {
	db := openTestDB(t)

	alert := &Alert{
		ID:              "single01",
		Email:           "user@example.com",
		Tradingsymbol:   "INFY",
		Exchange:        "NSE",
		InstrumentToken: 408065,
		TargetPrice:     1500.0,
		Direction:       DirectionAbove,
		CreatedAt:       time.Now().Truncate(time.Second),
	}

	require.NoError(t, db.SaveAlert(alert))

	alertMap, err := db.LoadAlerts()
	require.NoError(t, err)
	require.Len(t, alertMap["user@example.com"], 1)

	loaded := alertMap["user@example.com"][0]
	// Default alert_type should be "single" for pre-composite alerts.
	assert.Equal(t, domain.AlertTypeSingle, loaded.AlertType)
	assert.Empty(t, loaded.CompositeLogic)
	assert.Empty(t, loaded.CompositeName)
	assert.Empty(t, loaded.Conditions)
	// Existing fields must still work.
	assert.Equal(t, DirectionAbove, loaded.Direction)
	assert.Equal(t, 1500.0, loaded.TargetPrice)
}

// TestAlertDB_CompositeConditionsJSON_Malformed verifies that a row with
// invalid conditions_json is skipped with an explicit error rather than
// silently returning a broken Alert. Loading should fail loudly so the
// operator notices corruption.
func TestAlertDB_CompositeConditionsJSON_Malformed(t *testing.T) {
	db := openTestDB(t)

	// Insert a row with garbage JSON via raw SQL, bypassing SaveAlert's
	// marshaling. This simulates schema drift or manual DB edits.
	_, err := db.db.Exec(`INSERT INTO alerts (id, email, tradingsymbol, exchange,
		instrument_token, target_price, direction, triggered, created_at,
		alert_type, composite_logic, composite_name, conditions_json)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		"bad12345", "user@example.com", "SYM", "NSE", uint32(1), 0.0, "above", 0,
		time.Now().Format(time.RFC3339),
		"composite", "AND", "bad", "{not-json}")
	require.NoError(t, err)

	_, err = db.LoadAlerts()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "conditions_json")
}

// TestAlertMigration_AddCompositeColumns verifies migration from a pre-
// composite schema: an existing DB without alert_type/composite_* columns
// gets them added with safe defaults when opened by OpenDB.
func TestAlertMigration_AddCompositeColumns(t *testing.T) {
	// Simulate an old database that has the alerts table but no composite columns.
	raw, err := sql.Open("sqlite", ":memory:")
	require.NoError(t, err)
	defer raw.Close()

	oldDDL := `
CREATE TABLE IF NOT EXISTS alerts (
    id               TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    instrument_token INTEGER NOT NULL,
    target_price     REAL NOT NULL,
    direction        TEXT NOT NULL CHECK(direction IN ('above','below','drop_pct','rise_pct')),
    triggered        INTEGER NOT NULL DEFAULT 0,
    created_at       TEXT NOT NULL,
    triggered_at     TEXT,
    triggered_price  REAL,
    reference_price  REAL,
    notification_sent_at TEXT
);`
	_, err = raw.Exec(oldDDL)
	require.NoError(t, err)

	// Insert a legacy single-leg alert.
	_, err = raw.Exec(`INSERT INTO alerts (id, email, tradingsymbol, exchange, instrument_token, target_price, direction, triggered, created_at) VALUES (?,?,?,?,?,?,?,?,?)`,
		"legacy01", "user@example.com", "RELIANCE", "NSE", 738561, 2500.0, "above", 0, time.Now().Format(time.RFC3339))
	require.NoError(t, err)

	// Run migration.
	require.NoError(t, migrateAlerts(raw))

	// Verify composite columns exist.
	assertColumnExists(t, raw, "alerts", "alert_type")
	assertColumnExists(t, raw, "alerts", "composite_logic")
	assertColumnExists(t, raw, "alerts", "composite_name")
	assertColumnExists(t, raw, "alerts", "conditions_json")

	// Verify existing row is intact: alert_type defaults to 'single' (or NULL),
	// composite fields are NULL/empty.
	var alertType sql.NullString
	err = raw.QueryRow(`SELECT alert_type FROM alerts WHERE id = ?`, "legacy01").Scan(&alertType)
	require.NoError(t, err)
	// Either the column is NULL (added without default) or "single" (added with default).
	// We treat both as acceptable pre-composite state — LoadAlerts normalizes.
	if alertType.Valid {
		assert.Contains(t, []string{"single", ""}, alertType.String)
	}
}

// TestStore_AddComposite_AND exercises the high-level Store.AddComposite
// API: it should persist the composite alert and make it visible via List.
func TestStore_AddComposite_AND(t *testing.T) {
	s := newTestStore()

	conds := []domain.CompositeCondition{
		{
			Exchange: "NSE", Tradingsymbol: "NIFTY 50", InstrumentToken: 256265,
			Operator: domain.DirectionDropPct, Value: 0.5, ReferencePrice: 22500.0,
		},
		{
			Exchange: "NSE", Tradingsymbol: "INDIA VIX", InstrumentToken: 264969,
			Operator: domain.DirectionRisePct, Value: 15.0, ReferencePrice: 14.2,
		},
	}

	id, err := s.AddComposite("user@example.com", "nifty_vix", domain.CompositeLogicAnd, conds)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	list := s.List("user@example.com")
	require.Len(t, list, 1)
	a := list[0]
	assert.Equal(t, id, a.ID)
	assert.Equal(t, domain.AlertTypeComposite, a.AlertType)
	assert.Equal(t, domain.CompositeLogicAnd, a.CompositeLogic)
	assert.Equal(t, "nifty_vix", a.CompositeName)
	require.Len(t, a.Conditions, 2)
}

// TestStore_AddComposite_OR mirrors the AND happy path for ANY logic.
func TestStore_AddComposite_OR(t *testing.T) {
	s := newTestStore()

	conds := []domain.CompositeCondition{
		{Exchange: "NSE", Tradingsymbol: "RELIANCE", InstrumentToken: 738561,
			Operator: domain.DirectionAbove, Value: 3000.0},
		{Exchange: "NSE", Tradingsymbol: "TCS", InstrumentToken: 2953217,
			Operator: domain.DirectionBelow, Value: 3500.0},
	}

	id, err := s.AddComposite("u@example.com", "watch_list", domain.CompositeLogicAny, conds)
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	list := s.List("u@example.com")
	require.Len(t, list, 1)
	assert.Equal(t, domain.CompositeLogicAny, list[0].CompositeLogic)
}

// TestStore_AddComposite_RejectsEmptyConditions ensures the store rejects
// malformed input up-front (defense in depth — the use case validates too).
func TestStore_AddComposite_RejectsEmptyConditions(t *testing.T) {
	s := newTestStore()

	_, err := s.AddComposite("u@example.com", "empty", domain.CompositeLogicAnd, nil)
	require.Error(t, err)

	_, err = s.AddComposite("u@example.com", "empty", domain.CompositeLogicAnd, []domain.CompositeCondition{})
	require.Error(t, err)
}

// TestStore_AddComposite_EnforcesMaxAlertsPerUser ensures composite alerts
// are counted towards the same MaxAlertsPerUser ceiling as single alerts
// (per-user quota is per-row, not per-type).
func TestStore_AddComposite_EnforcesMaxAlertsPerUser(t *testing.T) {
	s := newTestStore()
	email := "capped@example.com"

	// Fill up to the limit with single alerts.
	for i := 0; i < MaxAlertsPerUser; i++ {
		_, err := s.Add(email, "SYM", "NSE", uint32(i+1), float64(i+1), DirectionAbove)
		require.NoError(t, err)
	}

	// Next composite add should fail.
	_, err := s.AddComposite(email, "overflow", domain.CompositeLogicAnd, []domain.CompositeCondition{
		{Exchange: "NSE", Tradingsymbol: "A", InstrumentToken: 1, Operator: domain.DirectionAbove, Value: 1},
		{Exchange: "NSE", Tradingsymbol: "B", InstrumentToken: 2, Operator: domain.DirectionBelow, Value: 2},
	})
	require.Error(t, err)
}

// TestStore_AddComposite_PersistsToDB verifies write-through persistence:
// the composite alert must survive a LoadFromDB round-trip.
func TestStore_AddComposite_PersistsToDB(t *testing.T) {
	db := openTestDB(t)
	s := NewStore(nil)
	s.SetDB(db)

	conds := []domain.CompositeCondition{
		{Exchange: "NSE", Tradingsymbol: "RELIANCE", InstrumentToken: 738561,
			Operator: domain.DirectionAbove, Value: 3000.0},
		{Exchange: "NSE", Tradingsymbol: "TCS", InstrumentToken: 2953217,
			Operator: domain.DirectionBelow, Value: 3500.0},
	}

	id, err := s.AddComposite("persist@example.com", "live", domain.CompositeLogicAnd, conds)
	require.NoError(t, err)
	require.NotEmpty(t, id)

	// Simulate restart: new Store, LoadFromDB.
	s2 := NewStore(nil)
	s2.SetDB(db)
	require.NoError(t, s2.LoadFromDB())

	list := s2.List("persist@example.com")
	require.Len(t, list, 1)
	assert.Equal(t, id, list[0].ID)
	assert.Equal(t, domain.CompositeLogicAnd, list[0].CompositeLogic)
	require.Len(t, list[0].Conditions, 2)
}

// assertColumnExists is a test helper that fails if the given column is
// missing from the table. Used for migration assertions.
func assertColumnExists(t *testing.T, db *sql.DB, table, column string) {
	t.Helper()
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info(?) WHERE name = ?`, table, column).Scan(&count)
	require.NoError(t, err)
	assert.Equal(t, 1, count, "expected column %s.%s to exist", table, column)
}

// TestCompositeCondition_JSONRoundtrip guards the on-disk wire format
// (conditions_json) against accidental schema drift. If a future refactor
// renames a JSON tag, this test fails and flags the need for a migration.
func TestCompositeCondition_JSONRoundtrip(t *testing.T) {
	orig := []domain.CompositeCondition{
		{
			Exchange:        "NSE",
			Tradingsymbol:   "RELIANCE",
			InstrumentToken: 738561,
			Operator:        domain.DirectionAbove,
			Value:           3000.0,
			ReferencePrice:  2800.0,
		},
	}
	raw, err := json.Marshal(orig)
	require.NoError(t, err)

	var decoded []domain.CompositeCondition
	require.NoError(t, json.Unmarshal(raw, &decoded))
	require.Len(t, decoded, 1)
	assert.Equal(t, orig[0], decoded[0])
}
