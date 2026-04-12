package alerts

import (
	"database/sql"
	"fmt"
	"strings"
)

// migrateRegistryCheckConstraint recreates the app_registry table with an expanded
// CHECK constraint that includes 'invalid' and 'replaced' statuses. This is needed
// because SQLite does not support ALTER CHECK.
func migrateRegistryCheckConstraint(db *sql.DB) error {
	// Check if the migration is needed by looking at the current table SQL.
	var tableSql string
	err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name='app_registry'`).Scan(&tableSql)
	if err != nil {
		return nil // table doesn't exist yet (will be created by DDL), nothing to migrate
	}
	// If the table already supports 'invalid', no migration needed.
	if strings.Contains(tableSql, "'invalid'") {
		return nil
	}

	// Recreate: new table → copy data → drop old → rename
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin registry migration: %w", err)
	}
	defer tx.Rollback() // #nosec G104 -- rollback after commit is a no-op

	if _, err := tx.Exec(`CREATE TABLE app_registry_new (
		id            TEXT PRIMARY KEY,
		api_key       TEXT NOT NULL,
		api_secret    TEXT NOT NULL,
		assigned_to   TEXT NOT NULL DEFAULT '',
		label         TEXT NOT NULL DEFAULT '',
		status        TEXT NOT NULL DEFAULT 'active' CHECK(status IN ('active','disabled','invalid','replaced')),
		registered_by TEXT NOT NULL DEFAULT '',
		source        TEXT NOT NULL DEFAULT 'admin',
		last_used_at  TEXT NOT NULL DEFAULT '',
		created_at    TEXT NOT NULL,
		updated_at    TEXT NOT NULL
	)`); err != nil {
		return fmt.Errorf("create registry_new: %w", err)
	}

	// Copy existing data. Use COALESCE for new columns that may not exist yet in the source.
	if _, err := tx.Exec(`INSERT INTO app_registry_new (id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at)
		SELECT id, api_key, api_secret, assigned_to, label, status, registered_by,
			COALESCE(source, 'admin'), COALESCE(last_used_at, ''), created_at, updated_at
		FROM app_registry`); err != nil {
		return fmt.Errorf("copy registry data: %w", err)
	}

	if _, err := tx.Exec(`DROP TABLE app_registry`); err != nil {
		return fmt.Errorf("drop old registry: %w", err)
	}
	if _, err := tx.Exec(`ALTER TABLE app_registry_new RENAME TO app_registry`); err != nil {
		return fmt.Errorf("rename registry: %w", err)
	}
	// Recreate indexes
	tx.Exec(`CREATE INDEX IF NOT EXISTS idx_app_registry_assigned ON app_registry(assigned_to)`) // #nosec G104 -- idempotent index creation
	tx.Exec(`CREATE INDEX IF NOT EXISTS idx_app_registry_api_key ON app_registry(api_key)`)     // #nosec G104 -- idempotent index creation

	return tx.Commit()
}

// migrateAlerts applies incremental schema migrations to the alerts table.
func migrateAlerts(db *sql.DB) error {
	// Check if reference_price column exists.
	var count int
	err := db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('alerts') WHERE name = 'reference_price'`).Scan(&count)
	if err != nil {
		return fmt.Errorf("check reference_price column: %w", err)
	}
	if count == 0 {
		if _, err := db.Exec(`ALTER TABLE alerts ADD COLUMN reference_price REAL`); err != nil {
			return fmt.Errorf("add reference_price column: %w", err)
		}
	}

	// Add notification_sent_at column if missing.
	// SQLite returns an error if the column already exists; ignore it.
	db.Exec(`ALTER TABLE alerts ADD COLUMN notification_sent_at TEXT`) // #nosec G104 -- idempotent migration

	return nil
}
