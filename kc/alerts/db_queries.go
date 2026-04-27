package alerts

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// LoadAlerts reads all alerts from the database grouped by email.
// Composite columns (alert_type, composite_logic, composite_name,
// conditions_json) are read via COALESCE so pre-composite rows decode
// cleanly with AlertTypeSingle. A malformed conditions_json fails loudly
// so data corruption is surfaced rather than silently producing a broken
// Alert — callers decide whether to halt startup or skip the row.
func (d *DB) LoadAlerts() (map[string][]*Alert, error) {
	rows, err := d.db.Query(`SELECT id, email, tradingsymbol, exchange, instrument_token,
		target_price, direction, triggered, created_at, triggered_at, triggered_price,
		reference_price, notification_sent_at,
		COALESCE(alert_type, 'single'), composite_logic, composite_name, conditions_json
		FROM alerts`)
	if err != nil {
		return nil, fmt.Errorf("query alerts: %w", err)
	}
	defer rows.Close()

	out := make(map[string][]*Alert)
	for rows.Next() {
		var (
			a                  Alert
			dir                string
			triggeredI         int
			createdAtS         string
			triggeredAt        sql.NullString
			trigPrice          sql.NullFloat64
			referencePrice     sql.NullFloat64
			notificationSentAt sql.NullString
			alertType          string
			compositeLogic     sql.NullString
			compositeName      sql.NullString
			conditionsJSON     sql.NullString
		)
		if err := rows.Scan(&a.ID, &a.Email, &a.Tradingsymbol, &a.Exchange,
			&a.InstrumentToken, &a.TargetPrice, &dir, &triggeredI,
			&createdAtS, &triggeredAt, &trigPrice, &referencePrice,
			&notificationSentAt,
			&alertType, &compositeLogic, &compositeName, &conditionsJSON); err != nil {
			return nil, fmt.Errorf("scan alert: %w", err)
		}
		a.Direction = Direction(dir)
		a.Triggered = triggeredI != 0
		a.CreatedAt, err = time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			return nil, fmt.Errorf("parse created_at: %w", err)
		}
		if triggeredAt.Valid {
			a.TriggeredAt, err = time.Parse(time.RFC3339, triggeredAt.String)
			if err != nil {
				return nil, fmt.Errorf("parse triggered_at: %w", err)
			}
		}
		if trigPrice.Valid {
			a.TriggeredPrice = trigPrice.Float64
		}
		if referencePrice.Valid {
			a.ReferencePrice = referencePrice.Float64
		}
		if notificationSentAt.Valid {
			a.NotificationSentAt, _ = time.Parse(time.RFC3339, notificationSentAt.String)
		}

		// Normalize composite fields. Pre-composite rows have empty
		// alert_type / NULL composite_* and decode as single-leg.
		switch alertType {
		case "", string(domain.AlertTypeSingle):
			a.AlertType = domain.AlertTypeSingle
		default:
			a.AlertType = domain.AlertType(alertType)
		}
		if compositeLogic.Valid {
			a.CompositeLogic = domain.CompositeLogic(compositeLogic.String)
		}
		if compositeName.Valid {
			a.CompositeName = compositeName.String
		}
		if conditionsJSON.Valid && conditionsJSON.String != "" {
			var conds []domain.CompositeCondition
			if err := json.Unmarshal([]byte(conditionsJSON.String), &conds); err != nil {
				return nil, fmt.Errorf("decode conditions_json for alert %s: %w", a.ID, err)
			}
			a.Conditions = conds
		}
		out[a.Email] = append(out[a.Email], &a)
	}
	return out, rows.Err()
}

// LoadTelegramChatIDs reads all email-to-chatID mappings.
func (d *DB) LoadTelegramChatIDs() (map[string]int64, error) {
	rows, err := d.db.Query(`SELECT email, chat_id FROM telegram_chat_ids`)
	if err != nil {
		return nil, fmt.Errorf("query telegram chat ids: %w", err)
	}
	defer rows.Close()

	out := make(map[string]int64)
	for rows.Next() {
		var email string
		var chatID int64
		if err := rows.Scan(&email, &chatID); err != nil {
			return nil, fmt.Errorf("scan telegram chat id: %w", err)
		}
		out[email] = chatID
	}
	return out, rows.Err()
}

// LoadTokens reads all cached Kite tokens from the database.
// If an encryption key is set, access tokens are decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
func (d *DB) LoadTokens() ([]*TokenEntry, error) {
	rows, err := d.db.Query(`SELECT email, access_token, user_id, user_name, stored_at FROM kite_tokens`)
	if err != nil {
		return nil, fmt.Errorf("query tokens: %w", err)
	}
	defer rows.Close()

	var out []*TokenEntry
	for rows.Next() {
		var t TokenEntry
		var storedAtS string
		if err := rows.Scan(&t.Email, &t.AccessToken, &t.UserID, &t.UserName, &storedAtS); err != nil {
			return nil, fmt.Errorf("scan token: %w", err)
		}
		if d.encryptionKey != nil {
			t.AccessToken = decrypt(d.encryptionKey, t.AccessToken)
		}
		storedAt, err := time.Parse(time.RFC3339, storedAtS)
		if err != nil {
			storedAt = time.Time{}
		}
		t.StoredAt = storedAt
		out = append(out, &t)
	}
	return out, rows.Err()
}

// LoadCredentials reads all stored Kite credentials from the database.
// If an encryption key is set, api_key and api_secret are decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
func (d *DB) LoadCredentials() ([]*CredentialEntry, error) {
	rows, err := d.db.Query(`SELECT email, api_key, api_secret, stored_at, COALESCE(app_id, '') FROM kite_credentials`)
	if err != nil {
		return nil, fmt.Errorf("query credentials: %w", err)
	}
	defer rows.Close()

	var out []*CredentialEntry
	for rows.Next() {
		var c CredentialEntry
		var storedAtS string
		if err := rows.Scan(&c.Email, &c.APIKey, &c.APISecret, &storedAtS, &c.AppID); err != nil {
			return nil, fmt.Errorf("scan credential: %w", err)
		}
		if d.encryptionKey != nil {
			c.APIKey = decrypt(d.encryptionKey, c.APIKey)
			c.APISecret = decrypt(d.encryptionKey, c.APISecret)
		}
		storedAt, err := time.Parse(time.RFC3339, storedAtS)
		if err != nil {
			storedAt = time.Time{}
		}
		c.StoredAt = storedAt
		out = append(out, &c)
	}
	return out, rows.Err()
}

// LoadClients reads all OAuth clients from the database.
// If an encryption key is set, client_secret is decrypted transparently.
// Pre-encryption plaintext values are returned as-is (migration-safe).
func (d *DB) LoadClients() ([]*ClientDBEntry, error) {
	rows, err := d.db.Query(`SELECT client_id, client_secret, redirect_uris, client_name, created_at, is_kite_key FROM oauth_clients`)
	if err != nil {
		return nil, fmt.Errorf("query oauth clients: %w", err)
	}
	defer rows.Close()

	var out []*ClientDBEntry
	for rows.Next() {
		var c ClientDBEntry
		var createdAtS string
		var isKiteKey int
		if err := rows.Scan(&c.ClientID, &c.ClientSecret, &c.RedirectURIs, &c.ClientName, &createdAtS, &isKiteKey); err != nil {
			return nil, fmt.Errorf("scan oauth client: %w", err)
		}
		if d.encryptionKey != nil && c.ClientSecret != "" {
			c.ClientSecret = decrypt(d.encryptionKey, c.ClientSecret)
		}
		createdAt, err := time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			createdAt = time.Time{}
		}
		c.CreatedAt = createdAt
		c.IsKiteAPIKey = isKiteKey != 0
		out = append(out, &c)
	}
	return out, rows.Err()
}

// LoadSessions reads all MCP sessions from the database.
// When encryption is enabled, session_id (PK) is an HMAC hash and the original
// session ID is recovered by decrypting session_id_enc. Rows without a valid
// encrypted ID are skipped (stale pre-migration data).
func (d *DB) LoadSessions() ([]*SessionDBEntry, error) {
	rows, err := d.db.Query(`SELECT session_id, email, created_at, expires_at, terminated, COALESCE(session_id_enc, '') FROM mcp_sessions`)
	if err != nil {
		return nil, fmt.Errorf("query sessions: %w", err)
	}
	defer rows.Close()

	var out []*SessionDBEntry
	for rows.Next() {
		var s SessionDBEntry
		var createdAtS, expiresAtS, sessionIDEnc string
		var terminatedI int
		if err := rows.Scan(&s.SessionID, &s.Email, &createdAtS, &expiresAtS, &terminatedI, &sessionIDEnc); err != nil {
			return nil, fmt.Errorf("scan session: %w", err)
		}

		// If encryption is enabled, the PK is a hash — recover original ID from encrypted column.
		if d.encryptionKey != nil && sessionIDEnc != "" {
			decrypted := decrypt(d.encryptionKey, sessionIDEnc)
			if decrypted != "" {
				s.SessionID = decrypted
			} else {
				// Decryption failed — skip this row (stale/corrupt data)
				continue
			}
		}

		createdAt, err := time.Parse(time.RFC3339, createdAtS)
		if err != nil {
			return nil, fmt.Errorf("parse session created_at: %w", err)
		}
		expiresAt, err := time.Parse(time.RFC3339, expiresAtS)
		if err != nil {
			return nil, fmt.Errorf("parse session expires_at: %w", err)
		}
		s.CreatedAt = createdAt
		s.ExpiresAt = expiresAt
		s.Terminated = terminatedI != 0
		out = append(out, &s)
	}
	return out, rows.Err()
}

// LoadTrailingStops reads all active trailing stops from the database.
func (d *DB) LoadTrailingStops() ([]*TrailingStop, error) {
	rows, err := d.db.Query(`SELECT id, email, exchange, tradingsymbol, instrument_token,
		order_id, variety, trail_amount, trail_pct, direction,
		high_water_mark, current_stop, active, created_at, deactivated_at,
		modify_count, last_modified_at
		FROM trailing_stops WHERE active = 1`)
	if err != nil {
		return nil, fmt.Errorf("query trailing stops: %w", err)
	}
	defer rows.Close()

	var out []*TrailingStop
	for rows.Next() {
		var (
			ts             TrailingStop
			activeI        int
			createdAtS     string
			deactivatedAt  sql.NullString
			lastModifiedAt sql.NullString
		)
		if err := rows.Scan(&ts.ID, &ts.Email, &ts.Exchange, &ts.Tradingsymbol,
			&ts.InstrumentToken, &ts.OrderID, &ts.Variety,
			&ts.TrailAmount, &ts.TrailPct, &ts.Direction,
			&ts.HighWaterMark, &ts.CurrentStop, &activeI,
			&createdAtS, &deactivatedAt, &ts.ModifyCount, &lastModifiedAt); err != nil {
			return nil, fmt.Errorf("scan trailing stop: %w", err)
		}
		ts.Active = activeI != 0
		ts.CreatedAt, _ = time.Parse(time.RFC3339, createdAtS)
		if deactivatedAt.Valid {
			ts.DeactivatedAt, _ = time.Parse(time.RFC3339, deactivatedAt.String)
		}
		if lastModifiedAt.Valid {
			ts.LastModifiedAt, _ = time.Parse(time.RFC3339, lastModifiedAt.String)
		}
		out = append(out, &ts)
	}
	return out, rows.Err()
}

// LoadDailyPnL reads daily P&L entries for a user within a date range (inclusive).
// Dates are in "2006-01-02" format.
//
// Currency-aware (Slice 6d): scans the holdings/positions/net pnl
// currency labels alongside the float magnitudes. Existing rows
// pre-migration backfill to 'INR' via the ALTER TABLE DEFAULT (see
// db_migrations.go), so callers always observe a non-empty Currency
// string on a successful Load.
func (d *DB) LoadDailyPnL(email, fromDate, toDate string) ([]*DailyPnLEntry, error) {
	rows, err := d.db.Query(`SELECT date, email,
		holdings_pnl, holdings_pnl_currency,
		positions_pnl, positions_pnl_currency,
		net_pnl, net_pnl_currency,
		holdings_count, trades_count
		FROM daily_pnl WHERE email = ? AND date >= ? AND date <= ?
		ORDER BY date ASC`, email, fromDate, toDate)
	if err != nil {
		return nil, fmt.Errorf("query daily pnl: %w", err)
	}
	defer rows.Close()

	var out []*DailyPnLEntry
	for rows.Next() {
		var e DailyPnLEntry
		if err := rows.Scan(&e.Date, &e.Email,
			&e.HoldingsPnL, &e.HoldingsPnLCurrency,
			&e.PositionsPnL, &e.PositionsPnLCurrency,
			&e.NetPnL, &e.NetPnLCurrency,
			&e.HoldingsCount, &e.TradesCount); err != nil {
			return nil, fmt.Errorf("scan daily pnl: %w", err)
		}
		out = append(out, &e)
	}
	return out, rows.Err()
}

// LoadRegistryEntries reads all app registrations from the database.
// If an encryption key is set, api_secret is decrypted transparently.
func (d *DB) LoadRegistryEntries() (map[string]*RegistryDBEntry, error) {
	rows, err := d.db.Query(`SELECT id, api_key, api_secret, assigned_to, label, status, registered_by, source, last_used_at, created_at, updated_at FROM app_registry`)
	if err != nil {
		return nil, fmt.Errorf("query app_registry: %w", err)
	}
	defer rows.Close()

	out := make(map[string]*RegistryDBEntry)
	for rows.Next() {
		var e RegistryDBEntry
		var source, lastUsedAtS, createdAtS, updatedAtS string
		if err := rows.Scan(&e.ID, &e.APIKey, &e.APISecret, &e.AssignedTo, &e.Label, &e.Status, &e.RegisteredBy, &source, &lastUsedAtS, &createdAtS, &updatedAtS); err != nil {
			return nil, fmt.Errorf("scan app_registry: %w", err)
		}
		if d.encryptionKey != nil {
			e.APIKey = decrypt(d.encryptionKey, e.APIKey)
			e.APISecret = decrypt(d.encryptionKey, e.APISecret)
		}
		e.Source = source
		if lastUsedAtS != "" {
			if t, err := time.Parse(time.RFC3339, lastUsedAtS); err == nil {
				e.LastUsedAt = &t
			}
		}
		if t, err := time.Parse(time.RFC3339, createdAtS); err == nil {
			e.CreatedAt = t
		}
		if t, err := time.Parse(time.RFC3339, updatedAtS); err == nil {
			e.UpdatedAt = t
		}
		out[e.ID] = &e
	}
	return out, rows.Err()
}
