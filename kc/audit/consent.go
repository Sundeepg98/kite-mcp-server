package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// ConsentAction enumerates the allowed values for the consent_action column.
// Matches the CHECK constraint in the consent_log DDL.
type ConsentAction string

const (
	// ConsentActionGrant records that the user affirmatively gave consent
	// (e.g. completed the OAuth authorization flow, flipped a dashboard toggle on).
	ConsentActionGrant ConsentAction = "grant"
	// ConsentActionWithdraw records that the user rescinded previously granted
	// consent (e.g. account deletion, toggled a scope off).
	ConsentActionWithdraw ConsentAction = "withdraw"
)

// ConsentMethod enumerates the allowed values for the method column.
// Matches the CHECK constraint in the consent_log DDL.
type ConsentMethod string

const (
	// ConsentMethodOAuthCallback indicates consent captured during the Kite
	// OAuth callback — the user authorised Kite + implicitly accepted the
	// privacy notice surfaced on our login page / terms.
	ConsentMethodOAuthCallback ConsentMethod = "oauth_callback"
	// ConsentMethodDashboardToggle indicates consent captured via an explicit
	// control on the user dashboard (e.g. "enable Telegram", "withdraw
	// analytics consent").
	ConsentMethodDashboardToggle ConsentMethod = "dashboard_toggle"
)

// ConsentLogEntry represents a single row in the consent_log table.
//
// The table is append-only: a grant and a subsequent withdraw both appear as
// rows, so the full consent history is reconstructable. DPB (Data Protection
// Board of India) may request this log during a DPDP Act 2023 audit.
//
// PII minimization: user_email_hash is SHA-256(lowercased email) — the raw
// email never enters this table. Callers should log the email in the main
// audit trail (kc/audit.Store) if they need it, not here.
type ConsentLogEntry struct {
	ID            int64         `json:"id"`
	UserEmailHash string        `json:"user_email_hash"`
	TimestampUTC  time.Time     `json:"timestamp_utc"`
	IPAddress     string        `json:"ip_address,omitempty"`
	UserAgent     string        `json:"user_agent,omitempty"`
	NoticeVersion string        `json:"notice_version"`
	ConsentAction ConsentAction `json:"consent_action"`
	Scope         string        `json:"scope"` // JSON-encoded — opaque to the store
	Method        ConsentMethod `json:"method"`
	ProofHash     string        `json:"proof_hash"`
}

// ConsentStore persists consent-grant and consent-withdraw events for DPDP
// Act 2023 compliance. It shares the SQLite connection pool with the main
// audit Store — a dedicated *sql.DB would violate the single-writer-pool
// invariant that SQLite WAL relies on.
type ConsentStore struct {
	db *alerts.DB
}

// NewConsentStore returns a new ConsentStore backed by the shared DB handle.
// Callers must invoke InitTable once at startup before Insert/List.
func NewConsentStore(db *alerts.DB) *ConsentStore {
	return &ConsentStore{db: db}
}

// InitTable creates the consent_log table and its supporting indexes if they
// do not already exist. Idempotent — safe to call at every startup.
//
// The CHECK constraints on consent_action and method mirror the ConsentAction
// and ConsentMethod constants. Extending those constants requires an
// ALTER-TABLE-recreate migration (SQLite can't drop CHECK constraints).
func (c *ConsentStore) InitTable() error {
	ddl := `
CREATE TABLE IF NOT EXISTS consent_log (
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
);
CREATE INDEX IF NOT EXISTS idx_consent_email_hash ON consent_log(user_email_hash);
CREATE INDEX IF NOT EXISTS idx_consent_timestamp ON consent_log(timestamp_utc);`
	if err := c.db.ExecDDL(ddl); err != nil {
		return fmt.Errorf("consent: create consent_log table: %w", err)
	}
	return nil
}

// Insert persists a consent event. On success, entry.ID is populated with the
// auto-increment row ID.
//
// Timestamp handling: we store the caller-supplied TimestampUTC explicitly
// rather than relying on CURRENT_TIMESTAMP, so that replayed events (e.g. a
// background worker draining a queue after restart) carry their original
// timestamp. Caller should always pass time.Now().UTC().
func (c *ConsentStore) Insert(entry *ConsentLogEntry) error {
	if entry == nil {
		return fmt.Errorf("consent: nil entry")
	}
	query := `INSERT INTO consent_log
		(user_email_hash, timestamp_utc, ip_address, user_agent,
		 notice_version, consent_action, scope, method, proof_hash)
		VALUES (?,?,?,?,?,?,?,?,?)`
	// Format timestamp as RFC3339Nano so text-scan retrieval below can parse
	// it round-trip without fractional-second loss.
	res, err := c.db.ExecResult(query,
		entry.UserEmailHash,
		entry.TimestampUTC.Format(time.RFC3339Nano),
		entry.IPAddress,
		entry.UserAgent,
		entry.NoticeVersion,
		string(entry.ConsentAction),
		entry.Scope,
		string(entry.Method),
		entry.ProofHash,
	)
	if err != nil {
		return fmt.Errorf("consent: insert: %w", err)
	}
	id, err := res.LastInsertId()
	if err == nil {
		entry.ID = id
	}
	return nil
}

// ListByEmailHash returns all consent events for the given user_email_hash
// ordered by timestamp_utc ASC (oldest first, so the consent history reads
// chronologically). Limit caps the result set; 0 or negative means "no cap".
func (c *ConsentStore) ListByEmailHash(emailHash string, limit int) ([]*ConsentLogEntry, error) {
	query := `SELECT id, user_email_hash, timestamp_utc, ip_address, user_agent,
		notice_version, consent_action, scope, method, proof_hash
		FROM consent_log
		WHERE user_email_hash = ?
		ORDER BY timestamp_utc ASC, id ASC`
	args := []any{emailHash}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := c.db.RawQuery(query, args...)
	if err != nil {
		return nil, fmt.Errorf("consent: list: %w", err)
	}
	defer rows.Close()

	var out []*ConsentLogEntry
	for rows.Next() {
		var (
			e      ConsentLogEntry
			ts     string
			action string
			method string
		)
		if err := rows.Scan(
			&e.ID,
			&e.UserEmailHash,
			&ts,
			&e.IPAddress,
			&e.UserAgent,
			&e.NoticeVersion,
			&action,
			&e.Scope,
			&method,
			&e.ProofHash,
		); err != nil {
			return nil, fmt.Errorf("consent: scan: %w", err)
		}
		parsed, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			// Fallback: CURRENT_TIMESTAMP default emits "YYYY-MM-DD HH:MM:SS"
			// (SQLite canonical) — retry parsing with that layout.
			if p2, err2 := time.Parse("2006-01-02 15:04:05", ts); err2 == nil {
				parsed = p2.UTC()
			} else {
				return nil, fmt.Errorf("consent: parse timestamp %q: %w", ts, err)
			}
		}
		e.TimestampUTC = parsed
		e.ConsentAction = ConsentAction(action)
		e.Method = ConsentMethod(method)
		out = append(out, &e)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("consent: rows: %w", err)
	}
	return out, nil
}

// HashEmail returns the hex-encoded SHA-256 digest of the lowercased email.
// This is the canonical function callers should use to produce user_email_hash
// values for Insert and ListByEmailHash. Returns "" for empty input so callers
// never accidentally store the hash of the empty string.
//
// Design: SHA-256 (not HMAC) is deliberate. The consent log must be verifiable
// by an auditor without our secret key — they should be able to hash the
// email from their records and match it against our log. HMAC would prevent
// that.
func HashEmail(email string) string {
	if email == "" {
		return ""
	}
	h := sha256.Sum256([]byte(strings.ToLower(email)))
	return hex.EncodeToString(h[:])
}

// ComputeProofHash returns the hex-encoded SHA-256 digest of the concatenation
// of noticeBytes || 0x00 || actionBytes. The separator byte prevents
// boundary-ambiguity attacks where moving bytes from one field to the other
// would otherwise produce the same hash.
//
// Callers: the OAuth callback should pass the canonical displayed-notice
// string (e.g. privacy policy text at the version shown) and a string
// describing the user action (e.g. "grant scopes=trading,analytics via
// oauth_callback").
func ComputeProofHash(noticeBytes, actionBytes string) string {
	h := sha256.New()
	h.Write([]byte(noticeBytes))
	h.Write([]byte{0x00})
	h.Write([]byte(actionBytes))
	return hex.EncodeToString(h.Sum(nil))
}
