package billing

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// Subscription status constants.
const (
	StatusActive   = "active"
	StatusCanceled = "canceled"
	StatusPastDue  = "past_due"
	StatusTrialing = "trialing"
)

// Subscription holds a user's billing subscription details.
type Subscription struct {
	AdminEmail       string    `json:"admin_email"`
	Tier             Tier      `json:"tier"`
	StripeCustomerID string    `json:"stripe_customer_id,omitempty"`
	StripeSubID      string    `json:"stripe_sub_id,omitempty"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
	MaxUsers int `json:"max_users"`
}

// Store is a thread-safe in-memory billing store backed by SQLite.
type Store struct {
	mu     sync.RWMutex
	subs   map[string]*Subscription // keyed by lowercase email
	db     *alerts.DB
	logger *slog.Logger
}

// NewStore creates a new billing store with SQLite persistence.
func NewStore(db *alerts.DB, logger *slog.Logger) *Store {
	return &Store{
		subs:   make(map[string]*Subscription),
		db:     db,
		logger: logger,
	}
}

// InitTable creates the billing table if it does not exist.
func (s *Store) InitTable() error {
	if s.db == nil {
		return nil
	}
	ddl := `
CREATE TABLE IF NOT EXISTS billing (
    admin_email        TEXT PRIMARY KEY,
    tier               INTEGER NOT NULL DEFAULT 0,
    stripe_customer_id TEXT DEFAULT '',
    stripe_sub_id      TEXT DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'active',
    expires_at         TEXT DEFAULT '',
    updated_at         TEXT NOT NULL
)`
	if err := s.db.ExecDDL(ddl); err != nil {
		return err
	}
	// Migration: add max_users column for family billing.
	_ = s.db.ExecDDL(`ALTER TABLE billing ADD COLUMN max_users INTEGER NOT NULL DEFAULT 1`)

	// Migration: rename billing PK from email to admin_email (idempotent).
	// Check if admin_email column already exists — if so, migration is done.
	var colCount int
	if row := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('billing') WHERE name='admin_email'`); row != nil {
		_ = row.Scan(&colCount)
	}
	if colCount == 0 {
		// Table rebuild: email → admin_email
		_ = s.db.ExecDDL(`CREATE TABLE IF NOT EXISTS billing_mig (
			admin_email        TEXT PRIMARY KEY,
			tier               INTEGER NOT NULL DEFAULT 0,
			stripe_customer_id TEXT DEFAULT '',
			stripe_sub_id      TEXT DEFAULT '',
			status             TEXT NOT NULL DEFAULT 'active',
			expires_at         TEXT DEFAULT '',
			updated_at         TEXT NOT NULL,
			max_users          INTEGER NOT NULL DEFAULT 1
		)`)
		_ = s.db.ExecDDL(`INSERT OR IGNORE INTO billing_mig (admin_email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, max_users) SELECT email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, COALESCE(max_users, 1) FROM billing`)
		_ = s.db.ExecDDL(`DROP TABLE billing`)
		_ = s.db.ExecDDL(`ALTER TABLE billing_mig RENAME TO billing`)
	}
	return nil
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.RawQuery(`SELECT admin_email, tier, stripe_customer_id, stripe_sub_id, status, COALESCE(expires_at, ''), updated_at, COALESCE(max_users, 1) FROM billing`)
	if err != nil {
		return fmt.Errorf("query billing: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var sub Subscription
		var tierInt int
		var maxUsers int
		var expiresAtS, updatedAtS string
		if err := rows.Scan(&sub.AdminEmail, &tierInt, &sub.StripeCustomerID, &sub.StripeSubID, &sub.Status, &expiresAtS, &updatedAtS, &maxUsers); err != nil { // COVERAGE: unreachable — SQLite query success implies scan success (dynamic typing)
			return fmt.Errorf("scan billing row: %w", err)
		}
		sub.MaxUsers = maxUsers
		sub.Tier = Tier(tierInt)
		sub.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtS)
		if expiresAtS != "" {
			sub.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtS)
		}
		s.subs[strings.ToLower(sub.AdminEmail)] = &sub
	}
	return rows.Err()
}

// GetTier returns the current billing tier for an email.
// Returns TierFree if the user has no subscription or the subscription is not active.
func (s *Store) GetTier(email string) Tier {
	key := strings.ToLower(email)

	s.mu.RLock()
	sub, ok := s.subs[key]
	s.mu.RUnlock()

	if !ok {
		return TierFree
	}
	// Only count active/trialing subscriptions that haven't expired.
	if sub.Status != StatusActive && sub.Status != StatusTrialing {
		return TierFree
	}
	if !sub.ExpiresAt.IsZero() && time.Now().After(sub.ExpiresAt) {
		return TierFree
	}
	return sub.Tier
}

// GetTierForUser returns the billing tier for a user, checking both
// direct subscription and admin parent linkage via adminEmailFn.
func (s *Store) GetTierForUser(email string, adminEmailFn func(string) string) Tier {
	key := strings.ToLower(email)
	if tier := s.GetTier(key); tier > TierFree {
		return tier
	}
	if adminEmailFn != nil {
		adminEmail := adminEmailFn(key)
		if adminEmail != "" && adminEmail != key {
			return s.GetTier(strings.ToLower(adminEmail))
		}
	}
	return TierFree
}

// SetSubscription creates or updates a subscription for the given email.
func (s *Store) SetSubscription(sub *Subscription) error {
	key := strings.ToLower(strings.TrimSpace(sub.AdminEmail))
	if key == "" {
		return fmt.Errorf("email is required")
	}

	now := time.Now()
	stored := *sub
	stored.AdminEmail = key
	stored.UpdatedAt = now

	s.mu.Lock()
	s.subs[key] = &stored
	s.mu.Unlock()

	if s.db != nil {
		var expiresAtS string
		if !stored.ExpiresAt.IsZero() {
			expiresAtS = stored.ExpiresAt.Format(time.RFC3339)
		}
		err := s.db.ExecInsert(
			`INSERT INTO billing (admin_email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, max_users)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(admin_email) DO UPDATE SET
			   tier = excluded.tier,
			   stripe_customer_id = excluded.stripe_customer_id,
			   stripe_sub_id = excluded.stripe_sub_id,
			   status = excluded.status,
			   expires_at = excluded.expires_at,
			   updated_at = excluded.updated_at,
			   max_users = excluded.max_users`,
			stored.AdminEmail, int(stored.Tier), stored.StripeCustomerID, stored.StripeSubID,
			stored.Status, expiresAtS, stored.UpdatedAt.Format(time.RFC3339), stored.MaxUsers,
		)
		if err != nil {
			if s.logger != nil {
				s.logger.Error("Failed to persist billing subscription", "email", key, "error", err)
			}
			return fmt.Errorf("persist subscription: %w", err)
		}
	}
	return nil
}

// GetSubscription returns the subscription for an email. Returns nil if not found.
func (s *Store) GetSubscription(email string) *Subscription {
	key := strings.ToLower(email)

	s.mu.RLock()
	sub, ok := s.subs[key]
	s.mu.RUnlock()

	if !ok {
		return nil
	}
	cp := *sub
	return &cp
}

// GetEmailByCustomerID returns the email associated with a Stripe customer ID.
// Returns "" if no mapping exists. This is populated when checkout.session.completed fires.
func (s *Store) GetEmailByCustomerID(customerID string) string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, sub := range s.subs {
		if sub.StripeCustomerID == customerID {
			return sub.AdminEmail
		}
	}
	return ""
}

// InitEventLogTable creates the webhook_events idempotency table.
func (s *Store) InitEventLogTable() error {
	if s.db == nil {
		return nil
	}
	ddl := `
CREATE TABLE IF NOT EXISTS webhook_events (
    event_id   TEXT PRIMARY KEY,
    event_type TEXT NOT NULL,
    created_at TEXT NOT NULL
)`
	return s.db.ExecDDL(ddl)
}

// IsEventProcessed returns true if the event has already been handled.
func (s *Store) IsEventProcessed(eventID string) bool {
	if s.db == nil {
		return false
	}
	var count int
	row := s.db.QueryRow(`SELECT COUNT(*) FROM webhook_events WHERE event_id = ?`, eventID)
	if err := row.Scan(&count); err != nil {
		return false
	}
	return count > 0
}

// MarkEventProcessed records that an event has been processed.
func (s *Store) MarkEventProcessed(eventID, eventType string) error {
	if s.db == nil {
		return nil
	}
	return s.db.ExecInsert(
		`INSERT OR IGNORE INTO webhook_events (event_id, event_type, created_at) VALUES (?, ?, ?)`,
		eventID, eventType, time.Now().Format(time.RFC3339),
	)
}
