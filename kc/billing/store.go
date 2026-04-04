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
	Email            string    `json:"email"`
	Tier             Tier      `json:"tier"`
	StripeCustomerID string    `json:"stripe_customer_id,omitempty"`
	StripeSubID      string    `json:"stripe_sub_id,omitempty"`
	Status           string    `json:"status"`
	ExpiresAt        time.Time `json:"expires_at,omitempty"`
	UpdatedAt        time.Time `json:"updated_at"`
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
    email              TEXT PRIMARY KEY,
    tier               INTEGER NOT NULL DEFAULT 0,
    stripe_customer_id TEXT DEFAULT '',
    stripe_sub_id      TEXT DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'active',
    expires_at         TEXT DEFAULT '',
    updated_at         TEXT NOT NULL
)`
	return s.db.ExecDDL(ddl)
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.RawQuery(`SELECT email, tier, stripe_customer_id, stripe_sub_id, status, COALESCE(expires_at, ''), updated_at FROM billing`)
	if err != nil {
		return fmt.Errorf("query billing: %w", err)
	}
	defer rows.Close()

	s.mu.Lock()
	defer s.mu.Unlock()

	for rows.Next() {
		var sub Subscription
		var tierInt int
		var expiresAtS, updatedAtS string
		if err := rows.Scan(&sub.Email, &tierInt, &sub.StripeCustomerID, &sub.StripeSubID, &sub.Status, &expiresAtS, &updatedAtS); err != nil {
			return fmt.Errorf("scan billing row: %w", err)
		}
		sub.Tier = Tier(tierInt)
		sub.UpdatedAt, _ = time.Parse(time.RFC3339, updatedAtS)
		if expiresAtS != "" {
			sub.ExpiresAt, _ = time.Parse(time.RFC3339, expiresAtS)
		}
		s.subs[strings.ToLower(sub.Email)] = &sub
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

// SetSubscription creates or updates a subscription for the given email.
func (s *Store) SetSubscription(sub *Subscription) error {
	key := strings.ToLower(strings.TrimSpace(sub.Email))
	if key == "" {
		return fmt.Errorf("email is required")
	}

	now := time.Now()
	stored := *sub
	stored.Email = key
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
			`INSERT INTO billing (email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at)
			 VALUES (?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(email) DO UPDATE SET
			   tier = excluded.tier,
			   stripe_customer_id = excluded.stripe_customer_id,
			   stripe_sub_id = excluded.stripe_sub_id,
			   status = excluded.status,
			   expires_at = excluded.expires_at,
			   updated_at = excluded.updated_at`,
			stored.Email, int(stored.Tier), stored.StripeCustomerID, stored.StripeSubID,
			stored.Status, expiresAtS, stored.UpdatedAt.Format(time.RFC3339),
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
