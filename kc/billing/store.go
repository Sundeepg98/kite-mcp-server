package billing

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Subscription status constants.
const (
	StatusActive   = "active"
	StatusCanceled = "canceled"
	StatusPastDue  = "past_due"
	StatusTrialing = "trialing"
)

// Subscription holds a user's billing subscription details.
//
// MonthlyAmount carries the per-month rupee amount for the active plan
// as a domain.Money value (Slice 4 of the Money VO sweep). The zero
// Money is the "no paid plan / Free" sentinel — IsZero() returns true
// for free or unset subscriptions; paid tiers carry the canonical
// TierMonthlyINR(Tier) amount unless an explicit override is supplied
// (enterprise contract, custom price). Stripe remains the source of
// truth for what the user is actually charged; MonthlyAmount is the
// in-process mirror used to annotate TierChangedEvent and to render
// the dashboard plan card.
type Subscription struct {
	AdminEmail       string       `json:"admin_email"`
	Tier             Tier         `json:"tier"`
	StripeCustomerID string       `json:"stripe_customer_id,omitempty"`
	StripeSubID      string       `json:"stripe_sub_id,omitempty"`
	Status           string       `json:"status"`
	ExpiresAt        time.Time    `json:"expires_at,omitempty"`
	UpdatedAt        time.Time    `json:"updated_at"`
	MaxUsers         int          `json:"max_users"`
	MonthlyAmount    domain.Money `json:"monthly_amount"`
}

// Store is a thread-safe in-memory billing store backed by SQLite.
type Store struct {
	mu     sync.RWMutex
	subs   map[string]*Subscription // keyed by lowercase email
	db *alerts.DB
	// SOLID 99→100 cleanup: the deprecated *slog.Logger field is
	// retired (zero in-package consumers; the only call site at
	// store.go:317 now uses loggerPort.Error with ctx threading).
	// NewStore still accepts a *slog.Logger parameter for back-compat
	// with app/wire.go and tests — the value is wrapped via
	// logport.NewSlog and stored on loggerPort.
	loggerPort logport.Logger
	// dispatcher is the optional domain event dispatcher. When set,
	// SetSubscription emits a domain.TierChangedEvent on every
	// effective tier transition. Nil-safe — older wirings or in-memory
	// test stores that never call SetEventDispatcher continue to
	// function without emitting events.
	dispatcher *domain.EventDispatcher
	// changeReason is consulted by SetSubscription to label the next
	// emitted TierChangedEvent. Cleared after each emit so callers
	// must opt in per call (defaulting to "" when not set).
	changeReason string
}

// SetEventDispatcher attaches a domain event dispatcher to the store.
// Once set, SetSubscription emits TierChangedEvent on every effective
// tier transition. Pattern mirrors usecases.CreateAlertUseCase /
// SessionService — the store stays usable without a dispatcher (older
// tests, in-memory wirings) and gains domain-event emission once wired.
func (s *Store) SetEventDispatcher(d *domain.EventDispatcher) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.dispatcher = d
}

// SetChangeReason labels the next TierChangedEvent with the supplied
// reason string ("stripe_checkout", "stripe_subscription_updated",
// "stripe_subscription_deleted", "admin_set_billing_tier"). The reason
// is consumed by the next SetSubscription call and cleared afterwards,
// so each call site must opt in by pairing this with its mutation.
// Concurrency-safe (held under store lock) but not transactional — if
// two callers race, the second overrides the first; given that
// SetSubscription is per-email and tier changes are infrequent, this
// is acceptable for an audit-log-only signal.
func (s *Store) SetChangeReason(reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.changeReason = reason
}

// NewStore creates a new billing store with SQLite persistence.
//
// Public signature retains *slog.Logger for backward-compat with
// app/wire.go's call site; the value is wrapped via logport.NewSlog
// onto loggerPort. The duplicate *slog.Logger field was retired
// during the SOLID 99→100 deprecation-shim sweep (see commit body).
func NewStore(db *alerts.DB, logger *slog.Logger) *Store {
	return &Store{
		subs:       make(map[string]*Subscription),
		db:         db,
		loggerPort: logport.NewSlog(logger),
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
	// Migration (Money VO Slice 4): add monthly_amount column for tier
	// pricing. REAL column (float64) so the schema stays primitive at
	// rest — Money is reconstructed via domain.NewINR on Scan, dropped
	// to .Float64() on Bind. Idempotent: ALTER COLUMN errors silently
	// when the column already exists, matching the max_users pattern
	// just above.
	_ = s.db.ExecDDL(`ALTER TABLE billing ADD COLUMN monthly_amount REAL NOT NULL DEFAULT 0`)

	// Migration: rename billing PK from email to admin_email (idempotent).
	// Check if admin_email column already exists — if so, migration is done.
	var colCount int
	if row := s.db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('billing') WHERE name='admin_email'`); row != nil {
		_ = row.Scan(&colCount)
	}
	if colCount == 0 {
		// Table rebuild: email → admin_email. Pre-rebuild rows had no
		// monthly_amount; default to 0 (Free / unset) so the rebuilt
		// table is well-formed and Slice 4's REAL boundary stays consistent
		// with the post-rebuild ALTER above.
		_ = s.db.ExecDDL(`CREATE TABLE IF NOT EXISTS billing_mig (
			admin_email        TEXT PRIMARY KEY,
			tier               INTEGER NOT NULL DEFAULT 0,
			stripe_customer_id TEXT DEFAULT '',
			stripe_sub_id      TEXT DEFAULT '',
			status             TEXT NOT NULL DEFAULT 'active',
			expires_at         TEXT DEFAULT '',
			updated_at         TEXT NOT NULL,
			max_users          INTEGER NOT NULL DEFAULT 1,
			monthly_amount     REAL NOT NULL DEFAULT 0
		)`)
		_ = s.db.ExecDDL(`INSERT OR IGNORE INTO billing_mig (admin_email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, max_users, monthly_amount) SELECT email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, COALESCE(max_users, 1), 0 FROM billing`)
		_ = s.db.ExecDDL(`DROP TABLE billing`)
		_ = s.db.ExecDDL(`ALTER TABLE billing_mig RENAME TO billing`)
	}
	return nil
}

// LoadFromDB populates the in-memory store from the database.
//
// monthly_amount is read as a REAL (float64) and reconstructed via
// domain.NewINR — this is the Slice 4 SQLite boundary: persistence stays
// primitive, the in-memory representation is Money. COALESCE guards
// pre-migration rows where the column might not have a value.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	rows, err := s.db.RawQuery(`SELECT admin_email, tier, stripe_customer_id, stripe_sub_id, status, COALESCE(expires_at, ''), updated_at, COALESCE(max_users, 1), COALESCE(monthly_amount, 0) FROM billing`)
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
		var monthlyAmount float64
		var expiresAtS, updatedAtS string
		if err := rows.Scan(&sub.AdminEmail, &tierInt, &sub.StripeCustomerID, &sub.StripeSubID, &sub.Status, &expiresAtS, &updatedAtS, &maxUsers, &monthlyAmount); err != nil { // COVERAGE: unreachable — SQLite query success implies scan success (dynamic typing)
			return fmt.Errorf("scan billing row: %w", err)
		}
		sub.MaxUsers = maxUsers
		sub.Tier = Tier(tierInt)
		// Reconstruct Money on the way out of the persistence boundary.
		// Empty/zero amount yields the zero INR Money (the "no paid
		// plan" sentinel) — IsZero() detection works without further
		// special-casing.
		sub.MonthlyAmount = domain.NewINR(monthlyAmount)
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
// On every successful write where the **effective** tier has changed
// (computed via effectiveTierOf below — applies the same status/expiry
// gating as GetTier), the store dispatches a domain.TierChangedEvent
// describing the transition. Identical-tier writes (idempotent webhook
// replays, status-only updates that don't shift the access tier) are
// silent so the audit log only records real state changes.
func (s *Store) SetSubscription(sub *Subscription) error {
	key := strings.ToLower(strings.TrimSpace(sub.AdminEmail))
	if key == "" {
		return fmt.Errorf("email is required")
	}

	now := time.Now()
	stored := *sub
	stored.AdminEmail = key
	stored.UpdatedAt = now
	// Slice 4: stamp the canonical monthly amount when the caller
	// leaves MonthlyAmount unset (zero Money). Webhook + admin tool
	// both take the lazy path — they never bother to populate
	// MonthlyAmount because they don't carry the price list. Callers
	// that supply an explicit value (enterprise contract, custom
	// price) are honoured. We use the IsZero sentinel rather than a
	// bare float compare to keep the boundary symmetric with
	// LoadFromDB and to side-step accidental "0.0 INR vs 0.0 USD"
	// confusion if the type ever goes multi-currency.
	if stored.MonthlyAmount.IsZero() {
		stored.MonthlyAmount = TierMonthlyINR(stored.Tier)
	}

	s.mu.Lock()
	prev := s.subs[key]
	fromTier := effectiveTierOf(prev, now)
	s.subs[key] = &stored
	toTier := effectiveTierOf(&stored, now)
	dispatcher := s.dispatcher
	reason := s.changeReason
	s.changeReason = ""
	s.mu.Unlock()

	if s.db != nil {
		var expiresAtS string
		if !stored.ExpiresAt.IsZero() {
			expiresAtS = stored.ExpiresAt.Format(time.RFC3339)
		}
		err := s.db.ExecInsert(
			`INSERT INTO billing (admin_email, tier, stripe_customer_id, stripe_sub_id, status, expires_at, updated_at, max_users, monthly_amount)
			 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
			 ON CONFLICT(admin_email) DO UPDATE SET
			   tier = excluded.tier,
			   stripe_customer_id = excluded.stripe_customer_id,
			   stripe_sub_id = excluded.stripe_sub_id,
			   status = excluded.status,
			   expires_at = excluded.expires_at,
			   updated_at = excluded.updated_at,
			   max_users = excluded.max_users,
			   monthly_amount = excluded.monthly_amount`,
			stored.AdminEmail, int(stored.Tier), stored.StripeCustomerID, stored.StripeSubID,
			stored.Status, expiresAtS, stored.UpdatedAt.Format(time.RFC3339), stored.MaxUsers,
			// .Float64() at the SQLite REAL bind boundary — the only
			// place in this package where Money drops back to a primitive,
			// matching the Slice 1 convention in
			// kc/riskguard/limits.go::persistLimits.
			stored.MonthlyAmount.Float64(),
		)
		if err != nil {
			if s.loggerPort != nil {
				// SetSubscription is sync; no request ctx in scope.
				// Background() is the appropriate seam.
				s.loggerPort.Error(context.Background(), "Failed to persist billing subscription", err, "email", key)
			}
			return fmt.Errorf("persist subscription: %w", err)
		}
	}

	// Dispatch tier-change event after persistence succeeds. We emit
	// only on real transitions so idempotent webhook replays don't
	// litter the audit log with no-op rows. Dispatcher is nil-safe.
	// Amount carries the to-tier monthly Money so audit consumers can
	// compute MRR delta from the event stream alone (no join into
	// the billing table).
	if dispatcher != nil && fromTier != toTier {
		dispatcher.Dispatch(domain.TierChangedEvent{
			UserEmail: key,
			FromTier:  int(fromTier),
			ToTier:    int(toTier),
			Amount:    TierMonthlyINR(toTier),
			Reason:    reason,
			Timestamp: now,
		})
	}
	return nil
}

// effectiveTierOf returns the tier a subscription would expose to
// downstream tool-access checks at the given instant. Mirrors GetTier
// semantics (status must be Active or Trialing; expired subscriptions
// fall back to Free) so TierChangedEvent reflects what tools actually
// see, not the raw stored Tier column. nil sub → Free (the default
// for users with no subscription row yet).
func effectiveTierOf(sub *Subscription, at time.Time) Tier {
	if sub == nil {
		return TierFree
	}
	if sub.Status != StatusActive && sub.Status != StatusTrialing {
		return TierFree
	}
	if !sub.ExpiresAt.IsZero() && at.After(sub.ExpiresAt) {
		return TierFree
	}
	return sub.Tier
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
