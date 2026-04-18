package alerts

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// The Alert entity + Direction type + trigger constants now live in
// kc/domain/alert.go as pure domain logic. This package re-exports them
// via type aliases so every existing caller (kc/alerts.Alert,
// alerts.DirectionAbove, etc.) keeps working without a rename cascade.
// Infrastructure concerns (Store, DB, persistence) stay in this package.

// Direction is an alias for domain.Direction.
type Direction = domain.Direction

// Alert is an alias for domain.Alert — the canonical entity definition.
type Alert = domain.Alert

// Alert direction constants. Re-exported from kc/domain for call-site
// compatibility — alerts.DirectionAbove still works.
const (
	DirectionAbove   = domain.DirectionAbove
	DirectionBelow   = domain.DirectionBelow
	DirectionDropPct = domain.DirectionDropPct
	DirectionRisePct = domain.DirectionRisePct

	// MaxAlertsPerUser is the maximum number of alerts a single user can have.
	// Persistence-layer limit, stays in this package.
	MaxAlertsPerUser = 100
)

// ValidDirections re-exports the domain's validation set.
var ValidDirections = domain.ValidDirections

// CompositeCondition is a type alias for the domain composite condition —
// keeps callers who import only kc/alerts working without pulling domain.
type CompositeCondition = domain.CompositeCondition

// CompositeLogic is a type alias for the domain composite logic operator.
type CompositeLogic = domain.CompositeLogic

// AlertType is a type alias for the domain alert type discriminator.
type AlertType = domain.AlertType

// Composite logic constants — re-exported so alerts.CompositeLogicAnd etc.
// resolve without the caller needing to import kc/domain.
const (
	CompositeLogicAnd  = domain.CompositeLogicAnd
	CompositeLogicAny  = domain.CompositeLogicAny
	AlertTypeSingle    = domain.AlertTypeSingle
	AlertTypeComposite = domain.AlertTypeComposite
)

// IsPercentageDirection re-exports the domain helper.
func IsPercentageDirection(d Direction) bool {
	return domain.IsPercentageDirection(d)
}

// NotifyCallback is invoked when an alert is triggered.
type NotifyCallback func(alert *Alert, currentPrice float64)

// Store is a thread-safe in-memory store for price alerts and Telegram chat IDs.
// Optionally backed by SQLite for persistence via SetDB.
type Store struct {
	mu       sync.RWMutex
	alerts   map[string][]*Alert  // email -> alerts
	telegram map[string]int64     // email -> chat ID
	onNotify NotifyCallback
	db       *DB                  // optional: write-through persistence
	logger   *slog.Logger
}

// NewStore creates a new alert store.
func NewStore(onNotify NotifyCallback) *Store {
	return &Store{
		alerts:   make(map[string][]*Alert),
		telegram: make(map[string]int64),
		onNotify: onNotify,
		logger:   slog.Default(),
	}
}

// SetLogger sets the logger for DB error reporting.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *Store) SetDB(db *DB) {
	s.db = db
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	alerts, err := s.db.LoadAlerts()
	if err != nil {
		return fmt.Errorf("load alerts: %w", err)
	}
	chatIDs, err := s.db.LoadTelegramChatIDs()
	if err != nil {
		return fmt.Errorf("load telegram chat ids: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for email, list := range alerts {
		s.alerts[email] = list
	}
	for email, chatID := range chatIDs {
		s.telegram[email] = chatID
	}
	return nil
}

// Add creates a new alert and returns its ID.
// Returns an error if the user already has MaxAlertsPerUser alerts.
func (s *Store) Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction Direction) (string, error) {
	return s.AddWithReferencePrice(email, tradingsymbol, exchange, instrumentToken, targetPrice, direction, 0)
}

// AddWithReferencePrice creates a new alert with an optional reference price (for percentage alerts) and returns its ID.
// Returns an error if the user already has MaxAlertsPerUser alerts.
func (s *Store) AddWithReferencePrice(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction Direction, referencePrice float64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.alerts[email]) >= MaxAlertsPerUser {
		return "", fmt.Errorf("maximum number of alerts (%d) reached for this user", MaxAlertsPerUser)
	}

	alert := &Alert{
		ID:              uuid.New().String()[:8],
		Email:           email,
		Tradingsymbol:   tradingsymbol,
		Exchange:        exchange,
		InstrumentToken: instrumentToken,
		TargetPrice:     targetPrice,
		Direction:       direction,
		ReferencePrice:  referencePrice,
		CreatedAt:       time.Now(),
	}

	s.alerts[email] = append(s.alerts[email], alert)
	if s.db != nil {
		if err := s.db.SaveAlert(alert); err != nil {
			s.logger.Error("Failed to persist alert", "id", alert.ID, "error", err)
		}
	}
	return alert.ID, nil
}

// AddComposite creates a new composite alert — an alert that combines
// 2+ per-instrument conditions via AND/ANY logic — and returns its ID.
//
// Composite alerts live in the same `alerts` table as single-leg alerts
// (Option B from the session handoff) with alert_type='composite', a
// JSON-encoded conditions payload, and the top-level Direction/TargetPrice
// fields intentionally zero — the evaluator walks Conditions instead.
//
// Returns an error if conditions is empty or the user has reached
// MaxAlertsPerUser. Business-logic validation (min/max legs, operator
// compatibility, reference-price requirements) lives in the use case and
// is assumed to have already run — this method only guards persistence
// invariants.
func (s *Store) AddComposite(email, name string, logic CompositeLogic, conds []CompositeCondition) (string, error) {
	if len(conds) == 0 {
		return "", fmt.Errorf("composite alert requires at least one condition")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if len(s.alerts[email]) >= MaxAlertsPerUser {
		return "", fmt.Errorf("maximum number of alerts (%d) reached for this user", MaxAlertsPerUser)
	}

	// Use the first leg as the "anchor" for InstrumentToken/Tradingsymbol/
	// Direction/TargetPrice so legacy columns stay populated and GetByToken
	// still finds the alert via its primary leg. The anchor direction also
	// satisfies any legacy CHECK(direction IN (...)) constraint that
	// pre-composite DBs may still carry (SQLite cannot drop CHECK via
	// ALTER). The evaluator branches on AlertType before inspecting these
	// fields, so composites are not evaluated as single-leg alerts.
	anchor := conds[0]

	alert := &Alert{
		ID:              uuid.New().String()[:8],
		Email:           email,
		Tradingsymbol:   anchor.Tradingsymbol,
		Exchange:        anchor.Exchange,
		InstrumentToken: anchor.InstrumentToken,
		TargetPrice:     anchor.Value,
		Direction:       anchor.Operator,
		ReferencePrice:  anchor.ReferencePrice,
		CreatedAt:       time.Now(),
		AlertType:       AlertTypeComposite,
		CompositeName:   name,
		CompositeLogic:  logic,
		// Copy conditions to prevent the caller mutating shared state after
		// the fact — same deep-copy policy as List().
		Conditions: append([]CompositeCondition(nil), conds...),
	}

	s.alerts[email] = append(s.alerts[email], alert)
	if s.db != nil {
		if err := s.db.SaveAlert(alert); err != nil {
			s.logger.Error("Failed to persist composite alert", "id", alert.ID, "error", err)
		}
	}
	return alert.ID, nil
}

// Delete removes an alert by ID for the given email.
func (s *Store) Delete(email, alertID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	alerts, ok := s.alerts[email]
	if !ok {
		return fmt.Errorf("no alerts found for %s", email)
	}

	for i, a := range alerts {
		if a.ID == alertID {
			s.alerts[email] = append(alerts[:i], alerts[i+1:]...)
			if s.db != nil {
				if err := s.db.DeleteAlert(email, alertID); err != nil {
					s.logger.Error("Failed to delete alert from DB", "id", alertID, "error", err)
				}
			}
			return nil
		}
	}

	return fmt.Errorf("alert %s not found", alertID)
}

// DeleteByEmail removes all alerts for the given email.
// Used during account deletion to clean up all user data.
func (s *Store) DeleteByEmail(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	delete(s.alerts, email)
	delete(s.telegram, email)

	if s.db != nil {
		if err := s.db.DeleteAlertsByEmail(email); err != nil {
			s.logger.Error("Failed to delete alerts from DB", "email", email, "error", err)
		}
		if err := s.db.DeleteTelegramChatID(email); err != nil {
			s.logger.Error("Failed to delete telegram chat ID from DB", "email", email, "error", err)
		}
	}
}

// List returns all alerts for the given email.
// Returns deep copies to prevent callers from mutating shared state.
func (s *Store) List(email string) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alerts := s.alerts[email]
	result := make([]*Alert, len(alerts))
	for i, a := range alerts {
		cp := *a
		result[i] = &cp
	}
	return result
}

// GetByToken returns all active (non-triggered) alerts matching the instrument token.
// Returns copies to prevent callers from mutating shared state.
func (s *Store) GetByToken(instrumentToken uint32) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []*Alert
	for _, alerts := range s.alerts {
		for _, a := range alerts {
			if a.InstrumentToken == instrumentToken && !a.Triggered {
				cp := *a
				matches = append(matches, &cp)
			}
		}
	}
	return matches
}

// MarkTriggered marks an alert as triggered with the current price.
// Returns true if the alert was newly triggered, false if already triggered or not found.
func (s *Store) MarkTriggered(alertID string, currentPrice float64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, alerts := range s.alerts {
		for _, a := range alerts {
			if a.ID == alertID {
				if !a.MarkTriggered(currentPrice) {
					return false
				}
				if s.db != nil {
					if err := s.db.UpdateTriggered(alertID, currentPrice, a.TriggeredAt); err != nil {
						s.logger.Error("Failed to persist triggered alert", "id", alertID, "error", err)
					}
				}
				return true
			}
		}
	}
	return false
}

// MarkNotificationSent records when a Telegram notification was sent for an alert.
func (s *Store) MarkNotificationSent(alertID string, sentAt time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, alerts := range s.alerts {
		for _, a := range alerts {
			if a.ID == alertID {
				a.NotificationSentAt = sentAt
				break
			}
		}
	}
	if s.db != nil {
		if err := s.db.UpdateAlertNotification(alertID, sentAt); err != nil {
			s.logger.Error("Failed to persist notification sent time", "id", alertID, "error", err)
		}
	}
}

// SetTelegramChatID sets the Telegram chat ID for a user.
func (s *Store) SetTelegramChatID(email string, chatID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telegram[email] = chatID
	if s.db != nil {
		if err := s.db.SaveTelegramChatID(email, chatID); err != nil {
			s.logger.Error("Failed to persist telegram chat ID", "email", email, "error", err)
		}
	}
}

// GetTelegramChatID returns the Telegram chat ID for a user.
func (s *Store) GetTelegramChatID(email string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chatID, ok := s.telegram[email]
	return chatID, ok
}

// GetEmailByChatID performs a reverse lookup: given a Telegram chat ID,
// returns the associated email. Returns ("", false) if not found.
func (s *Store) GetEmailByChatID(chatID int64) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for email, id := range s.telegram {
		if id == chatID {
			return email, true
		}
	}
	return "", false
}

// ListAll returns a deep copy of all alerts grouped by email.
// Returns deep copies to prevent callers from mutating shared state.
func (s *Store) ListAll() map[string][]*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string][]*Alert, len(s.alerts))
	for email, alerts := range s.alerts {
		cp := make([]*Alert, len(alerts))
		for i, a := range alerts {
			aCopy := *a
			cp[i] = &aCopy
		}
		out[email] = cp
	}
	return out
}

// ListAllTelegram returns a copy of all Telegram chat ID mappings.
func (s *Store) ListAllTelegram() map[string]int64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make(map[string]int64, len(s.telegram))
	for email, chatID := range s.telegram {
		out[email] = chatID
	}
	return out
}

// ActiveCount returns the number of active (non-triggered) alerts for a user.
func (s *Store) ActiveCount(email string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()

	count := 0
	for _, a := range s.alerts[email] {
		if !a.Triggered {
			count++
		}
	}
	return count
}
