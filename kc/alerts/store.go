package alerts

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Direction specifies the alert trigger direction.
type Direction string

const (
	DirectionAbove Direction = "above"
	DirectionBelow Direction = "below"

	// MaxAlertsPerUser is the maximum number of alerts a single user can have.
	MaxAlertsPerUser = 100
)

// Alert represents a price alert for a specific instrument.
type Alert struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Tradingsymbol   string    `json:"tradingsymbol"`
	Exchange        string    `json:"exchange"`
	InstrumentToken uint32    `json:"instrument_token"`
	TargetPrice     float64   `json:"target_price"`
	Direction       Direction `json:"direction"`
	Triggered       bool      `json:"triggered"`
	CreatedAt       time.Time `json:"created_at"`
	TriggeredAt     time.Time `json:"triggered_at,omitempty"`
	TriggeredPrice  float64   `json:"triggered_price,omitempty"`
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
				if a.Triggered {
					return false
				}
				a.Triggered = true
				a.TriggeredAt = time.Now()
				a.TriggeredPrice = currentPrice
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
