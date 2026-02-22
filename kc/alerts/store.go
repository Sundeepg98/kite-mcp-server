package alerts

import (
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
)

// Direction specifies the alert trigger direction.
type Direction string

const (
	DirectionAbove Direction = "above"
	DirectionBelow Direction = "below"
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
type Store struct {
	mu       sync.RWMutex
	alerts   map[string][]*Alert  // email -> alerts
	telegram map[string]int64     // email -> chat ID
	onNotify NotifyCallback
}

// NewStore creates a new alert store.
func NewStore(onNotify NotifyCallback) *Store {
	return &Store{
		alerts:   make(map[string][]*Alert),
		telegram: make(map[string]int64),
		onNotify: onNotify,
	}
}

// Add creates a new alert and returns its ID.
func (s *Store) Add(email, tradingsymbol, exchange string, instrumentToken uint32, targetPrice float64, direction Direction) string {
	s.mu.Lock()
	defer s.mu.Unlock()

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
	return alert.ID
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
			return nil
		}
	}

	return fmt.Errorf("alert %s not found", alertID)
}

// List returns all alerts for the given email.
func (s *Store) List(email string) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	alerts := s.alerts[email]
	result := make([]*Alert, len(alerts))
	copy(result, alerts)
	return result
}

// GetByToken returns all active (non-triggered) alerts matching the instrument token.
func (s *Store) GetByToken(instrumentToken uint32) []*Alert {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var matches []*Alert
	for _, alerts := range s.alerts {
		for _, a := range alerts {
			if a.InstrumentToken == instrumentToken && !a.Triggered {
				matches = append(matches, a)
			}
		}
	}
	return matches
}

// MarkTriggered marks an alert as triggered with the current price.
func (s *Store) MarkTriggered(alertID string, currentPrice float64) {
	s.mu.Lock()
	defer s.mu.Unlock()

	for _, alerts := range s.alerts {
		for _, a := range alerts {
			if a.ID == alertID {
				a.Triggered = true
				a.TriggeredAt = time.Now()
				a.TriggeredPrice = currentPrice
				return
			}
		}
	}
}

// SetTelegramChatID sets the Telegram chat ID for a user.
func (s *Store) SetTelegramChatID(email string, chatID int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.telegram[email] = chatID
}

// GetTelegramChatID returns the Telegram chat ID for a user.
func (s *Store) GetTelegramChatID(email string) (int64, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	chatID, ok := s.telegram[email]
	return chatID, ok
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
