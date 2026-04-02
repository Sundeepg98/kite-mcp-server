package alerts

import (
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/gokiteconnect/v4/models"
)

// TrailingStop represents a trailing stop-loss that modifies an existing SL order
// as the price moves favorably.
type TrailingStop struct {
	ID              string    `json:"id"`
	Email           string    `json:"email"`
	Exchange        string    `json:"exchange"`
	Tradingsymbol   string    `json:"tradingsymbol"`
	InstrumentToken uint32    `json:"instrument_token"`
	OrderID         string    `json:"order_id"`      // the SL order to modify
	Variety         string    `json:"variety"`        // order variety (regular, co, etc.)
	TrailAmount     float64   `json:"trail_amount"`   // absolute trail in rupees (e.g., 20.0)
	TrailPct        float64   `json:"trail_pct"`      // OR percentage trail (e.g., 1.5 for 1.5%)
	Direction       string    `json:"direction"`      // "long" (trail up) or "short" (trail down)
	HighWaterMark   float64   `json:"high_water_mark"` // best price seen since activation
	CurrentStop     float64   `json:"current_stop"`   // current stop-loss trigger price
	Active          bool      `json:"active"`
	CreatedAt       time.Time `json:"created_at"`
	DeactivatedAt   time.Time `json:"deactivated_at,omitempty"`
	ModifyCount     int       `json:"modify_count"`   // number of times the SL order was modified
	LastModifiedAt  time.Time `json:"last_modified_at,omitempty"`
}

// KiteOrderModifier abstracts the Kite API call to modify an order.
// This enables testing without a live Kite connection.
type KiteOrderModifier interface {
	ModifyOrder(variety string, orderID string, params kiteconnect.OrderParams) (kiteconnect.OrderResponse, error)
}

// TrailingStopManager manages active trailing stops, evaluates ticks, and
// modifies SL orders via the Kite API when the trailing stop moves.
type TrailingStopManager struct {
	mu     sync.RWMutex
	stops  map[string]*TrailingStop // id -> trailing stop
	byToken map[uint32][]string    // instrument_token -> list of trailing stop IDs

	// Rate limiting: at most 1 modify per 30s per trailing stop
	lastModify map[string]time.Time // trailing stop ID -> last modify time

	db     *DB
	logger *slog.Logger

	// getModifier returns a KiteOrderModifier for the given email.
	// Injected by the app layer since the manager package doesn't know about kc.Manager sessions.
	getModifier func(email string) (KiteOrderModifier, error)
}

// NewTrailingStopManager creates a new trailing stop manager.
func NewTrailingStopManager(logger *slog.Logger) *TrailingStopManager {
	return &TrailingStopManager{
		stops:      make(map[string]*TrailingStop),
		byToken:    make(map[uint32][]string),
		lastModify: make(map[string]time.Time),
		logger:     logger,
	}
}

// SetDB enables write-through persistence.
func (m *TrailingStopManager) SetDB(db *DB) {
	m.db = db
}

// SetModifier sets the function that provides a KiteOrderModifier for a given email.
func (m *TrailingStopManager) SetModifier(fn func(email string) (KiteOrderModifier, error)) {
	m.getModifier = fn
}

// LoadFromDB loads active trailing stops from the database.
func (m *TrailingStopManager) LoadFromDB() error {
	if m.db == nil {
		return nil
	}
	stops, err := m.db.LoadTrailingStops()
	if err != nil {
		return fmt.Errorf("load trailing stops: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ts := range stops {
		m.stops[ts.ID] = ts
		m.byToken[ts.InstrumentToken] = append(m.byToken[ts.InstrumentToken], ts.ID)
	}
	m.logger.Info("Trailing stops loaded from database", "count", len(stops))
	return nil
}

// Add creates a new trailing stop and returns its ID.
func (m *TrailingStopManager) Add(ts *TrailingStop) (string, error) {
	if ts.OrderID == "" {
		return "", fmt.Errorf("order_id is required")
	}
	if ts.Direction != "long" && ts.Direction != "short" {
		return "", fmt.Errorf("direction must be 'long' or 'short'")
	}
	if ts.TrailAmount <= 0 && ts.TrailPct <= 0 {
		return "", fmt.Errorf("either trail_amount or trail_pct must be positive")
	}
	if ts.CurrentStop <= 0 {
		return "", fmt.Errorf("current_stop (initial SL trigger price) must be positive")
	}
	if ts.HighWaterMark <= 0 {
		return "", fmt.Errorf("high_water_mark (initial reference price) must be positive")
	}

	ts.ID = uuid.New().String()[:8]
	ts.Active = true
	ts.CreatedAt = time.Now()
	if ts.Variety == "" {
		ts.Variety = "regular"
	}

	m.mu.Lock()
	defer m.mu.Unlock()

	// Limit: max 20 active trailing stops per user
	count := 0
	for _, s := range m.stops {
		if s.Email == ts.Email && s.Active {
			count++
		}
	}
	if count >= 20 {
		return "", fmt.Errorf("maximum 20 active trailing stops per user")
	}

	m.stops[ts.ID] = ts
	m.byToken[ts.InstrumentToken] = append(m.byToken[ts.InstrumentToken], ts.ID)

	if m.db != nil {
		if err := m.db.SaveTrailingStop(ts); err != nil {
			m.logger.Error("Failed to persist trailing stop", "id", ts.ID, "error", err)
		}
	}

	return ts.ID, nil
}

// Cancel deactivates a trailing stop.
func (m *TrailingStopManager) Cancel(email, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	ts, ok := m.stops[id]
	if !ok {
		return fmt.Errorf("trailing stop %s not found", id)
	}
	if ts.Email != email {
		return fmt.Errorf("trailing stop %s not found", id)
	}
	if !ts.Active {
		return fmt.Errorf("trailing stop %s is already inactive", id)
	}

	ts.Active = false
	ts.DeactivatedAt = time.Now()

	if m.db != nil {
		if err := m.db.DeactivateTrailingStop(id); err != nil {
			m.logger.Error("Failed to persist trailing stop deactivation", "id", id, "error", err)
		}
	}

	return nil
}

// List returns all trailing stops for the given email.
func (m *TrailingStopManager) List(email string) []*TrailingStop {
	m.mu.RLock()
	defer m.mu.RUnlock()

	var result []*TrailingStop
	for _, ts := range m.stops {
		if ts.Email == email {
			cp := *ts
			result = append(result, &cp)
		}
	}
	return result
}

// Evaluate processes a tick and updates trailing stops for the given instrument.
// This is called from the ticker's OnTick callback.
func (m *TrailingStopManager) Evaluate(email string, tick models.Tick) {
	m.mu.RLock()
	ids := m.byToken[tick.InstrumentToken]
	if len(ids) == 0 {
		m.mu.RUnlock()
		return
	}
	// Copy IDs to avoid holding the lock during API calls
	idsCopy := make([]string, len(ids))
	copy(idsCopy, ids)
	m.mu.RUnlock()

	for _, id := range idsCopy {
		m.evaluateOne(id, email, tick.LastPrice)
	}
}

// evaluateOne checks a single trailing stop against the current price.
func (m *TrailingStopManager) evaluateOne(id, email string, lastPrice float64) {
	m.mu.Lock()
	ts, ok := m.stops[id]
	if !ok || !ts.Active || ts.Email != email {
		m.mu.Unlock()
		return
	}

	// Check rate limit: at most once per 30 seconds
	if last, exists := m.lastModify[id]; exists && time.Since(last) < 30*time.Second {
		m.mu.Unlock()
		return
	}

	var newHWM float64
	var newStop float64
	modified := false

	switch ts.Direction {
	case "long":
		// Trailing up: track highest price, stop follows below
		if lastPrice > ts.HighWaterMark {
			newHWM = lastPrice
			if ts.TrailPct > 0 {
				newStop = newHWM * (1 - ts.TrailPct/100)
			} else {
				newStop = newHWM - ts.TrailAmount
			}
			// Only move stop UP (never down)
			if newStop > ts.CurrentStop {
				modified = true
			}
		}
	case "short":
		// Trailing down: track lowest price, stop follows above
		if lastPrice < ts.HighWaterMark || ts.HighWaterMark <= 0 {
			newHWM = lastPrice
			if ts.TrailPct > 0 {
				newStop = newHWM * (1 + ts.TrailPct/100)
			} else {
				newStop = newHWM + ts.TrailAmount
			}
			// Only move stop DOWN (never up)
			if newStop < ts.CurrentStop {
				modified = true
			}
		}
	}

	if !modified {
		// Still update high water mark even if stop didn't move
		if ts.Direction == "long" && lastPrice > ts.HighWaterMark {
			ts.HighWaterMark = lastPrice
		} else if ts.Direction == "short" && lastPrice < ts.HighWaterMark {
			ts.HighWaterMark = lastPrice
		}
		m.mu.Unlock()
		return
	}

	// Update state
	ts.HighWaterMark = newHWM
	oldStop := ts.CurrentStop
	ts.CurrentStop = newStop
	ts.ModifyCount++
	ts.LastModifiedAt = time.Now()
	m.lastModify[id] = time.Now()

	// Capture values for the API call (outside lock)
	orderID := ts.OrderID
	variety := ts.Variety

	m.mu.Unlock()

	// Persist updated state
	if m.db != nil {
		if err := m.db.UpdateTrailingStop(id, newHWM, newStop, ts.ModifyCount); err != nil {
			m.logger.Error("Failed to persist trailing stop update", "id", id, "error", err)
		}
	}

	// Modify the SL order via Kite API
	if m.getModifier == nil {
		m.logger.Warn("No order modifier configured for trailing stop", "id", id)
		return
	}

	modifier, err := m.getModifier(email)
	if err != nil {
		m.logger.Error("Failed to get order modifier", "id", id, "email", email, "error", err)
		return
	}

	orderParams := kiteconnect.OrderParams{
		TriggerPrice: newStop,
		OrderType:    "SL-M",
	}
	_, err = modifier.ModifyOrder(variety, orderID, orderParams)
	if err != nil {
		m.logger.Error("Failed to modify trailing SL order",
			"id", id,
			"order_id", orderID,
			"old_stop", oldStop,
			"new_stop", newStop,
			"error", err)
		return
	}

	m.logger.Info("Trailing stop modified",
		"id", id,
		"instrument", ts.Exchange+":"+ts.Tradingsymbol,
		"direction", ts.Direction,
		"hwm", newHWM,
		"old_stop", fmt.Sprintf("%.2f", oldStop),
		"new_stop", fmt.Sprintf("%.2f", newStop),
		"modify_count", ts.ModifyCount)
}
