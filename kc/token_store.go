package kc

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// KiteTokenEntry stores a Kite access token and metadata for a user.
type KiteTokenEntry struct {
	AccessToken string
	UserID      string
	UserName    string
	StoredAt    time.Time
}

// TokenChangeCallback is invoked when a token is stored or updated.
type TokenChangeCallback func(email string, entry *KiteTokenEntry)

// KiteTokenStore is a thread-safe in-memory map of email -> Kite access token.
// Used to cache tokens so users only need to login once per day.
// Optionally backed by SQLite for persistence via SetDB.
type KiteTokenStore struct {
	mu        sync.RWMutex
	tokens    map[string]*KiteTokenEntry
	onChange  []TokenChangeCallback
	db        *alerts.DB
	logger    *slog.Logger
}

// NewKiteTokenStore creates a new token store.
func NewKiteTokenStore() *KiteTokenStore {
	return &KiteTokenStore{
		tokens: make(map[string]*KiteTokenEntry),
	}
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *KiteTokenStore) SetDB(db *alerts.DB) {
	s.db = db
}

// SetLogger sets the logger for DB error reporting.
func (s *KiteTokenStore) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// LoadFromDB populates the in-memory store from the database.
func (s *KiteTokenStore) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	entries, err := s.db.LoadTokens()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, t := range entries {
		s.tokens[strings.ToLower(t.Email)] = &KiteTokenEntry{
			AccessToken: t.AccessToken,
			UserID:      t.UserID,
			UserName:    t.UserName,
			StoredAt:    t.StoredAt,
		}
	}
	return nil
}

// Get retrieves a stored token for the given email.
// Returns a copy to prevent callers from mutating shared state.
func (s *KiteTokenStore) Get(email string) (*KiteTokenEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.tokens[strings.ToLower(email)]
	if !ok {
		return nil, false
	}
	cp := *entry
	return &cp, true
}

// OnChange registers a callback that fires when a token is stored or updated.
func (s *KiteTokenStore) OnChange(cb TokenChangeCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, cb)
}

// Set stores a token for the given email and notifies observers.
// The entry is copied before storing to prevent the caller from mutating shared state.
func (s *KiteTokenStore) Set(email string, entry *KiteTokenEntry) {
	stored := *entry // copy before storing
	stored.StoredAt = time.Now()
	s.mu.Lock()
	key := strings.ToLower(email)
	s.tokens[key] = &stored
	callbacks := make([]TokenChangeCallback, len(s.onChange))
	copy(callbacks, s.onChange)
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveToken(key, stored.AccessToken, stored.UserID, stored.UserName, stored.StoredAt); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist token", "email", key, "error", err)
		}
	}

	// Notify observers outside the lock to avoid deadlocks.
	// Each callback receives its own copy to prevent cross-callback mutation.
	for _, cb := range callbacks {
		cp := stored
		cb(key, &cp)
	}
}

// Delete removes a token for the given email.
func (s *KiteTokenStore) Delete(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(email)
	delete(s.tokens, key)
	if s.db != nil {
		if err := s.db.DeleteToken(key); err != nil && s.logger != nil {
			s.logger.Error("Failed to delete persisted token", "email", key, "error", err)
		}
	}
}

// KiteTokenSummary is a redacted view of a token entry (no AccessToken exposed).
type KiteTokenSummary struct {
	Email    string    `json:"email"`
	UserID   string    `json:"user_id"`
	UserName string    `json:"user_name"`
	StoredAt time.Time `json:"stored_at"`
}

// ListAll returns a redacted summary of all cached tokens.
func (s *KiteTokenStore) ListAll() []KiteTokenSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KiteTokenSummary, 0, len(s.tokens))
	for email, v := range s.tokens {
		out = append(out, KiteTokenSummary{Email: email, UserID: v.UserID, UserName: v.UserName, StoredAt: v.StoredAt})
	}
	return out
}

// Count returns the number of stored tokens.
func (s *KiteTokenStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}
