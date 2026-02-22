package kc

import (
	"strings"
	"sync"
	"time"
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
type KiteTokenStore struct {
	mu        sync.RWMutex
	tokens    map[string]*KiteTokenEntry
	onChange  []TokenChangeCallback
}

// NewKiteTokenStore creates a new token store.
func NewKiteTokenStore() *KiteTokenStore {
	return &KiteTokenStore{
		tokens: make(map[string]*KiteTokenEntry),
	}
}

// Get retrieves a stored token for the given email.
func (s *KiteTokenStore) Get(email string) (*KiteTokenEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.tokens[strings.ToLower(email)]
	return entry, ok
}

// OnChange registers a callback that fires when a token is stored or updated.
func (s *KiteTokenStore) OnChange(cb TokenChangeCallback) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.onChange = append(s.onChange, cb)
}

// Set stores a token for the given email and notifies observers.
func (s *KiteTokenStore) Set(email string, entry *KiteTokenEntry) {
	s.mu.Lock()
	entry.StoredAt = time.Now()
	key := strings.ToLower(email)
	s.tokens[key] = entry
	callbacks := make([]TokenChangeCallback, len(s.onChange))
	copy(callbacks, s.onChange)
	s.mu.Unlock()

	// Notify observers outside the lock to avoid deadlocks
	for _, cb := range callbacks {
		cb(key, entry)
	}
}

// Delete removes a token for the given email.
func (s *KiteTokenStore) Delete(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.tokens, strings.ToLower(email))
}

// Count returns the number of stored tokens.
func (s *KiteTokenStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.tokens)
}
