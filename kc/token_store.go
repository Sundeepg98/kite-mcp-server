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

// KiteTokenStore is a thread-safe in-memory map of email -> Kite access token.
// Used to cache tokens so users only need to login once per day.
type KiteTokenStore struct {
	mu     sync.RWMutex
	tokens map[string]*KiteTokenEntry
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

// Set stores a token for the given email.
func (s *KiteTokenStore) Set(email string, entry *KiteTokenEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.StoredAt = time.Now()
	s.tokens[strings.ToLower(email)] = entry
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
