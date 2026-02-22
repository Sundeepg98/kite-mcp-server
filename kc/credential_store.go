package kc

import (
	"strings"
	"sync"
	"time"
)

// KiteCredentialEntry stores Kite API credentials for a user.
type KiteCredentialEntry struct {
	APIKey    string
	APISecret string
	StoredAt  time.Time
}

// KiteCredentialStore is a thread-safe in-memory map of email -> Kite API credentials.
// Used to support per-user Kite developer apps (Path B multi-user).
type KiteCredentialStore struct {
	mu          sync.RWMutex
	credentials map[string]*KiteCredentialEntry
}

// NewKiteCredentialStore creates a new credential store.
func NewKiteCredentialStore() *KiteCredentialStore {
	return &KiteCredentialStore{
		credentials: make(map[string]*KiteCredentialEntry),
	}
}

// Get retrieves stored credentials for the given email.
func (s *KiteCredentialStore) Get(email string) (*KiteCredentialEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.credentials[strings.ToLower(email)]
	return entry, ok
}

// Set stores credentials for the given email.
func (s *KiteCredentialStore) Set(email string, entry *KiteCredentialEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry.StoredAt = time.Now()
	s.credentials[strings.ToLower(email)] = entry
}

// Delete removes credentials for the given email.
func (s *KiteCredentialStore) Delete(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.credentials, strings.ToLower(email))
}

// KiteCredentialSummary is a redacted view of a credential entry (no APISecret exposed).
type KiteCredentialSummary struct {
	Email    string    `json:"email"`
	APIKey   string    `json:"api_key"`
	StoredAt time.Time `json:"stored_at"`
}

// ListAll returns a redacted summary of all stored credentials.
func (s *KiteCredentialStore) ListAll() []KiteCredentialSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KiteCredentialSummary, 0, len(s.credentials))
	for email, v := range s.credentials {
		out = append(out, KiteCredentialSummary{Email: email, APIKey: v.APIKey, StoredAt: v.StoredAt})
	}
	return out
}

// Count returns the number of stored credential entries.
func (s *KiteCredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.credentials)
}
