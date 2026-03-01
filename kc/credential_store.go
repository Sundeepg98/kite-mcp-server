package kc

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// KiteCredentialEntry stores a user's Kite developer app credentials.
type KiteCredentialEntry struct {
	APIKey    string
	APISecret string
	StoredAt  time.Time
}

// KiteCredentialStore is a thread-safe in-memory map of email -> Kite developer credentials.
// Optionally backed by SQLite for persistence via SetDB.
type KiteCredentialStore struct {
	mu     sync.RWMutex
	creds  map[string]*KiteCredentialEntry
	db     *alerts.DB
	logger *slog.Logger
}

// NewKiteCredentialStore creates a new credential store.
func NewKiteCredentialStore() *KiteCredentialStore {
	return &KiteCredentialStore{
		creds: make(map[string]*KiteCredentialEntry),
	}
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *KiteCredentialStore) SetDB(db *alerts.DB) {
	s.db = db
}

// SetLogger sets the logger for DB error reporting.
func (s *KiteCredentialStore) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// LoadFromDB populates the in-memory store from the database.
func (s *KiteCredentialStore) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	entries, err := s.db.LoadCredentials()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range entries {
		s.creds[strings.ToLower(c.Email)] = &KiteCredentialEntry{
			APIKey:    c.APIKey,
			APISecret: c.APISecret,
			StoredAt:  c.StoredAt,
		}
	}
	return nil
}

// Get retrieves stored credentials for the given email.
// Returns a copy to prevent callers from mutating shared state.
func (s *KiteCredentialStore) Get(email string) (*KiteCredentialEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry, ok := s.creds[strings.ToLower(email)]
	if !ok {
		return nil, false
	}
	cp := *entry
	return &cp, true
}

// Set stores credentials for the given email.
func (s *KiteCredentialStore) Set(email string, entry *KiteCredentialEntry) {
	s.mu.Lock()
	entry.StoredAt = time.Now()
	key := strings.ToLower(email)
	s.creds[key] = entry
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveCredential(key, entry.APIKey, entry.APISecret, entry.StoredAt); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist credential", "email", key, "error", err)
		}
	}
}

// Delete removes credentials for the given email.
func (s *KiteCredentialStore) Delete(email string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(email)
	delete(s.creds, key)
	if s.db != nil {
		if err := s.db.DeleteCredential(key); err != nil && s.logger != nil {
			s.logger.Error("Failed to delete persisted credential", "email", key, "error", err)
		}
	}
}

// KiteCredentialSummary is a redacted view of a credential entry (API secret masked).
type KiteCredentialSummary struct {
	Email         string    `json:"email"`
	APIKey        string    `json:"api_key"`
	APISecretHint string    `json:"api_secret_hint"`
	StoredAt      time.Time `json:"stored_at"`
}

// maskSecret returns a redacted version of a secret: first 4 + "****" + last 3 chars.
func maskSecret(s string) string {
	if len(s) <= 7 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-3:]
}

// ListAll returns a redacted summary of all stored credentials.
func (s *KiteCredentialStore) ListAll() []KiteCredentialSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]KiteCredentialSummary, 0, len(s.creds))
	for email, v := range s.creds {
		out = append(out, KiteCredentialSummary{
			Email:         email,
			APIKey:        v.APIKey,
			APISecretHint: maskSecret(v.APISecret),
			StoredAt:      v.StoredAt,
		})
	}
	return out
}

// GetSecretByAPIKey finds the API secret for a given API key by scanning all stored credentials.
// Used when the client_id (= API key) is known but the email is not yet resolved.
func (s *KiteCredentialStore) GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, entry := range s.creds {
		if entry.APIKey == apiKey {
			return entry.APISecret, true
		}
	}
	return "", false
}

// Count returns the number of stored credential entries.
func (s *KiteCredentialStore) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.creds)
}
