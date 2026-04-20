package kc

import (
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// KiteCredentialEntry stores a user's Kite developer app credentials.
type KiteCredentialEntry struct {
	APIKey    string
	APISecret string
	AppID     string // AppID = API key for Kite developer apps
	StoredAt  time.Time
}

// KiteCredentialStore is a thread-safe in-memory map of email -> Kite developer credentials.
// Optionally backed by SQLite for persistence via SetDB.
type KiteCredentialStore struct {
	mu                 sync.RWMutex
	creds              map[string]*KiteCredentialEntry
	db                 *alerts.DB
	logger             *slog.Logger
	onTokenInvalidate  func(email string) // called when API key changes to invalidate cached token
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

// OnTokenInvalidate registers a callback that is invoked when a user's API key
// changes, so the stale cached Kite token (issued for the old app) can be deleted.
func (s *KiteCredentialStore) OnTokenInvalidate(fn func(email string)) {
	s.onTokenInvalidate = fn
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
			AppID:     c.AppID,
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
	stored := *entry // copy to prevent caller mutation
	stored.StoredAt = time.Now()
	key := strings.ToLower(strings.TrimSpace(email))
	apiKeyChanged := false
	if existing, ok := s.creds[key]; ok && existing.APIKey != stored.APIKey {
		apiKeyChanged = true
		if s.logger != nil {
			s.logger.Warn("Overwriting credentials with different API key",
				"email", key, "old_key", existing.APIKey[:8]+"...", "new_key", stored.APIKey[:8]+"...")
		}
	}
	stored.AppID = stored.APIKey // AppID = API key for Kite developer apps
	s.creds[key] = &stored
	// Capture values for DB persist and callback before releasing lock.
	// After unlock, &stored is reachable via the map and could be read
	// concurrently; using locals avoids any data-race concern.
	apiKey := stored.APIKey
	apiSecret := stored.APISecret
	appID := stored.AppID
	storedAt := stored.StoredAt
	invalidateFn := s.onTokenInvalidate
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveCredential(key, apiKey, apiSecret, appID, storedAt); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist credential", "email", key, "error", err)
		}
	}

	// Invalidate cached token when API key changes — the old token was issued for a different app.
	if apiKeyChanged && invalidateFn != nil {
		invalidateFn(key)
		if s.logger != nil {
			s.logger.Info("Invalidated cached token due to API key change", "email", key)
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

// maskSecret returns a log-safe hint for a stored secret. Delegates to the
// domain APISecret value object so presentation rules live in one place.
// Invalid (empty) secrets produce the "****" placeholder via the VO
// constructor's error path — matches legacy behaviour for degenerate inputs.
func maskSecret(s string) string {
	sec, err := domain.NewAPISecret(s)
	if err != nil {
		return "****"
	}
	return sec.Masked()
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

// RawCredentialEntry is an unredacted credential entry used for internal operations like backfill.
type RawCredentialEntry struct {
	Email     string
	APIKey    string
	APISecret string
}

// ListAllRaw returns all credentials unredacted. Used internally for registry backfill.
func (s *KiteCredentialStore) ListAllRaw() []RawCredentialEntry {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]RawCredentialEntry, 0, len(s.creds))
	for email, v := range s.creds {
		out = append(out, RawCredentialEntry{
			Email:     email,
			APIKey:    v.APIKey,
			APISecret: v.APISecret,
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
