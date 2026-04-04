package registry

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// AppRegistration represents a pre-registered Kite app in the key registry.
// Admin registers these ahead of time; users are matched by email at login.
type AppRegistration struct {
	ID           string    `json:"id"`
	APIKey       string    `json:"api_key"`        // Kite API key (= client_id for Kite apps)
	APISecret    string    `json:"api_secret"`      // Kite API secret (encrypted at rest)
	AssignedTo   string    `json:"assigned_to"`     // expected email (empty = unassigned / open)
	Label        string    `json:"label"`           // e.g. "Personal Trading", "Mom's Account"
	Status       string    `json:"status"`          // active, disabled, invalid, replaced
	RegisteredBy string    `json:"registered_by"`   // admin email who registered it
	Source       string    `json:"source"`          // "admin", "self-provisioned", "migrated"
	LastUsedAt   *time.Time `json:"last_used_at"`   // last successful token exchange with this key
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// AppRegistrationSummary is a redacted view of a registration (API secret masked).
type AppRegistrationSummary struct {
	ID            string     `json:"id"`
	APIKey        string     `json:"api_key"`
	APISecretHint string     `json:"api_secret_hint"`
	AssignedTo    string     `json:"assigned_to"`
	Label         string     `json:"label"`
	Status        string     `json:"status"`
	RegisteredBy  string     `json:"registered_by"`
	Source        string     `json:"source"`
	LastUsedAt    *time.Time `json:"last_used_at"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
}

const (
	StatusActive   = "active"
	StatusDisabled = "disabled"
	StatusInvalid  = "invalid"   // Kite API rejected this key
	StatusReplaced = "replaced"  // User re-authenticated with a different key

	SourceAdmin           = "admin"
	SourceSelfProvisioned = "self-provisioned"
	SourceMigrated        = "migrated"
)

// Store is a thread-safe in-memory key registry, optionally backed by SQLite.
type Store struct {
	mu      sync.RWMutex
	entries map[string]*AppRegistration // keyed by ID
	db      *alerts.DB
	logger  *slog.Logger
}

// New creates a new registry store.
func New() *Store {
	return &Store{
		entries: make(map[string]*AppRegistration),
	}
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *Store) SetDB(db *alerts.DB) {
	s.db = db
}

// SetLogger sets the logger for DB error reporting.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	dbEntries, err := s.db.LoadRegistryEntries()
	if err != nil {
		return fmt.Errorf("load registry entries: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range dbEntries {
		s.entries[e.ID] = &AppRegistration{
			ID:           e.ID,
			APIKey:       e.APIKey,
			APISecret:    e.APISecret,
			AssignedTo:   e.AssignedTo,
			Label:        e.Label,
			Status:       e.Status,
			RegisteredBy: e.RegisteredBy,
			Source:       e.Source,
			LastUsedAt:   e.LastUsedAt,
			CreatedAt:    e.CreatedAt,
			UpdatedAt:    e.UpdatedAt,
		}
	}
	return nil
}

// Register adds a new app registration to the registry.
func (s *Store) Register(reg *AppRegistration) error {
	if reg.ID == "" {
		return fmt.Errorf("id is required")
	}
	if reg.APIKey == "" || reg.APISecret == "" {
		return fmt.Errorf("api_key and api_secret are required")
	}

	now := time.Now()
	entry := *reg // copy
	entry.AssignedTo = strings.ToLower(strings.TrimSpace(entry.AssignedTo))
	if entry.Status == "" {
		entry.Status = StatusActive
	}
	if entry.Source == "" {
		entry.Source = SourceAdmin
	}
	entry.CreatedAt = now
	entry.UpdatedAt = now

	s.mu.Lock()
	if _, exists := s.entries[entry.ID]; exists {
		s.mu.Unlock()
		return fmt.Errorf("registration with ID %q already exists", entry.ID)
	}
	s.entries[entry.ID] = &entry
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveRegistryEntry(toDBEntry(&entry)); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist registry entry", "id", entry.ID, "error", err)
		}
	}
	return nil
}

// Get retrieves a registration by ID.
func (s *Store) Get(id string) (*AppRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, false
	}
	cp := *e
	return &cp, true
}

// GetByAPIKey finds a registration by its API key.
func (s *Store) GetByAPIKey(apiKey string) (*AppRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.APIKey == apiKey && e.Status == StatusActive {
			cp := *e
			return &cp, true
		}
	}
	return nil, false
}

// GetByEmail finds the most recently updated active app registration assigned to this email.
// If no assigned entry is found, returns nil.
func (s *Store) GetByEmail(email string) (*AppRegistration, bool) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return nil, false
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	var best *AppRegistration
	for _, e := range s.entries {
		if e.Status != StatusActive {
			continue
		}
		if e.AssignedTo != email {
			continue
		}
		if best == nil || e.UpdatedAt.After(best.UpdatedAt) {
			best = e
		}
	}
	if best == nil {
		return nil, false
	}
	cp := *best
	return &cp, true
}

// List returns a redacted summary of all registered apps.
func (s *Store) List() []AppRegistrationSummary {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]AppRegistrationSummary, 0, len(s.entries))
	for _, e := range s.entries {
		out = append(out, AppRegistrationSummary{
			ID:            e.ID,
			APIKey:        maskKey(e.APIKey),
			APISecretHint: maskSecret(e.APISecret),
			AssignedTo:    e.AssignedTo,
			Label:         e.Label,
			Status:        e.Status,
			RegisteredBy:  e.RegisteredBy,
			Source:        e.Source,
			LastUsedAt:    e.LastUsedAt,
			CreatedAt:     e.CreatedAt,
			UpdatedAt:     e.UpdatedAt,
		})
	}
	return out
}

// Update modifies a registration's mutable fields (assigned_to, label, status).
func (s *Store) Update(id string, assignedTo, label, status string) error {
	s.mu.Lock()
	e, ok := s.entries[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registration %q not found", id)
	}
	if assignedTo != "" {
		e.AssignedTo = strings.ToLower(strings.TrimSpace(assignedTo))
	}
	if label != "" {
		e.Label = label
	}
	if status != "" {
		if status != StatusActive && status != StatusDisabled && status != StatusInvalid && status != StatusReplaced {
			s.mu.Unlock()
			return fmt.Errorf("invalid status %q (must be 'active', 'disabled', 'invalid', or 'replaced')", status)
		}
		e.Status = status
	}
	e.UpdatedAt = time.Now()
	// Copy for DB persistence
	entry := *e
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveRegistryEntry(toDBEntry(&entry)); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist registry update", "id", id, "error", err)
		}
	}
	return nil
}

// UpdateLastUsedAt records the most recent successful token exchange for this API key.
func (s *Store) UpdateLastUsedAt(apiKey string) {
	s.mu.Lock()
	var found *AppRegistration
	for _, e := range s.entries {
		if e.APIKey == apiKey && e.Status == StatusActive {
			found = e
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		return
	}
	now := time.Now()
	found.LastUsedAt = &now
	found.UpdatedAt = now
	entry := *found
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveRegistryEntry(toDBEntry(&entry)); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist registry last_used_at", "id", entry.ID, "error", err)
		}
	}
}

// MarkStatus sets the status of a registration found by API key.
// Unlike Update(), this does not require an ID and accepts any valid status.
func (s *Store) MarkStatus(apiKey, status string) {
	s.mu.Lock()
	var found *AppRegistration
	for _, e := range s.entries {
		if e.APIKey == apiKey {
			found = e
			break
		}
	}
	if found == nil {
		s.mu.Unlock()
		return
	}
	found.Status = status
	found.UpdatedAt = time.Now()
	entry := *found
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.SaveRegistryEntry(toDBEntry(&entry)); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist registry status change", "id", entry.ID, "status", status, "error", err)
		}
	}
}

// GetByAPIKeyAnyStatus finds a registration by its API key regardless of status.
func (s *Store) GetByAPIKeyAnyStatus(apiKey string) (*AppRegistration, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, e := range s.entries {
		if e.APIKey == apiKey {
			cp := *e
			return &cp, true
		}
	}
	return nil, false
}

// Delete removes a registration by ID.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	_, ok := s.entries[id]
	if !ok {
		s.mu.Unlock()
		return fmt.Errorf("registration %q not found", id)
	}
	delete(s.entries, id)
	s.mu.Unlock()

	if s.db != nil {
		if err := s.db.DeleteRegistryEntry(id); err != nil && s.logger != nil {
			s.logger.Error("Failed to delete persisted registry entry", "id", id, "error", err)
		}
	}
	return nil
}

// Count returns the number of registry entries.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries)
}

// HasEntries returns true if the registry has any entries.
func (s *Store) HasEntries() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.entries) > 0
}

// maskSecret returns a redacted version of a secret: first 4 + "****" + last 3 chars.
func maskSecret(s string) string {
	if len(s) <= 7 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-3:]
}

// maskKey returns a redacted version of an API key: first 4 + "****" + last 4 chars.
func maskKey(s string) string {
	if len(s) <= 8 {
		return "****"
	}
	return s[:4] + "****" + s[len(s)-4:]
}

// toDBEntry converts an AppRegistration to the DB entry type for persistence.
func toDBEntry(r *AppRegistration) *alerts.RegistryDBEntry {
	return &alerts.RegistryDBEntry{
		ID:           r.ID,
		APIKey:       r.APIKey,
		APISecret:    r.APISecret,
		AssignedTo:   r.AssignedTo,
		Label:        r.Label,
		Status:       r.Status,
		RegisteredBy: r.RegisteredBy,
		Source:       r.Source,
		LastUsedAt:   r.LastUsedAt,
		CreatedAt:    r.CreatedAt,
		UpdatedAt:    r.UpdatedAt,
	}
}
