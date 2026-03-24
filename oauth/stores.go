package oauth

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"log/slog"
	"sync"
	"time"
)

// AuthCodeEntry stores data associated with an issued authorization code.
type AuthCodeEntry struct {
	ClientID      string
	CodeChallenge string // S256-hashed code_challenge from the client
	RedirectURI   string
	Email         string // set at callback for normal flow (global credentials)
	RequestToken  string // set at callback for deferred exchange (per-user Kite credentials)
	ExpiresAt     time.Time
}

// maxAuthCodes is the maximum number of pending authorization codes.
// Once reached, new codes are rejected to prevent unbounded growth.
const maxAuthCodes = 10000

// AuthCodeStore is a thread-safe in-memory store for OAuth authorization codes.
type AuthCodeStore struct {
	mu        sync.RWMutex
	entries   map[string]*AuthCodeEntry
	done      chan struct{}
	closeOnce sync.Once
}

// NewAuthCodeStore creates a store and starts a background cleanup goroutine.
func NewAuthCodeStore() *AuthCodeStore {
	s := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}
	go s.cleanup()
	return s
}

// Close stops the background cleanup goroutine. Safe to call multiple times.
func (s *AuthCodeStore) Close() {
	s.closeOnce.Do(func() {
		close(s.done)
	})
}

// ErrAuthCodeStoreFull is returned when the auth code store has reached its capacity.
var ErrAuthCodeStoreFull = errors.New("auth code store is full")

// Generate creates a new random authorization code and stores the entry.
func (s *AuthCodeStore) Generate(entry *AuthCodeEntry) (string, error) {
	code, err := randomHex(32)
	if err != nil {
		return "", err
	}
	entry.ExpiresAt = time.Now().Add(10 * time.Minute)
	s.mu.Lock()
	if len(s.entries) >= maxAuthCodes {
		s.mu.Unlock()
		return "", ErrAuthCodeStoreFull
	}
	s.entries[code] = entry
	s.mu.Unlock()
	return code, nil
}

// Consume retrieves and deletes an authorization code (one-time use).
func (s *AuthCodeStore) Consume(code string) (*AuthCodeEntry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	entry, ok := s.entries[code]
	if !ok || time.Now().After(entry.ExpiresAt) {
		delete(s.entries, code)
		return nil, false
	}
	delete(s.entries, code)
	return entry, true
}

func (s *AuthCodeStore) cleanup() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-s.done:
			return
		case <-ticker.C:
			s.mu.Lock()
			now := time.Now()
			for k, v := range s.entries {
				if now.After(v.ExpiresAt) {
					delete(s.entries, k)
				}
			}
			s.mu.Unlock()
		}
	}
}

// ClientPersister provides optional persistence for OAuth clients.
type ClientPersister interface {
	SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error
	LoadClients() ([]*ClientLoadEntry, error)
	DeleteClient(clientID string) error
}

// ClientLoadEntry represents a client loaded from persistence.
type ClientLoadEntry struct {
	ClientID     string
	ClientSecret string
	RedirectURIs string // JSON-encoded []string
	ClientName   string
	CreatedAt    time.Time
	IsKiteAPIKey bool
}

// ClientEntry stores a dynamically registered client.
type ClientEntry struct {
	ClientSecret string
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
	IsKiteAPIKey bool // true if client_id is a user's Kite API key (per-user credentials)
}

// maxClients is the maximum number of dynamically registered OAuth clients.
// Once reached, the oldest client is evicted to make room.
const maxClients = 10000

// maxRedirectURIs is the maximum number of redirect URIs per client.
const maxRedirectURIs = 10

// ClientStore is a thread-safe in-memory store for dynamically registered OAuth clients.
// Optionally backed by a ClientPersister for persistence via SetPersister.
type ClientStore struct {
	mu        sync.RWMutex
	clients   map[string]*ClientEntry
	persister ClientPersister
	logger    *slog.Logger
}

// NewClientStore creates a new client store.
func NewClientStore() *ClientStore {
	return &ClientStore{clients: make(map[string]*ClientEntry)}
}

// SetPersister enables write-through persistence for OAuth clients.
func (s *ClientStore) SetPersister(p ClientPersister) {
	s.persister = p
}

// SetLogger sets the logger for persistence error reporting.
func (s *ClientStore) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// LoadFromDB populates the in-memory store from the persister.
func (s *ClientStore) LoadFromDB() error {
	if s.persister == nil {
		return nil
	}
	entries, err := s.persister.LoadClients()
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range entries {
		var uris []string
		if err := json.Unmarshal([]byte(e.RedirectURIs), &uris); err != nil {
			uris = nil
		}
		s.clients[e.ClientID] = &ClientEntry{
			ClientSecret: e.ClientSecret,
			RedirectURIs: uris,
			ClientName:   e.ClientName,
			CreatedAt:    e.CreatedAt,
			IsKiteAPIKey: e.IsKiteAPIKey,
		}
	}
	return nil
}

// evictOldest removes the oldest client by CreatedAt. Must be called with mu held.
func (s *ClientStore) evictOldest() {
	var oldestID string
	var oldestTime time.Time
	for id, c := range s.clients {
		if oldestID == "" || c.CreatedAt.Before(oldestTime) {
			oldestID = id
			oldestTime = c.CreatedAt
		}
	}
	if oldestID != "" {
		delete(s.clients, oldestID)
	}
}

// Register creates a new client with a random ID and secret.
func (s *ClientStore) Register(redirectURIs []string, clientName string) (clientID, clientSecret string, err error) {
	clientID, err = randomHex(16)
	if err != nil {
		return "", "", err
	}
	clientSecret, err = randomHex(32)
	if err != nil {
		return "", "", err
	}
	now := time.Now()
	s.mu.Lock()
	if len(s.clients) >= maxClients {
		s.evictOldest()
	}
	s.clients[clientID] = &ClientEntry{
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		ClientName:   clientName,
		CreatedAt:    now,
	}
	s.mu.Unlock()

	if s.persister != nil {
		urisJSON, _ := json.Marshal(redirectURIs)
		if err := s.persister.SaveClient(clientID, clientSecret, string(urisJSON), clientName, now, false); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist OAuth client", "client_id", clientID, "error", err)
		}
	}

	return clientID, clientSecret, nil
}

// Get retrieves a client by ID.
// Returns a copy to prevent callers from mutating shared state.
func (s *ClientStore) Get(clientID string) (*ClientEntry, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return nil, false
	}
	cp := *c
	cp.RedirectURIs = make([]string, len(c.RedirectURIs))
	copy(cp.RedirectURIs, c.RedirectURIs)
	return &cp, true
}

// ValidateRedirectURI checks if the URI is registered for the client.
func (s *ClientStore) ValidateRedirectURI(clientID, uri string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	if !ok {
		return false
	}
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

// RegisterKiteClient auto-registers a client where client_id is a Kite API key.
// No client_secret is stored — validation happens via Kite's GenerateSession at token exchange.
func (s *ClientStore) RegisterKiteClient(clientID string, redirectURIs []string) {
	now := time.Now()
	s.mu.Lock()
	if _, exists := s.clients[clientID]; exists {
		s.mu.Unlock()
		return
	}
	if len(s.clients) >= maxClients {
		s.evictOldest()
	}
	name := "kite-user"
	if len(clientID) >= 8 {
		name = "kite-user-" + clientID[:8]
	}
	s.clients[clientID] = &ClientEntry{
		RedirectURIs: redirectURIs,
		ClientName:   name,
		CreatedAt:    now,
		IsKiteAPIKey: true,
	}
	s.mu.Unlock()

	if s.persister != nil {
		urisJSON, _ := json.Marshal(redirectURIs)
		if err := s.persister.SaveClient(clientID, "", string(urisJSON), name, now, true); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist Kite OAuth client", "client_id", clientID, "error", err)
		}
	}
}

// IsKiteClient returns true if the client_id was registered as a Kite API key client.
func (s *ClientStore) IsKiteClient(clientID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	c, ok := s.clients[clientID]
	return ok && c.IsKiteAPIKey
}

// AddRedirectURI adds a redirect URI to an existing client if not already present.
// Capped at maxRedirectURIs per client to prevent abuse.
func (s *ClientStore) AddRedirectURI(clientID, uri string) {
	s.mu.Lock()
	c, ok := s.clients[clientID]
	if !ok {
		s.mu.Unlock()
		return
	}
	if len(c.RedirectURIs) >= maxRedirectURIs {
		s.mu.Unlock()
		return
	}
	for _, u := range c.RedirectURIs {
		if u == uri {
			s.mu.Unlock()
			return
		}
	}
	c.RedirectURIs = append(c.RedirectURIs, uri)
	// Capture values for persistence before releasing lock.
	uris := make([]string, len(c.RedirectURIs))
	copy(uris, c.RedirectURIs)
	secret := c.ClientSecret
	name := c.ClientName
	createdAt := c.CreatedAt
	isKiteKey := c.IsKiteAPIKey
	s.mu.Unlock()

	if s.persister != nil {
		urisJSON, _ := json.Marshal(uris)
		if err := s.persister.SaveClient(clientID, secret, string(urisJSON), name, createdAt, isKiteKey); err != nil && s.logger != nil {
			s.logger.Error("Failed to persist redirect URI update", "client_id", clientID, "error", err)
		}
	}
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
