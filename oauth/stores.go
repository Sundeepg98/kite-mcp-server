package oauth

import (
	"crypto/rand"
	"encoding/hex"
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

// AuthCodeStore is a thread-safe in-memory store for OAuth authorization codes.
type AuthCodeStore struct {
	mu      sync.RWMutex
	entries map[string]*AuthCodeEntry
}

// NewAuthCodeStore creates a store and starts a background cleanup goroutine.
func NewAuthCodeStore() *AuthCodeStore {
	s := &AuthCodeStore{entries: make(map[string]*AuthCodeEntry)}
	go s.cleanup()
	return s
}

// Generate creates a new random authorization code and stores the entry.
func (s *AuthCodeStore) Generate(entry *AuthCodeEntry) (string, error) {
	code, err := randomHex(32)
	if err != nil {
		return "", err
	}
	entry.ExpiresAt = time.Now().Add(10 * time.Minute)
	s.mu.Lock()
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
	for range ticker.C {
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

// ClientEntry stores a dynamically registered client.
type ClientEntry struct {
	ClientSecret string
	RedirectURIs []string
	ClientName   string
	CreatedAt    time.Time
	IsKiteAPIKey bool // true if client_id is a user's Kite API key (per-user credentials)
}

// ClientStore is a thread-safe in-memory store for dynamically registered OAuth clients.
type ClientStore struct {
	mu      sync.RWMutex
	clients map[string]*ClientEntry
}

// NewClientStore creates a new client store.
func NewClientStore() *ClientStore {
	return &ClientStore{clients: make(map[string]*ClientEntry)}
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
	s.mu.Lock()
	s.clients[clientID] = &ClientEntry{
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIs,
		ClientName:   clientName,
		CreatedAt:    time.Now(),
	}
	s.mu.Unlock()
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
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.clients[clientID]; exists {
		return
	}
	name := "kite-user"
	if len(clientID) >= 8 {
		name = "kite-user-" + clientID[:8]
	}
	s.clients[clientID] = &ClientEntry{
		RedirectURIs: redirectURIs,
		ClientName:   name,
		CreatedAt:    time.Now(),
		IsKiteAPIKey: true,
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
func (s *ClientStore) AddRedirectURI(clientID, uri string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.clients[clientID]
	if !ok {
		return
	}
	for _, u := range c.RedirectURIs {
		if u == uri {
			return
		}
	}
	c.RedirectURIs = append(c.RedirectURIs, uri)
}

func randomHex(n int) (string, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
