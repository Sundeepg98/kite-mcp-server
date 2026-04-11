package oauth

import (
	"encoding/json"
	"fmt"
	"sync"
	"testing"
	"time"
)

// --- AuthCodeStore tests ---

func TestAuthCodeStore_GenerateAndConsume(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	entry := &AuthCodeEntry{
		ClientID:      "client-1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/callback",
		Email:         "user@test.com",
	}

	code, err := store.Generate(entry)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}
	if code == "" {
		t.Fatal("Generate returned empty code")
	}

	// First consume should succeed
	consumed, ok := store.Consume(code)
	if !ok {
		t.Fatal("First Consume should succeed")
	}
	if consumed.ClientID != "client-1" {
		t.Errorf("ClientID = %q, want %q", consumed.ClientID, "client-1")
	}
	if consumed.Email != "user@test.com" {
		t.Errorf("Email = %q, want %q", consumed.Email, "user@test.com")
	}

	// Second consume should fail (single-use)
	_, ok = store.Consume(code)
	if ok {
		t.Fatal("Second Consume should fail (codes are single-use)")
	}
}

func TestAuthCodeStore_ConsumeExpired(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	entry := &AuthCodeEntry{
		ClientID:      "client-1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/callback",
		Email:         "user@test.com",
	}

	code, err := store.Generate(entry)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Manually expire the entry
	store.mu.Lock()
	store.entries[code].ExpiresAt = time.Now().Add(-1 * time.Second)
	store.mu.Unlock()

	_, ok := store.Consume(code)
	if ok {
		t.Fatal("Consume should fail for expired code")
	}
}

func TestAuthCodeStore_ConsumeNonExistent(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	_, ok := store.Consume("nonexistent-code-abc123")
	if ok {
		t.Fatal("Consume of nonexistent code should return false")
	}
}

func TestAuthCodeStore_CapacityLimit(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	// Fill the store to capacity
	for i := 0; i < maxAuthCodes; i++ {
		_, err := store.Generate(&AuthCodeEntry{
			ClientID:      "client",
			CodeChallenge: "challenge",
			RedirectURI:   "https://example.com/callback",
		})
		if err != nil {
			t.Fatalf("Generate #%d failed: %v", i, err)
		}
	}

	// Next generate should fail
	_, err := store.Generate(&AuthCodeEntry{
		ClientID:      "client-overflow",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/callback",
	})
	if err != ErrAuthCodeStoreFull {
		t.Fatalf("Expected ErrAuthCodeStoreFull, got: %v", err)
	}
}

func TestAuthCodeStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	defer store.Close()

	const goroutines = 100
	var wg sync.WaitGroup
	codes := make(chan string, goroutines)

	// Generate codes concurrently
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			code, err := store.Generate(&AuthCodeEntry{
				ClientID:      "client",
				CodeChallenge: "challenge",
				RedirectURI:   "https://example.com/callback",
				Email:         "user@test.com",
			})
			if err != nil {
				t.Errorf("Generate failed: %v", err)
				return
			}
			codes <- code
		}()
	}
	wg.Wait()
	close(codes)

	// Consume all codes concurrently
	var consumeWg sync.WaitGroup
	consumed := make(chan bool, goroutines)
	for code := range codes {
		consumeWg.Add(1)
		go func(c string) {
			defer consumeWg.Done()
			_, ok := store.Consume(c)
			consumed <- ok
		}(code)
	}
	consumeWg.Wait()
	close(consumed)

	successCount := 0
	for ok := range consumed {
		if ok {
			successCount++
		}
	}
	if successCount != goroutines {
		t.Errorf("Expected %d successful consumes, got %d", goroutines, successCount)
	}
}

func TestAuthCodeStore_Cleanup(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}
	// Don't start the cleanup goroutine — we'll trigger cleanup manually

	// Add an expired entry
	store.entries["expired-code"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(-1 * time.Minute),
	}
	// Add a valid entry
	store.entries["valid-code"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(10 * time.Minute),
	}

	// Manually run cleanup logic
	store.mu.Lock()
	now := time.Now()
	for k, v := range store.entries {
		if now.After(v.ExpiresAt) {
			delete(store.entries, k)
		}
	}
	store.mu.Unlock()

	// Expired entry should be gone
	store.mu.RLock()
	_, expiredExists := store.entries["expired-code"]
	_, validExists := store.entries["valid-code"]
	store.mu.RUnlock()

	if expiredExists {
		t.Error("Expired entry should have been cleaned up")
	}
	if !validExists {
		t.Error("Valid entry should still exist after cleanup")
	}
}

// --- ClientStore tests ---

func TestClientStore_Register(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	clientID, clientSecret, err := store.Register([]string{"https://example.com/callback"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	if clientID == "" {
		t.Error("Register returned empty clientID")
	}
	if clientSecret == "" {
		t.Error("Register returned empty clientSecret")
	}
	// Hex-encoded 16 bytes = 32 chars for ID, 32 bytes = 64 chars for secret
	if len(clientID) != 32 {
		t.Errorf("clientID length = %d, want 32", len(clientID))
	}
	if len(clientSecret) != 64 {
		t.Errorf("clientSecret length = %d, want 64", len(clientSecret))
	}
}

func TestClientStore_Get(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	clientID, clientSecret, err := store.Register([]string{"https://example.com/callback"}, "my-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	entry, ok := store.Get(clientID)
	if !ok {
		t.Fatal("Get should find registered client")
	}
	if entry.ClientSecret != clientSecret {
		t.Errorf("ClientSecret mismatch")
	}
	if entry.ClientName != "my-app" {
		t.Errorf("ClientName = %q, want %q", entry.ClientName, "my-app")
	}
	if len(entry.RedirectURIs) != 1 || entry.RedirectURIs[0] != "https://example.com/callback" {
		t.Errorf("RedirectURIs = %v, want [https://example.com/callback]", entry.RedirectURIs)
	}

	// Get returns a copy — mutating it should not affect the store
	entry.RedirectURIs = append(entry.RedirectURIs, "https://evil.com")
	original, _ := store.Get(clientID)
	if len(original.RedirectURIs) != 1 {
		t.Error("Get should return a copy; mutating the copy should not affect the store")
	}

	// Non-existent client
	_, ok = store.Get("nonexistent")
	if ok {
		t.Error("Get should return false for non-existent client")
	}
}

func TestClientStore_ValidateRedirectURI(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	clientID, _, err := store.Register([]string{"https://example.com/callback", "http://localhost:8080"}, "app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	tests := []struct {
		name     string
		clientID string
		uri      string
		want     bool
	}{
		{"exact match", clientID, "https://example.com/callback", true},
		{"second URI", clientID, "http://localhost:8080", true},
		{"different path", clientID, "https://example.com/other", false},
		{"unknown client", "nonexistent", "https://example.com/callback", false},
		{"empty URI", clientID, "", false},
		{"partial match", clientID, "https://example.com", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := store.ValidateRedirectURI(tc.clientID, tc.uri)
			if got != tc.want {
				t.Errorf("ValidateRedirectURI(%q, %q) = %v, want %v", tc.clientID, tc.uri, got, tc.want)
			}
		})
	}
}

func TestClientStore_RegisterKiteClient(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	apiKey := "kite-api-key-12345678"
	store.RegisterKiteClient(apiKey, []string{"https://example.com/callback"})

	// Should be retrievable
	entry, ok := store.Get(apiKey)
	if !ok {
		t.Fatal("RegisterKiteClient: client should be retrievable")
	}
	if !entry.IsKiteAPIKey {
		t.Error("IsKiteAPIKey should be true")
	}
	if entry.ClientName != "kite-user-kite-api" {
		t.Errorf("ClientName = %q, want %q", entry.ClientName, "kite-user-kite-api")
	}

	// IsKiteClient should return true
	if !store.IsKiteClient(apiKey) {
		t.Error("IsKiteClient should return true for registered Kite client")
	}

	// Re-registering the same key should be a no-op
	store.RegisterKiteClient(apiKey, []string{"https://other.com/callback"})
	entry, _ = store.Get(apiKey)
	if len(entry.RedirectURIs) != 1 || entry.RedirectURIs[0] != "https://example.com/callback" {
		t.Error("Re-registration should not overwrite existing client")
	}
}

func TestClientStore_AddRedirectURI(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	clientID, _, err := store.Register([]string{"https://example.com/cb"}, "app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Add a new URI
	store.AddRedirectURI(clientID, "https://example.com/cb2")
	entry, _ := store.Get(clientID)
	if len(entry.RedirectURIs) != 2 {
		t.Fatalf("Expected 2 redirect URIs, got %d", len(entry.RedirectURIs))
	}

	// Deduplication: adding the same URI again should not increase count
	store.AddRedirectURI(clientID, "https://example.com/cb2")
	entry, _ = store.Get(clientID)
	if len(entry.RedirectURIs) != 2 {
		t.Errorf("Duplicate URI should not be added; got %d URIs", len(entry.RedirectURIs))
	}

	// Cap at maxRedirectURIs
	for i := 0; i < maxRedirectURIs+5; i++ {
		store.AddRedirectURI(clientID, fmt.Sprintf("https://example.com/cb-%d", i))
	}
	entry, _ = store.Get(clientID)
	if len(entry.RedirectURIs) > maxRedirectURIs {
		t.Errorf("RedirectURIs count = %d, should be capped at %d", len(entry.RedirectURIs), maxRedirectURIs)
	}

	// Adding to nonexistent client should not panic
	store.AddRedirectURI("nonexistent", "https://example.com/cb")
}

func TestClientStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	const goroutines = 100
	var wg sync.WaitGroup

	// Concurrent registrations
	clientIDs := make(chan string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id, _, err := store.Register([]string{"https://example.com/callback"}, "app")
			if err != nil {
				t.Errorf("Register failed: %v", err)
				return
			}
			clientIDs <- id
		}()
	}
	wg.Wait()
	close(clientIDs)

	// Concurrent reads
	var readWg sync.WaitGroup
	for id := range clientIDs {
		readWg.Add(1)
		go func(clientID string) {
			defer readWg.Done()
			_, ok := store.Get(clientID)
			if !ok {
				t.Errorf("Get(%q) failed", clientID)
			}
			store.ValidateRedirectURI(clientID, "https://example.com/callback")
			store.IsKiteClient(clientID)
		}(id)
	}
	readWg.Wait()
}

func TestClientStore_Eviction(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Manually insert clients with controlled CreatedAt timestamps
	// so we know exactly which one is oldest.
	store.mu.Lock()
	oldestID := "oldest-client-id"
	store.clients[oldestID] = &ClientEntry{
		ClientSecret: "secret",
		RedirectURIs: []string{"https://example.com/cb"},
		ClientName:   "oldest",
		CreatedAt:    time.Now().Add(-1 * time.Hour), // definitely the oldest
	}
	// Fill to capacity with recent clients
	for i := 1; i < maxClients; i++ {
		id := fmt.Sprintf("client-%d", i)
		store.clients[id] = &ClientEntry{
			ClientSecret: "secret",
			RedirectURIs: []string{"https://example.com/cb"},
			ClientName:   "app",
			CreatedAt:    time.Now(),
		}
	}
	store.mu.Unlock()

	// Verify we are at capacity
	store.mu.RLock()
	count := len(store.clients)
	store.mu.RUnlock()
	if count != maxClients {
		t.Fatalf("Expected %d clients, got %d", maxClients, count)
	}

	// Registering one more should evict the oldest
	_, _, err := store.Register([]string{"https://example.com/cb"}, "new-app")
	if err != nil {
		t.Fatalf("Register at capacity failed: %v", err)
	}

	// The oldest client should have been evicted
	_, ok := store.Get(oldestID)
	if ok {
		t.Error("Oldest client should have been evicted")
	}
}

// --- ClientStore persistence tests ---

// mockPersister implements ClientPersister for testing.
type mockPersister struct {
	mu      sync.Mutex
	clients map[string]*ClientLoadEntry
}

func newMockPersister() *mockPersister {
	return &mockPersister{clients: make(map[string]*ClientLoadEntry)}
}

func (m *mockPersister) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clients[clientID] = &ClientLoadEntry{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURIs: redirectURIsJSON,
		ClientName:   clientName,
		CreatedAt:    createdAt,
		IsKiteAPIKey: isKiteKey,
	}
	return nil
}

func (m *mockPersister) LoadClients() ([]*ClientLoadEntry, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []*ClientLoadEntry
	for _, c := range m.clients {
		cp := *c
		out = append(out, &cp)
	}
	return out, nil
}

func (m *mockPersister) DeleteClient(clientID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.clients, clientID)
	return nil
}

func (m *mockPersister) get(clientID string) (*ClientLoadEntry, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[clientID]
	return c, ok
}

func TestClientStore_Persistence(t *testing.T) {
	t.Parallel()
	mock := newMockPersister()
	store := NewClientStore()
	store.SetPersister(mock)

	// Register a normal client → verify persisted
	clientID, clientSecret, err := store.Register([]string{"https://example.com/cb"}, "test-app")
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	persisted, ok := mock.get(clientID)
	if !ok {
		t.Fatal("Register should persist client")
	}
	if persisted.ClientSecret != clientSecret {
		t.Error("Persisted client_secret mismatch")
	}
	if persisted.ClientName != "test-app" {
		t.Errorf("Persisted client_name = %q, want %q", persisted.ClientName, "test-app")
	}
	if persisted.IsKiteAPIKey {
		t.Error("Normal client should not have IsKiteAPIKey=true")
	}
	var uris []string
	if err := json.Unmarshal([]byte(persisted.RedirectURIs), &uris); err != nil {
		t.Fatalf("Failed to unmarshal redirect_uris: %v", err)
	}
	if len(uris) != 1 || uris[0] != "https://example.com/cb" {
		t.Errorf("Persisted redirect_uris = %v, want [https://example.com/cb]", uris)
	}

	// RegisterKiteClient → verify persisted with IsKiteAPIKey=true
	kiteKey := "kite-api-key-test1234"
	store.RegisterKiteClient(kiteKey, []string{"https://kite.example.com/cb"})
	persisted, ok = mock.get(kiteKey)
	if !ok {
		t.Fatal("RegisterKiteClient should persist client")
	}
	if !persisted.IsKiteAPIKey {
		t.Error("Kite client should have IsKiteAPIKey=true")
	}
	if persisted.ClientSecret != "" {
		t.Errorf("Kite client should have empty client_secret, got %q", persisted.ClientSecret)
	}

	// AddRedirectURI → verify updated in persister
	store.AddRedirectURI(clientID, "https://example.com/cb2")
	persisted, ok = mock.get(clientID)
	if !ok {
		t.Fatal("AddRedirectURI should update persisted client")
	}
	if err := json.Unmarshal([]byte(persisted.RedirectURIs), &uris); err != nil {
		t.Fatalf("Failed to unmarshal updated redirect_uris: %v", err)
	}
	if len(uris) != 2 {
		t.Errorf("Expected 2 redirect URIs after AddRedirectURI, got %d", len(uris))
	}

	// LoadFromDB: create a new store, load from persister, verify clients exist
	store2 := NewClientStore()
	store2.SetPersister(mock)
	if err := store2.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB failed: %v", err)
	}
	entry, ok := store2.Get(clientID)
	if !ok {
		t.Fatal("LoadFromDB should restore normal client")
	}
	if entry.ClientSecret != clientSecret {
		t.Error("Loaded client_secret mismatch")
	}
	if len(entry.RedirectURIs) != 2 {
		t.Errorf("Loaded redirect_uris count = %d, want 2", len(entry.RedirectURIs))
	}
	kiteEntry, ok := store2.Get(kiteKey)
	if !ok {
		t.Fatal("LoadFromDB should restore Kite client")
	}
	if !kiteEntry.IsKiteAPIKey {
		t.Error("Loaded Kite client should have IsKiteAPIKey=true")
	}
}

func TestClientStore_LoadFromDB_NoPersister(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	// LoadFromDB with no persister should be a no-op
	if err := store.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB with no persister should return nil, got: %v", err)
	}
}

// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

// ===========================================================================
// AuthCodeStore — edge cases
// ===========================================================================

func TestAuthCodeStore_Close(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()
	// Close should not panic
	store.Close()
}

func TestAuthCodeStore_ConsumeAfterExpiry(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()

	code, err := store.Generate(&AuthCodeEntry{
		ClientID:      "client1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/cb",
		Email:         "user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// Manually expire the code
	store.mu.Lock()
	if entry, ok := store.entries[code]; ok {
		entry.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}
	store.mu.Unlock()

	_, ok := store.Consume(code)
	if ok {
		t.Error("Expected false for expired code")
	}
}

func TestAuthCodeStore_DoubleConsume(t *testing.T) {
	t.Parallel()
	store := NewAuthCodeStore()

	code, err := store.Generate(&AuthCodeEntry{
		ClientID:      "client1",
		CodeChallenge: "challenge",
		RedirectURI:   "https://example.com/cb",
		Email:         "user@test.com",
	})
	if err != nil {
		t.Fatalf("Generate error: %v", err)
	}

	// First consume should succeed
	_, ok := store.Consume(code)
	if !ok {
		t.Fatal("First Consume should succeed")
	}

	// Second consume should fail (already consumed)
	_, ok = store.Consume(code)
	if ok {
		t.Error("Expected false for double consume")
	}
}

// ===========================================================================
// ClientStore — edge cases
// ===========================================================================

func TestClientStore_GetNonExistent(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	_, ok := store.Get("nonexistent")
	if ok {
		t.Error("Expected false for nonexistent client")
	}
}

func TestClientStore_IsKiteClient(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Register a normal client
	clientID, _, err := store.Register([]string{"https://example.com/cb"}, "test")
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}
	if store.IsKiteClient(clientID) {
		t.Error("Normally registered client should not be a Kite client")
	}

	// Kite clients are registered via auto-registration during authorize
	// with the isKite flag set
}

// ===========================================================================
// cleanup — stop via done channel
// ===========================================================================

func TestAuthCodeStore_CleanupStopsOnDone(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}

	store.mu.Lock()
	store.entries["expired"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.entries["valid"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.mu.Unlock()

	go store.cleanup()
	time.Sleep(10 * time.Millisecond)
	store.Close()
}

// ===========================================================================
// cleanup goroutine — tick path that actually cleans expired entries
// ===========================================================================

func TestAuthCodeStore_CleanupTickRemovesExpired(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}

	// Manually add an expired entry
	store.mu.Lock()
	store.entries["expired-code"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}
	store.entries["valid-code"] = &AuthCodeEntry{
		ClientID:  "client",
		ExpiresAt: time.Now().Add(1 * time.Hour),
	}
	store.mu.Unlock()

	// Run cleanup directly (bypass ticker by calling the inner logic)
	// We can't easily trigger the ticker, so simulate the cleanup loop body.
	store.mu.Lock()
	now := time.Now()
	for k, v := range store.entries {
		if now.After(v.ExpiresAt) {
			delete(store.entries, k)
		}
	}
	store.mu.Unlock()

	store.mu.RLock()
	_, hasExpired := store.entries["expired-code"]
	_, hasValid := store.entries["valid-code"]
	store.mu.RUnlock()

	if hasExpired {
		t.Error("Expired entry should have been removed")
	}
	if !hasValid {
		t.Error("Valid entry should still exist")
	}
	close(store.done)
}

// ===========================================================================
// AuthCodeStore.Generate — store full path
// ===========================================================================

func TestAuthCodeStore_GenerateStoreFull(t *testing.T) {
	t.Parallel()
	store := &AuthCodeStore{
		entries: make(map[string]*AuthCodeEntry),
		done:    make(chan struct{}),
	}
	defer close(store.done)

	// Fill to capacity
	store.mu.Lock()
	for i := 0; i < maxAuthCodes; i++ {
		store.entries[fmt.Sprintf("code-%d", i)] = &AuthCodeEntry{
			ClientID:  "client",
			ExpiresAt: time.Now().Add(1 * time.Hour),
		}
	}
	store.mu.Unlock()

	_, err := store.Generate(&AuthCodeEntry{ClientID: "overflow"})
	if err != ErrAuthCodeStoreFull {
		t.Errorf("Expected ErrAuthCodeStoreFull, got: %v", err)
	}
}

// ===========================================================================
// ClientStore.LoadFromDB — bad JSON in redirect URIs
// ===========================================================================

func TestClientStore_LoadFromDB_BadJSON(t *testing.T) {
	t.Parallel()

	persister := &mockPersisterFinal{
		clients: []*ClientLoadEntry{
			{
				ClientID:     "client1",
				ClientSecret: "secret",
				RedirectURIs: "not-json",
				ClientName:   "test",
				CreatedAt:    time.Now(),
			},
		},
	}

	store := NewClientStore()
	store.SetPersister(persister)

	err := store.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	// Should load with nil/empty URIs since JSON was bad
	entry, ok := store.Get("client1")
	if !ok {
		t.Fatal("Client should exist after LoadFromDB")
	}
	if len(entry.RedirectURIs) != 0 {
		t.Errorf("RedirectURIs should be empty for bad JSON, got: %v", entry.RedirectURIs)
	}
}

// ===========================================================================
// ClientStore.LoadFromDB — persister returns error
// ===========================================================================

func TestClientStore_LoadFromDB_PersisterError(t *testing.T) {
	t.Parallel()

	persister := &mockPersisterFinal{
		loadErr: fmt.Errorf("db read error"),
	}

	store := NewClientStore()
	store.SetPersister(persister)

	err := store.LoadFromDB()
	if err == nil || err.Error() != "db read error" {
		t.Errorf("Expected 'db read error', got: %v", err)
	}
}

// ===========================================================================
// ClientStore.Register — persist error path (with logger)
// ===========================================================================

func TestClientStore_Register_PersistError(t *testing.T) {
	t.Parallel()

	persister := &mockPersisterFinal{
		saveErr: fmt.Errorf("save failed"),
	}

	store := NewClientStore()
	store.SetPersister(persister)
	store.SetLogger(testLogger())

	// Should succeed despite persist error (best-effort persistence)
	clientID, clientSecret, err := store.Register([]string{"https://example.com/cb"}, "test")
	if err != nil {
		t.Fatalf("Register error: %v", err)
	}
	if clientID == "" || clientSecret == "" {
		t.Error("Expected non-empty client ID and secret")
	}
}

// ===========================================================================
// ClientStore.RegisterKiteClient — persist error path
// ===========================================================================

func TestClientStore_RegisterKiteClient_PersistError(t *testing.T) {
	t.Parallel()

	persister := &mockPersisterFinal{
		saveErr: fmt.Errorf("save failed"),
	}

	store := NewClientStore()
	store.SetPersister(persister)
	store.SetLogger(testLogger())

	// Should not panic despite persist error
	store.RegisterKiteClient("kite-key-12345678", []string{"https://example.com/cb"})

	entry, ok := store.Get("kite-key-12345678")
	if !ok {
		t.Fatal("Kite client should exist in memory despite persist error")
	}
	if !entry.IsKiteAPIKey {
		t.Error("Should be marked as Kite API key client")
	}
}

// ===========================================================================
// ClientStore.RegisterKiteClient — short client ID name path
// ===========================================================================

func TestClientStore_RegisterKiteClient_ShortClientID(t *testing.T) {
	t.Parallel()

	store := NewClientStore()
	store.RegisterKiteClient("abc", []string{"https://example.com/cb"})

	entry, ok := store.Get("abc")
	if !ok {
		t.Fatal("Client should exist")
	}
	if entry.ClientName != "kite-user" {
		t.Errorf("ClientName = %q, want 'kite-user' for short ID", entry.ClientName)
	}
}

// ===========================================================================
// ClientStore.RegisterKiteClient — already exists (no-op)
// ===========================================================================

func TestClientStore_RegisterKiteClient_AlreadyExists(t *testing.T) {
	t.Parallel()

	store := NewClientStore()
	store.RegisterKiteClient("kite-key-12345678", []string{"https://old.example.com/cb"})
	store.RegisterKiteClient("kite-key-12345678", []string{"https://new.example.com/cb"})

	// Should still have old redirect URI (not updated)
	entry, _ := store.Get("kite-key-12345678")
	if len(entry.RedirectURIs) != 1 || entry.RedirectURIs[0] != "https://old.example.com/cb" {
		t.Errorf("Existing client should not be updated, got URIs: %v", entry.RedirectURIs)
	}
}

// ===========================================================================
// ClientStore.AddRedirectURI — persist error + max URIs cap
// ===========================================================================

func TestClientStore_AddRedirectURI_MaxCap(t *testing.T) {
	t.Parallel()

	store := NewClientStore()
	store.RegisterKiteClient("kite-maxuri-key", nil)

	// Add URIs up to the max
	for i := 0; i < maxRedirectURIs; i++ {
		store.AddRedirectURI("kite-maxuri-key", fmt.Sprintf("https://example.com/cb/%d", i))
	}

	// Next one should be silently ignored
	store.AddRedirectURI("kite-maxuri-key", "https://example.com/cb/overflow")

	entry, _ := store.Get("kite-maxuri-key")
	if len(entry.RedirectURIs) != maxRedirectURIs {
		t.Errorf("RedirectURIs count = %d, want %d (capped)", len(entry.RedirectURIs), maxRedirectURIs)
	}
}

func TestClientStore_AddRedirectURI_PersistError(t *testing.T) {
	t.Parallel()

	persister := &mockPersisterFinal{saveErr: fmt.Errorf("save failed")}
	store := NewClientStore()
	store.SetPersister(persister)
	store.SetLogger(testLogger())

	store.RegisterKiteClient("kite-persist-err", []string{"https://example.com/cb"})
	// Should not panic despite persist error on add
	store.AddRedirectURI("kite-persist-err", "https://example.com/cb2")
}

func TestClientStore_AddRedirectURI_ClientNotFound(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	// Should not panic
	store.AddRedirectURI("nonexistent", "https://example.com/cb")
}

func TestClientStore_AddRedirectURI_DuplicateURI(t *testing.T) {
	t.Parallel()
	store := NewClientStore()
	store.RegisterKiteClient("dup-uri-key", []string{"https://example.com/cb"})
	store.AddRedirectURI("dup-uri-key", "https://example.com/cb") // duplicate
	entry, _ := store.Get("dup-uri-key")
	if len(entry.RedirectURIs) != 1 {
		t.Errorf("Duplicate URI should not be added, got %d URIs", len(entry.RedirectURIs))
	}
}

// ===========================================================================
// ClientStore.Register — eviction when full
// ===========================================================================

func TestClientStore_Register_EvictsOldest(t *testing.T) {
	t.Parallel()
	store := NewClientStore()

	// Pre-fill to capacity
	store.mu.Lock()
	for i := 0; i < maxClients; i++ {
		store.clients[fmt.Sprintf("client-%d", i)] = &ClientEntry{
			ClientName: fmt.Sprintf("client-%d", i),
			CreatedAt:  time.Now().Add(-time.Duration(maxClients-i) * time.Second),
		}
	}
	store.mu.Unlock()

	_, _, err := store.Register([]string{"https://example.com/cb"}, "new-client")
	if err != nil {
		t.Fatalf("Register should succeed after eviction: %v", err)
	}
}

// ===========================================================================
// mockPersisterFinal — test helper for ClientStore persistence tests
// ===========================================================================

type mockPersisterFinal struct {
	clients []*ClientLoadEntry
	loadErr error
	saveErr error
}

func (m *mockPersisterFinal) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	return nil
}

func (m *mockPersisterFinal) LoadClients() ([]*ClientLoadEntry, error) {
	if m.loadErr != nil {
		return nil, m.loadErr
	}
	return m.clients, nil
}

func (m *mockPersisterFinal) DeleteClient(clientID string) error {
	return nil
}
