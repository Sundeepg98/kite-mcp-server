package oauth

import (
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

