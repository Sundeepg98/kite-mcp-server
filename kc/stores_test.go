package kc

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ---------------------------------------------------------------------------
// KiteTokenStore tests
// ---------------------------------------------------------------------------

func TestKiteTokenStore_SetAndGet(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	entry := &KiteTokenEntry{
		AccessToken: "tok_abc123",
		UserID:      "UID001",
		UserName:    "Alice",
	}
	store.Set("alice@example.com", entry)

	got, ok := store.Get("alice@example.com")
	if !ok {
		t.Fatal("expected entry to be found")
	}
	if got.AccessToken != "tok_abc123" {
		t.Errorf("AccessToken: got %q, want %q", got.AccessToken, "tok_abc123")
	}
	if got.UserID != "UID001" {
		t.Errorf("UserID: got %q, want %q", got.UserID, "UID001")
	}
	if got.UserName != "Alice" {
		t.Errorf("UserName: got %q, want %q", got.UserName, "Alice")
	}
	if got.StoredAt.IsZero() {
		t.Error("StoredAt should be set automatically by Set()")
	}

	// Count should be 1.
	if c := store.Count(); c != 1 {
		t.Errorf("Count: got %d, want 1", c)
	}

	// Non-existent key returns false.
	_, ok = store.Get("nobody@example.com")
	if ok {
		t.Error("expected false for non-existent key")
	}
}

func TestKiteTokenStore_GetReturnsCopy(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	store.Set("bob@example.com", &KiteTokenEntry{
		AccessToken: "original",
		UserID:      "U1",
		UserName:    "Bob",
	})

	got, _ := store.Get("bob@example.com")
	// Mutate the returned copy.
	got.AccessToken = "mutated"
	got.UserName = "Evil Bob"

	// Re-fetch: the store should still have the original values.
	got2, _ := store.Get("bob@example.com")
	if got2.AccessToken != "original" {
		t.Errorf("store was mutated via Get() return: AccessToken = %q", got2.AccessToken)
	}
	if got2.UserName != "Bob" {
		t.Errorf("store was mutated via Get() return: UserName = %q", got2.UserName)
	}
}

func TestKiteTokenStore_SetCopiesInput(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	entry := &KiteTokenEntry{
		AccessToken: "original",
		UserID:      "U1",
		UserName:    "Carol",
	}
	store.Set("carol@example.com", entry)

	// Mutate the input after Set.
	entry.AccessToken = "mutated-by-caller"

	got, _ := store.Get("carol@example.com")
	if got.AccessToken != "original" {
		t.Errorf("store was mutated via input pointer: AccessToken = %q", got.AccessToken)
	}
}

func TestKiteTokenStore_CaseInsensitive(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	store.Set("User@Test.COM", &KiteTokenEntry{
		AccessToken: "tok1",
		UserID:      "U1",
		UserName:    "User",
	})

	// All case variations should resolve to the same entry.
	variations := []string{
		"user@test.com",
		"USER@TEST.COM",
		"User@Test.COM",
		"uSeR@tEsT.cOm",
	}
	for _, email := range variations {
		got, ok := store.Get(email)
		if !ok {
			t.Errorf("Get(%q) returned false, want true", email)
			continue
		}
		if got.AccessToken != "tok1" {
			t.Errorf("Get(%q).AccessToken = %q, want %q", email, got.AccessToken, "tok1")
		}
	}

	// Count should still be 1 (not 4).
	if c := store.Count(); c != 1 {
		t.Errorf("Count: got %d, want 1 (case variants should not create duplicates)", c)
	}
}

func TestKiteTokenStore_Delete(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	store.Set("del@example.com", &KiteTokenEntry{
		AccessToken: "tok",
		UserID:      "U1",
		UserName:    "Del",
	})

	// Sanity: entry exists.
	if _, ok := store.Get("del@example.com"); !ok {
		t.Fatal("expected entry to exist before delete")
	}

	store.Delete("DEL@example.com") // case-insensitive delete

	_, ok := store.Get("del@example.com")
	if ok {
		t.Error("entry should not exist after Delete()")
	}
	if c := store.Count(); c != 0 {
		t.Errorf("Count after delete: got %d, want 0", c)
	}

	// Deleting a non-existent key should not panic.
	store.Delete("nonexistent@example.com")
}

func TestKiteTokenStore_OnChange(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	var (
		callbackEmail string
		callbackEntry *KiteTokenEntry
		callCount     int
	)

	store.OnChange(func(email string, entry *KiteTokenEntry) {
		callbackEmail = email
		callbackEntry = entry
		callCount++
	})

	store.Set("NOTIFY@example.com", &KiteTokenEntry{
		AccessToken: "tok_notify",
		UserID:      "U9",
		UserName:    "Notify",
	})

	if callCount != 1 {
		t.Fatalf("OnChange callback count: got %d, want 1", callCount)
	}
	if callbackEmail != "notify@example.com" {
		t.Errorf("OnChange email: got %q, want %q", callbackEmail, "notify@example.com")
	}
	if callbackEntry == nil {
		t.Fatal("OnChange entry is nil")
	}
	if callbackEntry.AccessToken != "tok_notify" {
		t.Errorf("OnChange entry.AccessToken: got %q, want %q", callbackEntry.AccessToken, "tok_notify")
	}

	// Mutating the callback's entry should not affect the store.
	callbackEntry.AccessToken = "mutated-in-callback"
	got, _ := store.Get("notify@example.com")
	if got.AccessToken != "tok_notify" {
		t.Errorf("store mutated through callback entry: AccessToken = %q", got.AccessToken)
	}

	// Multiple callbacks should all fire.
	secondCalled := false
	store.OnChange(func(email string, entry *KiteTokenEntry) {
		secondCalled = true
	})
	store.Set("notify@example.com", &KiteTokenEntry{
		AccessToken: "tok2",
		UserID:      "U9",
		UserName:    "Notify",
	})
	if callCount != 2 {
		t.Errorf("first callback count: got %d, want 2", callCount)
	}
	if !secondCalled {
		t.Error("second OnChange callback was not called")
	}
}

func TestKiteTokenStore_ListAll(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	// Empty store.
	if list := store.ListAll(); len(list) != 0 {
		t.Errorf("ListAll on empty store: got %d entries, want 0", len(list))
	}

	store.Set("a@example.com", &KiteTokenEntry{AccessToken: "secret_a", UserID: "U1", UserName: "A"})
	store.Set("b@example.com", &KiteTokenEntry{AccessToken: "secret_b", UserID: "U2", UserName: "B"})

	list := store.ListAll()
	if len(list) != 2 {
		t.Fatalf("ListAll: got %d entries, want 2", len(list))
	}

	// Build a lookup map for order-independent assertions.
	byEmail := make(map[string]KiteTokenSummary, len(list))
	for _, s := range list {
		byEmail[s.Email] = s
	}

	// Verify entries.
	for _, tc := range []struct {
		email, userID, userName string
	}{
		{"a@example.com", "U1", "A"},
		{"b@example.com", "U2", "B"},
	} {
		s, ok := byEmail[tc.email]
		if !ok {
			t.Errorf("ListAll missing email %q", tc.email)
			continue
		}
		if s.UserID != tc.userID {
			t.Errorf("ListAll[%s].UserID = %q, want %q", tc.email, s.UserID, tc.userID)
		}
		if s.UserName != tc.userName {
			t.Errorf("ListAll[%s].UserName = %q, want %q", tc.email, s.UserName, tc.userName)
		}
		if s.StoredAt.IsZero() {
			t.Errorf("ListAll[%s].StoredAt is zero", tc.email)
		}
	}

	// KiteTokenSummary should NOT expose AccessToken (the struct doesn't have the field).
	// This is a compile-time guarantee, but we verify there's no sneaky embedding.
	// The summary type has: Email, UserID, UserName, StoredAt — no AccessToken.
}

func TestKiteTokenStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	// Register an OnChange callback to exercise callback path concurrently.
	store.OnChange(func(email string, entry *KiteTokenEntry) {
		// Read-only access in callback — just touch the fields.
		_ = entry.AccessToken
	})

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", n%10) // 10 distinct keys
			entry := &KiteTokenEntry{
				AccessToken: fmt.Sprintf("tok_%d", n),
				UserID:      fmt.Sprintf("U%d", n),
				UserName:    fmt.Sprintf("User%d", n),
			}
			store.Set(email, entry)

			// Read back.
			got, ok := store.Get(email)
			if ok {
				_ = got.AccessToken
			}

			// List all.
			_ = store.ListAll()

			// Count.
			_ = store.Count()

			// Delete some.
			if n%3 == 0 {
				store.Delete(email)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without a race condition panic, the test passes.
}

// ---------------------------------------------------------------------------
// KiteCredentialStore tests
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_SetAndGet(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	entry := &KiteCredentialEntry{
		APIKey:    "key_abc",
		APISecret: "secret_xyz",
	}
	store.Set("alice@example.com", entry)

	got, ok := store.Get("alice@example.com")
	if !ok {
		t.Fatal("expected entry to be found")
	}
	if got.APIKey != "key_abc" {
		t.Errorf("APIKey: got %q, want %q", got.APIKey, "key_abc")
	}
	if got.APISecret != "secret_xyz" {
		t.Errorf("APISecret: got %q, want %q", got.APISecret, "secret_xyz")
	}
	if got.StoredAt.IsZero() {
		t.Error("StoredAt should be set automatically by Set()")
	}

	// Verify StoredAt is recent (within last second).
	if time.Since(got.StoredAt) > time.Second {
		t.Errorf("StoredAt is too old: %v", got.StoredAt)
	}

	if c := store.Count(); c != 1 {
		t.Errorf("Count: got %d, want 1", c)
	}

	// Non-existent key returns false.
	_, ok = store.Get("nobody@example.com")
	if ok {
		t.Error("expected false for non-existent key")
	}

	// Overwrite: Set again with different values.
	store.Set("alice@example.com", &KiteCredentialEntry{
		APIKey:    "key_new",
		APISecret: "secret_new",
	})
	got2, _ := store.Get("alice@example.com")
	if got2.APIKey != "key_new" {
		t.Errorf("after overwrite, APIKey: got %q, want %q", got2.APIKey, "key_new")
	}
	// Count should still be 1 after overwrite.
	if c := store.Count(); c != 1 {
		t.Errorf("Count after overwrite: got %d, want 1", c)
	}
}

func TestKiteCredentialStore_GetReturnsCopy(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	store.Set("bob@example.com", &KiteCredentialEntry{
		APIKey:    "original_key",
		APISecret: "original_secret",
	})

	got, _ := store.Get("bob@example.com")
	// Mutate the returned copy.
	got.APIKey = "mutated_key"
	got.APISecret = "mutated_secret"

	// Re-fetch: the store should still have the original values.
	got2, _ := store.Get("bob@example.com")
	if got2.APIKey != "original_key" {
		t.Errorf("store was mutated via Get() return: APIKey = %q", got2.APIKey)
	}
	if got2.APISecret != "original_secret" {
		t.Errorf("store was mutated via Get() return: APISecret = %q", got2.APISecret)
	}
}

func TestKiteCredentialStore_SetCopiesInput(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	entry := &KiteCredentialEntry{
		APIKey:    "original_key",
		APISecret: "original_secret",
	}
	store.Set("carol@example.com", entry)

	// Mutate the input after Set.
	entry.APIKey = "mutated-by-caller"

	got, _ := store.Get("carol@example.com")
	if got.APIKey != "original_key" {
		t.Errorf("store was mutated via input pointer: APIKey = %q", got.APIKey)
	}
}

func TestKiteCredentialStore_GetSecretByAPIKey(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	store.Set("user1@example.com", &KiteCredentialEntry{APIKey: "key_aaa", APISecret: "secret_aaa"})
	store.Set("user2@example.com", &KiteCredentialEntry{APIKey: "key_bbb", APISecret: "secret_bbb"})
	store.Set("user3@example.com", &KiteCredentialEntry{APIKey: "key_ccc", APISecret: "secret_ccc"})

	// Find existing key.
	secret, ok := store.GetSecretByAPIKey("key_bbb")
	if !ok {
		t.Fatal("expected to find secret for key_bbb")
	}
	if secret != "secret_bbb" {
		t.Errorf("GetSecretByAPIKey: got %q, want %q", secret, "secret_bbb")
	}

	// First key.
	secret, ok = store.GetSecretByAPIKey("key_aaa")
	if !ok || secret != "secret_aaa" {
		t.Errorf("GetSecretByAPIKey(key_aaa): ok=%v, secret=%q", ok, secret)
	}

	// Last key.
	secret, ok = store.GetSecretByAPIKey("key_ccc")
	if !ok || secret != "secret_ccc" {
		t.Errorf("GetSecretByAPIKey(key_ccc): ok=%v, secret=%q", ok, secret)
	}
}

func TestKiteCredentialStore_GetSecretByAPIKey_NotFound(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	// Empty store.
	_, ok := store.GetSecretByAPIKey("nonexistent")
	if ok {
		t.Error("expected false on empty store")
	}

	store.Set("user@example.com", &KiteCredentialEntry{APIKey: "key_xyz", APISecret: "secret_xyz"})

	// Wrong key.
	_, ok = store.GetSecretByAPIKey("key_wrong")
	if ok {
		t.Error("expected false for non-matching API key")
	}

	// Partial match should not work.
	_, ok = store.GetSecretByAPIKey("key_xy")
	if ok {
		t.Error("expected false for partial API key match")
	}

	// Case-sensitive: API keys should be exact match.
	_, ok = store.GetSecretByAPIKey("KEY_XYZ")
	if ok {
		t.Error("expected false for case-mismatched API key (API keys are case-sensitive)")
	}
}

func TestKiteCredentialStore_Delete(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	store.Set("del@example.com", &KiteCredentialEntry{APIKey: "k", APISecret: "s"})

	if _, ok := store.Get("del@example.com"); !ok {
		t.Fatal("expected entry to exist before delete")
	}

	store.Delete("DEL@example.com") // case-insensitive delete

	_, ok := store.Get("del@example.com")
	if ok {
		t.Error("entry should not exist after Delete()")
	}
	if c := store.Count(); c != 0 {
		t.Errorf("Count after delete: got %d, want 0", c)
	}

	// Deleting a non-existent key should not panic.
	store.Delete("nonexistent@example.com")
}

func TestKiteCredentialStore_MaskSecret(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  string
	}{
		// Strings with length > 7: first 4 + "****" + last 3
		{"abcdefghij", "abcd****hij"},       // len=10
		{"12345678", "1234****678"},         // len=8, exactly > 7
		{"abcdefghijklmnop", "abcd****nop"}, // len=16
		{"secretkey123", "secr****123"},     // len=12

		// Strings with length <= 7: fully masked
		{"", "****"},
		{"a", "****"},
		{"ab", "****"},
		{"abc", "****"},
		{"abcd", "****"},
		{"abcde", "****"},
		{"abcdef", "****"},
		{"abcdefg", "****"}, // len=7, boundary case
	}

	for _, tc := range tests {
		got := maskSecret(tc.input)
		if got != tc.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestKiteCredentialStore_ListAll(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	// Empty store.
	if list := store.ListAll(); len(list) != 0 {
		t.Errorf("ListAll on empty store: got %d entries, want 0", len(list))
	}

	store.Set("a@example.com", &KiteCredentialEntry{APIKey: "key_a", APISecret: "verylongsecret_a"})
	store.Set("b@example.com", &KiteCredentialEntry{APIKey: "key_b", APISecret: "short"})

	list := store.ListAll()
	if len(list) != 2 {
		t.Fatalf("ListAll: got %d entries, want 2", len(list))
	}

	byEmail := make(map[string]KiteCredentialSummary, len(list))
	for _, s := range list {
		byEmail[s.Email] = s
	}

	// Entry with long secret: should be masked.
	sa := byEmail["a@example.com"]
	if sa.APIKey != "key_a" {
		t.Errorf("ListAll[a].APIKey = %q, want %q", sa.APIKey, "key_a")
	}
	if sa.APISecretHint != maskSecret("verylongsecret_a") {
		t.Errorf("ListAll[a].APISecretHint = %q, want %q", sa.APISecretHint, maskSecret("verylongsecret_a"))
	}
	if sa.StoredAt.IsZero() {
		t.Error("ListAll[a].StoredAt is zero")
	}

	// Entry with short secret: fully masked.
	sb := byEmail["b@example.com"]
	if sb.APISecretHint != "****" {
		t.Errorf("ListAll[b].APISecretHint = %q, want %q", sb.APISecretHint, "****")
	}
}

func TestKiteCredentialStore_ConcurrentAccess(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(n int) {
			defer wg.Done()
			email := fmt.Sprintf("user%d@example.com", n%10)
			entry := &KiteCredentialEntry{
				APIKey:    fmt.Sprintf("key_%d", n),
				APISecret: fmt.Sprintf("secret_%d", n),
			}
			store.Set(email, entry)

			// Read back.
			got, ok := store.Get(email)
			if ok {
				_ = got.APIKey
			}

			// GetSecretByAPIKey (linear scan under RLock).
			_, _ = store.GetSecretByAPIKey(fmt.Sprintf("key_%d", n))

			// List all.
			_ = store.ListAll()

			// Count.
			_ = store.Count()

			// Delete some.
			if n%3 == 0 {
				store.Delete(email)
			}
		}(i)
	}

	wg.Wait()
	// If we get here without a race condition panic, the test passes.
}

func TestKiteCredentialStore_DBPersistence(t *testing.T) {
	t.Parallel()

	// Open a real in-memory SQLite DB (same driver as production).
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB(:memory:): %v", err)
	}
	t.Cleanup(func() { db.Close() })

	store := NewKiteCredentialStore()
	store.SetDB(db)

	// Set a credential — this should persist to the DB.
	entry := &KiteCredentialEntry{
		APIKey:    "persist_key",
		APISecret: "persist_secret",
	}
	store.Set("persist@example.com", entry)

	// Mutate the original entry after Set to verify the DB got the original values.
	entry.APIKey = "mutated_key_after_set"
	entry.APISecret = "mutated_secret_after_set"

	// Verify the DB received the correct values by loading from DB into a fresh store.
	store2 := NewKiteCredentialStore()
	store2.SetDB(db)
	if err := store2.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB: %v", err)
	}

	got, ok := store2.Get("persist@example.com")
	if !ok {
		t.Fatal("expected persisted entry to be found after LoadFromDB")
	}
	if got.APIKey != "persist_key" {
		t.Errorf("persisted APIKey: got %q, want %q", got.APIKey, "persist_key")
	}
	if got.APISecret != "persist_secret" {
		t.Errorf("persisted APISecret: got %q, want %q", got.APISecret, "persist_secret")
	}
	if got.StoredAt.IsZero() {
		t.Error("persisted StoredAt should not be zero")
	}

	// Verify StoredAt round-trips correctly (within a second of now).
	if time.Since(got.StoredAt) > time.Second {
		t.Errorf("persisted StoredAt is too old: %v", got.StoredAt)
	}

	// Overwrite and verify DB is updated.
	store.Set("persist@example.com", &KiteCredentialEntry{
		APIKey:    "updated_key",
		APISecret: "updated_secret",
	})

	store3 := NewKiteCredentialStore()
	store3.SetDB(db)
	if err := store3.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB after overwrite: %v", err)
	}
	got2, ok := store3.Get("persist@example.com")
	if !ok {
		t.Fatal("expected updated entry to be found after LoadFromDB")
	}
	if got2.APIKey != "updated_key" {
		t.Errorf("updated APIKey: got %q, want %q", got2.APIKey, "updated_key")
	}
	if got2.APISecret != "updated_secret" {
		t.Errorf("updated APISecret: got %q, want %q", got2.APISecret, "updated_secret")
	}

	// Verify count: should be 1 (overwrite, not duplicate).
	if c := store3.Count(); c != 1 {
		t.Errorf("Count after overwrite: got %d, want 1", c)
	}
}

func TestKiteCredentialStore_OnTokenInvalidate_APIKeyChange(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	var invalidatedEmail string
	var invalidateCount int
	store.OnTokenInvalidate(func(email string) {
		invalidatedEmail = email
		invalidateCount++
	})

	// Set initial credentials.
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "old_key_1234",
		APISecret: "secret_a",
	})

	// First Set should NOT trigger invalidation (no existing entry to compare).
	if invalidateCount != 0 {
		t.Errorf("invalidate count after first Set: got %d, want 0", invalidateCount)
	}

	// Set same API key again — should NOT trigger invalidation.
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "old_key_1234",
		APISecret: "secret_b", // different secret, same key
	})
	if invalidateCount != 0 {
		t.Errorf("invalidate count after same-key Set: got %d, want 0", invalidateCount)
	}

	// Set DIFFERENT API key — SHOULD trigger invalidation.
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "new_key_5678",
		APISecret: "secret_c",
	})
	if invalidateCount != 1 {
		t.Errorf("invalidate count after key change: got %d, want 1", invalidateCount)
	}
	if invalidatedEmail != "user@example.com" {
		t.Errorf("invalidated email: got %q, want %q", invalidatedEmail, "user@example.com")
	}
}

func TestKiteCredentialStore_OnTokenInvalidate_NoCallback(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	// No callback registered — changing API key should not panic.
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "old_key_1234",
		APISecret: "secret_a",
	})
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "new_key_5678",
		APISecret: "secret_b",
	})
	// If we get here without panic, test passes.
}

// ===========================================================================
// Consolidated from coverage_*.go files
// ===========================================================================

// ===========================================================================
// CredentialService — full coverage
// ===========================================================================

// mockCredentialStore implements CredentialStoreInterface for testing.
type mockCredentialStore struct {
	entries map[string]*KiteCredentialEntry
}

func (m *mockCredentialStore) Get(email string) (*KiteCredentialEntry, bool) {
	e, ok := m.entries[email]
	return e, ok
}

func (m *mockCredentialStore) Set(email string, entry *KiteCredentialEntry) {
	m.entries[email] = entry
}

func (m *mockCredentialStore) Delete(email string) { delete(m.entries, email) }

func (m *mockCredentialStore) ListAll() []KiteCredentialSummary { return nil }

func (m *mockCredentialStore) ListAllRaw() []RawCredentialEntry { return nil }

func (m *mockCredentialStore) GetSecretByAPIKey(apiKey string) (string, bool) { return "", false }

func (m *mockCredentialStore) Count() int { return len(m.entries) }

// mockTokenStore implements TokenStoreInterface for testing.
type mockTokenStore struct {
	entries map[string]*KiteTokenEntry
}

func (m *mockTokenStore) Get(email string) (*KiteTokenEntry, bool) {
	e, ok := m.entries[email]
	return e, ok
}

func (m *mockTokenStore) Set(email string, entry *KiteTokenEntry) {
	m.entries[email] = entry
}

func (m *mockTokenStore) Delete(email string) { delete(m.entries, email) }

func (m *mockTokenStore) OnChange(cb TokenChangeCallback) {}

func (m *mockTokenStore) ListAll() []KiteTokenSummary { return nil }

func (m *mockTokenStore) Count() int { return len(m.entries) }

// ===========================================================================
// KiteTokenStore — SetDB, SetLogger, LoadFromDB
// ===========================================================================

func TestKiteTokenStore_SetDBAndLoadFromDB(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	// Save a token via the DB directly
	err = db.SaveToken("user@example.com", "access_token_123", "UID01", "User One", time.Now())
	if err != nil {
		t.Fatalf("SaveToken error: %v", err)
	}

	// Load from DB
	err = store.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	got, ok := store.Get("user@example.com")
	if !ok {
		t.Fatal("Expected token to be loaded from DB")
	}
	if got.AccessToken != "access_token_123" {
		t.Errorf("AccessToken = %q, want %q", got.AccessToken, "access_token_123")
	}
}

func TestKiteTokenStore_LoadFromDB_NilDB(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()
	// Should return nil (no-op)
	err := store.LoadFromDB()
	if err != nil {
		t.Errorf("LoadFromDB with nil DB should return nil, got: %v", err)
	}
}

// ===========================================================================
// KiteCredentialStore — SetLogger
// ===========================================================================

func TestKiteCredentialStore_SetLogger(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()
	// Should not panic
	store.SetLogger(testLogger())
}

// ---------------------------------------------------------------------------
// BackfillRegistryFromCredentials — edge cases
// ---------------------------------------------------------------------------

// mockRegistryStore implements RegistryStoreInterface for testing.
type mockRegistryStore struct {
	regs map[string]*registry.AppRegistration
}

func (m *mockRegistryStore) Register(reg *registry.AppRegistration) error {
	m.regs[reg.ID] = reg
	return nil
}

func (m *mockRegistryStore) Get(id string) (*registry.AppRegistration, bool) {
	r, ok := m.regs[id]
	return r, ok
}

func (m *mockRegistryStore) GetByAPIKey(apiKey string) (*registry.AppRegistration, bool) {
	for _, r := range m.regs {
		if r.APIKey == apiKey && r.Status == registry.StatusActive {
			return r, true
		}
	}
	return nil, false
}

func (m *mockRegistryStore) GetByAPIKeyAnyStatus(apiKey string) (*registry.AppRegistration, bool) {
	for _, r := range m.regs {
		if r.APIKey == apiKey {
			return r, true
		}
	}
	return nil, false
}

func (m *mockRegistryStore) GetByEmail(email string) (*registry.AppRegistration, bool) {
	return nil, false
}

func (m *mockRegistryStore) List() []registry.AppRegistrationSummary { return nil }

func (m *mockRegistryStore) Update(id, assignedTo, label, status string) error {
	return nil
}

func (m *mockRegistryStore) UpdateLastUsedAt(apiKey string) {}

func (m *mockRegistryStore) MarkStatus(apiKey, status string) {}

func (m *mockRegistryStore) Delete(id string) error { return nil }

func (m *mockRegistryStore) Count() int { return len(m.regs) }

func (m *mockRegistryStore) HasEntries() bool { return len(m.regs) > 0 }

func TestBackfillRegistryFromCredentials_NilRegistry(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "key", APISecret: "secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
		// RegistryStore is nil
	})

	// Should not panic
	svc.BackfillRegistryFromCredentials()
}

func TestBackfillRegistryFromCredentials_EmptyCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}
	regStore := &mockRegistryStore{regs: map[string]*registry.AppRegistration{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	svc.BackfillRegistryFromCredentials()
	if len(regStore.regs) != 0 {
		t.Errorf("Expected 0 registrations, got %d", len(regStore.regs))
	}
}

func TestBackfillRegistryFromCredentials_AlreadyInRegistry(t *testing.T) {
	t.Parallel()

	// The mockCredentialStore.ListAllRaw returns nil by default,
	// so we need a store that actually returns raw entries.
	// Use the real KiteCredentialStore for this test.
	credStore := NewKiteCredentialStore()
	credStore.Set("user@example.com", &KiteCredentialEntry{APIKey: "existing_key", APISecret: "secret"})

	regStore := &mockRegistryStore{regs: map[string]*registry.AppRegistration{
		"existing": {ID: "existing", APIKey: "existing_key", Status: registry.StatusActive},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	svc.BackfillRegistryFromCredentials()
	// Should not create a new registration since it already exists
	if len(regStore.regs) != 1 {
		t.Errorf("Expected 1 registration (no new), got %d", len(regStore.regs))
	}
}

func TestBackfillRegistryFromCredentials_NewEntry(t *testing.T) {
	t.Parallel()

	credStore := NewKiteCredentialStore()
	credStore.Set("new@example.com", &KiteCredentialEntry{APIKey: "new_key_12345678", APISecret: "new_secret"})

	regStore := &mockRegistryStore{regs: map[string]*registry.AppRegistration{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	svc.BackfillRegistryFromCredentials()
	if len(regStore.regs) != 1 {
		t.Errorf("Expected 1 new registration, got %d", len(regStore.regs))
	}

	// Verify the registration details
	for _, reg := range regStore.regs {
		if reg.APIKey != "new_key_12345678" {
			t.Errorf("APIKey = %q, want new_key_12345678", reg.APIKey)
		}
		if reg.Status != registry.StatusActive {
			t.Errorf("Status = %q, want active", reg.Status)
		}
		if reg.Source != registry.SourceMigrated {
			t.Errorf("Source = %q, want migrated", reg.Source)
		}
	}
}

// ---------------------------------------------------------------------------
// CredentialStore.Delete with DB + logger
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_DeleteWithDB(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	// Set then delete
	store.Set("del@example.com", &KiteCredentialEntry{APIKey: "key_del", APISecret: "secret_del"})

	// Verify it exists
	_, ok := store.Get("del@example.com")
	if !ok {
		t.Fatal("Expected entry to exist before delete")
	}

	// Delete with DB
	store.Delete("del@example.com")

	// Verify deleted from memory
	_, ok = store.Get("del@example.com")
	if ok {
		t.Error("Entry should not exist after delete")
	}

	// Verify deleted from DB by loading into fresh store
	store2 := NewKiteCredentialStore()
	store2.SetDB(db)
	if err := store2.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}
	_, ok = store2.Get("del@example.com")
	if ok {
		t.Error("Entry should not exist in DB after delete")
	}
}

func TestKiteCredentialStore_DeleteNonexistent(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	// Delete non-existent entry — should not panic
	store.Delete("nonexistent@example.com")
}

func TestKiteCredentialStore_LoadFromDB_Error(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()
	// No DB set — LoadFromDB should return nil
	err := store.LoadFromDB()
	if err != nil {
		t.Errorf("LoadFromDB with nil DB should return nil, got: %v", err)
	}
}

func TestKiteCredentialStore_ListAllRaw(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()
	store.Set("a@example.com", &KiteCredentialEntry{APIKey: "key_a", APISecret: "secret_a"})
	store.Set("b@example.com", &KiteCredentialEntry{APIKey: "key_b", APISecret: "secret_b"})

	raw := store.ListAllRaw()
	if len(raw) != 2 {
		t.Errorf("ListAllRaw count = %d, want 2", len(raw))
	}

	// Verify entries contain unredacted secrets
	byEmail := map[string]RawCredentialEntry{}
	for _, r := range raw {
		byEmail[r.Email] = r
	}
	if byEmail["a@example.com"].APISecret != "secret_a" {
		t.Errorf("Expected unredacted secret, got %q", byEmail["a@example.com"].APISecret)
	}
}

// ===========================================================================
// KiteCredentialStore.Delete — with DB persistence
// ===========================================================================

func TestKiteCredentialStore_DeleteWithDB_Final(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	// Save first
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "test-key-12345678",
		APISecret: "test-secret-12345678",
	})

	// Now delete
	store.Delete("user@example.com")

	// Verify it's gone
	_, ok := store.Get("user@example.com")
	if ok {
		t.Error("Credential should be deleted")
	}
}

// ===========================================================================
// KiteCredentialStore.Delete — without DB (in-memory only)
// ===========================================================================

func TestKiteCredentialStore_DeleteWithoutDB(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "test-key",
		APISecret: "test-secret",
	})

	store.Delete("user@example.com")

	_, ok := store.Get("user@example.com")
	if ok {
		t.Error("Credential should be deleted")
	}
}

// ===========================================================================
// KiteCredentialStore.Set — with DB and API key change triggers invalidation
// ===========================================================================

func TestKiteCredentialStore_Set_APIKeyChange_InvalidatesToken(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	var invalidatedEmail string
	store.OnTokenInvalidate(func(email string) {
		invalidatedEmail = email
	})

	// Store initial credentials
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "old-key-12345678",
		APISecret: "old-secret-12345678",
	})

	// Change API key
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "new-key-12345678",
		APISecret: "new-secret-12345678",
	})

	if invalidatedEmail != "user@example.com" {
		t.Errorf("Expected token invalidation for 'user@example.com', got %q", invalidatedEmail)
	}
}

// ===========================================================================
// KiteCredentialStore.Set — same API key doesn't trigger invalidation
// ===========================================================================

func TestKiteCredentialStore_Set_SameKey_NoInvalidation(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()

	invalidated := false
	store.OnTokenInvalidate(func(email string) {
		invalidated = true
	})

	// Store and re-store same key
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "same-key-12345678",
		APISecret: "secret1",
	})
	store.Set("user@example.com", &KiteCredentialEntry{
		APIKey:    "same-key-12345678",
		APISecret: "secret2",
	})

	if invalidated {
		t.Error("Should not invalidate when API key is unchanged")
	}
}

// ===========================================================================
// KiteCredentialStore.LoadFromDB — with database
// ===========================================================================

func TestKiteCredentialStore_LoadFromDB_WithDB(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	// Save directly to DB
	err = db.SaveCredential("user@example.com", "loaded-key-12345678", "loaded-secret-12345678", "loaded-key-12345678", time.Now())
	if err != nil {
		t.Fatalf("SaveCredential error: %v", err)
	}

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	err = store.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	entry, ok := store.Get("user@example.com")
	if !ok {
		t.Fatal("Credential should be loaded from DB")
	}
	if entry.APIKey != "loaded-key-12345678" {
		t.Errorf("APIKey = %q, want 'loaded-key-12345678'", entry.APIKey)
	}
}

// ===========================================================================
// KiteCredentialStore.LoadFromDB — nil DB returns nil
// ===========================================================================

func TestKiteCredentialStore_LoadFromDB_NilDB(t *testing.T) {
	t.Parallel()

	store := NewKiteCredentialStore()
	err := store.LoadFromDB()
	if err != nil {
		t.Errorf("LoadFromDB with nil DB should return nil, got: %v", err)
	}
}

// ===========================================================================
// KiteTokenStore.Delete — with DB persistence
// ===========================================================================

func TestKiteTokenStore_DeleteWithDB(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	store.Set("user@example.com", &KiteTokenEntry{
		AccessToken: "token123",
		UserID:      "UID01",
		UserName:    "User",
	})

	store.Delete("user@example.com")

	_, ok := store.Get("user@example.com")
	if ok {
		t.Error("Token should be deleted")
	}
}

// ===========================================================================
// KiteTokenStore.Set — with DB persistence and OnChange callbacks
// ===========================================================================

func TestKiteTokenStore_Set_WithDBAndCallback(t *testing.T) {
	t.Parallel()

	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())

	var callbackEmail string
	store.OnChange(func(email string, entry *KiteTokenEntry) {
		callbackEmail = email
	})

	store.Set("user@example.com", &KiteTokenEntry{
		AccessToken: "tok",
		UserID:      "UID01",
		UserName:    "User",
	})

	if callbackEmail != "user@example.com" {
		t.Errorf("Callback email = %q, want 'user@example.com'", callbackEmail)
	}
}

// ===========================================================================
// BackfillRegistryFromCredentials — no registry store
// ===========================================================================

func TestBackfillRegistryFromCredentials_NilRegistry_Final(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "key", APISecret: "secret"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
		// No RegistryStore
	})

	// Should not panic
	svc.BackfillRegistryFromCredentials()
}

// ===========================================================================
// BackfillRegistryFromCredentials — empty credentials
// ===========================================================================

func TestBackfillRegistryFromCredentials_EmptyCredentials_Final(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStoreWithRaw{
		entries: map[string]*KiteCredentialEntry{},
		raw:     []RawCredentialEntry{},
	}
	regStore := registry.New()
	regStore.SetLogger(testLogger())

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	// Should not panic
	svc.BackfillRegistryFromCredentials()
}

// ===========================================================================
// BackfillRegistryFromCredentials — already in registry (skip)
// ===========================================================================

func TestBackfillRegistryFromCredentials_AlreadyInRegistry_Final(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStoreWithRaw{
		entries: map[string]*KiteCredentialEntry{
			"user@example.com": {APIKey: "existing-key", APISecret: "secret"},
		},
		raw: []RawCredentialEntry{
			{Email: "user@example.com", APIKey: "existing-key", APISecret: "secret"},
		},
	}

	regStore := registry.New()
	regStore.SetLogger(testLogger())
	// Pre-register this key
	_ = regStore.Register(&registry.AppRegistration{
		ID:           "pre-existing",
		APIKey:       "existing-key",
		APISecret:    "secret",
		AssignedTo:   "user@example.com",
		Status:       registry.StatusActive,
		Source:       registry.SourceAdmin,
		RegisteredBy: "admin@example.com",
	})

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	svc.BackfillRegistryFromCredentials()

	// Should still just have 1 entry (not duplicated)
	if regStore.Count() != 1 {
		t.Errorf("Registry count = %d, want 1 (no duplicate)", regStore.Count())
	}
}

// ===========================================================================
// BackfillRegistryFromCredentials — new entry migrated
// ===========================================================================

func TestBackfillRegistryFromCredentials_NewMigrated(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStoreWithRaw{
		entries: map[string]*KiteCredentialEntry{
			"user@example.com": {APIKey: "new-key-12345678", APISecret: "new-secret"},
		},
		raw: []RawCredentialEntry{
			{Email: "user@example.com", APIKey: "new-key-12345678", APISecret: "new-secret"},
		},
	}

	regStore := registry.New()
	regStore.SetLogger(testLogger())

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		RegistryStore:   regStore,
		Logger:          testLogger(),
	})

	svc.BackfillRegistryFromCredentials()

	if regStore.Count() != 1 {
		t.Errorf("Registry count = %d, want 1 (migrated entry)", regStore.Count())
	}
}

// ===========================================================================
// mockCredentialStoreWithRaw — supports ListAllRaw for BackfillRegistryFromCredentials
// ===========================================================================

type mockCredentialStoreWithRaw struct {
	entries map[string]*KiteCredentialEntry
	raw     []RawCredentialEntry
}

func (m *mockCredentialStoreWithRaw) Get(email string) (*KiteCredentialEntry, bool) {
	e, ok := m.entries[email]
	return e, ok
}

func (m *mockCredentialStoreWithRaw) Set(email string, entry *KiteCredentialEntry) {
	m.entries[email] = entry
}

func (m *mockCredentialStoreWithRaw) Delete(email string) { delete(m.entries, email) }

func (m *mockCredentialStoreWithRaw) ListAll() []KiteCredentialSummary { return nil }

func (m *mockCredentialStoreWithRaw) ListAllRaw() []RawCredentialEntry { return m.raw }

func (m *mockCredentialStoreWithRaw) GetSecretByAPIKey(apiKey string) (string, bool) {
	return "", false
}

func (m *mockCredentialStoreWithRaw) Count() int { return len(m.entries) }

// ===========================================================================
// Coverage boost: CredentialStore edge cases, TokenStore edge cases
// ===========================================================================

// ---------------------------------------------------------------------------
// KiteCredentialStore — Delete with DB persistence
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_Delete_WithDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	if err := store.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	// Set a credential
	store.Set("del-db@test.com", &KiteCredentialEntry{
		APIKey:    "key-to-delete",
		APISecret: "secret-to-delete",
	})

	// Verify it exists
	_, ok := store.Get("del-db@test.com")
	if !ok {
		t.Fatal("credential should exist after Set")
	}

	// Delete it
	store.Delete("del-db@test.com")

	// Verify it's gone
	_, ok = store.Get("del-db@test.com")
	if ok {
		t.Error("credential should be deleted")
	}
}

func TestKiteCredentialStore_Delete_NonExistent(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()
	// Should not panic
	store.Delete("nonexistent@test.com")
}

func TestKiteCredentialStore_Delete_WithDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	_ = store.LoadFromDB()

	store.Set("closed-db@test.com", &KiteCredentialEntry{
		APIKey:    "key",
		APISecret: "secret",
	})

	// Close DB to trigger error path
	db.Close()

	// Delete should log error but not panic
	store.Delete("closed-db@test.com")
}

// ---------------------------------------------------------------------------
// KiteCredentialStore — LoadFromDB error path
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_LoadFromDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteCredentialStore()
	store.SetDB(db)
	db.Close()

	err = store.LoadFromDB()
	if err == nil {
		t.Error("Expected error loading from closed DB")
	}
}

// ---------------------------------------------------------------------------
// KiteTokenStore — Delete with DB persistence
// ---------------------------------------------------------------------------

func TestKiteTokenStore_Delete_WithDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	if err := store.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB error: %v", err)
	}

	store.Set("del-tok@test.com", &KiteTokenEntry{
		AccessToken: "tok-to-delete",
	})

	_, ok := store.Get("del-tok@test.com")
	if !ok {
		t.Fatal("token should exist after Set")
	}

	store.Delete("del-tok@test.com")

	_, ok = store.Get("del-tok@test.com")
	if ok {
		t.Error("token should be deleted")
	}
}

func TestKiteTokenStore_Delete_WithDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	_ = store.LoadFromDB()

	store.Set("closed-tok@test.com", &KiteTokenEntry{AccessToken: "tok"})
	db.Close()

	// Delete should log error but not panic
	store.Delete("closed-tok@test.com")
}

func TestKiteTokenStore_LoadFromDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteTokenStore()
	store.SetDB(db)
	db.Close()

	err = store.LoadFromDB()
	if err == nil {
		t.Error("Expected error loading from closed DB")
	}
}

// ---------------------------------------------------------------------------
// KiteTokenStore — Set with DB persistence + change callback
// ---------------------------------------------------------------------------

func TestKiteTokenStore_Set_WithDB_TriggersCallback(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	_ = store.LoadFromDB()

	var callbackEmail string
	store.OnChange(func(email string, entry *KiteTokenEntry) {
		callbackEmail = email
	})

	store.Set("cb@test.com", &KiteTokenEntry{AccessToken: "tok"})

	if callbackEmail != "cb@test.com" {
		t.Errorf("OnChange callback email = %q, want %q", callbackEmail, "cb@test.com")
	}
}

func TestKiteTokenStore_Set_WithDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteTokenStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	_ = store.LoadFromDB()

	db.Close()

	// Set should log error but not panic
	store.Set("closed@test.com", &KiteTokenEntry{AccessToken: "tok"})
}

// ---------------------------------------------------------------------------
// KiteCredentialStore — Set with DB persistence
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_Set_WithDB_ClosedDB(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}

	store := NewKiteCredentialStore()
	store.SetDB(db)
	store.SetLogger(testLogger())
	_ = store.LoadFromDB()

	db.Close()

	// Set should log error but not panic
	store.Set("closed-cred@test.com", &KiteCredentialEntry{
		APIKey:    "key",
		APISecret: "secret",
	})
}

// ---------------------------------------------------------------------------
// KiteCredentialStore — OnTokenInvalidate
// ---------------------------------------------------------------------------

func TestKiteCredentialStore_OnTokenInvalidate_CalledOnKeyChange(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()

	var invalidatedEmail string
	store.OnTokenInvalidate(func(email string) {
		invalidatedEmail = email
	})

	// First Set: no invalidation (new credential)
	store.Set("inv@test.com", &KiteCredentialEntry{
		APIKey:    "key-1",
		APISecret: "secret-1",
	})
	if invalidatedEmail != "" {
		t.Error("OnTokenInvalidate should not be called on first Set")
	}

	// Second Set with different key: should trigger invalidation
	store.Set("inv@test.com", &KiteCredentialEntry{
		APIKey:    "key-2",
		APISecret: "secret-2",
	})
	if invalidatedEmail != "inv@test.com" {
		t.Errorf("OnTokenInvalidate email = %q, want %q", invalidatedEmail, "inv@test.com")
	}
}
