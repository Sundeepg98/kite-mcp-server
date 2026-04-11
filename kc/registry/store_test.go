package registry

import (
	"log/slog"
	"testing"
	"time"
)

func TestRegisterAndGet(t *testing.T) {
	s := New()

	reg := &AppRegistration{
		ID:           "app-1",
		APIKey:       "test_api_key_12345",
		APISecret:    "test_api_secret_67890",
		AssignedTo:   "user@example.com",
		Label:        "Test Account",
		RegisteredBy: "admin@example.com",
	}

	if err := s.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Get by ID
	got, ok := s.Get("app-1")
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.APIKey != "test_api_key_12345" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "test_api_key_12345")
	}
	if got.Status != StatusActive {
		t.Errorf("Status = %q, want %q", got.Status, StatusActive)
	}
}

func TestRegisterDuplicate(t *testing.T) {
	s := New()

	reg := &AppRegistration{
		ID:        "app-1",
		APIKey:    "key1",
		APISecret: "secret1",
	}
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	reg2 := &AppRegistration{
		ID:        "app-1",
		APIKey:    "key2",
		APISecret: "secret2",
	}
	if err := s.Register(reg2); err == nil {
		t.Fatal("Expected error on duplicate ID, got nil")
	}
}

func TestGetByEmail(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key1", APISecret: "secret1",
		AssignedTo: "alice@example.com", Label: "Alice's App",
	})
	s.Register(&AppRegistration{
		ID: "app-2", APIKey: "key2", APISecret: "secret2",
		AssignedTo: "bob@example.com", Label: "Bob's App",
	})
	s.Register(&AppRegistration{
		ID: "app-disabled", APIKey: "key3", APISecret: "secret3",
		AssignedTo: "alice@example.com", Label: "Disabled",
	})
	// Disable the third one
	s.Update("app-disabled", "", "", StatusDisabled)

	// Alice should get app-1 (the active one)
	got, ok := s.GetByEmail("alice@example.com")
	if !ok {
		t.Fatal("GetByEmail returned not found for alice")
	}
	if got.APIKey != "key1" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "key1")
	}

	// Bob should get app-2
	got, ok = s.GetByEmail("bob@example.com")
	if !ok {
		t.Fatal("GetByEmail returned not found for bob")
	}
	if got.APIKey != "key2" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "key2")
	}

	// Unknown email
	_, ok = s.GetByEmail("nobody@example.com")
	if ok {
		t.Fatal("GetByEmail should return not found for unknown email")
	}

	// Case insensitive
	got, ok = s.GetByEmail("ALICE@EXAMPLE.COM")
	if !ok {
		t.Fatal("GetByEmail should be case-insensitive")
	}
	if got.APIKey != "key1" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "key1")
	}
}

func TestGetByAPIKey(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "unique_key_abc", APISecret: "secret_abc",
	})

	got, ok := s.GetByAPIKey("unique_key_abc")
	if !ok {
		t.Fatal("GetByAPIKey returned not found")
	}
	if got.APISecret != "secret_abc" {
		t.Errorf("APISecret = %q, want %q", got.APISecret, "secret_abc")
	}

	_, ok = s.GetByAPIKey("nonexistent")
	if ok {
		t.Fatal("GetByAPIKey should return not found for unknown key")
	}
}

func TestUpdate(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key1", APISecret: "secret1",
		AssignedTo: "old@example.com", Label: "Old Label",
	})

	if err := s.Update("app-1", "new@example.com", "New Label", StatusActive); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got, _ := s.Get("app-1")
	if got.AssignedTo != "new@example.com" {
		t.Errorf("AssignedTo = %q, want %q", got.AssignedTo, "new@example.com")
	}
	if got.Label != "New Label" {
		t.Errorf("Label = %q, want %q", got.Label, "New Label")
	}

	// Disable
	if err := s.Update("app-1", "", "", StatusDisabled); err != nil {
		t.Fatalf("Update (disable) failed: %v", err)
	}
	got, _ = s.Get("app-1")
	if got.Status != StatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, StatusDisabled)
	}

	// Invalid status
	if err := s.Update("app-1", "", "", "bogus"); err == nil {
		t.Fatal("Expected error on invalid status")
	}

	// Valid new statuses (invalid, replaced)
	if err := s.Update("app-1", "", "", StatusInvalid); err != nil {
		t.Fatalf("Update (invalid) failed: %v", err)
	}
	got, _ = s.Get("app-1")
	if got.Status != StatusInvalid {
		t.Errorf("Status = %q, want %q", got.Status, StatusInvalid)
	}
	if err := s.Update("app-1", "", "", StatusReplaced); err != nil {
		t.Fatalf("Update (replaced) failed: %v", err)
	}
	got, _ = s.Get("app-1")
	if got.Status != StatusReplaced {
		t.Errorf("Status = %q, want %q", got.Status, StatusReplaced)
	}

	// Not found
	if err := s.Update("nonexistent", "", "", StatusActive); err == nil {
		t.Fatal("Expected error on nonexistent ID")
	}
}

func TestDelete(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key1", APISecret: "secret1",
	})

	if err := s.Delete("app-1"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	_, ok := s.Get("app-1")
	if ok {
		t.Fatal("Get should return not found after delete")
	}

	if err := s.Delete("app-1"); err == nil {
		t.Fatal("Expected error on double delete")
	}
}

func TestListAndCount(t *testing.T) {
	s := New()

	if s.Count() != 0 {
		t.Errorf("Count = %d, want 0", s.Count())
	}

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "test_key_abcdefgh", APISecret: "test_secret_12345678",
	})
	s.Register(&AppRegistration{
		ID: "app-2", APIKey: "test_key_ijklmnop", APISecret: "short",
	})

	if s.Count() != 2 {
		t.Errorf("Count = %d, want 2", s.Count())
	}

	list := s.List()
	if len(list) != 2 {
		t.Fatalf("List len = %d, want 2", len(list))
	}

	// Secrets should be masked
	for _, item := range list {
		if item.APISecretHint == item.APIKey {
			t.Error("API secret should be masked in list")
		}
	}
}

func TestHasEntries(t *testing.T) {
	s := New()

	if s.HasEntries() {
		t.Fatal("HasEntries should be false for empty store")
	}

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key1", APISecret: "secret1",
	})

	if !s.HasEntries() {
		t.Fatal("HasEntries should be true after register")
	}
}

func TestMaskSecret(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "****"},
		{"short", "****"},
		{"1234567", "****"},
		{"12345678", "1234****678"},
		{"abcdefghijklmnop", "abcd****nop"},
	}
	for _, tt := range tests {
		got := maskSecret(tt.input)
		if got != tt.want {
			t.Errorf("maskSecret(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestRegisterValidation(t *testing.T) {
	s := New()

	// Missing ID
	if err := s.Register(&AppRegistration{APIKey: "k", APISecret: "s"}); err == nil {
		t.Fatal("Expected error on missing ID")
	}

	// Missing APIKey
	if err := s.Register(&AppRegistration{ID: "x", APISecret: "s"}); err == nil {
		t.Fatal("Expected error on missing APIKey")
	}

	// Missing APISecret
	if err := s.Register(&AppRegistration{ID: "x", APIKey: "k"}); err == nil {
		t.Fatal("Expected error on missing APISecret")
	}
}

func TestSetLogger(t *testing.T) {
	s := New()
	logger := slog.Default()
	s.SetLogger(logger)
	// No panic = success. Logger is used internally for DB error reporting.
}

func TestSetDB_NilDB(t *testing.T) {
	s := New()
	s.SetDB(nil)
	// No panic = success. With nil DB, persistence is disabled.
}

func TestLoadFromDB_NilDB(t *testing.T) {
	s := New()
	// With no DB set, LoadFromDB should be a no-op.
	err := s.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB with nil DB should return nil, got: %v", err)
	}
}

func TestUpdateLastUsedAt(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key_update_last", APISecret: "secret1",
	})

	// Update last used at.
	s.UpdateLastUsedAt("key_update_last")

	got, ok := s.Get("app-1")
	if !ok {
		t.Fatal("Get returned not found after UpdateLastUsedAt")
	}
	if got.LastUsedAt == nil {
		t.Fatal("LastUsedAt should be set after UpdateLastUsedAt")
	}

	// Non-existent key should be a no-op.
	s.UpdateLastUsedAt("nonexistent_key")
}

func TestUpdateLastUsedAt_InactiveKey(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key_inactive", APISecret: "secret1",
	})
	s.Update("app-1", "", "", StatusDisabled)

	// Should be a no-op for inactive keys (GetByAPIKey only matches active).
	s.UpdateLastUsedAt("key_inactive")

	got, _ := s.Get("app-1")
	if got.LastUsedAt != nil {
		t.Fatal("LastUsedAt should not be set for inactive keys")
	}
}

func TestMarkStatus(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key_mark", APISecret: "secret1",
	})

	// Mark as invalid.
	s.MarkStatus("key_mark", StatusInvalid)

	got, _ := s.Get("app-1")
	if got.Status != StatusInvalid {
		t.Errorf("Status = %q, want %q", got.Status, StatusInvalid)
	}

	// Mark as replaced.
	s.MarkStatus("key_mark", StatusReplaced)
	got, _ = s.Get("app-1")
	if got.Status != StatusReplaced {
		t.Errorf("Status = %q, want %q", got.Status, StatusReplaced)
	}

	// Non-existent key is a no-op.
	s.MarkStatus("nonexistent_key", StatusActive)
}

func TestGetByAPIKeyAnyStatus(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-1", APIKey: "key_any_status", APISecret: "secret1",
	})

	// Should find active entry.
	got, ok := s.GetByAPIKeyAnyStatus("key_any_status")
	if !ok {
		t.Fatal("GetByAPIKeyAnyStatus should find active entry")
	}
	if got.Status != StatusActive {
		t.Errorf("Status = %q, want %q", got.Status, StatusActive)
	}

	// Disable it.
	s.Update("app-1", "", "", StatusDisabled)

	// GetByAPIKey (active only) should not find it.
	_, ok = s.GetByAPIKey("key_any_status")
	if ok {
		t.Fatal("GetByAPIKey should not find disabled entry")
	}

	// GetByAPIKeyAnyStatus should still find it.
	got, ok = s.GetByAPIKeyAnyStatus("key_any_status")
	if !ok {
		t.Fatal("GetByAPIKeyAnyStatus should find disabled entry")
	}
	if got.Status != StatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, StatusDisabled)
	}

	// Non-existent key.
	_, ok = s.GetByAPIKeyAnyStatus("nonexistent")
	if ok {
		t.Fatal("GetByAPIKeyAnyStatus should return false for unknown key")
	}
}

func TestToDBEntry(t *testing.T) {
	now := time.Now()
	lastUsed := now.Add(-time.Hour)
	reg := &AppRegistration{
		ID:           "app-1",
		APIKey:       "test_key",
		APISecret:    "test_secret",
		AssignedTo:   "user@example.com",
		Label:        "Test",
		Status:       StatusActive,
		RegisteredBy: "admin@example.com",
		Source:       SourceAdmin,
		LastUsedAt:   &lastUsed,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	entry := toDBEntry(reg)

	if entry.ID != reg.ID {
		t.Errorf("ID = %q, want %q", entry.ID, reg.ID)
	}
	if entry.APIKey != reg.APIKey {
		t.Errorf("APIKey = %q, want %q", entry.APIKey, reg.APIKey)
	}
	if entry.APISecret != reg.APISecret {
		t.Errorf("APISecret = %q, want %q", entry.APISecret, reg.APISecret)
	}
	if entry.AssignedTo != reg.AssignedTo {
		t.Errorf("AssignedTo = %q, want %q", entry.AssignedTo, reg.AssignedTo)
	}
	if entry.Label != reg.Label {
		t.Errorf("Label = %q, want %q", entry.Label, reg.Label)
	}
	if entry.Status != reg.Status {
		t.Errorf("Status = %q, want %q", entry.Status, reg.Status)
	}
	if entry.RegisteredBy != reg.RegisteredBy {
		t.Errorf("RegisteredBy = %q, want %q", entry.RegisteredBy, reg.RegisteredBy)
	}
	if entry.Source != reg.Source {
		t.Errorf("Source = %q, want %q", entry.Source, reg.Source)
	}
	if entry.LastUsedAt == nil || !entry.LastUsedAt.Equal(lastUsed) {
		t.Error("LastUsedAt should match")
	}
	if !entry.CreatedAt.Equal(now) {
		t.Error("CreatedAt should match")
	}
	if !entry.UpdatedAt.Equal(now) {
		t.Error("UpdatedAt should match")
	}
}

func TestMaskKey(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"", "****"},
		{"short", "****"},
		{"12345678", "****"},
		{"123456789", "1234****6789"},
		{"abcdefghijklmnop", "abcd****mnop"},
	}
	for _, tt := range tests {
		got := maskKey(tt.input)
		if got != tt.want {
			t.Errorf("maskKey(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
}

func TestGetByEmail_EmptyEmail(t *testing.T) {
	s := New()
	_, ok := s.GetByEmail("")
	if ok {
		t.Fatal("GetByEmail should return false for empty email")
	}
	_, ok = s.GetByEmail("   ")
	if ok {
		t.Fatal("GetByEmail should return false for whitespace email")
	}
}

func TestRegisterDefaults(t *testing.T) {
	s := New()

	reg := &AppRegistration{
		ID:        "app-defaults",
		APIKey:    "key_defaults",
		APISecret: "secret_defaults",
	}
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	got, ok := s.Get("app-defaults")
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.Status != StatusActive {
		t.Errorf("Default Status = %q, want %q", got.Status, StatusActive)
	}
	if got.Source != SourceAdmin {
		t.Errorf("Default Source = %q, want %q", got.Source, SourceAdmin)
	}
	if got.CreatedAt.IsZero() {
		t.Error("CreatedAt should be set")
	}
	if got.UpdatedAt.IsZero() {
		t.Error("UpdatedAt should be set")
	}
}

func TestRegisterNormalizesEmail(t *testing.T) {
	s := New()

	s.Register(&AppRegistration{
		ID: "app-email", APIKey: "key1", APISecret: "secret1",
		AssignedTo: "  USER@EXAMPLE.COM  ",
	})

	got, ok := s.Get("app-email")
	if !ok {
		t.Fatal("Get returned not found")
	}
	if got.AssignedTo != "user@example.com" {
		t.Errorf("AssignedTo = %q, want %q", got.AssignedTo, "user@example.com")
	}
}
