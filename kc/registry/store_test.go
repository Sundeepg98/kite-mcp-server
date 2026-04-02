package registry

import (
	"testing"
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
	if err := s.Update("app-1", "", "", "invalid"); err == nil {
		t.Fatal("Expected error on invalid status")
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
