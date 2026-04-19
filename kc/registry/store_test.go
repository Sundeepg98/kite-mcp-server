package registry

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

func TestRegisterAndGet(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
	s := New()
	logger := slog.Default()
	s.SetLogger(logger)
	// No panic = success. Logger is used internally for DB error reporting.
}

func TestSetDB_NilDB(t *testing.T) {
	t.Parallel()
	s := New()
	s.SetDB(nil)
	// No panic = success. With nil DB, persistence is disabled.
}

func TestLoadFromDB_NilDB(t *testing.T) {
	t.Parallel()
	s := New()
	// With no DB set, LoadFromDB should be a no-op.
	err := s.LoadFromDB()
	if err != nil {
		t.Fatalf("LoadFromDB with nil DB should return nil, got: %v", err)
	}
}

func TestUpdateLastUsedAt(t *testing.T) {
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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
	t.Parallel()
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

// ---------------------------------------------------------------------------
// Helper: create a temp DB for persistence tests.
// ---------------------------------------------------------------------------

func openTestDB(t *testing.T) *alerts.DB {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "test.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB failed: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// ---------------------------------------------------------------------------
// LoadFromDB — full path (non-nil DB with data)
// ---------------------------------------------------------------------------

func TestLoadFromDB_WithData(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)

	// Persist entries via DB directly.
	now := time.Now().Truncate(time.Second)
	lastUsed := now.Add(-time.Hour)
	if err := db.SaveRegistryEntry(&alerts.RegistryDBEntry{
		ID:           "app-load-1",
		APIKey:       "load_key_1",
		APISecret:    "load_secret_1",
		AssignedTo:   "loader@example.com",
		Label:        "Loaded App",
		Status:       StatusActive,
		RegisteredBy: "admin@example.com",
		Source:       SourceAdmin,
		LastUsedAt:   &lastUsed,
		CreatedAt:    now,
		UpdatedAt:    now,
	}); err != nil {
		t.Fatalf("SaveRegistryEntry failed: %v", err)
	}

	if err := db.SaveRegistryEntry(&alerts.RegistryDBEntry{
		ID:         "app-load-2",
		APIKey:     "load_key_2",
		APISecret:  "load_secret_2",
		AssignedTo: "loader2@example.com",
		Label:      "Loaded App 2",
		Status:     StatusDisabled,
		Source:     SourceSelfProvisioned,
		CreatedAt:  now,
		UpdatedAt:  now,
	}); err != nil {
		t.Fatalf("SaveRegistryEntry failed: %v", err)
	}

	// Create a fresh store and load from DB.
	s := New()
	s.SetDB(db)
	if err := s.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB failed: %v", err)
	}

	if s.Count() != 2 {
		t.Fatalf("Count = %d, want 2", s.Count())
	}

	got, ok := s.Get("app-load-1")
	if !ok {
		t.Fatal("app-load-1 not found after LoadFromDB")
	}
	if got.APIKey != "load_key_1" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "load_key_1")
	}
	if got.AssignedTo != "loader@example.com" {
		t.Errorf("AssignedTo = %q, want %q", got.AssignedTo, "loader@example.com")
	}
	if got.Label != "Loaded App" {
		t.Errorf("Label = %q, want %q", got.Label, "Loaded App")
	}
	if got.Status != StatusActive {
		t.Errorf("Status = %q, want %q", got.Status, StatusActive)
	}
	if got.Source != SourceAdmin {
		t.Errorf("Source = %q, want %q", got.Source, SourceAdmin)
	}
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt should be set")
	}

	got2, ok := s.Get("app-load-2")
	if !ok {
		t.Fatal("app-load-2 not found after LoadFromDB")
	}
	if got2.Status != StatusDisabled {
		t.Errorf("Status = %q, want %q", got2.Status, StatusDisabled)
	}
}

func TestLoadFromDB_EmptyDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	if err := s.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB on empty DB should not fail: %v", err)
	}
	if s.Count() != 0 {
		t.Errorf("Count = %d, want 0", s.Count())
	}
}

// ---------------------------------------------------------------------------
// Register — with DB persistence
// ---------------------------------------------------------------------------

func TestRegister_PersistsToDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	reg := &AppRegistration{
		ID:           "app-persist",
		APIKey:       "persist_key_abc",
		APISecret:    "persist_secret_xyz",
		AssignedTo:   "persist@example.com",
		Label:        "Persisted",
		RegisteredBy: "admin@example.com",
		Source:       SourceSelfProvisioned,
	}
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	// Verify it was persisted by loading from DB into a new store.
	s2 := New()
	s2.SetDB(db)
	if err := s2.LoadFromDB(); err != nil {
		t.Fatalf("LoadFromDB failed: %v", err)
	}
	got, ok := s2.Get("app-persist")
	if !ok {
		t.Fatal("app-persist not found in DB")
	}
	if got.APIKey != "persist_key_abc" {
		t.Errorf("APIKey = %q, want %q", got.APIKey, "persist_key_abc")
	}
	if got.Source != SourceSelfProvisioned {
		t.Errorf("Source = %q, want %q", got.Source, SourceSelfProvisioned)
	}
}

// ---------------------------------------------------------------------------
// Register — with explicit status/source (no defaults)
// ---------------------------------------------------------------------------

func TestRegister_ExplicitStatusAndSource(t *testing.T) {
	t.Parallel()
	s := New()
	reg := &AppRegistration{
		ID:        "app-explicit",
		APIKey:    "key1",
		APISecret: "secret1",
		Status:    StatusDisabled,
		Source:    SourceMigrated,
	}
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register failed: %v", err)
	}
	got, _ := s.Get("app-explicit")
	if got.Status != StatusDisabled {
		t.Errorf("Status = %q, want %q", got.Status, StatusDisabled)
	}
	if got.Source != SourceMigrated {
		t.Errorf("Source = %q, want %q", got.Source, SourceMigrated)
	}
}

// ---------------------------------------------------------------------------
// Update — with DB persistence
// ---------------------------------------------------------------------------

func TestUpdate_PersistsToDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	s.Register(&AppRegistration{
		ID: "app-upd", APIKey: "upd_key", APISecret: "upd_secret",
	})

	if err := s.Update("app-upd", "updated@example.com", "Updated Label", StatusActive); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	// Verify in DB.
	s2 := New()
	s2.SetDB(db)
	s2.LoadFromDB()
	got, _ := s2.Get("app-upd")
	if got.AssignedTo != "updated@example.com" {
		t.Errorf("AssignedTo = %q, want %q", got.AssignedTo, "updated@example.com")
	}
	if got.Label != "Updated Label" {
		t.Errorf("Label = %q, want %q", got.Label, "Updated Label")
	}
}

func TestUpdate_EmptyFieldsNoChange(t *testing.T) {
	t.Parallel()
	s := New()
	s.Register(&AppRegistration{
		ID: "app-noop", APIKey: "k", APISecret: "s",
		AssignedTo: "orig@example.com", Label: "Original", Status: StatusActive,
	})

	// Passing empty fields should not change anything except UpdatedAt.
	if err := s.Update("app-noop", "", "", ""); err != nil {
		t.Fatalf("Update failed: %v", err)
	}

	got, _ := s.Get("app-noop")
	if got.AssignedTo != "orig@example.com" {
		t.Errorf("AssignedTo = %q, want %q (should not change)", got.AssignedTo, "orig@example.com")
	}
	if got.Label != "Original" {
		t.Errorf("Label = %q, want %q (should not change)", got.Label, "Original")
	}
	if got.Status != StatusActive {
		t.Errorf("Status = %q, want %q (should not change)", got.Status, StatusActive)
	}
}

// ---------------------------------------------------------------------------
// UpdateLastUsedAt — with DB persistence
// ---------------------------------------------------------------------------

func TestUpdateLastUsedAt_PersistsToDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	s.Register(&AppRegistration{
		ID: "app-lu", APIKey: "lu_key", APISecret: "lu_secret",
	})

	s.UpdateLastUsedAt("lu_key")

	// Verify in DB.
	s2 := New()
	s2.SetDB(db)
	s2.LoadFromDB()
	got, _ := s2.Get("app-lu")
	if got.LastUsedAt == nil {
		t.Error("LastUsedAt should be set in DB after UpdateLastUsedAt")
	}
}

// ---------------------------------------------------------------------------
// MarkStatus — with DB persistence
// ---------------------------------------------------------------------------

func TestMarkStatus_PersistsToDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	s.Register(&AppRegistration{
		ID: "app-ms", APIKey: "ms_key", APISecret: "ms_secret",
	})

	s.MarkStatus("ms_key", StatusInvalid)

	// Verify in DB.
	s2 := New()
	s2.SetDB(db)
	s2.LoadFromDB()
	got, _ := s2.Get("app-ms")
	if got.Status != StatusInvalid {
		t.Errorf("Status = %q, want %q", got.Status, StatusInvalid)
	}
}

// ---------------------------------------------------------------------------
// Delete — with DB persistence
// ---------------------------------------------------------------------------

func TestDelete_PersistsToDB(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.Default())

	s.Register(&AppRegistration{
		ID: "app-del", APIKey: "del_key", APISecret: "del_secret",
	})

	if err := s.Delete("app-del"); err != nil {
		t.Fatalf("Delete failed: %v", err)
	}

	// Verify in DB.
	s2 := New()
	s2.SetDB(db)
	s2.LoadFromDB()
	if s2.Count() != 0 {
		t.Errorf("Count = %d, want 0 after delete", s2.Count())
	}
}

// ---------------------------------------------------------------------------
// GetByEmail — multiple entries, picks most recent UpdatedAt
// ---------------------------------------------------------------------------

func TestGetByEmail_PicksMostRecentUpdate(t *testing.T) {
	t.Parallel()
	s := New()

	// Register two entries for the same email. The second one will have a later UpdatedAt.
	s.Register(&AppRegistration{
		ID: "app-old", APIKey: "key_old", APISecret: "secret_old",
		AssignedTo: "multi@example.com", Label: "Old One",
	})
	// Small sleep to ensure different timestamps.
	time.Sleep(2 * time.Millisecond)
	s.Register(&AppRegistration{
		ID: "app-new", APIKey: "key_new", APISecret: "secret_new",
		AssignedTo: "multi@example.com", Label: "New One",
	})

	got, ok := s.GetByEmail("multi@example.com")
	if !ok {
		t.Fatal("GetByEmail returned not found")
	}
	if got.ID != "app-new" {
		t.Errorf("ID = %q, want %q (should pick most recent)", got.ID, "app-new")
	}
}

// ---------------------------------------------------------------------------
// DB error logging (logger nil path — no logger set, db operations fail silently)
// ---------------------------------------------------------------------------

func TestRegister_DBErrorNoLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	// Close the DB to force errors.
	db.Close()

	s := New()
	s.SetDB(db)
	// No logger set — should not panic even when DB operations fail.

	reg := &AppRegistration{
		ID: "app-dberr", APIKey: "k", APISecret: "s",
	}
	// Register should succeed in-memory even if DB fails.
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register should succeed in-memory: %v", err)
	}
	if s.Count() != 1 {
		t.Errorf("Count = %d, want 1", s.Count())
	}
}

func TestUpdate_DBErrorNoLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.Register(&AppRegistration{
		ID: "app-dberr2", APIKey: "k", APISecret: "s",
	})
	db.Close()
	// No logger set — Update should not panic when DB fails.
	if err := s.Update("app-dberr2", "new@example.com", "", ""); err != nil {
		t.Fatalf("Update should succeed in-memory: %v", err)
	}
}

func TestUpdateLastUsedAt_DBErrorNoLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.Register(&AppRegistration{
		ID: "app-dberr3", APIKey: "k3", APISecret: "s",
	})
	db.Close()
	// Should not panic.
	s.UpdateLastUsedAt("k3")
}

func TestMarkStatus_DBErrorNoLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.Register(&AppRegistration{
		ID: "app-dberr4", APIKey: "k4", APISecret: "s",
	})
	db.Close()
	// Should not panic.
	s.MarkStatus("k4", StatusInvalid)
}

func TestDelete_DBErrorNoLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.Register(&AppRegistration{
		ID: "app-dberr5", APIKey: "k5", APISecret: "s",
	})
	db.Close()
	// Should not panic — in-memory delete should still succeed.
	if err := s.Delete("app-dberr5"); err != nil {
		t.Fatalf("Delete should succeed in-memory: %v", err)
	}
}

// ---------------------------------------------------------------------------
// DB error with logger (errors logged but not returned)
// ---------------------------------------------------------------------------

func TestRegister_DBErrorWithLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	// Close DB to force write failure.
	db.Close()

	// Should succeed in-memory, logging the DB error.
	reg := &AppRegistration{
		ID: "app-dblog", APIKey: "k", APISecret: "s",
	}
	if err := s.Register(reg); err != nil {
		t.Fatalf("Register should succeed in-memory: %v", err)
	}
}

func TestDelete_DBErrorWithLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	s.Register(&AppRegistration{
		ID: "app-dblog2", APIKey: "k", APISecret: "s",
	})
	db.Close()

	// Should succeed in-memory, logging the DB error.
	if err := s.Delete("app-dblog2"); err != nil {
		t.Fatalf("Delete should succeed in-memory: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LoadFromDB — DB error path
// ---------------------------------------------------------------------------

func TestLoadFromDB_DBError(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	db.Close() // Close to force errors.

	s := New()
	s.SetDB(db)
	err := s.LoadFromDB()
	if err == nil {
		t.Fatal("LoadFromDB should return error with closed DB")
	}
}

// ---------------------------------------------------------------------------
// Update — DB error with logger (exercises the logging branch)
// ---------------------------------------------------------------------------

func TestUpdate_DBErrorWithLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	s.Register(&AppRegistration{
		ID: "app-uplog", APIKey: "k", APISecret: "s",
	})
	db.Close()

	// Should succeed in-memory, logging the DB error.
	if err := s.Update("app-uplog", "new@example.com", "", ""); err != nil {
		t.Fatalf("Update should succeed in-memory: %v", err)
	}
}

// ---------------------------------------------------------------------------
// UpdateLastUsedAt — DB error with logger
// ---------------------------------------------------------------------------

func TestUpdateLastUsedAt_DBErrorWithLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	s.Register(&AppRegistration{
		ID: "app-lulog", APIKey: "lulog_key", APISecret: "s",
	})
	db.Close()

	// Should not panic.
	s.UpdateLastUsedAt("lulog_key")
}

// ---------------------------------------------------------------------------
// MarkStatus — DB error with logger
// ---------------------------------------------------------------------------

func TestMarkStatus_DBErrorWithLogger(t *testing.T) {
	t.Parallel()
	db := openTestDB(t)
	s := New()
	s.SetDB(db)
	s.SetLogger(slog.New(slog.NewTextHandler(os.Stderr, nil)))

	s.Register(&AppRegistration{
		ID: "app-mslog", APIKey: "mslog_key", APISecret: "s",
	})
	db.Close()

	// Should not panic.
	s.MarkStatus("mslog_key", StatusInvalid)
}
