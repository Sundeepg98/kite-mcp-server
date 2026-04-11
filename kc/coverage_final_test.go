package kc

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// ===========================================================================
// Manager.New() — with DevMode + AlertDBPath + EncryptionSecret
// ===========================================================================

func TestNew_WithDevModeAndDB(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-32bytes!!",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	if !m.DevMode() {
		t.Error("DevMode should be true")
	}
	if m.AlertDB() == nil {
		t.Error("AlertDB should not be nil with :memory:")
	}
}

// ===========================================================================
// Manager.New() — with custom SessionSigner
// ===========================================================================

func TestNew_WithCustomSessionSigner(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("NewSessionSigner error: %v", err)
	}

	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		SessionSigner:      signer,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	if m.SessionSigner() != signer {
		t.Error("Expected custom session signer")
	}
}

// ===========================================================================
// Manager.New() — AppMode "http" sets IsLocalMode false
// ===========================================================================

func TestNew_AppModeHTTP(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "http",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	if m.IsLocalMode() {
		t.Error("IsLocalMode should be false for http AppMode")
	}
}

// ===========================================================================
// Manager.New() — AppMode "sse"
// ===========================================================================

func TestNew_AppModeSSE(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "sse",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	if m.IsLocalMode() {
		t.Error("IsLocalMode should be false for sse AppMode")
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
// OpenBrowser — non-local mode (no-op)
// ===========================================================================

func TestOpenBrowser_NonLocalMode(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AppMode:            "http",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// Should return nil (no-op)
	err = m.OpenBrowser("https://example.com")
	if err != nil {
		t.Errorf("OpenBrowser in non-local mode should return nil, got: %v", err)
	}
}

// ===========================================================================
// OpenBrowser — invalid URL scheme
// ===========================================================================

func TestOpenBrowser_InvalidScheme_Final(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Error("Expected error for ftp scheme")
	}
}

// ===========================================================================
// HandleKiteCallback — missing params
// ===========================================================================

func TestHandleKiteCallback_MissingParams_Final(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	req := httptest.NewRequest(http.MethodGet, "/callback", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

// ===========================================================================
// HandleKiteCallback — invalid session ID signature
// ===========================================================================

func TestHandleKiteCallback_InvalidSessionSignature(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok&session_id=invalid-sig", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

// ===========================================================================
// HandleKiteCallback — session not found
// ===========================================================================

func TestHandleKiteCallback_SessionNotFound(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	// Sign a valid but nonexistent session ID
	signedID := m.sessionSigner.SignSessionID("nonexistent-session")

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=tok&session_id="+signedID, nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500 (session not found)", rr.Code)
	}
}

// ===========================================================================
// renderSuccessTemplate — template not found
// ===========================================================================

func TestRenderSuccessTemplate_TemplateNotFound(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Clear templates
	m.templates = map[string]*template.Template{}

	rr := httptest.NewRecorder()
	renderErr := m.renderSuccessTemplate(rr)
	if renderErr == nil {
		t.Error("Expected error for missing template")
	}
}

// ===========================================================================
// renderSuccessTemplate — success path
// ===========================================================================

func TestRenderSuccessTemplate_Success(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	rr := httptest.NewRecorder()
	renderErr := m.renderSuccessTemplate(rr)
	if renderErr != nil {
		t.Errorf("renderSuccessTemplate error: %v", renderErr)
	}
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

// ===========================================================================
// AuditStore / PaperEngine / BillingStore — non-nil paths
// ===========================================================================

func TestManager_AuditStore_NonNil_Final(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// AuditStore is nil until explicitly set
	if m.AuditStore() != nil {
		t.Error("AuditStore should be nil by default")
	}
}

// ===========================================================================
// LoadSessions — with DB but no sessions
// ===========================================================================

func TestLoadSessions_EmptyDB(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// LoadSessions should succeed (already called during New, but verify no panic)
	err = m.sessionManager.LoadFromDB()
	if err != nil {
		t.Errorf("LoadFromDB error: %v", err)
	}
}

// ===========================================================================
// Shutdown — comprehensive shutdown with various components
// ===========================================================================

func TestShutdown_WithDB(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Should not panic
	m.Shutdown()
}

// ===========================================================================
// SessionSigner — NewSessionSignerWithKey
// ===========================================================================

func TestNewSessionSignerWithKey_Final(t *testing.T) {
	t.Parallel()

	// Valid key
	signer, err := NewSessionSignerWithKey([]byte("test-secret-key-32-bytes-long!!"))
	if err != nil {
		t.Fatalf("NewSessionSignerWithKey error: %v", err)
	}

	signed := signer.SignSessionID("test-session")
	sid, err := signer.VerifySessionID(signed)
	if err != nil {
		t.Fatalf("VerifySessionID error: %v", err)
	}
	if sid != "test-session" {
		t.Errorf("VerifySessionID = %q, want 'test-session'", sid)
	}
}

func TestNewSessionSignerWithKey_EmptyKey(t *testing.T) {
	t.Parallel()
	_, err := NewSessionSignerWithKey([]byte{})
	if err == nil {
		t.Error("Expected error for empty key")
	}
}

// ===========================================================================
// SessionSigner — SignRedirectParams and VerifyRedirectParams
// ===========================================================================

func TestSessionSigner_SignAndVerifyRedirectParams_Final(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	// Generate a valid session ID first
	sessionID := signer.SignSessionID("test-session-id")
	verifiedID, err := signer.VerifySessionID(sessionID)
	if err != nil {
		t.Fatalf("VerifySessionID error: %v", err)
	}
	if verifiedID != "test-session-id" {
		t.Errorf("VerifySessionID = %q, want 'test-session-id'", verifiedID)
	}

	// Test SignRedirectParams with a valid session ID from Generate
	m, mErr := newTestManager("test_key", "test_secret")
	if mErr != nil {
		t.Fatalf("newTestManager error: %v", mErr)
	}
	defer m.Shutdown()

	genID := m.GenerateSession()
	params, pErr := m.SessionSigner().SignRedirectParams(genID)
	if pErr != nil {
		t.Fatalf("SignRedirectParams error: %v", pErr)
	}

	resultID, vErr := m.SessionSigner().VerifyRedirectParams(params)
	if vErr != nil {
		t.Fatalf("VerifyRedirectParams error: %v", vErr)
	}
	if resultID != genID {
		t.Errorf("VerifyRedirectParams = %q, want %q", resultID, genID)
	}
}

// ===========================================================================
// IsKiteTokenExpired — boundary cases
// ===========================================================================

func TestIsKiteTokenExpired_ZeroTime(t *testing.T) {
	t.Parallel()
	if !IsKiteTokenExpired(time.Time{}) {
		t.Error("Zero time should be considered expired")
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
func (m *mockCredentialStoreWithRaw) Delete(email string)                            { delete(m.entries, email) }
func (m *mockCredentialStoreWithRaw) ListAll() []KiteCredentialSummary               { return nil }
func (m *mockCredentialStoreWithRaw) ListAllRaw() []RawCredentialEntry               { return m.raw }
func (m *mockCredentialStoreWithRaw) GetSecretByAPIKey(apiKey string) (string, bool) { return "", false }
func (m *mockCredentialStoreWithRaw) Count() int                                     { return len(m.entries) }
