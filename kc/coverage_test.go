package kc

import (
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// ===========================================================================
// AlertService — getters and setters
// ===========================================================================

func TestAlertService_Getters(t *testing.T) {
	t.Parallel()

	store := alerts.NewStore(nil)
	eval := alerts.NewEvaluator(store, testLogger())
	trail := alerts.NewTrailingStopManager(testLogger())

	svc := NewAlertService(AlertServiceConfig{
		AlertStore:      store,
		AlertEvaluator:  eval,
		TrailingStopMgr: trail,
	})

	if svc.AlertStore() != store {
		t.Error("AlertStore() should return the configured store")
	}
	if svc.AlertEvaluator() != eval {
		t.Error("AlertEvaluator() should return the configured evaluator")
	}
	if svc.TrailingStopManager() != trail {
		t.Error("TrailingStopManager() should return the configured manager")
	}
	if svc.TelegramNotifier() != nil {
		t.Error("TelegramNotifier() should return nil when not set")
	}
	if svc.PnLService() != nil {
		t.Error("PnLService() should return nil when not set")
	}
}

func TestAlertService_SetPnLService(t *testing.T) {
	t.Parallel()

	svc := NewAlertService(AlertServiceConfig{})
	if svc.PnLService() != nil {
		t.Error("PnLService should be nil initially")
	}

	// Create a dummy PnL service
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB error: %v", err)
	}
	defer db.Close()
	pnlSvc := alerts.NewPnLSnapshotService(db, nil, nil, testLogger())

	svc.SetPnLService(pnlSvc)
	if svc.PnLService() != pnlSvc {
		t.Error("PnLService() should return the set service")
	}
}

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
func (m *mockCredentialStore) Delete(email string)                              { delete(m.entries, email) }
func (m *mockCredentialStore) ListAll() []KiteCredentialSummary                 { return nil }
func (m *mockCredentialStore) ListAllRaw() []RawCredentialEntry                 { return nil }
func (m *mockCredentialStore) GetSecretByAPIKey(apiKey string) (string, bool)   { return "", false }
func (m *mockCredentialStore) Count() int                                       { return len(m.entries) }

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
func (m *mockTokenStore) Delete(email string)                 { delete(m.entries, email) }
func (m *mockTokenStore) OnChange(cb TokenChangeCallback)     {}
func (m *mockTokenStore) ListAll() []KiteTokenSummary         { return nil }
func (m *mockTokenStore) Count() int                          { return len(m.entries) }

func TestCredentialService_ResolveCredentials_PerUser(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "user-key", APISecret: "user-secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "global-key",
		APISecret:       "global-secret",
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	key, secret, err := svc.ResolveCredentials("user@example.com")
	if err != nil {
		t.Fatalf("ResolveCredentials error: %v", err)
	}
	if key != "user-key" {
		t.Errorf("API key = %q, want %q", key, "user-key")
	}
	if secret != "user-secret" {
		t.Errorf("API secret = %q, want %q", secret, "user-secret")
	}
}

func TestCredentialService_ResolveCredentials_GlobalFallback(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "global-key",
		APISecret:       "global-secret",
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	key, secret, err := svc.ResolveCredentials("unknown@example.com")
	if err != nil {
		t.Fatalf("ResolveCredentials error: %v", err)
	}
	if key != "global-key" || secret != "global-secret" {
		t.Errorf("Expected global credentials, got key=%q secret=%q", key, secret)
	}
}

func TestCredentialService_ResolveCredentials_NoCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	_, _, err := svc.ResolveCredentials("user@example.com")
	if err == nil {
		t.Error("Expected error when no credentials available")
	}
}

func TestCredentialService_HasCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "key", APISecret: "secret"},
	}}
	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.HasCredentials("user@example.com") {
		t.Error("HasCredentials should return true for existing user")
	}
	if svc.HasCredentials("unknown@example.com") {
		t.Error("HasCredentials should return false for unknown user (no global creds)")
	}
}

func TestCredentialService_GetAccessTokenForEmail(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "cached-token"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		AccessToken:     "global-token",
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	// Per-user token
	token := svc.GetAccessTokenForEmail("user@example.com")
	if token != "cached-token" {
		t.Errorf("token = %q, want %q", token, "cached-token")
	}

	// Global fallback
	token = svc.GetAccessTokenForEmail("unknown@example.com")
	if token != "global-token" {
		t.Errorf("token = %q, want %q", token, "global-token")
	}

	// Empty email uses global
	token = svc.GetAccessTokenForEmail("")
	if token != "global-token" {
		t.Errorf("token = %q, want %q", token, "global-token")
	}
}

func TestCredentialService_HasCachedToken(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "tok"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.HasCachedToken("user@example.com") {
		t.Error("HasCachedToken should return true")
	}
	if svc.HasCachedToken("unknown@example.com") {
		t.Error("HasCachedToken should return false for unknown")
	}
	if svc.HasCachedToken("") {
		t.Error("HasCachedToken should return false for empty email")
	}
}

func TestCredentialService_HasUserCredentials(t *testing.T) {
	t.Parallel()

	credStore := &mockCredentialStore{entries: map[string]*KiteCredentialEntry{
		"user@example.com": {APIKey: "k", APISecret: "s"},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: credStore,
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})

	if !svc.HasUserCredentials("user@example.com") {
		t.Error("HasUserCredentials should return true")
	}
	if svc.HasUserCredentials("unknown@example.com") {
		t.Error("HasUserCredentials should return false")
	}
	if svc.HasUserCredentials("") {
		t.Error("HasUserCredentials should return false for empty")
	}
}

func TestCredentialService_HasGlobalCredentials(t *testing.T) {
	t.Parallel()

	svc := NewCredentialService(CredentialServiceConfig{
		APIKey:          "key",
		APISecret:       "secret",
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})
	if !svc.HasGlobalCredentials() {
		t.Error("HasGlobalCredentials should return true")
	}

	svc2 := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      &mockTokenStore{entries: map[string]*KiteTokenEntry{}},
		Logger:          testLogger(),
	})
	if svc2.HasGlobalCredentials() {
		t.Error("HasGlobalCredentials should return false when no global creds")
	}
}

func TestCredentialService_IsTokenValid(t *testing.T) {
	t.Parallel()

	tokenStore := &mockTokenStore{entries: map[string]*KiteTokenEntry{
		"user@example.com": {AccessToken: "tok", StoredAt: time.Now()},
	}}

	svc := NewCredentialService(CredentialServiceConfig{
		CredentialStore: &mockCredentialStore{entries: map[string]*KiteCredentialEntry{}},
		TokenStore:      tokenStore,
		Logger:          testLogger(),
	})

	if !svc.IsTokenValid("user@example.com") {
		t.Error("IsTokenValid should return true for recently stored token")
	}
	if svc.IsTokenValid("unknown@example.com") {
		t.Error("IsTokenValid should return false for unknown email")
	}
}

// ===========================================================================
// IsKiteTokenExpired
// ===========================================================================

func TestIsKiteTokenExpired_RecentToken(t *testing.T) {
	t.Parallel()
	// Token stored just now should NOT be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
}

func TestIsKiteTokenExpired_OldToken(t *testing.T) {
	t.Parallel()
	// Token stored 2 days ago should be expired
	if !IsKiteTokenExpired(time.Now().Add(-48 * time.Hour)) {
		t.Error("Token stored 2 days ago should be expired")
	}
}

// ===========================================================================
// FamilyService
// ===========================================================================

func TestFamilyService_NilStores(t *testing.T) {
	t.Parallel()

	fs := NewFamilyService(nil, nil, nil)
	if fs == nil {
		t.Fatal("NewFamilyService should not return nil")
	}

	// AdminEmailFn with nil store
	fn := fs.AdminEmailFn()
	if fn("user@example.com") != "" {
		t.Error("AdminEmailFn should return empty with nil store")
	}

	// ListMembers with nil store
	members := fs.ListMembers("admin@example.com")
	if members != nil {
		t.Error("ListMembers should return nil with nil store")
	}

	// MemberCount with nil store
	if fs.MemberCount("admin@example.com") != 0 {
		t.Error("MemberCount should return 0 with nil store")
	}

	// MaxUsers with nil billing store
	if fs.MaxUsers("admin@example.com") != 1 {
		t.Errorf("MaxUsers with nil billing store should return 1, got %d", fs.MaxUsers("admin@example.com"))
	}

	// CanInvite with nil stores
	ok, current, max := fs.CanInvite("admin@example.com")
	if !ok {
		t.Error("CanInvite should return true when 0 < 1")
	}
	if current != 0 || max != 1 {
		t.Errorf("CanInvite: current=%d max=%d, want 0, 1", current, max)
	}

	// RemoveMember with nil store
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err == nil {
		t.Error("RemoveMember should error with nil store")
	}
}

// ===========================================================================
// Manager — accessor tests for 0% coverage getters
// ===========================================================================

func TestManager_AccessorGetters(t *testing.T) {
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// CredentialSvc
	if m.CredentialSvc() == nil {
		t.Error("CredentialSvc() should not be nil")
	}

	// SessionSvc
	if m.SessionSvc() == nil {
		t.Error("SessionSvc() should not be nil")
	}

	// PortfolioSvc
	if m.PortfolioSvc() == nil {
		t.Error("PortfolioSvc() should not be nil")
	}

	// OrderSvc
	if m.OrderSvc() == nil {
		t.Error("OrderSvc() should not be nil")
	}

	// AlertSvc
	if m.AlertSvc() == nil {
		t.Error("AlertSvc() should not be nil")
	}

	// FamilyService (nil by default)
	if m.FamilyService() != nil {
		t.Error("FamilyService() should be nil by default")
	}

	// SetFamilyService / FamilyService
	fs := NewFamilyService(nil, nil, nil)
	m.SetFamilyService(fs)
	if m.FamilyService() != fs {
		t.Error("FamilyService() should return the set service")
	}

	// IsLocalMode (default is stdio)
	if !m.IsLocalMode() {
		t.Error("IsLocalMode() should return true for default config")
	}

	// ExternalURL
	if m.ExternalURL() != "" {
		t.Error("ExternalURL() should be empty by default")
	}

	// AdminSecretPath
	if m.AdminSecretPath() != "" {
		t.Error("AdminSecretPath() should be empty by default")
	}

	// DevMode
	if m.DevMode() {
		t.Error("DevMode() should be false by default")
	}

	// HasPreAuth
	if m.HasPreAuth() {
		t.Error("HasPreAuth() should be false when no global token set")
	}

	// HasGlobalCredentials
	if !m.HasGlobalCredentials() {
		t.Error("HasGlobalCredentials() should be true when key/secret set")
	}

	// APIKey
	if m.APIKey() != "test_key" {
		t.Errorf("APIKey() = %q, want %q", m.APIKey(), "test_key")
	}

	// TokenStore
	if m.TokenStore() == nil {
		t.Error("TokenStore() should not be nil")
	}

	// TokenStoreConcrete
	if m.TokenStoreConcrete() == nil {
		t.Error("TokenStoreConcrete() should not be nil")
	}

	// CredentialStore
	if m.CredentialStore() == nil {
		t.Error("CredentialStore() should not be nil")
	}

	// CredentialStoreConcrete
	if m.CredentialStoreConcrete() == nil {
		t.Error("CredentialStoreConcrete() should not be nil")
	}

	// AlertStore
	if m.AlertStore() == nil {
		t.Error("AlertStore() should not be nil")
	}

	// AlertStoreConcrete
	if m.AlertStoreConcrete() == nil {
		t.Error("AlertStoreConcrete() should not be nil")
	}

	// TelegramStore
	if m.TelegramStore() == nil {
		t.Error("TelegramStore() should not be nil")
	}

	// TickerService (nil because no ticker configured)
	// Just check no panic
	_ = m.TickerService()
	_ = m.TickerServiceConcrete()

	// InstrumentsManager
	if m.InstrumentsManager() == nil {
		t.Error("InstrumentsManager() should not be nil")
	}
	if m.InstrumentsManagerConcrete() == nil {
		t.Error("InstrumentsManagerConcrete() should not be nil")
	}

	// TelegramNotifier (nil because no telegram configured)
	if m.TelegramNotifier() != nil {
		t.Error("TelegramNotifier() should be nil by default")
	}

	// IsTokenValid
	if m.IsTokenValid("user@example.com") {
		t.Error("IsTokenValid should be false for unknown email")
	}

	// TrailingStopManager
	if m.TrailingStopManager() == nil {
		t.Error("TrailingStopManager() should not be nil")
	}

	// PnLService (nil by default)
	if m.PnLService() != nil {
		t.Error("PnLService() should be nil by default")
	}

	// SetPnLService
	m.SetPnLService(nil)

	// MCPServer (nil by default)
	if m.MCPServer() != nil {
		t.Error("MCPServer() should be nil by default")
	}
	m.SetMCPServer("dummy")
	if m.MCPServer() != "dummy" {
		t.Error("MCPServer() should return what was set")
	}

	// AuditStore (nil by default)
	if m.AuditStore() != nil {
		t.Error("AuditStore() should be nil by default")
	}
	if m.AuditStoreConcrete() != nil {
		t.Error("AuditStoreConcrete() should be nil by default")
	}
	m.SetAuditStore(nil)

	// RiskGuard (nil by default)
	if m.RiskGuard() != nil {
		t.Error("RiskGuard() should be nil by default")
	}
	m.SetRiskGuard(nil)

	// PaperEngine (nil by default)
	if m.PaperEngine() != nil {
		t.Error("PaperEngine() should be nil by default")
	}
	if m.PaperEngineConcrete() != nil {
		t.Error("PaperEngineConcrete() should be nil by default")
	}
	m.SetPaperEngine(nil)

	// BillingStore (nil by default)
	if m.BillingStore() != nil {
		t.Error("BillingStore() should be nil by default")
	}
	if m.BillingStoreConcrete() != nil {
		t.Error("BillingStoreConcrete() should be nil by default")
	}
	m.SetBillingStore(nil)

	// InvitationStore (nil by default)
	if m.InvitationStore() != nil {
		t.Error("InvitationStore() should be nil by default")
	}
	m.SetInvitationStore(nil)

	// EventDispatcher (nil by default)
	if m.EventDispatcher() != nil {
		t.Error("EventDispatcher() should be nil by default")
	}
	m.SetEventDispatcher(nil)

	// EventStoreConcrete (nil by default)
	if m.EventStoreConcrete() != nil {
		t.Error("EventStoreConcrete() should be nil by default")
	}
	m.SetEventStore(nil)

	// WatchlistStore
	if m.WatchlistStore() == nil {
		t.Error("WatchlistStore() should not be nil")
	}
	if m.WatchlistStoreConcrete() == nil {
		t.Error("WatchlistStoreConcrete() should not be nil")
	}

	// UserStore (nil by default — not set in test config)
	_ = m.UserStore()
	_ = m.UserStoreConcrete()

	// RegistryStore (nil by default)
	_ = m.RegistryStore()
	_ = m.RegistryStoreConcrete()

	// HasUserCredentials
	if m.HasUserCredentials("user@example.com") {
		t.Error("HasUserCredentials should be false for unknown user")
	}

	// GetAPIKeyForEmail (falls back to global)
	if m.GetAPIKeyForEmail("user@example.com") != "test_key" {
		t.Errorf("GetAPIKeyForEmail = %q, want %q", m.GetAPIKeyForEmail("user@example.com"), "test_key")
	}

	// GetAPISecretForEmail (falls back to global)
	if m.GetAPISecretForEmail("user@example.com") != "test_secret" {
		t.Errorf("GetAPISecretForEmail = %q, want %q", m.GetAPISecretForEmail("user@example.com"), "test_secret")
	}

	// GetAccessTokenForEmail (no token)
	if m.GetAccessTokenForEmail("user@example.com") != "" {
		t.Error("GetAccessTokenForEmail should return empty for unknown user (no global token)")
	}

	// HasCachedToken
	if m.HasCachedToken("user@example.com") {
		t.Error("HasCachedToken should be false for unknown user")
	}

	// HasMetrics (no metrics store by default)
	if m.HasMetrics() {
		t.Error("HasMetrics should be false by default")
	}

	// AlertDB
	if m.AlertDB() != nil {
		t.Error("AlertDB should be nil by default")
	}
}

// ===========================================================================
// Manager — truncKey
// ===========================================================================

func TestTruncKey(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		n     int
		want  string
	}{
		{"abcdefgh", 4, "abcd"},
		{"abc", 4, "abc"},
		{"abcd", 4, "abcd"},
		{"", 4, ""},
	}
	for _, tc := range tests {
		got := truncKey(tc.input, tc.n)
		if got != tc.want {
			t.Errorf("truncKey(%q, %d) = %q, want %q", tc.input, tc.n, got, tc.want)
		}
	}
}

// ===========================================================================
// ManagedSessionService
// ===========================================================================

func TestManagedSessionService(t *testing.T) {
	t.Parallel()

	// Nil registry
	svc := NewManagedSessionService(nil)
	if svc.ActiveCount() != 0 {
		t.Errorf("ActiveCount with nil registry = %d, want 0", svc.ActiveCount())
	}
	if svc.TerminateByEmail("user@example.com") != 0 {
		t.Error("TerminateByEmail with nil registry should return 0")
	}
	if svc.Registry() != nil {
		t.Error("Registry should be nil")
	}

	// With registry
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	reg := m.SessionManager()
	svc2 := NewManagedSessionService(reg)
	if svc2.Registry() != reg {
		t.Error("Registry() should return the configured registry")
	}
	if svc2.ActiveCount() != 0 {
		t.Errorf("ActiveCount with empty registry = %d, want 0", svc2.ActiveCount())
	}
}

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

// ===========================================================================
// SessionSigner — SetSignatureExpiry, VerifySessionID, VerifyRedirectParams, getSecretKey
// ===========================================================================

func TestSessionSigner_SetSignatureExpiry(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("NewSessionSigner error: %v", err)
	}

	signer.SetSignatureExpiry(1 * time.Hour)

	// Sign and verify should still work
	signed := signer.SignSessionID("test-session-123")
	sessionID, err := signer.VerifySessionID(signed)
	if err != nil {
		t.Fatalf("VerifySessionID error: %v", err)
	}
	if sessionID != "test-session-123" {
		t.Errorf("sessionID = %q, want %q", sessionID, "test-session-123")
	}
}

func TestSessionSigner_VerifySessionID_InvalidFormat(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	// No dot separator
	_, err := signer.VerifySessionID("noseparator")
	if err == nil {
		t.Error("Expected error for invalid format")
	}

	// Invalid base64
	_, err = signer.VerifySessionID("payload.!!!invalid-base64!!!")
	if err == nil {
		t.Error("Expected error for invalid base64")
	}

	// Tampered signature
	signed := signer.SignSessionID("test-session")
	tampered := signed[:len(signed)-5] + "XXXXX"
	_, err = signer.VerifySessionID(tampered)
	if err == nil {
		t.Error("Expected error for tampered signature")
	}
}

func TestSessionSigner_VerifyRedirectParams(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	// Invalid format (no session_id= prefix)
	_, err := signer.VerifyRedirectParams("invalid=xxx")
	if err == nil {
		t.Error("Expected error for missing session_id= prefix")
	}

	// Empty value
	_, err = signer.VerifyRedirectParams("session_id=")
	if err == nil {
		t.Error("Expected error for empty session_id value")
	}
}

func TestSessionSigner_GetSecretKey(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	key := signer.getSecretKey()
	if len(key) != 32 {
		t.Errorf("key length = %d, want 32", len(key))
	}

	// Should return a copy (modifying it should not affect the signer)
	key[0] = 0xFF
	key2 := signer.getSecretKey()
	if key[0] == key2[0] {
		t.Error("getSecretKey should return a copy")
	}
}

// ===========================================================================
// Manager — more accessor tests for remaining 0% methods
// ===========================================================================

func TestManager_MoreAccessors(t *testing.T) {
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// NewManager (deprecated constructor)
	m2, err := NewManager("k", "s", testLogger())
	if err != nil {
		t.Fatalf("NewManager error: %v", err)
	}
	m2.Shutdown()

	// GetOrCreateSessionWithEmail - use an existing session but clear its data first
	sessionID := m.GenerateSession()
	// Clear data to force re-creation
	m.sessionManager.UpdateSessionData(sessionID, nil)
	kd, _, err := m.GetOrCreateSessionWithEmail(sessionID, "test@example.com")
	if err != nil {
		t.Fatalf("GetOrCreateSessionWithEmail error: %v", err)
	}
	if kd == nil {
		t.Error("Expected non-nil session data")
	}

	// ClearSessionData
	sessionID2 := m.GenerateSession()
	err = m.ClearSessionData(sessionID2)
	if err != nil {
		t.Fatalf("ClearSessionData error: %v", err)
	}

	// IncrementMetric (no-op when metrics is nil)
	m.IncrementMetric("test_metric")

	// TrackDailyUser (no-op when metrics is nil)
	m.TrackDailyUser("user1")

	// IncrementDailyMetric (no-op when metrics is nil)
	m.IncrementDailyMetric("daily_test")

	// ManagedSessionSvc
	if m.ManagedSessionSvc() == nil {
		t.Error("ManagedSessionSvc should not be nil")
	}

	// SessionSigner
	if m.SessionSigner() == nil {
		t.Error("SessionSigner should not be nil")
	}

	// UpdateSessionSignerExpiry
	m.UpdateSessionSignerExpiry(1 * time.Hour)

	// GetInstrumentsStats
	stats := m.GetInstrumentsStats()
	_ = stats // just verify no panic

	// ForceInstrumentsUpdate (may fail but shouldn't panic)
	_ = m.ForceInstrumentsUpdate()
}

// ===========================================================================
// SessionRegistry — TerminateByEmail, UpdateSessionField
// ===========================================================================

func TestSessionRegistry_TerminateByEmail(t *testing.T) {
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	sm := m.SessionManager()

	// Create sessions and set email data
	id1 := sm.Generate()
	id2 := sm.Generate()
	id3 := sm.Generate()

	// Set email on sessions via GetOrCreateSessionData
	sm.GetOrCreateSessionData(id1, func() any {
		kd := &KiteSessionData{Email: "user@example.com"}
		kd.Kite = NewKiteConnect("test_key")
		return kd
	})
	sm.GetOrCreateSessionData(id2, func() any {
		kd := &KiteSessionData{Email: "user@example.com"}
		kd.Kite = NewKiteConnect("test_key")
		return kd
	})
	sm.GetOrCreateSessionData(id3, func() any {
		kd := &KiteSessionData{Email: "other@example.com"}
		kd.Kite = NewKiteConnect("test_key")
		return kd
	})

	count := sm.TerminateByEmail("user@example.com")
	if count != 2 {
		t.Errorf("TerminateByEmail returned %d, want 2", count)
	}

	// user@example.com sessions should be terminated
	isTerminated1, err1 := sm.Validate(id1)
	if err1 != nil {
		t.Errorf("Validate(id1) unexpected error: %v", err1)
	}
	if !isTerminated1 {
		t.Error("Session id1 should be terminated")
	}

	// other@example.com should still be valid (not terminated)
	isTerminated3, err3 := sm.Validate(id3)
	if err3 != nil {
		t.Errorf("Validate(id3) unexpected error: %v", err3)
	}
	if isTerminated3 {
		t.Error("Session id3 should not be terminated")
	}
}

func TestSessionRegistry_UpdateSessionField(t *testing.T) {
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	sm := m.SessionManager()
	id := sm.Generate()

	// Set initial data
	sm.GetOrCreateSessionData(id, func() any {
		return &KiteSessionData{Email: "user@example.com"}
	})

	// Update a field
	err = sm.UpdateSessionField(id, func(data any) {
		if kd, ok := data.(*KiteSessionData); ok {
			kd.Email = "updated@example.com"
		}
	})
	if err != nil {
		t.Fatalf("UpdateSessionField error: %v", err)
	}

	// Verify update
	data, err := sm.GetSessionData(id)
	if err != nil {
		t.Fatalf("GetSessionData error: %v", err)
	}
	kd := data.(*KiteSessionData)
	if kd.Email != "updated@example.com" {
		t.Errorf("Email = %q, want %q", kd.Email, "updated@example.com")
	}

	// UpdateSessionField on nonexistent session
	err = sm.UpdateSessionField("nonexistent", func(data any) {})
	if err == nil {
		t.Error("Expected error for nonexistent session")
	}
}
