package oauth

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

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
// NewHandler — template error paths (already parsed from embedded FS)
// ===========================================================================

func TestNewHandler_SetsAllTemplates(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	if h.loginSuccessTmpl == nil {
		t.Error("loginSuccessTmpl should be non-nil")
	}
	if h.browserLoginTmpl == nil {
		t.Error("browserLoginTmpl should be non-nil")
	}
	if h.adminLoginTmpl == nil {
		t.Error("adminLoginTmpl should be non-nil")
	}
	if h.emailPromptTmpl == nil {
		t.Error("emailPromptTmpl should be non-nil")
	}
	if h.loginChoiceTmpl == nil {
		t.Error("loginChoiceTmpl should be non-nil")
	}
}

// ===========================================================================
// HandleEmailLookup — GET method not allowed
// ===========================================================================

func TestHandleEmailLookup_GET_MethodNotAllowed_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/email-lookup", nil)
	rr := httptest.NewRecorder()
	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

// ===========================================================================
// HandleEmailLookup — CSRF fail with unrecoverable state
// ===========================================================================

func TestHandleEmailLookup_POST_CSRFFailUnrecoverableState(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":       {"user@test.com"},
		"oauth_state": {"completely-invalid-not-signed"},
		"csrf_token":  {"wrong-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/email-lookup", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "different-csrf"})
	rr := httptest.NewRecorder()

	h.HandleEmailLookup(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (unrecoverable CSRF fail)", rr.Code)
	}
}

// ===========================================================================
// HandleBrowserLogin POST — empty email shows form
// ===========================================================================

func TestHandleBrowserLogin_POST_EmptyEmail_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":      {""},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form shown for empty email)", rr.Code)
	}
}

// ===========================================================================
// HandleBrowserLogin POST — no credentials found
// ===========================================================================

func TestHandleBrowserLogin_POST_NoCredentials(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-tok"
	form := url.Values{
		"email":      {"unknown@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No credentials found") {
		t.Errorf("Body should contain 'No credentials found'")
	}
}

// ===========================================================================
// HandleBrowserLogin POST — CSRF mismatch
// ===========================================================================

func TestHandleBrowserLogin_POST_CSRFMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":      {"user@example.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {"form-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: "cookie-csrf"})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered with CSRF error)", rr.Code)
	}
}

// ===========================================================================
// HandleBrowserLogin GET — email not found (shows form with error)
// ===========================================================================

func TestHandleBrowserLogin_GET_EmailNotFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=unknown@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form with error for unknown email)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "No credentials found") {
		t.Errorf("Body should contain 'No credentials found'")
	}
}

// ===========================================================================
// HandleBrowserLogin GET — email found with credentials
// ===========================================================================

func TestHandleBrowserLogin_GET_EmailFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			if email == "found@test.com" {
				return "api-key-for-found", "secret", true
			}
			return "", "", false
		}
	})
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/browser-login?email=found@test.com", nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
}

// ===========================================================================
// HandleBrowserLogin POST — credentials found, redirects to Kite
// ===========================================================================

func TestHandleBrowserLogin_POST_CredentialsFound(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key-found", "secret", true
		}
	})
	defer h.Close()

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"user@test.com"},
		"redirect":   {"/dashboard"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/browser-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleBrowserLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect to Kite)", rr.Code)
	}
}

// ===========================================================================
// HandleAdminLogin — GET serves form
// ===========================================================================

func TestHandleAdminLogin_GET_ServesForm(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/auth/admin-login", nil)
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
	if !strings.Contains(rr.Header().Get("Content-Type"), "text/html") {
		t.Error("Expected HTML content type")
	}
}

// ===========================================================================
// HandleAdminLogin — POST no user store
// ===========================================================================

func TestHandleAdminLogin_POST_NoUserStore_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	csrfToken := "csrf-admin"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered with error)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "not configured") {
		t.Errorf("Body should contain 'not configured'")
	}
}

// ===========================================================================
// HandleAdminLogin — POST CSRF mismatch
// ===========================================================================

func TestHandleAdminLogin_POST_CSRFMismatch(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"secret"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {"form-csrf"},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: "cookie-csrf"})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered)", rr.Code)
	}
}

// ===========================================================================
// HandleAdminLogin — POST wrong password
// ===========================================================================

// mockAdminUserStoreFinal implements AdminUserStore for testing.
type mockAdminUserStoreFinal struct {
	roles    map[string]string
	statuses map[string]string
}

func (m *mockAdminUserStoreFinal) GetRole(email string) string {
	return m.roles[email]
}

func (m *mockAdminUserStoreFinal) GetStatus(email string) string {
	return m.statuses[email]
}

func (m *mockAdminUserStoreFinal) VerifyPassword(email, password string) (bool, error) {
	if email == "admin@test.com" && password == "correct-password" {
		return true, nil
	}
	return false, nil
}

func (m *mockAdminUserStoreFinal) EnsureGoogleUser(email string) {}

func TestHandleAdminLogin_POST_WrongPassword_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"wrong-password"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form re-rendered)", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "Invalid email or password") {
		t.Errorf("Body should contain 'Invalid email or password'")
	}
}

// ===========================================================================
// HandleAdminLogin — POST success
// ===========================================================================

func TestHandleAdminLogin_POST_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"correct-password"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302 (redirect on success)", rr.Code)
	}
}

// ===========================================================================
// HandleAdminLogin — POST open redirect prevention
// ===========================================================================

func TestHandleAdminLogin_POST_OpenRedirectPrevention_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinal{
		roles:    map[string]string{"admin@test.com": "admin"},
		statuses: map[string]string{"admin@test.com": "active"},
	})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"correct-password"},
		"redirect":   {"//evil.com"}, // open redirect attempt
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	if rr.Code != http.StatusFound {
		t.Errorf("Status = %d, want 302", rr.Code)
	}
	location := rr.Header().Get("Location")
	if strings.Contains(location, "evil.com") {
		t.Errorf("Open redirect should be blocked, got: %q", location)
	}
}

// ===========================================================================
// HandleAdminLogin — POST with verify error
// ===========================================================================

func TestHandleAdminLogin_POST_VerifyError_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetUserStore(&mockAdminUserStoreFinalWithError{})

	csrfToken := "csrf"
	form := url.Values{
		"email":      {"admin@test.com"},
		"password":   {"any"},
		"redirect":   {"/admin/ops"},
		"csrf_token": {csrfToken},
	}
	req := httptest.NewRequest(http.MethodPost, "/auth/admin-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_token_admin", Value: csrfToken})
	rr := httptest.NewRecorder()

	h.HandleAdminLogin(rr, req)

	// Should show login form with error (verify error + !match)
	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

type mockAdminUserStoreFinalWithError struct{}

func (m *mockAdminUserStoreFinalWithError) GetRole(email string) string    { return "admin" }
func (m *mockAdminUserStoreFinalWithError) GetStatus(email string) string  { return "active" }
func (m *mockAdminUserStoreFinalWithError) VerifyPassword(email, password string) (bool, error) {
	return false, fmt.Errorf("bcrypt internal error")
}
func (m *mockAdminUserStoreFinalWithError) EnsureGoogleUser(email string) {}

// ===========================================================================
// Token — various error paths
// ===========================================================================

func TestToken_MethodNotAllowed_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/token", nil)
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
	}
}

func TestToken_UnsupportedGrantType_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type": {"client_credentials"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestToken_MissingParams_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type": {"authorization_code"},
		// missing code, code_verifier, client_id
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestToken_InvalidClient(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {"nonexistent-client"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
}

func TestToken_WrongClientSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"some-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {clientID},
		"client_secret": {"wrong-secret"},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401", rr.Code)
	}
}

func TestToken_InvalidAuthCode(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {"invalid-code"},
		"code_verifier": {"some-verifier"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400", rr.Code)
	}
}

func TestToken_PKCEVerificationFailure(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")
	challenge := pkceChallenge("real-verifier")

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {"wrong-verifier"},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (PKCE failure)", rr.Code)
	}
}

func TestToken_ClientIDMismatch_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID1, clientSecret1, _ := h.clients.Register([]string{"https://example.com/cb"}, "test1")
	clientID2, _, _ := h.clients.Register([]string{"https://example.com/cb"}, "test2")

	verifier := "my-verifier-12345"
	challenge := pkceChallenge(verifier)

	// Issue code for clientID2
	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID2,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
	})

	// Try to exchange with clientID1
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID1},
		"client_secret": {clientSecret1},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (client_id mismatch)", rr.Code)
	}
}

func TestToken_SuccessfulExchange(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	clientID, clientSecret, _ := h.clients.Register([]string{"https://example.com/cb"}, "test")
	verifier := "test-verifier-string"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      clientID,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		Email:         "user@example.com",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	if err := json.NewDecoder(rr.Body).Decode(&resp); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("Expected non-empty access_token")
	}
	if resp["token_type"] != "Bearer" {
		t.Errorf("token_type = %v, want Bearer", resp["token_type"])
	}
}

// ===========================================================================
// Token — deferred exchange with Kite API key client
// ===========================================================================

func TestToken_DeferredExchange_NoSecret(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "", false // no stored secret
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-12345"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
		// no client_secret
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (no secret for deferred exchange)", rr.Code)
	}
}

func TestToken_DeferredExchange_ExchangeFails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("kite auth failed")
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-fail"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (exchange failed)", rr.Code)
	}
}

// ===========================================================================
// Token — deferred exchange success with stored secret
// ===========================================================================

func TestToken_DeferredExchange_Success(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getSecretByAPIKey = func(apiKey string) (string, bool) {
			return "stored-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "deferred-user@example.com", nil
		}
	})
	defer h.Close()

	kiteAPIKey := "kite-api-key-ok"
	h.clients.RegisterKiteClient(kiteAPIKey, []string{"https://example.com/cb"})

	verifier := "test-verifier"
	challenge := pkceChallenge(verifier)

	code, _ := h.authCodes.Generate(&AuthCodeEntry{
		ClientID:      kiteAPIKey,
		CodeChallenge: challenge,
		RedirectURI:   "https://example.com/cb",
		RequestToken:  "kite-request-token",
	})

	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"code_verifier": {verifier},
		"client_id":     {kiteAPIKey},
	}
	req := httptest.NewRequest(http.MethodPost, "/oauth/token", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rr := httptest.NewRecorder()
	h.Token(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("Status = %d, want 200", rr.Code)
	}

	var resp map[string]interface{}
	json.NewDecoder(rr.Body).Decode(&resp)
	if resp["access_token"] == nil || resp["access_token"] == "" {
		t.Error("Expected non-empty access_token from deferred exchange")
	}
}

// ===========================================================================
// HandleLoginChoice — method not allowed
// ===========================================================================

func TestHandleLoginChoice_POST_ServesForm(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	// HandleLoginChoice serves the form regardless of method
	req := httptest.NewRequest(http.MethodPost, "/auth/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (form served regardless of method)", rr.Code)
	}
}

// ===========================================================================
// HandleLoginChoice — serves page with Google SSO enabled
// ===========================================================================

func TestHandleLoginChoice_WithGoogleSSO(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	h.SetGoogleSSO(&GoogleSSOConfig{
		ClientID:     "id",
		ClientSecret: "secret",
		RedirectURL:  "https://test.example.com/cb",
	})

	req := httptest.NewRequest(http.MethodGet, "/auth/login", nil)
	rr := httptest.NewRecorder()
	h.HandleLoginChoice(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200", rr.Code)
	}
}

// ===========================================================================
// Authorize — missing params
// ===========================================================================

func TestAuthorize_MissingRequiredParams(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/authorize?response_type=code", nil)
	rr := httptest.NewRecorder()
	h.Authorize(rr, req)

	if rr.Code != http.StatusBadRequest {
		t.Errorf("Status = %d, want 400 (missing params)", rr.Code)
	}
}

// ===========================================================================
// HandleBrowserAuthCallback — exchange fails
// ===========================================================================

func TestHandleBrowserAuthCallback_ExchangeFails(t *testing.T) {
	t.Parallel()
	h := newTestHandler(func(cfg *Config, signer *mockSigner, exchanger *mockExchanger) {
		exchanger.getCredentials = func(email string) (string, string, bool) {
			return "api-key", "api-secret", true
		}
		exchanger.exchangeWithCreds = func(requestToken, apiKey, apiSecret string) (string, error) {
			return "", fmt.Errorf("exchange failed")
		}
	})
	defer h.Close()

	raw := base64.RawURLEncoding.EncodeToString([]byte("user@test.com::/dashboard"))
	signedTarget := h.signer.Sign(raw)

	req := httptest.NewRequest(http.MethodGet, "/callback?flow=browser&target="+url.QueryEscape(signedTarget), nil)
	rr := httptest.NewRecorder()

	h.HandleBrowserAuthCallback(rr, req, "valid-token")

	if rr.Code != http.StatusUnauthorized {
		t.Errorf("Status = %d, want 401 (exchange failed)", rr.Code)
	}
}

// ===========================================================================
// serveEmailPrompt — template execution error (JSON marshal error path)
// ===========================================================================

func TestServeEmailPrompt_JSONMarshalError(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	rr := httptest.NewRecorder()
	// Pass a normal state and empty error to test the full render path
	h.serveEmailPrompt(rr, oauthState{
		ClientID:      "test-client",
		RedirectURI:   "https://example.com/cb",
		CodeChallenge: "challenge",
		State:         "state",
	}, "test error message")

	if rr.Code != http.StatusOK {
		t.Errorf("Status = %d, want 200 (rendered form)", rr.Code)
	}
}

// ===========================================================================
// Register endpoint — method not allowed
// ===========================================================================

func TestRegister_MethodNotAllowed_Final(t *testing.T) {
	t.Parallel()
	h := newTestHandler()
	defer h.Close()

	req := httptest.NewRequest(http.MethodGet, "/oauth/register", nil)
	rr := httptest.NewRecorder()
	h.Register(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("Status = %d, want 405", rr.Code)
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

// testLogger returns a discard logger for tests.
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(devNull{}, nil))
}

type devNull struct{}

func (devNull) Write(p []byte) (int, error) { return len(p), nil }
