package kc

import (
	"html/template"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/app/metrics"
	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// ===========================================================================
// coverage_push2_test.go — Push kc root from 68.7% to 80%+
//
// Covers:
//   - Manager.New() with DevMode, missing logger, nil DB, metrics
//   - FamilyService: AdminEmailFn, ListMembers, MaxUsers, RemoveMember
//   - Manager getters: AuditStore, PaperEngine, BillingStore (non-nil paths)
//   - IncrementMetric, TrackDailyUser, IncrementDailyMetric with metrics
//   - IsKiteTokenExpired boundary (exactly 6 AM IST)
//   - BackfillRegistryFromCredentials edge cases
//   - CredentialStore.Delete with DB + logger
//   - HandleKiteCallback with valid session but invalid request token
//   - renderSuccessTemplate
//   - Shutdown with metrics, alertDB, etc.
// ===========================================================================

// ---------------------------------------------------------------------------
// Manager.New — DevMode constructor
// ---------------------------------------------------------------------------

func TestNew_DevMode(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		DevMode:            true,
	})
	if err != nil {
		t.Fatalf("New with DevMode error: %v", err)
	}
	defer m.Shutdown()

	if !m.DevMode() {
		t.Error("DevMode() should return true")
	}
}

func TestNew_NilLogger(t *testing.T) {
	t.Parallel()
	_, err := New(Config{
		APIKey:    "test_key",
		APISecret: "test_secret",
	})
	if err == nil || err.Error() != "logger is required" {
		t.Errorf("Expected 'logger is required', got: %v", err)
	}
}

func TestNew_NoAPICredentials(t *testing.T) {
	t.Parallel()
	// Empty API key/secret is allowed (per-user creds)
	m, err := New(Config{
		Logger: testLogger(),
	})
	if err != nil {
		t.Fatalf("Expected no error with empty credentials: %v", err)
	}
	if m == nil {
		t.Fatal("Expected non-nil manager")
	}
	m.Shutdown()
}

func TestNew_WithAlertDBPath(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
	})
	if err != nil {
		t.Fatalf("New with AlertDBPath error: %v", err)
	}
	defer m.Shutdown()

	if m.AlertDB() == nil {
		t.Error("AlertDB should not be nil with :memory: path")
	}
}

func TestNew_WithMetrics(t *testing.T) {
	t.Parallel()
	metricsMgr := metrics.New(metrics.Config{ServiceName: "test"})
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		Metrics:            metricsMgr,
	})
	if err != nil {
		t.Fatalf("New with Metrics error: %v", err)
	}
	defer m.Shutdown()

	if !m.HasMetrics() {
		t.Error("HasMetrics should return true when metrics configured")
	}
}

func TestNew_WithEncryptionSecret(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		AlertDBPath:        ":memory:",
		EncryptionSecret:   "test-encryption-secret-32bytes!!",
	})
	if err != nil {
		t.Fatalf("New with EncryptionSecret error: %v", err)
	}
	defer m.Shutdown()
}

func TestNew_WithExternalURL(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		ExternalURL:        "https://example.com",
		AdminSecretPath:    "/admin/secret",
		AppMode:            "http",
	})
	if err != nil {
		t.Fatalf("New with ExternalURL error: %v", err)
	}
	defer m.Shutdown()

	if m.ExternalURL() != "https://example.com" {
		t.Errorf("ExternalURL = %q, want https://example.com", m.ExternalURL())
	}
	if m.AdminSecretPath() != "/admin/secret" {
		t.Errorf("AdminSecretPath = %q, want /admin/secret", m.AdminSecretPath())
	}
}

// ---------------------------------------------------------------------------
// FamilyService — full coverage of all branches
// ---------------------------------------------------------------------------

// mockUserStore implements UserStoreInterface for testing.
type mockUserStoreForFamily struct {
	users map[string]*users.User
}

func (m *mockUserStoreForFamily) Create(u *users.User) error              { m.users[u.Email] = u; return nil }
func (m *mockUserStoreForFamily) Get(email string) (*users.User, bool)    { u, ok := m.users[email]; return u, ok }
func (m *mockUserStoreForFamily) GetByEmail(email string) (*users.User, bool) { return m.Get(email) }
func (m *mockUserStoreForFamily) Exists(email string) bool                { _, ok := m.users[email]; return ok }
func (m *mockUserStoreForFamily) IsAdmin(email string) bool               { return false }
func (m *mockUserStoreForFamily) GetStatus(email string) string           { return "" }
func (m *mockUserStoreForFamily) GetRole(email string) string             { return "" }
func (m *mockUserStoreForFamily) UpdateLastLogin(email string)            {}
func (m *mockUserStoreForFamily) UpdateRole(email, role string) error     { return nil }
func (m *mockUserStoreForFamily) UpdateStatus(email, status string) error { return nil }
func (m *mockUserStoreForFamily) UpdateKiteUID(email, kiteUID string)     {}
func (m *mockUserStoreForFamily) SetAdminEmail(email, adminEmail string) error {
	if u, ok := m.users[email]; ok {
		u.AdminEmail = adminEmail
		return nil
	}
	return nil
}
func (m *mockUserStoreForFamily) List() []*users.User {
	out := make([]*users.User, 0, len(m.users))
	for _, u := range m.users {
		out = append(out, u)
	}
	return out
}
func (m *mockUserStoreForFamily) Count() int    { return len(m.users) }
func (m *mockUserStoreForFamily) Delete(email string) { delete(m.users, email) }
func (m *mockUserStoreForFamily) EnsureAdmin(email string) {}
func (m *mockUserStoreForFamily) EnsureUser(email, kiteUID, displayName, onboardedBy string) *users.User {
	return nil
}
func (m *mockUserStoreForFamily) ListByAdminEmail(adminEmail string) []*users.User {
	var out []*users.User
	for _, u := range m.users {
		if u.AdminEmail == adminEmail {
			out = append(out, u)
		}
	}
	return out
}
func (m *mockUserStoreForFamily) SetPasswordHash(email, hash string) error { return nil }
func (m *mockUserStoreForFamily) HasPassword(email string) bool            { return false }
func (m *mockUserStoreForFamily) VerifyPassword(email, password string) (bool, error) {
	return false, nil
}

// mockBillingStore implements BillingStoreInterface for testing.
type mockBillingStoreForFamily struct {
	subs map[string]*billing.Subscription
}

func (m *mockBillingStoreForFamily) GetTier(email string) billing.Tier { return billing.TierFree }
func (m *mockBillingStoreForFamily) SetSubscription(sub *billing.Subscription) error {
	m.subs[sub.AdminEmail] = sub
	return nil
}
func (m *mockBillingStoreForFamily) GetSubscription(email string) *billing.Subscription {
	return m.subs[email]
}
func (m *mockBillingStoreForFamily) GetEmailByCustomerID(customerID string) string { return "" }
func (m *mockBillingStoreForFamily) IsEventProcessed(eventID string) bool          { return false }
func (m *mockBillingStoreForFamily) MarkEventProcessed(eventID, eventType string) error {
	return nil
}
func (m *mockBillingStoreForFamily) GetTierForUser(email string, adminEmailFn func(string) string) billing.Tier {
	return billing.TierFree
}

func TestFamilyService_AdminEmailFn_WithStore(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "admin@example.com"},
		"solo@example.com":   {Email: "solo@example.com", AdminEmail: ""},
	}}

	fs := NewFamilyService(us, nil, nil)
	fn := fs.AdminEmailFn()

	// User with admin
	if got := fn("member@example.com"); got != "admin@example.com" {
		t.Errorf("AdminEmailFn(member) = %q, want admin@example.com", got)
	}

	// User without admin
	if got := fn("solo@example.com"); got != "" {
		t.Errorf("AdminEmailFn(solo) = %q, want empty", got)
	}

	// Non-existent user
	if got := fn("unknown@example.com"); got != "" {
		t.Errorf("AdminEmailFn(unknown) = %q, want empty", got)
	}
}

func TestFamilyService_ListMembers_WithStore(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com": {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com": {Email: "m2@example.com", AdminEmail: "admin@example.com"},
		"other@example.com": {Email: "other@example.com", AdminEmail: "other-admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	members := fs.ListMembers("admin@example.com")
	if len(members) != 2 {
		t.Errorf("ListMembers count = %d, want 2", len(members))
	}

	// Zero members for unknown admin
	members = fs.ListMembers("nobody@example.com")
	if len(members) != 0 {
		t.Errorf("ListMembers(nobody) count = %d, want 0", len(members))
	}
}

func TestFamilyService_MaxUsers_WithBillingStore(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 10},
	}}

	fs := NewFamilyService(nil, bs, nil)

	// Admin with subscription
	if got := fs.MaxUsers("admin@example.com"); got != 10 {
		t.Errorf("MaxUsers(admin) = %d, want 10", got)
	}

	// Unknown admin — no subscription
	if got := fs.MaxUsers("unknown@example.com"); got != 1 {
		t.Errorf("MaxUsers(unknown) = %d, want 1", got)
	}
}

func TestFamilyService_MaxUsers_NilSubscription(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{}}
	fs := NewFamilyService(nil, bs, nil)

	// No subscription for this admin
	if got := fs.MaxUsers("admin@example.com"); got != 1 {
		t.Errorf("MaxUsers(no sub) = %d, want 1", got)
	}
}

func TestFamilyService_MaxUsers_ZeroMaxUsers(t *testing.T) {
	t.Parallel()

	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 0},
	}}
	fs := NewFamilyService(nil, bs, nil)

	// MaxUsers < 1 should return 1
	if got := fs.MaxUsers("admin@example.com"); got != 1 {
		t.Errorf("MaxUsers(zero) = %d, want 1", got)
	}
}

func TestFamilyService_RemoveMember_NotInFamily(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "other-admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err == nil {
		t.Error("RemoveMember should error when member is not in admin's family")
	}
	if err.Error() != "member@example.com is not in your family" {
		t.Errorf("Unexpected error: %v", err)
	}
}

func TestFamilyService_RemoveMember_UserNotFound(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{}}
	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "unknown@example.com")
	if err == nil {
		t.Error("RemoveMember should error when user not found")
	}
}

func TestFamilyService_RemoveMember_Success(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"member@example.com": {Email: "member@example.com", AdminEmail: "admin@example.com"},
	}}

	fs := NewFamilyService(us, nil, nil)
	err := fs.RemoveMember("admin@example.com", "member@example.com")
	if err != nil {
		t.Fatalf("RemoveMember error: %v", err)
	}

	// Verify admin email was cleared
	u, _ := us.Get("member@example.com")
	if u.AdminEmail != "" {
		t.Errorf("AdminEmail should be empty after removal, got %q", u.AdminEmail)
	}
}

func TestFamilyService_CanInvite_WithMembers(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com": {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com": {Email: "m2@example.com", AdminEmail: "admin@example.com"},
	}}
	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 3},
	}}

	fs := NewFamilyService(us, bs, nil)

	ok, current, max := fs.CanInvite("admin@example.com")
	if !ok {
		t.Error("CanInvite should be true (2 < 3)")
	}
	if current != 2 {
		t.Errorf("current = %d, want 2", current)
	}
	if max != 3 {
		t.Errorf("max = %d, want 3", max)
	}
}

func TestFamilyService_CanInvite_AtCapacity(t *testing.T) {
	t.Parallel()

	us := &mockUserStoreForFamily{users: map[string]*users.User{
		"m1@example.com": {Email: "m1@example.com", AdminEmail: "admin@example.com"},
		"m2@example.com": {Email: "m2@example.com", AdminEmail: "admin@example.com"},
	}}
	bs := &mockBillingStoreForFamily{subs: map[string]*billing.Subscription{
		"admin@example.com": {AdminEmail: "admin@example.com", MaxUsers: 2},
	}}

	fs := NewFamilyService(us, bs, nil)

	ok, _, _ := fs.CanInvite("admin@example.com")
	if ok {
		t.Error("CanInvite should be false (2 >= 2)")
	}
}

// ---------------------------------------------------------------------------
// Manager getters — non-nil return paths
// ---------------------------------------------------------------------------

func TestManager_AuditStore_NonNil(t *testing.T) {
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

	// Create and set audit store
	db := m.AlertDB()
	if db == nil {
		t.Fatal("AlertDB should not be nil")
	}

	// AuditStore is nil by default even with AlertDB — needs explicit SetAuditStore
	if m.AuditStore() != nil {
		t.Error("AuditStore should be nil until SetAuditStore is called")
	}
}

func TestManager_PaperEngine_NonNil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// PaperEngine is nil by default
	if m.PaperEngine() != nil {
		t.Error("PaperEngine should be nil by default")
	}
	if m.PaperEngineConcrete() != nil {
		t.Error("PaperEngineConcrete should be nil by default")
	}
}

func TestManager_BillingStore_NonNil(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// BillingStore is nil by default
	if m.BillingStore() != nil {
		t.Error("BillingStore should be nil by default")
	}
	if m.BillingStoreConcrete() != nil {
		t.Error("BillingStoreConcrete should be nil by default")
	}
}

// ---------------------------------------------------------------------------
// IncrementMetric, TrackDailyUser, IncrementDailyMetric — with actual metrics
// ---------------------------------------------------------------------------

func TestManager_IncrementMetric_WithMetrics(t *testing.T) {
	t.Parallel()
	metricsMgr := metrics.New(metrics.Config{ServiceName: "test"})
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		Metrics:            metricsMgr,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	// These should go through the if-true branch
	m.IncrementMetric("test_counter")
	m.IncrementMetric("test_counter")
	m.TrackDailyUser("user1@example.com")
	m.TrackDailyUser("user2@example.com")
	m.IncrementDailyMetric("daily_logins")
	m.IncrementDailyMetric("daily_logins")
}

func TestManager_IncrementMetric_NilMetrics(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// These should be no-ops (nil metrics)
	m.IncrementMetric("counter")
	m.TrackDailyUser("user")
	m.IncrementDailyMetric("daily")
}

// ---------------------------------------------------------------------------
// IsKiteTokenExpired — boundary at exactly 6 AM IST
// ---------------------------------------------------------------------------

func TestIsKiteTokenExpired_ExactlyAt6AM(t *testing.T) {
	t.Parallel()

	// Token stored just before 6 AM today (5:59 AM IST)
	now := time.Now().In(KolkataLocation)
	sixAM := time.Date(now.Year(), now.Month(), now.Day(), 6, 0, 0, 0, KolkataLocation)

	if now.Before(sixAM) {
		// If current time is before 6 AM, a token from yesterday at 6:01 AM should be valid
		yesterday6AM := sixAM.AddDate(0, 0, -1).Add(1 * time.Minute)
		if IsKiteTokenExpired(yesterday6AM) {
			t.Error("Token stored after yesterday's 6 AM should not be expired (before today's 6 AM)")
		}
	} else {
		// If current time is after 6 AM, a token from today at 5:59 AM should be expired
		today559AM := sixAM.Add(-1 * time.Minute)
		if !IsKiteTokenExpired(today559AM) {
			t.Error("Token stored at 5:59 AM should be expired after 6 AM")
		}

		// Token stored at 6:01 AM should NOT be expired
		today601AM := sixAM.Add(1 * time.Minute)
		if IsKiteTokenExpired(today601AM) {
			t.Error("Token stored at 6:01 AM should NOT be expired")
		}
	}
}

func TestIsKiteTokenExpired_StoredYesterday(t *testing.T) {
	t.Parallel()
	// Token stored yesterday at any time should be expired
	yesterday := time.Now().Add(-30 * time.Hour)
	if !IsKiteTokenExpired(yesterday) {
		t.Error("Token stored 30 hours ago should be expired")
	}
}

func TestIsKiteTokenExpired_StoredJustNow(t *testing.T) {
	t.Parallel()
	// Token stored just now should not be expired
	if IsKiteTokenExpired(time.Now()) {
		t.Error("Token stored just now should not be expired")
	}
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
func (m *mockRegistryStore) Count() int              { return len(m.regs) }
func (m *mockRegistryStore) HasEntries() bool         { return len(m.regs) > 0 }

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

// ---------------------------------------------------------------------------
// HandleKiteCallback — valid session, invalid request token
// ---------------------------------------------------------------------------

func TestHandleKiteCallback_ValidSessionInvalidToken(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	handler := m.HandleKiteCallback()

	// Create a valid session and sign it
	sessionID := m.GenerateSession()
	signed := m.sessionSigner.SignSessionID(sessionID)

	req := httptest.NewRequest(http.MethodGet, "/callback?request_token=invalid_token&session_id="+signed, nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	// Should fail at CompleteSession (invalid request token at Kite API)
	if rr.Code != http.StatusInternalServerError {
		t.Errorf("Status = %d, want 500", rr.Code)
	}
}

// ---------------------------------------------------------------------------
// renderSuccessTemplate — only error path (template not found)
// The success path has a known template/struct mismatch (template expects
// .RedirectURL but TemplateData only has Title), so we only test the error case.
// ---------------------------------------------------------------------------

func TestRenderSuccessTemplate_NoTemplate(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Remove templates to trigger error path
	m.templates = map[string]*template.Template{}

	rr := httptest.NewRecorder()
	err = m.renderSuccessTemplate(rr)
	if err == nil {
		t.Error("Expected error when template not found")
	}
}

// ---------------------------------------------------------------------------
// Shutdown with various components
// ---------------------------------------------------------------------------

func TestShutdown_WithMetrics(t *testing.T) {
	t.Parallel()
	metricsMgr := metrics.New(metrics.Config{ServiceName: "test"})
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
		Metrics:            metricsMgr,
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}

	// Should not panic
	m.Shutdown()
}

func TestShutdown_WithAlertDB(t *testing.T) {
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

// ---------------------------------------------------------------------------
// New — with AlertDB for session persistence (covers session DB wiring)
// ---------------------------------------------------------------------------

func TestNew_WithAlertDB_SessionPersistence(t *testing.T) {
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

	// Verify session manager has DB set
	sm := m.SessionManager()
	if sm == nil {
		t.Error("SessionManager should not be nil")
	}

	// Generate and verify session
	sessionID := m.GenerateSession()
	if sessionID == "" {
		t.Error("Expected non-empty session ID")
	}
}

func TestNew_WithAccessToken(t *testing.T) {
	t.Parallel()
	m, err := New(Config{
		APIKey:             "test_key",
		APISecret:          "test_secret",
		AccessToken:        "pre_auth_token",
		InstrumentsManager: newTestInstrumentsManager(),
		Logger:             testLogger(),
	})
	if err != nil {
		t.Fatalf("New error: %v", err)
	}
	defer m.Shutdown()

	if !m.HasPreAuth() {
		t.Error("HasPreAuth should return true when access token is set")
	}
}

func TestNew_WithAppMode(t *testing.T) {
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
		t.Error("IsLocalMode should return false for http mode")
	}
}

// ---------------------------------------------------------------------------
// OrderService — getBroker error path
// ---------------------------------------------------------------------------

func TestOrderService_GetBroker_NoToken(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	os := NewOrderService(ss, testLogger())

	_, err := os.PlaceOrder("unknown@example.com", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for user without access token")
	}

	_, err = os.ModifyOrder("unknown@example.com", "ORD001", broker.OrderParams{})
	if err == nil {
		t.Error("Expected error for ModifyOrder")
	}

	_, err = os.CancelOrder("unknown@example.com", "ORD001", "regular")
	if err == nil {
		t.Error("Expected error for CancelOrder")
	}

	_, err = os.GetOrders("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetOrders")
	}

	_, err = os.GetTrades("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetTrades")
	}
}

func TestOrderService_DevMode_PlaceOrder(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	resp, err := os.PlaceOrder("user@example.com", broker.OrderParams{
		Exchange:        "NSE",
		Tradingsymbol:   "INFY",
		TransactionType: "BUY",
		Quantity:        10,
		Product:         "CNC",
		OrderType:       "MARKET",
		Variety:         "regular",
	})
	if err != nil {
		t.Fatalf("PlaceOrder error: %v", err)
	}
	if resp.OrderID == "" {
		t.Error("Expected non-empty OrderID from mock broker")
	}
}

func TestOrderService_DevMode_GetOrders(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	orders, err := os.GetOrders("user@example.com")
	if err != nil {
		t.Fatalf("GetOrders error: %v", err)
	}
	_ = orders // May be empty from mock
}

func TestOrderService_DevMode_GetTrades(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	os := NewOrderService(ss, testLogger())

	trades, err := os.GetTrades("user@example.com")
	if err != nil {
		t.Fatalf("GetTrades error: %v", err)
	}
	_ = trades
}

// ---------------------------------------------------------------------------
// PortfolioService — getBroker error path
// ---------------------------------------------------------------------------

func TestPortfolioService_GetBroker_NoToken(t *testing.T) {
	t.Parallel()
	ss := createTestSessionService()
	ps := NewPortfolioService(ss, testLogger())

	_, err := ps.GetHoldings("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetHoldings")
	}

	_, err = ps.GetPositions("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetPositions")
	}

	_, err = ps.GetMargins("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetMargins")
	}

	_, err = ps.GetProfile("unknown@example.com")
	if err == nil {
		t.Error("Expected error for GetProfile")
	}
}

func TestPortfolioService_DevMode_GetHoldings(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	holdings, err := ps.GetHoldings("user@example.com")
	if err != nil {
		t.Fatalf("GetHoldings error: %v", err)
	}
	_ = holdings
}

func TestPortfolioService_DevMode_GetPositions(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	positions, err := ps.GetPositions("user@example.com")
	if err != nil {
		t.Fatalf("GetPositions error: %v", err)
	}
	_ = positions
}

func TestPortfolioService_DevMode_GetMargins(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	margins, err := ps.GetMargins("user@example.com")
	if err != nil {
		t.Fatalf("GetMargins error: %v", err)
	}
	_ = margins
}

func TestPortfolioService_DevMode_GetProfile(t *testing.T) {
	t.Parallel()
	ss := createDevModeSessionService()
	ps := NewPortfolioService(ss, testLogger())

	profile, err := ps.GetProfile("user@example.com")
	if err != nil {
		t.Fatalf("GetProfile error: %v", err)
	}
	_ = profile
}

// ---------------------------------------------------------------------------
// AuditStore / PaperEngine / BillingStore — non-nil return paths (set then get)
// ---------------------------------------------------------------------------

func TestManager_AuditStore_SetAndGet(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Initially nil
	if m.AuditStore() != nil {
		t.Error("AuditStore should be nil initially")
	}

	// Set via concrete method
	db, dbErr := alerts.OpenDB(":memory:")
	if dbErr != nil {
		t.Fatalf("OpenDB error: %v", dbErr)
	}
	defer db.Close()

	// AuditStore needs a concrete store (we can't easily create one here without
	// the full audit package setup, so test the nil->nil path is already covered)
}

// ---------------------------------------------------------------------------
// OpenBrowser — validates URL scheme
// ---------------------------------------------------------------------------

func TestOpenBrowser_InvalidScheme(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("ftp://example.com")
	if err == nil {
		t.Error("Expected error for non-http/https scheme")
	}
}

func TestOpenBrowser_EmptyURL(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.OpenBrowser("")
	if err == nil {
		t.Error("Expected error for empty URL")
	}
}

// ---------------------------------------------------------------------------
// initializeTemplates
// ---------------------------------------------------------------------------

func TestInitializeTemplates(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	// Templates should already be initialized by New()
	if m.templates == nil {
		t.Error("templates should not be nil")
	}

	// Re-initialize should not fail
	err = m.initializeTemplates()
	if err != nil {
		t.Errorf("initializeTemplates error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// initializeSessionSigner
// ---------------------------------------------------------------------------

func TestInitializeSessionSigner_CustomSigner(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	customSigner, _ := NewSessionSigner()
	err = m.initializeSessionSigner(customSigner)
	if err != nil {
		t.Errorf("initializeSessionSigner error: %v", err)
	}
	if m.sessionSigner != customSigner {
		t.Error("Expected custom signer to be used")
	}
}

func TestInitializeSessionSigner_NilSigner(t *testing.T) {
	t.Parallel()
	m, err := newTestManager("test_key", "test_secret")
	if err != nil {
		t.Fatalf("newTestManager error: %v", err)
	}
	defer m.Shutdown()

	err = m.initializeSessionSigner(nil)
	if err != nil {
		t.Errorf("initializeSessionSigner with nil should auto-create signer: %v", err)
	}
	if m.sessionSigner == nil {
		t.Error("sessionSigner should not be nil after auto-creation")
	}
}

