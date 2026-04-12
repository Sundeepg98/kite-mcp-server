// Shared test doubles for the kc root package.
//
// All mock types used by multiple _test.go files in package kc live here so
// the scattered-mocks pattern doesn't recur. Each mock is declared exactly
// once; test files in the same package pick them up automatically.
package kc

import (
	"time"

	"github.com/zerodha/kite-mcp-server/kc/billing"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// ---------------------------------------------------------------------------
// mockCredentialStore — implements CredentialStoreInterface.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockCredentialStoreWithRaw — supports ListAllRaw for backfill tests.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockTokenStore — implements TokenStoreInterface.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockRegistryStore — implements RegistryStoreInterface.
// ---------------------------------------------------------------------------

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

// ---------------------------------------------------------------------------
// mockMetrics — implements the metrics interface used by Manager.
// ---------------------------------------------------------------------------

type mockMetrics struct{}

func (m *mockMetrics) Increment(key string)         {}
func (m *mockMetrics) TrackDailyUser(userID string) {}
func (m *mockMetrics) IncrementDaily(key string)    {}
func (m *mockMetrics) Shutdown()                    {}

// ---------------------------------------------------------------------------
// mockSessionDB — in-memory SessionDB double.
// ---------------------------------------------------------------------------

type mockSessionDB struct {
	sessions map[string]*SessionLoadEntry
}

func newMockSessionDB() *mockSessionDB {
	return &mockSessionDB{sessions: make(map[string]*SessionLoadEntry)}
}

func (m *mockSessionDB) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	m.sessions[sessionID] = &SessionLoadEntry{
		SessionID:  sessionID,
		Email:      email,
		CreatedAt:  createdAt,
		ExpiresAt:  expiresAt,
		Terminated: terminated,
	}
	return nil
}

func (m *mockSessionDB) LoadSessions() ([]*SessionLoadEntry, error) {
	var out []*SessionLoadEntry
	for _, s := range m.sessions {
		cp := *s
		out = append(out, &cp)
	}
	return out, nil
}

func (m *mockSessionDB) DeleteSession(sessionID string) error {
	delete(m.sessions, sessionID)
	return nil
}

// ---------------------------------------------------------------------------
// mockUserStoreForFamily — implements FamilyUserStore.
// ---------------------------------------------------------------------------

type mockUserStoreForFamily struct {
	users map[string]*users.User
}

func (m *mockUserStoreForFamily) Get(email string) (*users.User, bool) {
	u, ok := m.users[email]
	return u, ok
}

func (m *mockUserStoreForFamily) SetAdminEmail(email, adminEmail string) error {
	if u, ok := m.users[email]; ok {
		u.AdminEmail = adminEmail
		return nil
	}
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

// ---------------------------------------------------------------------------
// mockBillingStoreForFamily — implements BillingStoreInterface.
// ---------------------------------------------------------------------------

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

func (m *mockBillingStoreForFamily) IsEventProcessed(eventID string) bool { return false }

func (m *mockBillingStoreForFamily) MarkEventProcessed(eventID, eventType string) error {
	return nil
}

func (m *mockBillingStoreForFamily) GetTierForUser(email string, adminEmailFn func(string) string) billing.Tier {
	return billing.TierFree
}
