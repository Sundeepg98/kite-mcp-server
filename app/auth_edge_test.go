package app

// Tests for kiteExchangerAdapter using broker.Authenticator injection.
// Covers ExchangeRequestToken and ExchangeWithCredentials success paths
// with user provisioning, token storage, credential storage, and registry updates.

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// TestExchangeRequestToken_WithUserStore_Success tests the full success path
// including user auto-provisioning via userStore.
func TestExchangeRequestToken_WithUserStore_Success(t *testing.T) {
	t.Parallel()

	tokenStore := kc.NewKiteTokenStore()
	credStore := kc.NewKiteCredentialStore()
	regStore := registry.New()
	userStore := users.NewStore()

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-api-key",
		apiSecret:     "global-api-secret",
		tokenStore:    tokenStore,
		credentialStore: credStore,
		registryStore: regStore,
		userStore:     userStore,
		logger:        testLogger(),
		authenticator: newMockAuth("alice@example.com", "AL1234", "Alice Trader", "tok-alice"),
	}

	email, err := adapter.ExchangeRequestToken("test-request-token")
	require.NoError(t, err)
	assert.Equal(t, "alice@example.com", email)

	// Verify token was stored
	entry, ok := tokenStore.Get("alice@example.com")
	assert.True(t, ok)
	assert.Equal(t, "tok-alice", entry.AccessToken)
	assert.Equal(t, "AL1234", entry.UserID)
	assert.Equal(t, "Alice Trader", entry.UserName)

	// Verify user was auto-provisioned
	status := userStore.GetStatus("alice@example.com")
	assert.NotEqual(t, users.StatusSuspended, status)
	assert.NotEqual(t, users.StatusOffboarded, status)
}

// TestExchangeWithCredentials_WithUserStore_Success tests the per-user
// credentials path with user provisioning and credential storage.
func TestExchangeWithCredentials_WithUserStore_Success(t *testing.T) {
	t.Parallel()

	tokenStore := kc.NewKiteTokenStore()
	credStore := kc.NewKiteCredentialStore()
	regStore := registry.New()
	userStore := users.NewStore()

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    tokenStore,
		credentialStore: credStore,
		registryStore: regStore,
		userStore:     userStore,
		logger:        testLogger(),
		authenticator: newMockAuth("bob@example.com", "BO5678", "Bob Investor", "tok-bob"),
	}

	email, err := adapter.ExchangeWithCredentials("test-request-token", "bob-api-key", "bob-api-secret")
	require.NoError(t, err)
	assert.Equal(t, "bob@example.com", email)

	// Verify token stored
	entry, ok := tokenStore.Get("bob@example.com")
	assert.True(t, ok)
	assert.Equal(t, "tok-bob", entry.AccessToken)

	// Verify per-user credentials stored
	credEntry, ok := credStore.Get("bob@example.com")
	assert.True(t, ok)
	assert.Equal(t, "bob-api-key", credEntry.APIKey)
	assert.Equal(t, "bob-api-secret", credEntry.APISecret)

	// Verify user auto-provisioned
	status := userStore.GetStatus("bob@example.com")
	assert.NotEqual(t, users.StatusSuspended, status)
}

// TestExchangeWithCredentials_RegistryNewKey tests that a new per-user key
// is auto-registered in the registry on first use.
func TestExchangeWithCredentials_RegistryNewKey(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: regStore,
		userStore:     users.NewStore(),
		logger:        testLogger(),
		authenticator: newMockAuth("carol@example.com", "CA9012", "Carol", "tok-carol"),
	}

	email, err := adapter.ExchangeWithCredentials("req-token", "carol-key", "carol-secret")
	require.NoError(t, err)
	assert.Equal(t, "carol@example.com", email)

	// Verify key was registered in registry
	regEntry, found := regStore.GetByAPIKeyAnyStatus("carol-key")
	require.True(t, found, "expected carol-key to be registered in registry")
	assert.Equal(t, "carol@example.com", regEntry.AssignedTo)
	assert.Equal(t, registry.StatusActive, regEntry.Status)
	assert.Equal(t, registry.SourceSelfProvisioned, regEntry.Source)
}

// TestExchangeWithCredentials_RegistryOldKeyReplaced tests that when a user
// switches API keys, the old key is marked as replaced.
func TestExchangeWithCredentials_RegistryOldKeyReplaced(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	// Pre-register an old key for this user
	err := regStore.Register(&registry.AppRegistration{
		ID:           "old-dave-reg",
		APIKey:       "dave-old-key",
		APISecret:    "dave-old-secret",
		AssignedTo:   "dave@example.com",
		Label:        "Old Key",
		Status:       registry.StatusActive,
		Source:       registry.SourceSelfProvisioned,
		RegisteredBy: "dave@example.com",
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: regStore,
		userStore:     users.NewStore(),
		logger:        testLogger(),
		authenticator: newMockAuth("dave@example.com", "DV3456", "Dave", "tok-dave"),
	}

	email, err := adapter.ExchangeWithCredentials("req-token", "dave-new-key", "dave-new-secret")
	require.NoError(t, err)
	assert.Equal(t, "dave@example.com", email)

	// Old key should be marked as replaced
	oldEntry, found := regStore.GetByAPIKeyAnyStatus("dave-old-key")
	require.True(t, found)
	assert.Equal(t, registry.StatusReplaced, oldEntry.Status)

	// New key should be active
	newEntry, found := regStore.GetByAPIKeyAnyStatus("dave-new-key")
	require.True(t, found)
	assert.Equal(t, registry.StatusActive, newEntry.Status)
}

// TestExchangeRequestToken_RegistryLastUsedAt tests that ExchangeRequestToken
// updates the last-used timestamp of the global API key.
func TestExchangeRequestToken_RegistryLastUsedAt(t *testing.T) {
	t.Parallel()

	regStore := registry.New()
	err := regStore.Register(&registry.AppRegistration{
		ID:        "global-key-reg",
		APIKey:    "global-api-key",
		APISecret: "global-api-secret",
		Status:    registry.StatusActive,
		Source:    registry.SourceAdmin,
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-api-key",
		apiSecret:     "global-api-secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: regStore,
		logger:        testLogger(),
		authenticator: newMockAuth("eve@example.com", "EV7890", "Eve", "tok-eve"),
	}

	email, err := adapter.ExchangeRequestToken("req-token")
	require.NoError(t, err)
	assert.Equal(t, "eve@example.com", email)

	// Verify last_used_at was updated
	regEntry, found := regStore.GetByAPIKeyAnyStatus("global-api-key")
	require.True(t, found)
	assert.False(t, regEntry.LastUsedAt.IsZero(), "expected LastUsedAt to be set")
}

// TestExchangeRequestToken_NoRegistryStore tests that ExchangeRequestToken
// works correctly when registryStore is nil (minimal setup).
func TestExchangeRequestToken_NoRegistryStore_Factory(t *testing.T) {
	t.Parallel()

	adapter := &kiteExchangerAdapter{
		apiKey:        "key",
		apiSecret:     "secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore: nil,
		logger:        testLogger(),
		authenticator: newMockAuth("frank@example.com", "FR1111", "Frank", "tok-frank"),
	}

	email, err := adapter.ExchangeRequestToken("req-token")
	require.NoError(t, err)
	assert.Equal(t, "frank@example.com", email)
}

// TestExchangeWithCredentials_NoRegistryStore tests per-user credentials
// path without a registry store.
func TestExchangeWithCredentials_NoRegistryStore_Factory(t *testing.T) {
	t.Parallel()

	tokenStore := kc.NewKiteTokenStore()
	credStore := kc.NewKiteCredentialStore()

	adapter := &kiteExchangerAdapter{
		apiKey:        "global-key",
		apiSecret:     "global-secret",
		tokenStore:    tokenStore,
		credentialStore: credStore,
		registryStore: nil,
		logger:        testLogger(),
		authenticator: newMockAuth("grace@example.com", "GR2222", "Grace", "tok-grace"),
	}

	email, err := adapter.ExchangeWithCredentials("req-token", "grace-key", "grace-secret")
	require.NoError(t, err)
	assert.Equal(t, "grace@example.com", email)

	// Credentials still stored even without registry
	credEntry, ok := credStore.Get("grace@example.com")
	assert.True(t, ok)
	assert.Equal(t, "grace-key", credEntry.APIKey)
}

// TestExchangeRequestToken_FallbackToUserID tests that when the Kite API
// returns an empty email, the user_id is used as the identity.
func TestExchangeRequestToken_FallbackToUserID_Factory(t *testing.T) {
	t.Parallel()

	adapter := &kiteExchangerAdapter{
		apiKey:        "key",
		apiSecret:     "secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:        testLogger(),
		authenticator: newMockAuth("", "ZK4444", "No Email User", "tok-noemail"),
	}

	email, err := adapter.ExchangeRequestToken("req-token")
	require.NoError(t, err)
	assert.Equal(t, "ZK4444", email) // falls back to user_id
}

// TestExchangeRequestToken_KiteAPIError tests the error path when
// the authenticator returns an error.
func TestExchangeRequestToken_KiteAPIError_Factory(t *testing.T) {
	t.Parallel()

	adapter := &kiteExchangerAdapter{
		apiKey:        "key",
		apiSecret:     "secret",
		tokenStore:    kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		logger:        testLogger(),
		authenticator: newMockAuthError("Invalid checksum"),
	}

	_, err := adapter.ExchangeRequestToken("bad-token")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "kite generate session")
}

// TestGetCredentials_PerUser tests that per-user credentials are returned
// when they exist in the credential store.
func TestGetCredentials_PerUser_Factory(t *testing.T) {
	t.Parallel()
	credStore := kc.NewKiteCredentialStore()
	credStore.Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey:    "per-user-key",
		APISecret: "per-user-secret",
	})

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		credentialStore: credStore,
	}

	key, secret, ok := adapter.GetCredentials("user@test.com")
	assert.True(t, ok)
	assert.Equal(t, "per-user-key", key)
	assert.Equal(t, "per-user-secret", secret)
}

// TestGetCredentials_FallbackToGlobal tests that global credentials are
// returned when the user has no per-user credentials.
func TestGetCredentials_FallbackToGlobal_Factory(t *testing.T) {
	t.Parallel()
	credStore := kc.NewKiteCredentialStore()

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		credentialStore: credStore,
	}

	key, secret, ok := adapter.GetCredentials("unknown@test.com")
	assert.True(t, ok)
	assert.Equal(t, "global-key", key)
	assert.Equal(t, "global-secret", secret)
}

// TestGetCredentials_NoCredentials tests that false is returned when
// neither per-user nor global credentials exist.
func TestGetCredentials_NoCredentials_Factory(t *testing.T) {
	t.Parallel()
	credStore := kc.NewKiteCredentialStore()

	adapter := &kiteExchangerAdapter{
		apiKey:          "",
		apiSecret:       "",
		credentialStore: credStore,
	}

	_, _, ok := adapter.GetCredentials("nobody@test.com")
	assert.False(t, ok)
}

// TestGetSecretByAPIKey tests the secret lookup by API key.
func TestGetSecretByAPIKey_Factory(t *testing.T) {
	t.Parallel()
	credStore := kc.NewKiteCredentialStore()
	credStore.Set("user@test.com", &kc.KiteCredentialEntry{
		APIKey:    "lookup-key",
		APISecret: "lookup-secret",
	})

	adapter := &kiteExchangerAdapter{
		credentialStore: credStore,
	}

	secret, ok := adapter.GetSecretByAPIKey("lookup-key")
	assert.True(t, ok)
	assert.Equal(t, "lookup-secret", secret)

	_, ok = adapter.GetSecretByAPIKey("nonexistent-key")
	assert.False(t, ok)
}

// ===========================================================================
// Merged from adapters_coverage_test.go — exchange-related tests
// ===========================================================================

func TestExchangeWithCredentials_KeyExistsDiffUser_Push100Extra(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	// Pre-register the per-user key as belonging to "other@test.com"
	err := regStore.Register(&registry.AppRegistration{
		ID:           "existing-key-reg",
		APIKey:       "per-user-key",
		APISecret:    "per-user-secret",
		AssignedTo:   "other@test.com",
		Label:        "Other User",
		Status:       registry.StatusActive,
		Source:       registry.SourceSelfProvisioned,
		RegisteredBy: "other@test.com",
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore:   regStore,
		userStore:       users.NewStore(),
		logger:          testLogger(),
		authenticator:   newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	// Exchange with per-user-key succeeds -- mock returns email "test@example.com"
	// which is different from the key's assigned user "other@test.com"
	email, err := adapter.ExchangeWithCredentials("test-request-token", "per-user-key", "per-user-secret")
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", email)

	// Key should now be re-assigned to test@example.com
	entry, found := regStore.GetByAPIKeyAnyStatus("per-user-key")
	require.True(t, found)
	assert.Equal(t, "test@example.com", entry.AssignedTo)
}

func TestExchangeWithCredentials_RegisterError_Push100Extra(t *testing.T) {
	t.Parallel()

	regStore := registry.New()

	// Pre-register with the exact ID that ExchangeWithCredentials will generate.
	conflictID := "self-test@example.com-new-user"
	err := regStore.Register(&registry.AppRegistration{
		ID:         conflictID,
		APIKey:     "different-key-for-conflict",
		APISecret:  "different-secret-for-conflict",
		AssignedTo: "someone@test.com",
		Status:     registry.StatusActive,
		Source:     registry.SourceAdmin,
	})
	require.NoError(t, err)

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		registryStore:   regStore,
		userStore:       users.NewStore(),
		logger:          testLogger(),
		authenticator:   newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	// Exchange with "new-user-key" -- key not in registry -- Register with conflictID -- error
	email, err := adapter.ExchangeWithCredentials("test-request-token", "new-user-key", "new-user-secret")
	// Should succeed despite registry error (logged as warning, not fatal)
	require.NoError(t, err)
	assert.Equal(t, "test@example.com", email)
}

func TestExchangeWithCredentials_SuspendedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusSuspended)

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:       uStore,
		logger:          testLogger(),
		authenticator:   newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeWithCredentials("test-request-token", "per-key", "per-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}

func TestExchangeWithCredentials_OffboardedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusOffboarded)

	adapter := &kiteExchangerAdapter{
		apiKey:          "global-key",
		apiSecret:       "global-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:       uStore,
		logger:          testLogger(),
		authenticator:   newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeWithCredentials("test-request-token", "per-key", "per-secret")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "offboarded")
}

func TestExchangeRequestToken_SuspendedUser_Push100Extra(t *testing.T) {
	t.Parallel()

	uStore := users.NewStore()
	uStore.EnsureUser("test@example.com", "XY1234", "Test User", "self")
	uStore.UpdateStatus("test@example.com", users.StatusSuspended)

	adapter := &kiteExchangerAdapter{
		apiKey:          "test-api-key",
		apiSecret:       "test-api-secret",
		tokenStore:      kc.NewKiteTokenStore(),
		credentialStore: kc.NewKiteCredentialStore(),
		userStore:       uStore,
		logger:          testLogger(),
		authenticator:   newMockAuth("test@example.com", "XY1234", "Test User", "mock-access-token"),
	}

	_, err := adapter.ExchangeRequestToken("test-request-token")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "suspended")
}
