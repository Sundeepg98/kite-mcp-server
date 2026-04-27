package usecases

// oauth_bridge_usecases_test.go — coverage close-out for the nine
// OAuth-bridge use cases at 0%. These were dark because production
// wires them through the kc.Manager bootstrap (app/wire.go), which
// requires a full app fixture; the use cases themselves only depend
// on narrow ports defined in the same file (UserProvisioner,
// KiteTokenWriter, KiteCredentialWriter, RegistrySync,
// OAuthClientStore, RegistryAdminWriter), so unit tests with
// hand-rolled stubs reach 100% without a Manager fixture.
//
// Sub-commit C of Wave B option 1 (app/ HTTP integration tests).

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// ===========================================================================
// Stubs for the narrow ports
// ===========================================================================

// stubUserProvisioner records every call so tests can assert on
// invocation order + arguments. Intentionally hand-rolled rather than
// using a mocking library — keeps the dependency surface narrow.
type stubUserProvisioner struct {
	statusByEmail   map[string]string
	ensureRet       UserRecord
	calls           []string
	lastEnsureArgs  [4]string // email, kiteUID, displayName, onboardedBy
	lastUpdateUID   [2]string // email, kiteUID
	lastLoginEmails []string
}

func (s *stubUserProvisioner) GetStatus(email string) string {
	s.calls = append(s.calls, "GetStatus:"+email)
	return s.statusByEmail[email]
}

func (s *stubUserProvisioner) EnsureUser(email, kiteUID, displayName, onboardedBy string) UserRecord {
	s.calls = append(s.calls, "EnsureUser:"+email)
	s.lastEnsureArgs = [4]string{email, kiteUID, displayName, onboardedBy}
	return s.ensureRet
}

func (s *stubUserProvisioner) UpdateLastLogin(email string) {
	s.calls = append(s.calls, "UpdateLastLogin:"+email)
	s.lastLoginEmails = append(s.lastLoginEmails, email)
}

func (s *stubUserProvisioner) UpdateKiteUID(email, kiteUID string) {
	s.calls = append(s.calls, "UpdateKiteUID:"+email)
	s.lastUpdateUID = [2]string{email, kiteUID}
}

// stubUserRecord implements the UserRecord port.
type stubUserRecord struct{ kiteUID string }

func (s *stubUserRecord) GetKiteUID() string { return s.kiteUID }

// stubKiteTokenWriter records token writes.
type stubKiteTokenWriter struct {
	last [4]string // email, accessToken, userID, userName
	hits int
}

func (s *stubKiteTokenWriter) SetToken(email, accessToken, userID, userName string) {
	s.last = [4]string{email, accessToken, userID, userName}
	s.hits++
}

// stubKiteCredentialWriter records credential writes.
type stubKiteCredentialWriter struct {
	last [3]string // email, apiKey, apiSecret
	hits int
}

func (s *stubKiteCredentialWriter) SetCredentials(email, apiKey, apiSecret string) {
	s.last = [3]string{email, apiKey, apiSecret}
	s.hits++
}

// stubRegistrySync records every call so the SyncRegistryAfterLogin
// use case's three branches can be asserted independently.
type stubRegistrySync struct {
	keyByEmail        map[string]string
	ownerByAPIKey     map[string]string // empty string = "exists but no owner"
	apiKeyExists      map[string]bool   // distinguishes "found, owner=''" from "not found"
	registerErr       error
	updateErr         error
	calls             []string
	lastRegisterArgs  [8]string // id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy
	lastUpdateArgs    [4]string // apiKey, newAssignedTo, label, status
	lastLastUsedKey   string
	lastMarkStatusKey string
	lastMarkStatusVal string
}

func (s *stubRegistrySync) GetByEmail(email string) (string, bool) {
	s.calls = append(s.calls, "GetByEmail:"+email)
	k, ok := s.keyByEmail[email]
	return k, ok
}

func (s *stubRegistrySync) GetByAPIKeyAnyStatus(apiKey string) (string, bool) {
	s.calls = append(s.calls, "GetByAPIKeyAnyStatus:"+apiKey)
	if !s.apiKeyExists[apiKey] {
		return "", false
	}
	return s.ownerByAPIKey[apiKey], true
}

func (s *stubRegistrySync) MarkStatus(apiKey, status string) {
	s.calls = append(s.calls, "MarkStatus:"+apiKey+":"+status)
	s.lastMarkStatusKey = apiKey
	s.lastMarkStatusVal = status
}

func (s *stubRegistrySync) Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error {
	s.calls = append(s.calls, "Register:"+id)
	s.lastRegisterArgs = [8]string{id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy}
	return s.registerErr
}

func (s *stubRegistrySync) Update(apiKey, newAssignedTo, label, status string) error {
	s.calls = append(s.calls, "Update:"+apiKey)
	s.lastUpdateArgs = [4]string{apiKey, newAssignedTo, label, status}
	return s.updateErr
}

func (s *stubRegistrySync) UpdateLastUsedAt(apiKey string) {
	s.calls = append(s.calls, "UpdateLastUsedAt:"+apiKey)
	s.lastLastUsedKey = apiKey
}

// stubOAuthClientStore records save/delete calls.
type stubOAuthClientStore struct {
	saveErr        error
	deleteErr      error
	lastSaveArgs   [4]string // clientID, clientSecret, redirectURIsJSON, clientName
	lastSaveTime   time.Time
	lastSaveIsKite bool
	lastDeleteID   string
	saveHits       int
	deleteHits     int
}

func (s *stubOAuthClientStore) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	s.lastSaveArgs = [4]string{clientID, clientSecret, redirectURIsJSON, clientName}
	s.lastSaveTime = createdAt
	s.lastSaveIsKite = isKiteKey
	s.saveHits++
	return s.saveErr
}

func (s *stubOAuthClientStore) DeleteClient(clientID string) error {
	s.lastDeleteID = clientID
	s.deleteHits++
	return s.deleteErr
}

// stubRegistryAdminWriter records admin-side registry mutations.
type stubRegistryAdminWriter struct {
	registerErr      error
	updateErr        error
	deleteErr        error
	lastRegisterArgs [8]string
	lastUpdateArgs   [4]string
	lastDeleteID     string
}

func (s *stubRegistryAdminWriter) Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error {
	s.lastRegisterArgs = [8]string{id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy}
	return s.registerErr
}

func (s *stubRegistryAdminWriter) Update(id, assignedTo, label, status string) error {
	s.lastUpdateArgs = [4]string{id, assignedTo, label, status}
	return s.updateErr
}

func (s *stubRegistryAdminWriter) Delete(id string) error {
	s.lastDeleteID = id
	return s.deleteErr
}

// ===========================================================================
// ProvisionUserOnLoginUseCase
// ===========================================================================

// TestProvisionUserOnLogin_NilProvisioner pins the no-op contract:
// passing a nil UserProvisioner means dev-mode / single-user; the
// use case returns nil without error.
func TestProvisionUserOnLogin_NilProvisioner(t *testing.T) {
	t.Parallel()
	uc := NewProvisionUserOnLoginUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "trader@test.com",
	})
	assert.NoError(t, err)
}

// TestProvisionUserOnLogin_SuspendedReturnsErr pins the suspended-status
// rejection path: GetStatus="suspended" → ErrUserSuspended (callers
// emit 403).
func TestProvisionUserOnLogin_SuspendedReturnsErr(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{
		statusByEmail: map[string]string{"trader@test.com": UserStatusSuspended},
	}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "Trader@Test.com", // upper-case to verify lowercase normalization
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserSuspended))
	// Status check uses lowercased email.
	assert.Contains(t, stub.calls, "GetStatus:trader@test.com")
}

// TestProvisionUserOnLogin_OffboardedReturnsErr pins the offboarded
// branch — distinct from suspended (terminal vs reactivatable).
func TestProvisionUserOnLogin_OffboardedReturnsErr(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{
		statusByEmail: map[string]string{"trader@test.com": UserStatusOffboarded},
	}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "trader@test.com",
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, ErrUserOffboarded))
}

// TestProvisionUserOnLogin_NewUserBackfillsKiteUID covers the happy
// path for a first-time login: EnsureUser returns a record with no
// prior KiteUID; the use case calls UpdateKiteUID to backfill it.
func TestProvisionUserOnLogin_NewUserBackfillsKiteUID(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{
		ensureRet: &stubUserRecord{kiteUID: ""}, // no prior UID
	}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "Trader@Test.com", KiteUID: "AB1234", DisplayName: "Trader",
	})
	require.NoError(t, err)
	// Email lowercased on every store interaction.
	assert.Equal(t, "trader@test.com", stub.lastEnsureArgs[0])
	assert.Equal(t, "AB1234", stub.lastEnsureArgs[1])
	assert.Equal(t, "Trader", stub.lastEnsureArgs[2])
	assert.Equal(t, "self", stub.lastEnsureArgs[3])
	// LastLogin stamped.
	assert.Equal(t, []string{"trader@test.com"}, stub.lastLoginEmails)
	// KiteUID backfilled.
	assert.Equal(t, [2]string{"trader@test.com", "AB1234"}, stub.lastUpdateUID)
}

// TestProvisionUserOnLogin_ExistingUserSkipsUIDBackfill covers the
// returning-user path: EnsureUser returns a record that already has a
// KiteUID, so UpdateKiteUID is NOT called (avoids unnecessary DB write).
func TestProvisionUserOnLogin_ExistingUserSkipsUIDBackfill(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{
		ensureRet: &stubUserRecord{kiteUID: "ALREADY_SET"},
	}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "trader@test.com", KiteUID: "AB1234",
	})
	require.NoError(t, err)
	// No UpdateKiteUID call.
	assert.Equal(t, [2]string{"", ""}, stub.lastUpdateUID)
}

// TestProvisionUserOnLogin_NilEnsureResult covers the defensive
// "EnsureUser returned nil" branch (misconfigured store). The use
// case returns nil without calling UpdateLastLogin.
func TestProvisionUserOnLogin_NilEnsureResult(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{ensureRet: nil}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "trader@test.com",
	})
	require.NoError(t, err)
	assert.Empty(t, stub.lastLoginEmails, "no LastLogin write when EnsureUser returns nil")
}

// TestProvisionUserOnLogin_EmptyKiteUIDSkipsBackfill covers the third
// guard branch: even if u.KiteUID is empty, we don't backfill when
// cmd.KiteUID itself is empty (no source for the UID).
func TestProvisionUserOnLogin_EmptyKiteUIDSkipsBackfill(t *testing.T) {
	t.Parallel()
	stub := &stubUserProvisioner{ensureRet: &stubUserRecord{kiteUID: ""}}
	uc := NewProvisionUserOnLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.ProvisionUserOnLoginCommand{
		Email: "trader@test.com", // no KiteUID in the command
	})
	require.NoError(t, err)
	assert.Equal(t, [2]string{"", ""}, stub.lastUpdateUID)
}

// ===========================================================================
// CacheKiteAccessTokenUseCase
// ===========================================================================

// TestCacheKiteAccessToken_HappyPath covers the lowercase-and-write
// contract.
func TestCacheKiteAccessToken_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubKiteTokenWriter{}
	uc := NewCacheKiteAccessTokenUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.CacheKiteAccessTokenCommand{
		Email:       "Trader@Test.com",
		AccessToken: "tok_abc",
		UserID:      "U1",
		UserName:    "Trader",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.hits)
	assert.Equal(t, [4]string{"trader@test.com", "tok_abc", "U1", "Trader"}, stub.last)
}

// TestCacheKiteAccessToken_NilWriterIsNoop pins the defensive
// nil-writer guard.
func TestCacheKiteAccessToken_NilWriterIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewCacheKiteAccessTokenUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.CacheKiteAccessTokenCommand{
		Email: "trader@test.com",
	})
	assert.NoError(t, err)
}

// ===========================================================================
// StoreUserKiteCredentialsUseCase
// ===========================================================================

// TestStoreUserKiteCredentials_HappyPath covers the lowercase-and-write
// contract.
func TestStoreUserKiteCredentials_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubKiteCredentialWriter{}
	uc := NewStoreUserKiteCredentialsUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.StoreUserKiteCredentialsCommand{
		Email:     "Trader@Test.com",
		APIKey:    "api_key_1",
		APISecret: "api_secret_1",
	})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.hits)
	assert.Equal(t, [3]string{"trader@test.com", "api_key_1", "api_secret_1"}, stub.last)
}

// TestStoreUserKiteCredentials_NilWriterIsNoop pins the guard.
func TestStoreUserKiteCredentials_NilWriterIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewStoreUserKiteCredentialsUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.StoreUserKiteCredentialsCommand{
		Email: "trader@test.com",
	})
	assert.NoError(t, err)
}

// ===========================================================================
// SyncRegistryAfterLoginUseCase — three branches plus rotation
// ===========================================================================

// TestSyncRegistryAfterLogin_NilOrEmpty covers the two skip-fast paths:
// nil registry or empty APIKey returns nil without calls.
func TestSyncRegistryAfterLogin_NilOrEmpty(t *testing.T) {
	t.Parallel()
	t.Run("nil registry", func(t *testing.T) {
		uc := NewSyncRegistryAfterLoginUseCase(nil, testLogger())
		err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
			Email: "u@t.com", APIKey: "k1", AutoRegister: true,
		})
		assert.NoError(t, err)
	})
	t.Run("empty APIKey", func(t *testing.T) {
		stub := &stubRegistrySync{}
		uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
		err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
			Email: "u@t.com", APIKey: "", AutoRegister: true,
		})
		assert.NoError(t, err)
		assert.Empty(t, stub.calls, "empty APIKey must skip all registry calls")
	})
}

// TestSyncRegistryAfterLogin_AutoRegisterNewKey covers branch 1:
// AutoRegister=true + APIKey not in registry → Register call.
func TestSyncRegistryAfterLogin_AutoRegisterNewKey(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{}, // user has no prior key
		apiKeyExists:  map[string]bool{},   // APIKey not in registry
		ownerByAPIKey: map[string]string{},
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email:        "Trader@Test.com",
		APIKey:       "new_api_key_xyz",
		APISecret:    "new_secret",
		Label:        "my-app",
		AutoRegister: true,
	})
	require.NoError(t, err)

	// Register called with all the expected args.
	assert.Equal(t, "new_api_key_xyz", stub.lastRegisterArgs[1]) // apiKey
	assert.Equal(t, "new_secret", stub.lastRegisterArgs[2])     // apiSecret
	assert.Equal(t, "trader@test.com", stub.lastRegisterArgs[3]) // assignedTo (lowercased)
	assert.Equal(t, "my-app", stub.lastRegisterArgs[4])          // label
	assert.Equal(t, RegistryStatusActive, stub.lastRegisterArgs[5])
	assert.Equal(t, RegistrySourceSelfProvisioned, stub.lastRegisterArgs[6])
	// LastUsedAt always stamped.
	assert.Equal(t, "new_api_key_xyz", stub.lastLastUsedKey)
}

// TestSyncRegistryAfterLogin_AutoRegisterReassign covers branch 2:
// AutoRegister=true + APIKey exists with different owner → Update.
func TestSyncRegistryAfterLogin_AutoRegisterReassign(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{},
		apiKeyExists:  map[string]bool{"shared_key": true},
		ownerByAPIKey: map[string]string{"shared_key": "old_owner@t.com"},
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email: "new_owner@t.com", APIKey: "shared_key", AutoRegister: true,
	})
	require.NoError(t, err)
	// Update called to reassign.
	assert.Equal(t, "shared_key", stub.lastUpdateArgs[0])
	assert.Equal(t, "new_owner@t.com", stub.lastUpdateArgs[1])
	// LastUsedAt stamped.
	assert.Equal(t, "shared_key", stub.lastLastUsedKey)
}

// TestSyncRegistryAfterLogin_AutoRegisterSameOwnerSkipsUpdate covers
// the "already mine" path: APIKey exists AND assignedTo matches —
// no Update call, just LastUsedAt.
func TestSyncRegistryAfterLogin_AutoRegisterSameOwnerSkipsUpdate(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{},
		apiKeyExists:  map[string]bool{"my_key": true},
		ownerByAPIKey: map[string]string{"my_key": "trader@t.com"},
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email: "trader@t.com", APIKey: "my_key", AutoRegister: true,
	})
	require.NoError(t, err)
	// No Update.
	assert.Equal(t, [4]string{"", "", "", ""}, stub.lastUpdateArgs)
	// LastUsedAt still stamped.
	assert.Equal(t, "my_key", stub.lastLastUsedKey)
}

// TestSyncRegistryAfterLogin_KeyRotationMarksOldReplaced covers the
// rotation audit-trail behaviour: prior different-key holding → mark
// old as Replaced before processing the new key.
func TestSyncRegistryAfterLogin_KeyRotationMarksOldReplaced(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{"trader@t.com": "old_key"},
		apiKeyExists:  map[string]bool{},
		ownerByAPIKey: map[string]string{},
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email: "trader@t.com", APIKey: "new_key", APISecret: "s", AutoRegister: true,
	})
	require.NoError(t, err)
	// Old key marked Replaced.
	assert.Equal(t, "old_key", stub.lastMarkStatusKey)
	assert.Equal(t, RegistryStatusReplaced, stub.lastMarkStatusVal)
}

// TestSyncRegistryAfterLogin_NoAutoRegisterStampsOnly covers the
// "AutoRegister=false" path: skips both branches, only stamps
// LastUsedAt. This is the global-credential branch.
func TestSyncRegistryAfterLogin_NoAutoRegisterStampsOnly(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{"trader@t.com": "old_key"},
		apiKeyExists:  map[string]bool{},
		ownerByAPIKey: map[string]string{},
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email: "trader@t.com", APIKey: "any_key", AutoRegister: false,
	})
	require.NoError(t, err)
	// No Register or Update or MarkStatus.
	assert.Empty(t, stub.lastRegisterArgs[0])
	assert.Empty(t, stub.lastMarkStatusKey,
		"AutoRegister=false must NOT mark old key as replaced")
	// LastUsedAt always stamped on the current key.
	assert.Equal(t, "any_key", stub.lastLastUsedKey)
}

// TestSyncRegistryAfterLogin_RegisterErrorLogged covers the
// Register-error branch: error from the store is logged but doesn't
// fail the use case (defensive — better to keep login working than
// fail on a registry issue).
func TestSyncRegistryAfterLogin_RegisterErrorLogged(t *testing.T) {
	t.Parallel()
	stub := &stubRegistrySync{
		keyByEmail:    map[string]string{},
		apiKeyExists:  map[string]bool{},
		ownerByAPIKey: map[string]string{},
		registerErr:   errors.New("disk full"),
	}
	uc := NewSyncRegistryAfterLoginUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SyncRegistryAfterLoginCommand{
		Email: "trader@t.com", APIKey: "k", APISecret: "s", AutoRegister: true,
	})
	// Register failed but the use case swallows it — login still proceeds.
	require.NoError(t, err)
	// LastUsedAt still attempted.
	assert.Equal(t, "k", stub.lastLastUsedKey)
}

// ===========================================================================
// SaveOAuthClientUseCase / DeleteOAuthClientUseCase
// ===========================================================================

// TestSaveOAuthClient_HappyPath pins the round-trip from CreatedAtUnix
// (nanos) to time.Time and the IsKiteAPIKey flag.
func TestSaveOAuthClient_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubOAuthClientStore{}
	uc := NewSaveOAuthClientUseCase(stub, testLogger())

	now := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	err := uc.Execute(context.Background(), cqrs.SaveOAuthClientCommand{
		ClientID:         "cid",
		ClientSecret:     "csecret",
		RedirectURIsJSON: `["https://x"]`,
		ClientName:       "MyApp",
		CreatedAtUnix:    now.UnixNano(),
		IsKiteAPIKey:     true,
	})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.saveHits)
	assert.Equal(t, "cid", stub.lastSaveArgs[0])
	assert.Equal(t, "csecret", stub.lastSaveArgs[1])
	assert.Equal(t, `["https://x"]`, stub.lastSaveArgs[2])
	assert.Equal(t, "MyApp", stub.lastSaveArgs[3])
	assert.True(t, stub.lastSaveTime.Equal(now), "createdAt round-trip via UnixNano()")
	assert.True(t, stub.lastSaveIsKite)
}

// TestSaveOAuthClient_NilStoreIsNoop pins the guard.
func TestSaveOAuthClient_NilStoreIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewSaveOAuthClientUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.SaveOAuthClientCommand{ClientID: "cid"})
	assert.NoError(t, err)
}

// TestSaveOAuthClient_StoreErrorPropagates pins error-propagation.
func TestSaveOAuthClient_StoreErrorPropagates(t *testing.T) {
	t.Parallel()
	stub := &stubOAuthClientStore{saveErr: errors.New("constraint violation")}
	uc := NewSaveOAuthClientUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.SaveOAuthClientCommand{ClientID: "cid"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "constraint violation")
}

// TestDeleteOAuthClient_HappyPath + nil + error.
func TestDeleteOAuthClient_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubOAuthClientStore{}
	uc := NewDeleteOAuthClientUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteOAuthClientCommand{ClientID: "cid"})
	require.NoError(t, err)
	assert.Equal(t, 1, stub.deleteHits)
	assert.Equal(t, "cid", stub.lastDeleteID)
}

func TestDeleteOAuthClient_NilStoreIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewDeleteOAuthClientUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteOAuthClientCommand{ClientID: "cid"})
	assert.NoError(t, err)
}

func TestDeleteOAuthClient_StoreErrorPropagates(t *testing.T) {
	t.Parallel()
	stub := &stubOAuthClientStore{deleteErr: errors.New("not found")}
	uc := NewDeleteOAuthClientUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.DeleteOAuthClientCommand{ClientID: "cid"})
	require.Error(t, err)
}

// ===========================================================================
// AdminRegisterApp / AdminUpdateRegistry / AdminDeleteRegistry
// ===========================================================================

// TestAdminRegisterApp_HappyPath pins the wiring: the use case must
// stamp Status=active and Source=admin (not pass-through from the
// command — those are policy decisions made by the use case).
func TestAdminRegisterApp_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubRegistryAdminWriter{}
	uc := NewAdminRegisterAppUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminRegisterAppCommand{
		ID: "id1", APIKey: "k1", APISecret: "s1",
		AssignedTo: "owner@t.com", Label: "test", RegisteredBy: "admin@t.com",
	})
	require.NoError(t, err)
	assert.Equal(t, "id1", stub.lastRegisterArgs[0])
	assert.Equal(t, "k1", stub.lastRegisterArgs[1])
	assert.Equal(t, "s1", stub.lastRegisterArgs[2])
	assert.Equal(t, "owner@t.com", stub.lastRegisterArgs[3])
	assert.Equal(t, "test", stub.lastRegisterArgs[4])
	assert.Equal(t, RegistryStatusActive, stub.lastRegisterArgs[5],
		"use case must stamp Status=active regardless of input")
	assert.Equal(t, RegistrySourceAdmin, stub.lastRegisterArgs[6],
		"use case must stamp Source=admin (vs self-provisioned)")
	assert.Equal(t, "admin@t.com", stub.lastRegisterArgs[7])
}

func TestAdminRegisterApp_NilWriterIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewAdminRegisterAppUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminRegisterAppCommand{ID: "id"})
	assert.NoError(t, err)
}

func TestAdminUpdateRegistry_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubRegistryAdminWriter{}
	uc := NewAdminUpdateRegistryUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUpdateRegistryCommand{
		ID: "id1", AssignedTo: "newowner@t.com", Label: "renamed", Status: "active",
	})
	require.NoError(t, err)
	assert.Equal(t, [4]string{"id1", "newowner@t.com", "renamed", "active"}, stub.lastUpdateArgs)
}

func TestAdminUpdateRegistry_NilWriterIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewAdminUpdateRegistryUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminUpdateRegistryCommand{ID: "id"})
	assert.NoError(t, err)
}

func TestAdminDeleteRegistry_HappyPath(t *testing.T) {
	t.Parallel()
	stub := &stubRegistryAdminWriter{}
	uc := NewAdminDeleteRegistryUseCase(stub, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminDeleteRegistryCommand{ID: "id1"})
	require.NoError(t, err)
	assert.Equal(t, "id1", stub.lastDeleteID)
}

func TestAdminDeleteRegistry_NilWriterIsNoop(t *testing.T) {
	t.Parallel()
	uc := NewAdminDeleteRegistryUseCase(nil, testLogger())
	err := uc.Execute(context.Background(), cqrs.AdminDeleteRegistryCommand{ID: "id"})
	assert.NoError(t, err)
}

// ===========================================================================
// truncForLog (pure helper, was 0%)
// ===========================================================================

// TestTruncForLog covers both branches: short-or-equal returns the
// string + ellipsis; longer truncates to n chars + ellipsis.
func TestTruncForLog(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		in   string
		n    int
		want string
	}{
		{"empty", "", 8, "..."},
		{"shorter than n", "abc", 8, "abc..."},
		{"exactly n", "abcdefgh", 8, "abcdefgh..."},
		{"longer than n", "abcdefghIJKLMNOP", 8, "abcdefgh..."},
		{"longer with n=4", "abcdefgh", 4, "abcd..."},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, truncForLog(tc.in, tc.n))
		})
	}
}
