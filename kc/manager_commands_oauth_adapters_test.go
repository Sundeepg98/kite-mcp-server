package kc

// Coverage for the thin store adapters in manager_commands_oauth.go that
// bridge concrete kc/users / KiteTokenStore / KiteCredentialStore /
// kc/registry / kc/alerts.DB stores to the narrow ports defined in
// kc/usecases/oauth_bridge_usecases.go.
//
// Each adapter is a pass-through translator: arguments map 1:1 onto the
// underlying store call. Coverage gap before this file: 18 functions at
// 0%. After: each adapter is exercised with a real in-memory store
// (no mocks, no SQLite for the in-memory ones; :memory: SQLite for
// alerts.DB which actually requires a real connection).
//
// Test discipline: every test t.Parallel(); errors injected by routing
// through real stores rather than test doubles. No goroutines, no I/O
// beyond :memory: SQLite. Hand-rolled assertions (no testify) to match
// the rest of kc/.

import (
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// quietOAuthAdapterLogger discards log output for hermetic tests.
func quietOAuthAdapterLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestCommandBus returns an in-memory CommandBus suitable for the wiring
// smoke test below.
func newTestCommandBus() *cqrs.InMemoryBus {
	return cqrs.NewInMemoryBus()
}

// ---------------------------------------------------------------------------
// userProvisionerAdapter — bridges *users.Store to usecases.UserProvisioner.
// ---------------------------------------------------------------------------

func TestUserProvisionerAdapter_GetStatus_KnownAndUnknown(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	a := &userProvisionerAdapter{store: store}

	// Unknown user -> empty string per *users.Store.GetStatus contract.
	if got := a.GetStatus("nobody@example.com"); got != "" {
		t.Errorf("unknown user GetStatus: got %q, want empty", got)
	}

	// Provision a user, then GetStatus must return their persisted status.
	u := store.EnsureUser("alice@example.com", "uid-A", "Alice", "test")
	if u == nil {
		t.Fatal("EnsureUser returned nil for valid email")
	}
	got := a.GetStatus("alice@example.com")
	if got != users.StatusActive {
		t.Errorf("GetStatus(alice): got %q, want %q", got, users.StatusActive)
	}

	// Email-case insensitivity is a *users.Store contract — re-prove via adapter.
	if got := a.GetStatus("ALICE@example.com"); got != users.StatusActive {
		t.Errorf("uppercase GetStatus: got %q, want %q", got, users.StatusActive)
	}
}

func TestUserProvisionerAdapter_EnsureUser_NewUserReturnsAdapter(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	a := &userProvisionerAdapter{store: store}

	rec := a.EnsureUser("bob@example.com", "kite-uid-B", "Bob Display", "test-onboarding")
	if rec == nil {
		t.Fatal("EnsureUser returned nil for new user")
	}
	// Returned UserRecord must expose KiteUID via the adapter wrapper.
	if got := rec.GetKiteUID(); got != "kite-uid-B" {
		t.Errorf("GetKiteUID: got %q, want kite-uid-B", got)
	}

	// Underlying store must now contain the user.
	if got := store.GetStatus("bob@example.com"); got != users.StatusActive {
		t.Errorf("after EnsureUser, store status: got %q, want active", got)
	}
}

func TestUserProvisionerAdapter_EnsureUser_EmptyEmailReturnsNil(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	a := &userProvisionerAdapter{store: store}

	// EnsureUser with whitespace/empty email -> *users.Store returns nil ->
	// adapter must propagate as nil (not panic dereferencing).
	if rec := a.EnsureUser("", "uid", "name", "test"); rec != nil {
		t.Errorf("empty email: got non-nil rec, want nil")
	}
	if rec := a.EnsureUser("   ", "uid", "name", "test"); rec != nil {
		t.Errorf("whitespace email: got non-nil rec, want nil")
	}
}

func TestUserProvisionerAdapter_EnsureUser_ExistingUserReturnsAdapter(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	store.EnsureUser("carol@example.com", "uid-C-original", "Carol", "first-time")

	a := &userProvisionerAdapter{store: store}
	rec := a.EnsureUser("carol@example.com", "uid-C-DUPLICATE", "Carol-2", "second-call")
	if rec == nil {
		t.Fatal("EnsureUser returned nil for existing user (must idempotently return existing record)")
	}
	// Idempotent: existing user wins; KiteUID must be the original, not the dup.
	if got := rec.GetKiteUID(); got != "uid-C-original" {
		t.Errorf("EnsureUser on existing: got KiteUID %q, want original uid-C-original", got)
	}
}

func TestUserProvisionerAdapter_UpdateLastLogin_Delegates(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	store.EnsureUser("dave@example.com", "uid-D", "Dave", "test")
	a := &userProvisionerAdapter{store: store}

	// Read the user's LastLogin pre-call. EnsureUser does NOT seed LastLogin.
	pre, ok := store.Get("dave@example.com")
	if !ok {
		t.Fatal("user not found pre-UpdateLastLogin")
	}
	preLogin := pre.LastLogin

	// Call adapter's UpdateLastLogin.
	a.UpdateLastLogin("dave@example.com")

	// Verify the underlying store recorded the login.
	post, ok := store.Get("dave@example.com")
	if !ok {
		t.Fatal("user disappeared post-UpdateLastLogin")
	}
	if !post.LastLogin.After(preLogin) && post.LastLogin.Equal(preLogin) {
		t.Errorf("LastLogin not updated: pre=%v, post=%v", preLogin, post.LastLogin)
	}

	// Adapter must be a silent no-op for unknown email — *users.Store
	// guarantees that contract, so the adapter must too.
	a.UpdateLastLogin("nobody@example.com") // expected: no panic, no error
}

func TestUserProvisionerAdapter_UpdateKiteUID_Delegates(t *testing.T) {
	t.Parallel()
	store := users.NewStore()
	store.EnsureUser("eve@example.com", "uid-E-original", "Eve", "test")
	a := &userProvisionerAdapter{store: store}

	a.UpdateKiteUID("eve@example.com", "uid-E-NEW")

	got, ok := store.Get("eve@example.com")
	if !ok {
		t.Fatal("user not found post-UpdateKiteUID")
	}
	if got.KiteUID != "uid-E-NEW" {
		t.Errorf("UpdateKiteUID: got %q, want uid-E-NEW", got.KiteUID)
	}

	// Adapter must be a silent no-op for unknown email.
	a.UpdateKiteUID("nobody@example.com", "uid-X") // no panic, no error
}

// ---------------------------------------------------------------------------
// userRecordAdapter — exposes only KiteUID for the use case.
// ---------------------------------------------------------------------------

func TestUserRecordAdapter_GetKiteUID(t *testing.T) {
	t.Parallel()
	u := &users.User{KiteUID: "wrapped-uid"}
	r := &userRecordAdapter{u: u}

	if got := r.GetKiteUID(); got != "wrapped-uid" {
		t.Errorf("GetKiteUID: got %q, want wrapped-uid", got)
	}

	// Empty KiteUID propagates as empty string.
	r2 := &userRecordAdapter{u: &users.User{}}
	if got := r2.GetKiteUID(); got != "" {
		t.Errorf("empty user GetKiteUID: got %q, want empty", got)
	}
}

// ---------------------------------------------------------------------------
// kiteTokenWriterAdapter — bridges KiteTokenStore.Set to KiteTokenWriter.
// ---------------------------------------------------------------------------

func TestKiteTokenWriterAdapter_SetToken_Persists(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()
	a := &kiteTokenWriterAdapter{store: store}

	a.SetToken("frank@example.com", "access-token-F", "user-F", "Frank")

	got, ok := store.Get("frank@example.com")
	if !ok {
		t.Fatal("token not stored")
	}
	if got.AccessToken != "access-token-F" {
		t.Errorf("AccessToken: got %q, want access-token-F", got.AccessToken)
	}
	if got.UserID != "user-F" {
		t.Errorf("UserID: got %q, want user-F", got.UserID)
	}
	if got.UserName != "Frank" {
		t.Errorf("UserName: got %q, want Frank", got.UserName)
	}
	if got.StoredAt.IsZero() {
		t.Error("StoredAt was not set by underlying store")
	}
}

func TestKiteTokenWriterAdapter_SetToken_Overwrite(t *testing.T) {
	t.Parallel()
	store := NewKiteTokenStore()
	a := &kiteTokenWriterAdapter{store: store}

	a.SetToken("grace@example.com", "old-token", "user-G", "Grace")
	a.SetToken("grace@example.com", "new-token", "user-G", "Grace")

	got, ok := store.Get("grace@example.com")
	if !ok {
		t.Fatal("token missing after overwrite")
	}
	if got.AccessToken != "new-token" {
		t.Errorf("Overwrite: got %q, want new-token", got.AccessToken)
	}
}

// ---------------------------------------------------------------------------
// kiteCredentialWriterAdapter — bridges KiteCredentialStore.Set.
// ---------------------------------------------------------------------------

func TestKiteCredentialWriterAdapter_SetCredentials_Persists(t *testing.T) {
	t.Parallel()
	store := NewKiteCredentialStore()
	a := &kiteCredentialWriterAdapter{store: store}

	a.SetCredentials("henry@example.com", "api-key-H", "api-secret-H")

	got, ok := store.Get("henry@example.com")
	if !ok {
		t.Fatal("credentials not stored")
	}
	if got.APIKey != "api-key-H" {
		t.Errorf("APIKey: got %q, want api-key-H", got.APIKey)
	}
	if got.APISecret != "api-secret-H" {
		t.Errorf("APISecret: got %q, want api-secret-H", got.APISecret)
	}
}

// ---------------------------------------------------------------------------
// registrySyncAdapter — bridges *registry.Store to usecases.RegistrySync.
// ---------------------------------------------------------------------------

// regSyncFixture seeds a registry store with one active entry so each adapter
// test can target a known starting state. Returns the store + the adapter.
func regSyncFixture(t *testing.T, apiKey, assignedTo, label string) (*registry.Store, *registrySyncAdapter) {
	t.Helper()
	store := registry.New()
	if err := store.Register(&registry.AppRegistration{
		ID:           "reg-id-1",
		APIKey:       apiKey,
		APISecret:    "secret-1",
		AssignedTo:   assignedTo,
		Label:        label,
		Status:       registry.StatusActive,
		Source:       registry.SourceAdmin,
		RegisteredBy: "test-suite",
	}); err != nil {
		t.Fatalf("seed registry: %v", err)
	}
	return store, &registrySyncAdapter{store: store}
}

func TestRegistrySyncAdapter_GetByEmail_FoundAndMissing(t *testing.T) {
	t.Parallel()
	_, a := regSyncFixture(t, "key-1", "owner@example.com", "Production")

	apiKey, ok := a.GetByEmail("owner@example.com")
	if !ok {
		t.Fatal("expected found for seeded email")
	}
	if apiKey != "key-1" {
		t.Errorf("GetByEmail: got apiKey %q, want key-1", apiKey)
	}

	apiKey, ok = a.GetByEmail("stranger@example.com")
	if ok {
		t.Errorf("expected not-found for stranger email, got apiKey %q", apiKey)
	}
	if apiKey != "" {
		t.Errorf("not-found case must return empty apiKey, got %q", apiKey)
	}
}

func TestRegistrySyncAdapter_GetByAPIKeyAnyStatus_ReturnsAssignedTo(t *testing.T) {
	t.Parallel()
	_, a := regSyncFixture(t, "key-A", "owner-a@example.com", "App-A")

	owner, ok := a.GetByAPIKeyAnyStatus("key-A")
	if !ok {
		t.Fatal("expected found")
	}
	// The adapter intentionally returns AssignedTo (the email), NOT the API
	// key, so the use case can decide on reassignment.
	if owner != "owner-a@example.com" {
		t.Errorf("returned owner: got %q, want owner-a@example.com", owner)
	}

	// Unknown key -> empty + false.
	owner, ok = a.GetByAPIKeyAnyStatus("does-not-exist")
	if ok || owner != "" {
		t.Errorf("unknown key: got (%q, %v), want (\"\", false)", owner, ok)
	}
}

func TestRegistrySyncAdapter_MarkStatus_Updates(t *testing.T) {
	t.Parallel()
	store, a := regSyncFixture(t, "key-M", "owner@example.com", "Label-M")

	a.MarkStatus("key-M", registry.StatusDisabled)

	got, ok := store.GetByAPIKeyAnyStatus("key-M")
	if !ok {
		t.Fatal("entry vanished")
	}
	if got.Status != registry.StatusDisabled {
		t.Errorf("Status: got %q, want %q", got.Status, registry.StatusDisabled)
	}

	// MarkStatus on unknown key is silent no-op (per *registry.Store contract).
	a.MarkStatus("not-a-key", registry.StatusInvalid) // no panic, no error
}

func TestRegistrySyncAdapter_Register_NewEntry(t *testing.T) {
	t.Parallel()
	store := registry.New()
	a := &registrySyncAdapter{store: store}

	err := a.Register("reg-new", "key-new", "secret-new", "new-owner@example.com",
		"NewLabel", registry.StatusActive, registry.SourceAdmin, "test-suite")
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	got, ok := store.Get("reg-new")
	if !ok {
		t.Fatal("registered entry not found")
	}
	if got.APIKey != "key-new" {
		t.Errorf("APIKey: got %q, want key-new", got.APIKey)
	}
	if got.AssignedTo != "new-owner@example.com" {
		t.Errorf("AssignedTo: got %q, want new-owner@example.com", got.AssignedTo)
	}
	if got.Status != registry.StatusActive {
		t.Errorf("Status: got %q, want active", got.Status)
	}
}

func TestRegistrySyncAdapter_Register_DuplicateIDError(t *testing.T) {
	t.Parallel()
	store, a := regSyncFixture(t, "key-1", "owner@example.com", "label")

	// Same ID -> *registry.Store returns "already exists" error; adapter
	// must propagate.
	err := a.Register("reg-id-1", "different-key", "different-secret",
		"someone-else@example.com", "Other", registry.StatusActive,
		registry.SourceAdmin, "test")
	if err == nil {
		t.Fatal("expected duplicate-ID error from Register, got nil")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error should mention 'already exists': got %v", err)
	}
	// Sanity: original entry untouched.
	got, _ := store.Get("reg-id-1")
	if got.APIKey != "key-1" {
		t.Errorf("duplicate attempt mutated original: APIKey=%q", got.APIKey)
	}
}

func TestRegistrySyncAdapter_Update_KnownAPIKey(t *testing.T) {
	t.Parallel()
	_, a := regSyncFixture(t, "key-U", "old-owner@example.com", "OldLabel")

	err := a.Update("key-U", "new-owner@example.com", "NewLabel", registry.StatusActive)
	if err != nil {
		t.Fatalf("Update: %v", err)
	}

	// The adapter looks up by API key, then forwards to store.Update(id, ...).
	owner, ok := a.GetByAPIKeyAnyStatus("key-U")
	if !ok {
		t.Fatal("entry missing after Update")
	}
	if owner != "new-owner@example.com" {
		t.Errorf("AssignedTo after Update: got %q, want new-owner@example.com", owner)
	}
}

func TestRegistrySyncAdapter_Update_UnknownAPIKeyError(t *testing.T) {
	t.Parallel()
	store := registry.New()
	a := &registrySyncAdapter{store: store}

	err := a.Update("ghost-key", "new-owner@example.com", "label", registry.StatusActive)
	if err == nil {
		t.Fatal("expected error for unknown apiKey, got nil")
	}
	if !strings.Contains(err.Error(), "no entry") {
		t.Errorf("error should mention missing entry: got %v", err)
	}
}

func TestRegistrySyncAdapter_UpdateLastUsedAt_NoOpForUnknownKey(t *testing.T) {
	t.Parallel()
	store, a := regSyncFixture(t, "key-X", "owner@example.com", "label")

	// Unknown key: silent no-op (per *registry.Store contract).
	a.UpdateLastUsedAt("not-a-key")
	got, _ := store.GetByAPIKeyAnyStatus("key-X")
	if got.LastUsedAt != nil {
		t.Errorf("untouched entry has LastUsedAt set: %v", got.LastUsedAt)
	}

	// Known key: persists a non-nil LastUsedAt.
	a.UpdateLastUsedAt("key-X")
	got, _ = store.GetByAPIKeyAnyStatus("key-X")
	if got.LastUsedAt == nil {
		t.Error("known-key UpdateLastUsedAt did not set LastUsedAt")
	}
}

// ---------------------------------------------------------------------------
// registryAdminWriterAdapter — admin-write surface, distinct port.
// ---------------------------------------------------------------------------

func TestRegistryAdminWriterAdapter_RegisterUpdateDelete_Roundtrip(t *testing.T) {
	t.Parallel()
	store := registry.New()
	a := &registryAdminWriterAdapter{store: store}

	// Register
	if err := a.Register("admin-1", "admin-key", "admin-secret",
		"admin-owner@example.com", "AdminLabel", registry.StatusActive,
		registry.SourceAdmin, "admin-test"); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// Update — admin path uses ID directly (NOT the lookup-by-apiKey from the
	// sync path). label-only mod here.
	if err := a.Update("admin-1", "", "RenamedLabel", ""); err != nil {
		t.Fatalf("Update: %v", err)
	}
	got, ok := store.Get("admin-1")
	if !ok {
		t.Fatal("entry missing post-Update")
	}
	if got.Label != "RenamedLabel" {
		t.Errorf("Label: got %q, want RenamedLabel", got.Label)
	}
	if got.AssignedTo != "admin-owner@example.com" {
		t.Errorf("Update should not have wiped AssignedTo: got %q", got.AssignedTo)
	}

	// Delete
	if err := a.Delete("admin-1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, ok := store.Get("admin-1"); ok {
		t.Error("entry survived Delete")
	}
}

func TestRegistryAdminWriterAdapter_Delete_UnknownIDError(t *testing.T) {
	t.Parallel()
	store := registry.New()
	a := &registryAdminWriterAdapter{store: store}

	if err := a.Delete("ghost-id"); err == nil {
		t.Error("expected error for missing id, got nil")
	}
}

// ---------------------------------------------------------------------------
// oauthClientStoreAdapter — bridges *alerts.DB.SaveClient/DeleteClient.
// ---------------------------------------------------------------------------

// findClientByID is a small helper that queries via LoadClients and returns
// the matching entry. *alerts.DB exposes LoadClients (all rows) but no
// per-ID Get; this keeps the test free of SQL while still verifying writes.
func findClientByID(t *testing.T, db *alerts.DB, id string) (*alerts.ClientDBEntry, bool) {
	t.Helper()
	all, err := db.LoadClients()
	if err != nil {
		t.Fatalf("LoadClients: %v", err)
	}
	for _, c := range all {
		if c.ClientID == id {
			return c, true
		}
	}
	return nil, false
}

func TestOAuthClientStoreAdapter_SaveAndDeleteClient(t *testing.T) {
	t.Parallel()
	db, err := alerts.OpenDB(":memory:")
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { db.Close() })

	a := &oauthClientStoreAdapter{db: db}

	createdAt := time.Date(2026, 4, 26, 12, 0, 0, 0, time.UTC)
	if err := a.SaveClient("client-1", "client-secret-1",
		`["http://localhost/cb"]`, "Client One", createdAt, false); err != nil {
		t.Fatalf("SaveClient: %v", err)
	}

	got, ok := findClientByID(t, db, "client-1")
	if !ok {
		t.Fatal("client not found after SaveClient")
	}
	if got.ClientID != "client-1" {
		t.Errorf("ClientID: got %q, want client-1", got.ClientID)
	}
	if got.ClientName != "Client One" {
		t.Errorf("ClientName: got %q, want Client One", got.ClientName)
	}
	if got.IsKiteAPIKey {
		t.Error("IsKiteAPIKey: got true, want false (passed false)")
	}

	// Save same ID again — should be UPSERT (INSERT OR REPLACE).
	if err := a.SaveClient("client-1", "different-secret",
		`["http://localhost/new-cb"]`, "Client One Updated", createdAt, true); err != nil {
		t.Fatalf("re-SaveClient: %v", err)
	}
	got, ok = findClientByID(t, db, "client-1")
	if !ok {
		t.Fatal("client missing post-upsert")
	}
	if got.ClientName != "Client One Updated" {
		t.Errorf("upsert: got ClientName %q, want updated", got.ClientName)
	}
	if !got.IsKiteAPIKey {
		t.Error("IsKiteAPIKey: got false, want true (passed true on re-save)")
	}

	// DeleteClient
	if err := a.DeleteClient("client-1"); err != nil {
		t.Fatalf("DeleteClient: %v", err)
	}
	if _, ok := findClientByID(t, db, "client-1"); ok {
		t.Error("client still present after DeleteClient")
	}

	// Delete unknown — DELETE WHERE no-match is not an error in SQLite.
	if err := a.DeleteClient("never-existed"); err != nil {
		t.Errorf("DeleteClient unknown ID should be no-op, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// registerOAuthBridgeCommands — wiring smoke test
// ---------------------------------------------------------------------------
//
// The 6 closure handlers inside registerOAuthBridgeCommands are only
// reachable when the function is called and the resulting commandBus
// receives the corresponding command type. We exercise the wiring via
// Manager construction with the in-memory stores already set up — that
// alone covers the "Register all 6 handlers" path without dispatching
// commands (which would require the full use-case stack).
//
// Coverage benefit: the closures don't fully execute, but the
// register-error-propagation paths and the regWriter / clientStore
// closures themselves do.

func TestManager_OAuthBridgeCommands_Registered(t *testing.T) {
	t.Parallel()
	// Set up only enough Manager state for registerOAuthBridgeCommands to
	// run without panic.
	m := &Manager{
		commandBus:      newTestCommandBus(),
		userStore:       users.NewStore(),
		tokenStore:      NewKiteTokenStore(),
		credentialStore: NewKiteCredentialStore(),
		registryStore:   registry.New(),
		Logger:          quietOAuthAdapterLogger(),
	}

	if err := m.registerOAuthBridgeCommands(); err != nil {
		t.Fatalf("registerOAuthBridgeCommands: %v", err)
	}
	// The command bus now has 9 handlers registered (6 OAuth bridge +
	// 3 admin registry). We only assert the call returned nil — that's the
	// happy-path wiring contract. Re-running it must error (duplicate
	// registration), proving the bus wired correctly.
	err := m.registerOAuthBridgeCommands()
	if err == nil {
		t.Error("expected duplicate-registration error on second call, got nil")
	}
}
