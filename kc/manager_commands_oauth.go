package kc

import (
	"context"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-cqrs"
	"github.com/algo2go/kite-mcp-registry"
	"github.com/algo2go/kite-mcp-usecases"
	"github.com/algo2go/kite-mcp-users"
)

// manager_commands_oauth.go — wires CommandBus handlers for the OAuth/login
// bridge commands defined in kc/cqrs/commands_ext.go. These are the writes
// that previously happened inline inside app/adapters.go (kiteExchanger
// Adapter and clientPersisterAdapter); routing them through the bus
// satisfies the CQRS contract uniformly.
//
// Tier 2.2 (Path A.28 follow-up to Tier 1 closure-DI track): the registrar
// has been extracted to a package-level pure function
// (registerOAuthBridgeCommandsOnBus) following the same precedent
// established at usecases.RegisterOAuthClientHandlers — a one-shot
// stateless registrar that takes (bus, deps, logger) as parameters.
// The Manager method `(m *Manager) registerOAuthBridgeCommands()` becomes
// a 1-line delegator that constructs the deps from Manager fields and
// calls the package-level function.
//
// Why pure-function (not Tier 1's closure-DI struct):
//   - Registrars are one-shot (run once at Manager init) — no state held
//     for Manager's lifetime
//   - Existing precedent at usecases.RegisterOAuthClientHandlers is the
//     same shape (called from both Manager init AND
//     app/adapters_local_bus.go for parallel local-bus mirror)
//   - Closure-DI struct ceremony would add wrapping without behavioural
//     improvement
//
// Handler bodies are thin: each constructs the use case from the
// dependency stores (via narrow adapters defined below) and dispatches.
// No business logic lives here — the use cases own all rules.

// OAuthBridgeRegistrarDeps holds the store dependencies needed to register
// the OAuth-bridge command handlers. The package-level registrar consumes
// this struct so it can be shared across multiple bus instances (production
// Manager + the local-bus mirror in app/adapters_local_bus.go style
// follow-ups, if any).
//
// Note: AlertDB is provided as a getter closure (not a *alerts.DB value
// directly) because the OAuth-client-store handler reaches it lazily —
// only when a SaveOAuthClient/DeleteOAuthClient command arrives. The
// closure preserves the original "evaluate at command-dispatch time"
// semantics; constructing the deps eagerly with a *alerts.DB would
// dereference Manager.AlertDB() at registration time and panic on test
// fixtures that don't initialize the stores facade.
type OAuthBridgeRegistrarDeps struct {
	UserStore       *users.Store
	TokenStore      *KiteTokenStore
	CredentialStore *KiteCredentialStore
	RegistryStore   *registry.Store
	AlertDBGetter   func() *alerts.DB // lazy access for OAuth client store; nil-safe
}

// registerOAuthBridgeCommandsOnBus is the package-level pure-function
// registrar. Wires the 6 OAuth-bridge commands (+ delegated 2 OAuth-client
// + 3 admin-registry commands) onto the given bus, using the stores in
// deps. nil-safe: each handler checks its dep before adapting.
//
// Returns the first registration error, if any. The handler closures
// capture deps by value so post-construction mutations of the source
// stores (which are pointer types here) remain visible — same observable
// semantics as the prior Manager-method body.
func registerOAuthBridgeCommandsOnBus(
	bus *cqrs.InMemoryBus,
	deps OAuthBridgeRegistrarDeps,
	logger *slog.Logger,
) error {
	// ProvisionUserOnLoginCommand
	if err := bus.Register(reflect.TypeFor[cqrs.ProvisionUserOnLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ProvisionUserOnLoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.UserProvisioner
		if deps.UserStore != nil {
			port = &userProvisionerAdapter{store: deps.UserStore}
		}
		uc := usecases.NewProvisionUserOnLoginUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// CacheKiteAccessTokenCommand
	if err := bus.Register(reflect.TypeFor[cqrs.CacheKiteAccessTokenCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CacheKiteAccessTokenCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.KiteTokenWriter
		if deps.TokenStore != nil {
			port = &kiteTokenWriterAdapter{store: deps.TokenStore}
		}
		uc := usecases.NewCacheKiteAccessTokenUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// StoreUserKiteCredentialsCommand
	if err := bus.Register(reflect.TypeFor[cqrs.StoreUserKiteCredentialsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StoreUserKiteCredentialsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.KiteCredentialWriter
		if deps.CredentialStore != nil {
			port = &kiteCredentialWriterAdapter{store: deps.CredentialStore}
		}
		uc := usecases.NewStoreUserKiteCredentialsUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// SyncRegistryAfterLoginCommand
	if err := bus.Register(reflect.TypeFor[cqrs.SyncRegistryAfterLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SyncRegistryAfterLoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.RegistrySync
		if deps.RegistryStore != nil {
			port = &registrySyncAdapter{store: deps.RegistryStore}
		}
		uc := usecases.NewSyncRegistryAfterLoginUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// SaveOAuthClient + DeleteOAuthClient handler pair — registration shape
	// is canonicalised in usecases.RegisterOAuthClientHandlers (Phase B/D
	// F6 close). The mirror in app/adapters_local_bus.go's
	// newLocalOAuthClientBus calls the same helper with its fresh
	// in-process bus + localOAuthClientStore adapter.
	//
	// Lazy: AlertDBGetter() is invoked at command-dispatch time, not at
	// registration time, preserving the original "stores facade may not
	// be initialised on minimal test fixtures" tolerance.
	clientStore := func() usecases.OAuthClientStore {
		if deps.AlertDBGetter == nil {
			return nil
		}
		db := deps.AlertDBGetter()
		if db == nil {
			return nil
		}
		return &oauthClientStoreAdapter{db: db}
	}
	if err := usecases.RegisterOAuthClientHandlers(bus, clientStore, logger, "cqrs"); err != nil {
		return err
	}

	// Admin registry mutations — replaces the direct registryStore.Register
	// /Update/Delete calls in kc/ops/handler_admin.go so admin writes hit
	// LoggingMiddleware uniformly.
	regWriter := func() usecases.RegistryAdminWriter {
		if deps.RegistryStore == nil {
			return nil
		}
		return &registryAdminWriterAdapter{store: deps.RegistryStore}
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminRegisterAppCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminRegisterAppCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminRegisterAppUseCase(regWriter(), logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminUpdateRegistryCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUpdateRegistryCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminUpdateRegistryUseCase(regWriter(), logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := bus.Register(reflect.TypeFor[cqrs.AdminDeleteRegistryCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminDeleteRegistryCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminDeleteRegistryUseCase(regWriter(), logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	return nil
}

// registerOAuthBridgeCommands wires the 6 OAuth-bridge commands by
// delegating to the package-level pure-function registrar
// (registerOAuthBridgeCommandsOnBus). This 1-line method preserves the
// existing call-site contract (m.registerOAuthBridgeCommands() is invoked
// from kc/manager_cqrs_register.go's registerCQRSHandlers chain) while
// the actual registration logic lives in the testable package-level
// function above.
func (m *Manager) registerOAuthBridgeCommands() error {
	return registerOAuthBridgeCommandsOnBus(m.commandBus, OAuthBridgeRegistrarDeps{
		UserStore:       m.userStore,
		TokenStore:      m.tokenStore,
		CredentialStore: m.credentialStore,
		RegistryStore:   m.registryStore,
		AlertDBGetter:   m.AlertDB,
	}, m.Logger)
}

// registryAdminWriterAdapter bridges *registry.Store to the admin
// RegistryAdminWriter port. Defined separately from registrySyncAdapter
// so the admin-write path doesn't depend on the (sync-rotation) port.
type registryAdminWriterAdapter struct {
	store *registry.Store
}

func (a *registryAdminWriterAdapter) Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error {
	return a.store.Register(&registry.AppRegistration{
		ID:           id,
		APIKey:       apiKey,
		APISecret:    apiSecret,
		AssignedTo:   assignedTo,
		Label:        label,
		Status:       status,
		Source:       source,
		RegisteredBy: registeredBy,
	})
}

func (a *registryAdminWriterAdapter) Update(id, assignedTo, label, status string) error {
	return a.store.Update(id, assignedTo, label, status)
}

func (a *registryAdminWriterAdapter) Delete(id string) error {
	return a.store.Delete(id)
}

// --- adapter shims: bridge concrete stores to the narrow ports defined
// in kc/usecases/oauth_bridge_usecases.go ---

// userProvisionerAdapter bridges *users.Store to usecases.UserProvisioner.
type userProvisionerAdapter struct {
	store *users.Store
}

func (a *userProvisionerAdapter) GetStatus(email string) string {
	return a.store.GetStatus(email)
}

func (a *userProvisionerAdapter) EnsureUser(email, kiteUID, displayName, onboardedBy string) usecases.UserRecord {
	u := a.store.EnsureUser(email, kiteUID, displayName, onboardedBy)
	if u == nil {
		return nil
	}
	return &userRecordAdapter{u: u}
}

func (a *userProvisionerAdapter) UpdateLastLogin(email string) {
	a.store.UpdateLastLogin(email)
}

func (a *userProvisionerAdapter) UpdateKiteUID(email, kiteUID string) {
	a.store.UpdateKiteUID(email, kiteUID)
}

// userRecordAdapter exposes only the fields the use case needs.
type userRecordAdapter struct {
	u *users.User
}

func (r *userRecordAdapter) GetKiteUID() string {
	return r.u.KiteUID
}

// kiteTokenWriterAdapter bridges *KiteTokenStore.Set to KiteTokenWriter.
type kiteTokenWriterAdapter struct {
	store *KiteTokenStore
}

func (a *kiteTokenWriterAdapter) SetToken(email, accessToken, userID, userName string) {
	a.store.Set(email, &KiteTokenEntry{
		AccessToken: accessToken,
		UserID:      userID,
		UserName:    userName,
	})
}

// kiteCredentialWriterAdapter bridges *KiteCredentialStore.Set to KiteCredentialWriter.
type kiteCredentialWriterAdapter struct {
	store *KiteCredentialStore
}

func (a *kiteCredentialWriterAdapter) SetCredentials(email, apiKey, apiSecret string) {
	a.store.Set(email, &KiteCredentialEntry{
		APIKey:    apiKey,
		APISecret: apiSecret,
	})
}

// registrySyncAdapter bridges *registry.Store to usecases.RegistrySync.
// Translates between the use case's plain-string contract and the
// registry's *registry.AppRegistration internal struct.
type registrySyncAdapter struct {
	store *registry.Store
}

func (a *registrySyncAdapter) GetByEmail(email string) (string, bool) {
	reg, found := a.store.GetByEmail(email)
	if !found {
		return "", false
	}
	return reg.APIKey, true
}

func (a *registrySyncAdapter) GetByAPIKeyAnyStatus(apiKey string) (string, bool) {
	reg, found := a.store.GetByAPIKeyAnyStatus(apiKey)
	if !found {
		return "", false
	}
	// Use case wants the AssignedTo email so it can decide whether to reassign.
	return reg.AssignedTo, true
}

func (a *registrySyncAdapter) MarkStatus(apiKey, status string) {
	a.store.MarkStatus(apiKey, status)
}

func (a *registrySyncAdapter) Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error {
	return a.store.Register(&registry.AppRegistration{
		ID:           id,
		APIKey:       apiKey,
		APISecret:    apiSecret,
		AssignedTo:   assignedTo,
		Label:        label,
		Status:       status,
		Source:       source,
		RegisteredBy: registeredBy,
	})
}

// Update is invoked by the use case when an existing key needs reassignment
// to a new owner. The use case passes (apiKey, newAssignedTo, label, status).
// We translate apiKey → registry ID by looking the row up first.
func (a *registrySyncAdapter) Update(apiKey, newAssignedTo, label, status string) error {
	reg, found := a.store.GetByAPIKeyAnyStatus(apiKey)
	if !found {
		return fmt.Errorf("registry: no entry for apiKey lookup during reassignment")
	}
	return a.store.Update(reg.ID, newAssignedTo, label, status)
}

func (a *registrySyncAdapter) UpdateLastUsedAt(apiKey string) {
	a.store.UpdateLastUsedAt(apiKey)
}

// oauthClientStoreAdapter bridges *alerts.DB to usecases.OAuthClientStore.
type oauthClientStoreAdapter struct {
	db *alerts.DB
}

func (a *oauthClientStoreAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	return a.db.SaveClient(clientID, clientSecret, redirectURIsJSON, clientName, createdAt, isKiteKey)
}

func (a *oauthClientStoreAdapter) DeleteClient(clientID string) error {
	return a.db.DeleteClient(clientID)
}
