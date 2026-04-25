package kc

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// manager_commands_oauth.go — wires CommandBus handlers for the OAuth/login
// bridge commands defined in kc/cqrs/commands_ext.go. These are the writes
// that previously happened inline inside app/adapters.go (kiteExchanger
// Adapter and clientPersisterAdapter); routing them through the bus
// satisfies the CQRS contract uniformly.
//
// Handler bodies are thin: each constructs the use case from concrete
// stores held by the Manager (via narrow adapters defined below) and
// dispatches. No business logic lives here — the use cases own all rules.

// registerOAuthBridgeCommands wires the 6 OAuth-bridge commands.
func (m *Manager) registerOAuthBridgeCommands() error {
	// ProvisionUserOnLoginCommand
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.ProvisionUserOnLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ProvisionUserOnLoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.UserProvisioner
		if m.userStore != nil {
			port = &userProvisionerAdapter{store: m.userStore}
		}
		uc := usecases.NewProvisionUserOnLoginUseCase(port, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// CacheKiteAccessTokenCommand
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.CacheKiteAccessTokenCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CacheKiteAccessTokenCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.KiteTokenWriter
		if m.tokenStore != nil {
			port = &kiteTokenWriterAdapter{store: m.tokenStore}
		}
		uc := usecases.NewCacheKiteAccessTokenUseCase(port, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// StoreUserKiteCredentialsCommand
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.StoreUserKiteCredentialsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StoreUserKiteCredentialsCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.KiteCredentialWriter
		if m.credentialStore != nil {
			port = &kiteCredentialWriterAdapter{store: m.credentialStore}
		}
		uc := usecases.NewStoreUserKiteCredentialsUseCase(port, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// SyncRegistryAfterLoginCommand
	if err := m.commandBus.Register(reflect.TypeFor[cqrs.SyncRegistryAfterLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SyncRegistryAfterLoginCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		var port usecases.RegistrySync
		if m.registryStore != nil {
			port = &registrySyncAdapter{store: m.registryStore}
		}
		uc := usecases.NewSyncRegistryAfterLoginUseCase(port, m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// SaveOAuthClientCommand + DeleteOAuthClientCommand share an adapter.
	clientStore := func() usecases.OAuthClientStore {
		db := m.AlertDB()
		if db == nil {
			return nil
		}
		return &oauthClientStoreAdapter{db: db}
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.SaveOAuthClientCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SaveOAuthClientCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewSaveOAuthClientUseCase(clientStore(), m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.DeleteOAuthClientCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteOAuthClientCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewDeleteOAuthClientUseCase(clientStore(), m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	// Admin registry mutations — replaces the direct registryStore.Register
	// /Update/Delete calls in kc/ops/handler_admin.go so admin writes hit
	// LoggingMiddleware uniformly.
	regWriter := func() usecases.RegistryAdminWriter {
		if m.registryStore == nil {
			return nil
		}
		return &registryAdminWriterAdapter{store: m.registryStore}
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminRegisterAppCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminRegisterAppCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminRegisterAppUseCase(regWriter(), m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminUpdateRegistryCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminUpdateRegistryCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminUpdateRegistryUseCase(regWriter(), m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	if err := m.commandBus.Register(reflect.TypeFor[cqrs.AdminDeleteRegistryCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.AdminDeleteRegistryCommand)
		if !ok {
			return nil, fmt.Errorf("cqrs: unexpected command type %T", msg)
		}
		uc := usecases.NewAdminDeleteRegistryUseCase(regWriter(), m.Logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		return err
	}

	return nil
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
