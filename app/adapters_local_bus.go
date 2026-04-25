package app

// adapters_local_bus.go — provides the in-process CommandBus instances
// adapters fall back to when no manager-supplied bus has been wired
// (typically unit tests that construct adapters by struct literal).
//
// The buses returned here are FUNCTIONALLY identical to the manager-
// wired buses: same use cases, same handler dispatch, same logging
// middleware. The ONLY difference is provenance — these are constructed
// inside the adapter via ensureBus() rather than wired by the manager.
//
// CQRS invariant: every write in app/adapters.go goes through Dispatch.
// No code path performs a raw store write. Tests that need to exercise
// the writes must let ensureBus() run; the resulting bus dispatches to
// the same use case handlers production uses.

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"reflect"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/registry"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
)

// localBusLogger normalises a possibly-nil logger to a discard logger so
// the LoggingMiddleware never panics on a nil receiver. Tests that build
// adapters by struct literal often omit the logger; production always
// wires one.
func localBusLogger(l *slog.Logger) *slog.Logger {
	if l != nil {
		return l
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// oauthBridgeStores carries the concrete stores the local bus's handlers
// need to bind. Each store may be nil — handlers no-op when their backing
// store is missing (mirrors the production handler's nil-check pattern in
// kc/manager_commands_oauth.go).
type oauthBridgeStores struct {
	Users       *users.Store
	Tokens      *kc.KiteTokenStore
	Credentials *kc.KiteCredentialStore
	Registry    *registry.Store
}

// newLocalOAuthBridgeBus constructs a CommandBus pre-registered with the
// four OAuth-bridge command handlers used by kiteExchangerAdapter:
// ProvisionUserOnLogin, CacheKiteAccessToken, StoreUserKiteCredentials,
// SyncRegistryAfterLogin.
//
// Production never hits this path — kcManager.CommandBus() wires its own
// bus with these handlers. The local bus is structurally identical so
// adapter behaviour is invariant under "did the test wire a manager".
func newLocalOAuthBridgeBus(logger *slog.Logger, stores oauthBridgeStores) cqrs.CommandBus {
	logger = localBusLogger(logger)
	bus := cqrs.NewInMemoryBus(cqrs.LoggingMiddleware(logger))

	// ProvisionUserOnLoginCommand — the user-store mutation path.
	if err := bus.Register(reflect.TypeFor[cqrs.ProvisionUserOnLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.ProvisionUserOnLoginCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		var port usecases.UserProvisioner
		if stores.Users != nil {
			port = &localUserProvisioner{store: stores.Users}
		}
		uc := usecases.NewProvisionUserOnLoginUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		// Register only fails on duplicate type — impossible here.
		panic(err)
	}

	// CacheKiteAccessTokenCommand
	if err := bus.Register(reflect.TypeFor[cqrs.CacheKiteAccessTokenCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.CacheKiteAccessTokenCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		var port usecases.KiteTokenWriter
		if stores.Tokens != nil {
			port = &localKiteTokenWriter{store: stores.Tokens}
		}
		uc := usecases.NewCacheKiteAccessTokenUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		panic(err)
	}

	// StoreUserKiteCredentialsCommand
	if err := bus.Register(reflect.TypeFor[cqrs.StoreUserKiteCredentialsCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.StoreUserKiteCredentialsCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		var port usecases.KiteCredentialWriter
		if stores.Credentials != nil {
			port = &localKiteCredentialWriter{store: stores.Credentials}
		}
		uc := usecases.NewStoreUserKiteCredentialsUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		panic(err)
	}

	// SyncRegistryAfterLoginCommand
	if err := bus.Register(reflect.TypeFor[cqrs.SyncRegistryAfterLoginCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SyncRegistryAfterLoginCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		var port usecases.RegistrySync
		if stores.Registry != nil {
			port = &localRegistrySync{store: stores.Registry}
		}
		uc := usecases.NewSyncRegistryAfterLoginUseCase(port, logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		panic(err)
	}

	return bus
}

// newLocalOAuthClientBus constructs a CommandBus with the two OAuth
// client-persistence handlers used by clientPersisterAdapter.
func newLocalOAuthClientBus(logger *slog.Logger, db *alerts.DB) cqrs.CommandBus {
	logger = localBusLogger(logger)
	bus := cqrs.NewInMemoryBus(cqrs.LoggingMiddleware(logger))
	clientStore := func() usecases.OAuthClientStore {
		if db == nil {
			return nil
		}
		return &localOAuthClientStore{db: db}
	}
	if err := bus.Register(reflect.TypeFor[cqrs.SaveOAuthClientCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.SaveOAuthClientCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		uc := usecases.NewSaveOAuthClientUseCase(clientStore(), logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		panic(err)
	}
	if err := bus.Register(reflect.TypeFor[cqrs.DeleteOAuthClientCommand](), func(ctx context.Context, msg any) (any, error) {
		cmd, ok := msg.(cqrs.DeleteOAuthClientCommand)
		if !ok {
			return nil, fmt.Errorf("local bus: unexpected command type %T", msg)
		}
		uc := usecases.NewDeleteOAuthClientUseCase(clientStore(), logger)
		return nil, uc.Execute(ctx, cmd)
	}); err != nil {
		panic(err)
	}
	return bus
}

// --- local port adapters: mirror kc/manager_commands_oauth.go's adapters
// but live in the app package so the test-mode local bus has somewhere to
// implement the narrow ports without the manager. Production handlers
// continue to use the kc-package adapters.

type localUserProvisioner struct {
	store *users.Store
}

func (a *localUserProvisioner) GetStatus(email string) string {
	return a.store.GetStatus(email)
}
func (a *localUserProvisioner) EnsureUser(email, kiteUID, displayName, onboardedBy string) usecases.UserRecord {
	u := a.store.EnsureUser(email, kiteUID, displayName, onboardedBy)
	if u == nil {
		return nil
	}
	return &localUserRecord{u: u}
}
func (a *localUserProvisioner) UpdateLastLogin(email string)        { a.store.UpdateLastLogin(email) }
func (a *localUserProvisioner) UpdateKiteUID(email, kiteUID string) { a.store.UpdateKiteUID(email, kiteUID) }

type localUserRecord struct{ u *users.User }

func (r *localUserRecord) GetKiteUID() string { return r.u.KiteUID }

type localKiteTokenWriter struct {
	store *kc.KiteTokenStore
}

func (a *localKiteTokenWriter) SetToken(email, accessToken, userID, userName string) {
	a.store.Set(email, &kc.KiteTokenEntry{
		AccessToken: accessToken,
		UserID:      userID,
		UserName:    userName,
	})
}

type localKiteCredentialWriter struct {
	store *kc.KiteCredentialStore
}

func (a *localKiteCredentialWriter) SetCredentials(email, apiKey, apiSecret string) {
	a.store.Set(email, &kc.KiteCredentialEntry{
		APIKey:    apiKey,
		APISecret: apiSecret,
	})
}

type localRegistrySync struct {
	store *registry.Store
}

func (a *localRegistrySync) GetByEmail(email string) (string, bool) {
	reg, found := a.store.GetByEmail(email)
	if !found {
		return "", false
	}
	return reg.APIKey, true
}
func (a *localRegistrySync) GetByAPIKeyAnyStatus(apiKey string) (string, bool) {
	reg, found := a.store.GetByAPIKeyAnyStatus(apiKey)
	if !found {
		return "", false
	}
	return reg.AssignedTo, true
}
func (a *localRegistrySync) MarkStatus(apiKey, status string) {
	a.store.MarkStatus(apiKey, status)
}
func (a *localRegistrySync) Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error {
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
func (a *localRegistrySync) Update(apiKey, newAssignedTo, label, status string) error {
	reg, found := a.store.GetByAPIKeyAnyStatus(apiKey)
	if !found {
		return fmt.Errorf("registry: no entry for apiKey lookup during reassignment")
	}
	return a.store.Update(reg.ID, newAssignedTo, label, status)
}
func (a *localRegistrySync) UpdateLastUsedAt(apiKey string) {
	a.store.UpdateLastUsedAt(apiKey)
}

type localOAuthClientStore struct {
	db *alerts.DB
}

func (a *localOAuthClientStore) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	return a.db.SaveClient(clientID, clientSecret, redirectURIsJSON, clientName, createdAt, isKiteKey)
}
func (a *localOAuthClientStore) DeleteClient(clientID string) error {
	return a.db.DeleteClient(clientID)
}
