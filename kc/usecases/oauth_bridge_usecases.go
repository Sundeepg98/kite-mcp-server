package usecases

// oauth_bridge_usecases.go — use cases that bridge the OAuth login flow's
// previously-direct store mutations onto the CQRS bus. Each command in
// kc/cqrs/commands_ext.go has exactly one use case here; the manager
// wires concrete kc/users, kc/registry, kc/alerts and kc internal stores
// behind the narrow ports defined below.
//
// Why a "bridge" file instead of folding into existing service files?
// The kiteExchangerAdapter and clientPersisterAdapter sit at the
// app-side OAuth-callback boundary, mutating cross-cutting state
// (users, tokens, credentials, registry, OAuth-client table). They
// don't fit any single existing aggregate root cleanly — bridging is
// the honest description of what they do.

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// ErrUserSuspended is returned by ProvisionUserOnLoginUseCase when the
// target email already has the suspended status set in the user store.
// Callers (the OAuth-callback handler) should fail the login and emit a
// 403 to the client.
var ErrUserSuspended = errors.New("user account is suspended")

// ErrUserOffboarded is returned by ProvisionUserOnLoginUseCase when the
// target email is offboarded — terminal status, distinct from suspended
// (suspended can be re-activated by an admin).
var ErrUserOffboarded = errors.New("user account has been offboarded")

// --- Ports ---

// UserProvisioner is the narrow port the ProvisionUserOnLogin use case needs.
// Implementations adapt kc/users.Store. EnsureUser is an upsert that returns
// the canonical record (or nil if the store is misconfigured); the use case
// uses the returned record to decide whether to backfill the Kite UID.
type UserProvisioner interface {
	GetStatus(email string) string
	EnsureUser(email, kiteUID, displayName, onboardedBy string) UserRecord
	UpdateLastLogin(email string)
	UpdateKiteUID(email, kiteUID string)
}

// UserRecord exposes only the fields the bridge use case needs to decide
// follow-up writes — keeps usecases.UserProvisioner free of the full
// kc/users.User struct which would create an import cycle.
type UserRecord interface {
	GetKiteUID() string
}

// User-status sentinels for the bridge; mirrors the kc/users package
// constants (Suspended/Offboarded). Keeping them as exported strings here
// means usecases doesn't import kc/users.
const (
	UserStatusSuspended  = "suspended"
	UserStatusOffboarded = "offboarded"
)

// KiteTokenWriter persists Kite access tokens.
type KiteTokenWriter interface {
	SetToken(email, accessToken, userID, userName string)
}

// KiteCredentialWriter persists per-user Kite API key/secret pairs.
type KiteCredentialWriter interface {
	SetCredentials(email, apiKey, apiSecret string)
}

// RegistrySync is the port for SyncRegistryAfterLogin. Mirrors the few
// methods kiteExchangerAdapter calls on kc/registry.Store — narrow enough
// to test with a fake.
//
// Update is keyed by APIKey here (not by registry-internal ID) because
// the use case identifies rows by APIKey at this layer. The adapter is
// responsible for translating APIKey → ID.
type RegistrySync interface {
	GetByEmail(email string) (apiKey string, found bool)
	GetByAPIKeyAnyStatus(apiKey string) (assignedTo string, found bool)
	MarkStatus(apiKey, status string)
	Register(id, apiKey, apiSecret, assignedTo, label, status, source, registeredBy string) error
	Update(apiKey, newAssignedTo, label, status string) error
	UpdateLastUsedAt(apiKey string)
}

// OAuthClientStore persists OAuth dynamic-client registrations.
type OAuthClientStore interface {
	SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error
	DeleteClient(clientID string) error
}

// --- ProvisionUserOnLogin ---

// ProvisionUserOnLoginUseCase upserts a user record on first login (or
// updates the LastLogin timestamp on subsequent logins) and backfills the
// Kite UID if it was previously empty. Suspended/offboarded users return
// an error so the caller can fail the login.
type ProvisionUserOnLoginUseCase struct {
	users  UserProvisioner
	logger *slog.Logger
}

// NewProvisionUserOnLoginUseCase builds the use case. Passing a nil
// UserProvisioner is allowed — the use case becomes a no-op
// (mirrors the dev-mode adapter behaviour).
func NewProvisionUserOnLoginUseCase(p UserProvisioner, logger *slog.Logger) *ProvisionUserOnLoginUseCase {
	return &ProvisionUserOnLoginUseCase{users: p, logger: logger}
}

// Execute runs the use case.
func (uc *ProvisionUserOnLoginUseCase) Execute(_ context.Context, cmd cqrs.ProvisionUserOnLoginCommand) error {
	if uc.users == nil {
		return nil
	}
	email := strings.ToLower(cmd.Email)
	status := uc.users.GetStatus(email)
	if status == UserStatusSuspended {
		return ErrUserSuspended
	}
	if status == UserStatusOffboarded {
		return ErrUserOffboarded
	}
	u := uc.users.EnsureUser(email, cmd.KiteUID, cmd.DisplayName, "self")
	if u == nil {
		return nil
	}
	uc.users.UpdateLastLogin(email)
	if cmd.KiteUID != "" && u.GetKiteUID() == "" {
		uc.users.UpdateKiteUID(email, cmd.KiteUID)
	}
	return nil
}

// --- CacheKiteAccessToken ---

// CacheKiteAccessTokenUseCase writes the Kite access token to the per-user
// token cache. Always lowercases the email.
type CacheKiteAccessTokenUseCase struct {
	tokens KiteTokenWriter
	logger *slog.Logger
}

// NewCacheKiteAccessTokenUseCase builds the use case.
func NewCacheKiteAccessTokenUseCase(t KiteTokenWriter, logger *slog.Logger) *CacheKiteAccessTokenUseCase {
	return &CacheKiteAccessTokenUseCase{tokens: t, logger: logger}
}

// Execute runs the use case. A nil tokens writer is a no-op (defensive —
// production always wires the store).
func (uc *CacheKiteAccessTokenUseCase) Execute(_ context.Context, cmd cqrs.CacheKiteAccessTokenCommand) error {
	if uc.tokens == nil {
		return nil
	}
	uc.tokens.SetToken(strings.ToLower(cmd.Email), cmd.AccessToken, cmd.UserID, cmd.UserName)
	return nil
}

// --- StoreUserKiteCredentials ---

// StoreUserKiteCredentialsUseCase writes per-user API key/secret to the
// credential store after a successful bring-your-own-keys login.
type StoreUserKiteCredentialsUseCase struct {
	creds  KiteCredentialWriter
	logger *slog.Logger
}

// NewStoreUserKiteCredentialsUseCase builds the use case.
func NewStoreUserKiteCredentialsUseCase(c KiteCredentialWriter, logger *slog.Logger) *StoreUserKiteCredentialsUseCase {
	return &StoreUserKiteCredentialsUseCase{creds: c, logger: logger}
}

// Execute runs the use case.
func (uc *StoreUserKiteCredentialsUseCase) Execute(_ context.Context, cmd cqrs.StoreUserKiteCredentialsCommand) error {
	if uc.creds == nil {
		return nil
	}
	uc.creds.SetCredentials(strings.ToLower(cmd.Email), cmd.APIKey, cmd.APISecret)
	return nil
}

// --- SyncRegistryAfterLogin ---

// Registry status / source sentinels mirrored from kc/registry to keep
// usecases free of an import on that package. Values must match
// kc/registry/store.go's StatusActive / StatusReplaced /
// SourceSelfProvisioned constants exactly — they're persisted to SQLite
// and consumed by registry queries.
const (
	RegistryStatusActive          = "active"
	RegistryStatusReplaced        = "replaced"
	RegistrySourceSelfProvisioned = "self-provisioned"
)

// SyncRegistryAfterLoginUseCase mirrors kiteExchangerAdapter.ExchangeWith
// Credentials' registry-side bookkeeping behind a port, dispatched as a
// command. Three behaviors:
//
//  1. AutoRegister=true + APIKey not in registry → new self_provisioned entry
//  2. AutoRegister=true + APIKey already exists with a different owner → reassign
//  3. Always: stamp LastUsedAt on the current APIKey if non-empty
//
// If the user previously had a different APIKey, that prior entry is
// marked Replaced so audit trails show the rotation.
type SyncRegistryAfterLoginUseCase struct {
	registry RegistrySync
	logger   *slog.Logger
}

// NewSyncRegistryAfterLoginUseCase builds the use case.
func NewSyncRegistryAfterLoginUseCase(r RegistrySync, logger *slog.Logger) *SyncRegistryAfterLoginUseCase {
	return &SyncRegistryAfterLoginUseCase{registry: r, logger: logger}
}

// Execute runs the use case.
func (uc *SyncRegistryAfterLoginUseCase) Execute(_ context.Context, cmd cqrs.SyncRegistryAfterLoginCommand) error {
	if uc.registry == nil || cmd.APIKey == "" {
		return nil
	}
	email := strings.ToLower(cmd.Email)

	if cmd.AutoRegister {
		// If user previously held a DIFFERENT key, mark it Replaced for audit.
		if oldKey, found := uc.registry.GetByEmail(email); found && oldKey != cmd.APIKey {
			uc.registry.MarkStatus(oldKey, RegistryStatusReplaced)
			if uc.logger != nil {
				uc.logger.Info("Marked old registry key as replaced",
					"email", email, "old_key", truncForLog(oldKey, 8), "new_key", truncForLog(cmd.APIKey, 8))
			}
		}

		assignedTo, exists := uc.registry.GetByAPIKeyAnyStatus(cmd.APIKey)
		switch {
		case !exists:
			regID := "self-" + email + "-" + truncForLog(cmd.APIKey, 8)
			if err := uc.registry.Register(regID, cmd.APIKey, cmd.APISecret, email, cmd.Label, RegistryStatusActive, RegistrySourceSelfProvisioned, email); err != nil {
				if uc.logger != nil {
					uc.logger.Warn("Failed to auto-register self-provisioned key",
						"email", email, "error", err)
				}
			} else if uc.logger != nil {
				uc.logger.Info("Auto-registered self-provisioned key",
					"email", email, "api_key", truncForLog(cmd.APIKey, 8))
			}
		case assignedTo != email:
			// Reassign: pass APIKey; the adapter translates to registry ID.
			_ = uc.registry.Update(cmd.APIKey, email, "", "")
		}
	}

	uc.registry.UpdateLastUsedAt(cmd.APIKey)
	return nil
}

// truncForLog safely truncates a string for logging without panic on
// short input.
func truncForLog(s string, n int) string {
	if len(s) <= n {
		return s + "..."
	}
	return s[:n] + "..."
}

// --- SaveOAuthClient / DeleteOAuthClient ---

// SaveOAuthClientUseCase persists an OAuth dynamic-client registration.
type SaveOAuthClientUseCase struct {
	store  OAuthClientStore
	logger *slog.Logger
}

// NewSaveOAuthClientUseCase builds the use case.
func NewSaveOAuthClientUseCase(s OAuthClientStore, logger *slog.Logger) *SaveOAuthClientUseCase {
	return &SaveOAuthClientUseCase{store: s, logger: logger}
}

// Execute runs the use case.
func (uc *SaveOAuthClientUseCase) Execute(_ context.Context, cmd cqrs.SaveOAuthClientCommand) error {
	if uc.store == nil {
		return nil
	}
	createdAt := time.Unix(0, cmd.CreatedAtUnix)
	return uc.store.SaveClient(cmd.ClientID, cmd.ClientSecret, cmd.RedirectURIsJSON, cmd.ClientName, createdAt, cmd.IsKiteAPIKey)
}

// DeleteOAuthClientUseCase deletes an OAuth dynamic-client registration.
type DeleteOAuthClientUseCase struct {
	store  OAuthClientStore
	logger *slog.Logger
}

// NewDeleteOAuthClientUseCase builds the use case.
func NewDeleteOAuthClientUseCase(s OAuthClientStore, logger *slog.Logger) *DeleteOAuthClientUseCase {
	return &DeleteOAuthClientUseCase{store: s, logger: logger}
}

// Execute runs the use case.
func (uc *DeleteOAuthClientUseCase) Execute(_ context.Context, cmd cqrs.DeleteOAuthClientCommand) error {
	if uc.store == nil {
		return nil
	}
	return uc.store.DeleteClient(cmd.ClientID)
}
