package kc

import (
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/registry"
)

// CredentialService owns credential resolution: per-user vs global credentials,
// API key lookup, and registry backfill. Extracted from Manager as part of
// Clean Architecture / SOLID refactoring.
//
// Dependencies are interface types (Dependency Inversion Principle), enabling
// mock injection for testing.
type CredentialService struct {
	apiKey          string
	apiSecret       string
	accessToken     string // global pre-auth token (local dev)
	credentialStore CredentialStoreInterface
	tokenStore      TokenStoreInterface
	registryStore   RegistryStoreInterface
	logger          *slog.Logger
}

// CredentialServiceConfig holds dependencies for creating a CredentialService.
type CredentialServiceConfig struct {
	APIKey          string
	APISecret       string
	AccessToken     string
	CredentialStore CredentialStoreInterface
	TokenStore      TokenStoreInterface
	RegistryStore   RegistryStoreInterface
	Logger          *slog.Logger
}

// NewCredentialService creates a new CredentialService with the given dependencies.
func NewCredentialService(cfg CredentialServiceConfig) *CredentialService {
	return &CredentialService{
		apiKey:          cfg.APIKey,
		apiSecret:       cfg.APISecret,
		accessToken:     cfg.AccessToken,
		credentialStore: cfg.CredentialStore,
		tokenStore:      cfg.TokenStore,
		registryStore:   cfg.RegistryStore,
		logger:          cfg.Logger,
	}
}

// ResolveCredentials returns the (apiKey, apiSecret) for a user.
// Per-user credentials take priority; global credentials are the fallback.
func (cs *CredentialService) ResolveCredentials(email string) (apiKey, apiSecret string, err error) {
	apiKey = cs.GetAPIKeyForEmail(email)
	apiSecret = cs.GetAPISecretForEmail(email)
	if apiKey == "" || apiSecret == "" {
		return "", "", fmt.Errorf("no Kite credentials available for %q", email)
	}
	return apiKey, apiSecret, nil
}

// HasCredentials returns true if credentials can be resolved for the email
// (either per-user or global).
func (cs *CredentialService) HasCredentials(email string) bool {
	apiKey := cs.GetAPIKeyForEmail(email)
	apiSecret := cs.GetAPISecretForEmail(email)
	return apiKey != "" && apiSecret != ""
}

// GetAPIKeyForEmail returns the API key: per-user if registered, otherwise global.
func (cs *CredentialService) GetAPIKeyForEmail(email string) string {
	if email != "" {
		if entry, ok := cs.credentialStore.Get(email); ok {
			return entry.APIKey
		}
	}
	return cs.apiKey
}

// GetAPISecretForEmail returns the API secret: per-user if registered, otherwise global.
func (cs *CredentialService) GetAPISecretForEmail(email string) string {
	if email != "" {
		if entry, ok := cs.credentialStore.Get(email); ok {
			return entry.APISecret
		}
	}
	return cs.apiSecret
}

// GetAccessTokenForEmail returns the cached access token for a given email.
func (cs *CredentialService) GetAccessTokenForEmail(email string) string {
	if email != "" {
		if entry, ok := cs.tokenStore.Get(email); ok {
			return entry.AccessToken
		}
	}
	return cs.accessToken // fallback to global pre-auth token
}

// HasPreAuth returns true if the service has a pre-set access token.
func (cs *CredentialService) HasPreAuth() bool {
	return cs.accessToken != ""
}

// HasCachedToken returns true if there's a cached Kite token for the given email.
func (cs *CredentialService) HasCachedToken(email string) bool {
	if email == "" {
		return false
	}
	_, ok := cs.tokenStore.Get(email)
	return ok
}

// HasUserCredentials returns true if per-user Kite credentials exist for the given email.
func (cs *CredentialService) HasUserCredentials(email string) bool {
	if email == "" {
		return false
	}
	_, ok := cs.credentialStore.Get(email)
	return ok
}

// HasGlobalCredentials returns true if global API key/secret are configured (from env vars).
func (cs *CredentialService) HasGlobalCredentials() bool {
	return cs.apiKey != "" && cs.apiSecret != ""
}

// IsTokenValid returns true if the user has a cached Kite token that has not expired.
func (cs *CredentialService) IsTokenValid(email string) bool {
	entry, ok := cs.tokenStore.Get(email)
	if !ok {
		return false
	}
	return !IsKiteTokenExpired(entry.StoredAt)
}

// BackfillRegistryFromCredentials syncs existing credentials into the registry.
// This handles pre-registry self-provisioned keys that were stored before the registry existed.
func (cs *CredentialService) BackfillRegistryFromCredentials() {
	if cs.registryStore == nil {
		return
	}
	creds := cs.credentialStore.ListAllRaw()
	if len(creds) == 0 {
		return
	}
	backfilled := 0
	for _, cred := range creds {
		if _, found := cs.registryStore.GetByAPIKeyAnyStatus(cred.APIKey); found {
			continue // already in registry
		}
		regID := fmt.Sprintf("migrated-%s-%s", cred.Email, truncKey(cred.APIKey, 8))
		if err := cs.registryStore.Register(&registry.AppRegistration{
			ID:           regID,
			APIKey:       cred.APIKey,
			APISecret:    cred.APISecret,
			AssignedTo:   cred.Email,
			Label:        "Migrated",
			Status:       registry.StatusActive,
			Source:       registry.SourceMigrated,
			RegisteredBy: cred.Email,
		}); err != nil {
			cs.logger.Warn("Failed to backfill registry from credentials",
				"email", cred.Email, "error", err)
		} else {
			backfilled++
		}
	}
	if backfilled > 0 {
		cs.logger.Info("Backfilled registry from existing credentials", "count", backfilled)
	}
}

// ---------------------------------------------------------------------------
// Manager-level delegators (thin pass-throughs to m.credentialSvc)
// ---------------------------------------------------------------------------

// HasPreAuth returns true if the manager has a pre-set access token.
func (m *Manager) HasPreAuth() bool {
	return m.credentialSvc.HasPreAuth()
}

// HasCachedToken returns true if there's a cached Kite token for the given email.
func (m *Manager) HasCachedToken(email string) bool {
	return m.credentialSvc.HasCachedToken(email)
}

// HasGlobalCredentials returns true if global API key/secret are configured.
func (m *Manager) HasGlobalCredentials() bool {
	return m.credentialSvc.HasGlobalCredentials()
}

// IsTokenValid returns true if the user has a cached Kite token that has not expired.
func (m *Manager) IsTokenValid(email string) bool {
	return m.credentialSvc.IsTokenValid(email)
}

// HasUserCredentials returns true if per-user Kite credentials exist for the given email.
func (m *Manager) HasUserCredentials(email string) bool {
	return m.credentialSvc.HasUserCredentials(email)
}

// GetAPIKeyForEmail returns the API key for a user (per-user or global fallback).
func (m *Manager) GetAPIKeyForEmail(email string) string {
	return m.credentialSvc.GetAPIKeyForEmail(email)
}

// GetAPISecretForEmail returns the API secret for a user (per-user or global fallback).
func (m *Manager) GetAPISecretForEmail(email string) string {
	return m.credentialSvc.GetAPISecretForEmail(email)
}

// GetAccessTokenForEmail returns the cached access token for the given email.
func (m *Manager) GetAccessTokenForEmail(email string) string {
	return m.credentialSvc.GetAccessTokenForEmail(email)
}
