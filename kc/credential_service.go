package kc

import (
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/domain"
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

// resolveDomain looks up the per-user credential for email, lifts it into
// a domain.Credential value object, then delegates the per-user-vs-global
// fallback rule to domain.ResolveCredentials. Empty email → no per-user
// lookup (just global). Invalid stored entries (e.g. blank apiKey) bypass
// per-user and fall through to global, mirroring the legacy semantics.
//
// Centralising the lookup in one private helper means every public
// accessor on CredentialService is a thin delegate to a domain rule.
func (cs *CredentialService) resolveDomain(email string) domain.CredentialResolution {
	var perUser domain.Credential
	if email != "" {
		if entry, ok := cs.credentialStore.Get(email); ok {
			// Best-effort lift; invalid entries become the zero value
			// which domain.ResolveCredentials treats as "no per-user".
			if k, kerr := domain.NewAPIKey(entry.APIKey); kerr == nil {
				if s, serr := domain.NewAPISecret(entry.APISecret); serr == nil {
					if cred, cerr := domain.NewCredential(email, k, s); cerr == nil {
						perUser = cred
					}
				}
			}
		}
	}
	res, _ := domain.ResolveCredentials(perUser, cs.apiKey, cs.apiSecret)
	return res
}

// ResolveCredentials returns the (apiKey, apiSecret) for a user.
// Per-user credentials take priority; global credentials are the fallback.
//
// Thin orchestrator: delegates the rule to domain.ResolveCredentials so
// the per-user-vs-global decision lives on a value object that any layer
// can consult independently.
func (cs *CredentialService) ResolveCredentials(email string) (apiKey, apiSecret string, err error) {
	res := cs.resolveDomain(email)
	if !res.IsResolved() {
		return "", "", fmt.Errorf("no Kite credentials available for %q", email)
	}
	return res.APIKey(), res.APISecret(), nil
}

// HasCredentials returns true if credentials can be resolved for the email
// (either per-user or global). Delegates to domain.CredentialResolution.IsResolved.
func (cs *CredentialService) HasCredentials(email string) bool {
	return cs.resolveDomain(email).IsResolved()
}

// GetAPIKeyForEmail returns the API key: per-user if registered, otherwise global.
// Thin delegate to domain.CredentialResolution.APIKey.
func (cs *CredentialService) GetAPIKeyForEmail(email string) string {
	return cs.resolveDomain(email).APIKey()
}

// GetAPISecretForEmail returns the API secret: per-user if registered, otherwise global.
// Thin delegate to domain.CredentialResolution.APISecret.
func (cs *CredentialService) GetAPISecretForEmail(email string) string {
	return cs.resolveDomain(email).APISecret()
}

// QualifiesForTrading is the canonical "can this user place orders right
// now" rule. Combines credential availability + session authenticity via
// the domain aggregate; no service-layer logic. Single source of truth so
// every call site (place_order, modify_order, GTT, etc.) gets identical
// answers.
func (cs *CredentialService) QualifiesForTrading(email string) bool {
	res := cs.resolveDomain(email)
	if !res.IsResolved() {
		return false
	}
	entry, ok := cs.tokenStore.Get(email)
	if !ok {
		return false
	}
	return res.QualifiesForTrading(ToDomainSession(email, entry))
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
// Delegates to domain.Session.IsExpired via the ToDomainSession converter so the
// 06:00 IST refresh rule lives on the rich entity rather than being re-derived
// here.
func (cs *CredentialService) IsTokenValid(email string) bool {
	entry, ok := cs.tokenStore.Get(email)
	if !ok {
		return false
	}
	return !ToDomainSession(email, entry).IsExpired()
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

// QualifiesForTrading delegates to credentialSvc.QualifiesForTrading.
// Returns true iff the user has resolvable credentials AND a non-expired
// cached Kite token.
func (m *Manager) QualifiesForTrading(email string) bool {
	return m.credentialSvc.QualifiesForTrading(email)
}
