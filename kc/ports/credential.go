package ports

// CredentialPort is the bounded-context contract for resolving per-user
// and global Kite API credentials and the corresponding cached tokens.
//
// It is the exact method set of kc.CredentialResolver (same 8 methods).
// The Manager satisfies this port transparently via its credentialSvc
// delegate (see kc/credential_service.go). Callers should prefer
// ports.CredentialPort over kc.CredentialResolver; the latter is
// retained as a deprecated alias until Phase B/D finish migrating.
//
// Call sites currently reached:
//   - mcp/alert_tools.go, mcp/common.go (via ToolHandlerDeps.Credentials)
//   - mcp/setup_tools.go, mcp/ticker_tools.go, mcp/trailing_tools.go
//     (direct *kc.Manager — migrate gradually)
//   - app/adapters.go (telegramManagerAdapter passthroughs)
type CredentialPort interface {
	// GetAPIKeyForEmail returns the API key: per-user if registered, otherwise global.
	GetAPIKeyForEmail(email string) string

	// GetAPISecretForEmail returns the API secret: per-user if registered, otherwise global.
	GetAPISecretForEmail(email string) string

	// GetAccessTokenForEmail returns the cached access token for a given email.
	GetAccessTokenForEmail(email string) string

	// HasPreAuth returns true if the manager has a pre-set access token.
	HasPreAuth() bool

	// HasCachedToken returns true if there's a cached Kite token for the email.
	HasCachedToken(email string) bool

	// HasUserCredentials returns true if per-user credentials exist.
	HasUserCredentials(email string) bool

	// HasGlobalCredentials returns true if global API key/secret are configured.
	HasGlobalCredentials() bool

	// IsTokenValid returns true if the user has a valid (non-expired) cached token.
	IsTokenValid(email string) bool
}
