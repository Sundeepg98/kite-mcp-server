package cqrs

// commands_ext.go — OAuth/session-bridge commands for the writes that
// previously bypassed the bus inside app/adapters.go (kiteExchangerAdapter
// and clientPersisterAdapter). Routing those mutations through the bus
// satisfies the CQRS contract (every write through a typed command) and
// gives the same audit/observability layer the rest of the writes get
// via LoggingMiddleware.
//
// These commands replace 8 direct store calls in app/adapters.go:
//   - UserStore.UpdateLastLogin / UpdateKiteUID         → ProvisionUserOnLogin
//   - KiteTokenStore.Set                                 → CacheKiteAccessToken
//   - KiteCredentialStore.Set                            → StoreUserKiteCredentials
//   - registry.Update + registry.UpdateLastUsedAt        → SyncRegistryAfterLogin
//   - alerts.DB.SaveClient / DeleteClient                → SaveOAuthClient / DeleteOAuthClient

// ProvisionUserOnLoginCommand requests provisioning a user on first OAuth
// login (or updating the last-login timestamp on subsequent logins). The
// handler also fills in the Kite UID if it was previously empty — most
// users get the UID from Kite's profile call after the very first login.
//
// Returns no error for missing UserStore (single-user / dev mode) — the
// adapter provisionUser used to be a no-op in that case.
type ProvisionUserOnLoginCommand struct {
	Email       string `json:"email"`
	KiteUID     string `json:"kite_uid"`
	DisplayName string `json:"display_name"`
}

// CacheKiteAccessTokenCommand requests writing a fresh Kite access token to
// the per-user token cache after a successful OAuth callback. Always
// keys by lowercased email.
type CacheKiteAccessTokenCommand struct {
	Email       string `json:"email"`
	AccessToken string `json:"access_token"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
}

// StoreUserKiteCredentialsCommand requests persisting a user's per-user
// Kite API key/secret (used by the bring-your-own-keys onboarding path).
type StoreUserKiteCredentialsCommand struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"`
}

// SyncRegistryAfterLoginCommand requests updating the OAuth key registry
// after a successful login: marks any prior key as Replaced, registers a
// new self-provisioned entry if missing, reassigns an existing entry to
// the right owner if needed, and stamps the LastUsedAt timestamp.
//
// PriorKeyHandling: pass empty APISecret/Label to skip the auto-register
// path (use case for the global-credential branch where we only stamp
// last-used).
type SyncRegistryAfterLoginCommand struct {
	Email     string `json:"email"`
	APIKey    string `json:"api_key"`
	APISecret string `json:"api_secret"` // empty → don't auto-register
	Label     string `json:"label"`      // optional label for new entries
	// AutoRegister controls whether a missing entry should be inserted
	// as self-provisioned. Falsy → only stamp last-used timestamp on
	// existing entries.
	AutoRegister bool `json:"auto_register"`
}

// SaveOAuthClientCommand requests persisting an OAuth dynamic-client
// registration to the alerts DB. Replaces the direct alerts.DB.SaveClient
// call from clientPersisterAdapter so every write to the OAuth-client table
// flows through the bus and is logged by LoggingMiddleware.
type SaveOAuthClientCommand struct {
	ClientID         string `json:"client_id"`
	ClientSecret     string `json:"client_secret"`
	RedirectURIsJSON string `json:"redirect_uris_json"`
	ClientName       string `json:"client_name"`
	CreatedAtUnix    int64  `json:"created_at_unix"` // unix nanos so the command is plain data
	IsKiteAPIKey     bool   `json:"is_kite_api_key"`
}

// DeleteOAuthClientCommand requests deleting an OAuth dynamic-client
// registration. Replaces the direct alerts.DB.DeleteClient call.
type DeleteOAuthClientCommand struct {
	ClientID string `json:"client_id"`
}

// AdminRegisterAppCommand requests registering a new key-registry entry
// from the admin dashboard. Source is always admin (vs self-provisioned).
// Replaces the direct registryStore.Register call in kc/ops/handler_admin.go.
type AdminRegisterAppCommand struct {
	ID           string `json:"id"`
	APIKey       string `json:"api_key"`
	APISecret    string `json:"api_secret"`
	AssignedTo   string `json:"assigned_to"`
	Label        string `json:"label"`
	RegisteredBy string `json:"registered_by"` // admin email
}

// AdminUpdateRegistryCommand requests updating an existing key-registry
// entry's assigned_to / label / status. Replaces the direct
// registryStore.Update call.
type AdminUpdateRegistryCommand struct {
	ID         string `json:"id"`
	AssignedTo string `json:"assigned_to"`
	Label      string `json:"label"`
	Status     string `json:"status"`
}

// AdminDeleteRegistryCommand requests removing a key-registry entry.
// Replaces the direct registryStore.Delete call.
type AdminDeleteRegistryCommand struct {
	ID string `json:"id"`
}

// WithdrawConsentCommand exercises the user's DPDP §6(4) right to
// rescind previously-granted consent. The command stamps every active
// grant in consent_log with withdrawn_at and appends a "withdraw" row
// describing the action. Reason is plain text recorded for operations;
// DPDP doesn't require a justification, but operators benefit from
// having one when correlating with support tickets.
//
// Email is plaintext — the use case hashes it via audit.HashEmail
// before touching the consent_log so the table never carries the raw
// address. NoticeVersion identifies which privacy notice is currently
// in force; the use case records this on the withdraw row as the
// "version withdrawn from".
type WithdrawConsentCommand struct {
	Email         string `json:"email"`
	Reason        string `json:"reason,omitempty"`
	NoticeVersion string `json:"notice_version,omitempty"`
	IPAddress     string `json:"ip_address,omitempty"`
	UserAgent     string `json:"user_agent,omitempty"`
}
