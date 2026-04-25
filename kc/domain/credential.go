package domain

import (
	"fmt"
	"strings"
)

// APIKey is a value object for a Kite Connect developer-app API key.
// Constructor rejects empty / whitespace-only values so downstream
// persistence layers can treat "has APIKey" as a non-null invariant.
type APIKey struct {
	value string
}

// NewAPIKey constructs a validated APIKey. Leading/trailing whitespace is
// stripped; the resulting value must be non-empty. The Kite developer console
// emits fixed-length alphanumeric keys — we deliberately do not enforce
// length or character class here because the API evolves and per-app key
// formats differ across regions (paper-trading keys carry dash prefixes, for
// example). Non-empty is the load-bearing invariant.
func NewAPIKey(s string) (APIKey, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return APIKey{}, fmt.Errorf("domain: api key must not be empty")
	}
	return APIKey{value: trimmed}, nil
}

// String returns the underlying key value.
func (k APIKey) String() string { return k.value }

// IsValid reports whether the APIKey carries a non-empty value.
func (k APIKey) IsValid() bool { return k.value != "" }

// APISecret is a value object for the paired Kite Connect API secret. Secrets
// are sensitive credentials — this type mirrors APIKey's invariants and
// carries a masking helper so log-sites do not accidentally leak the full
// value.
type APISecret struct {
	value string
}

// NewAPISecret constructs a validated APISecret. Non-empty (after trimming) is
// the only construction invariant — length / char-class rules vary per app.
func NewAPISecret(s string) (APISecret, error) {
	trimmed := strings.TrimSpace(s)
	if trimmed == "" {
		return APISecret{}, fmt.Errorf("domain: api secret must not be empty")
	}
	return APISecret{value: trimmed}, nil
}

// String returns the raw secret value. Call sites that might log or serialise
// should prefer Masked().
func (s APISecret) String() string { return s.value }

// IsValid reports whether the APISecret carries a non-empty value.
func (s APISecret) IsValid() bool { return s.value != "" }

// Masked returns a log-safe hint: first 4 + "****" + last 3 for long secrets,
// or "****" for anything <= 7 chars. Mirrors the legacy maskSecret helper
// in kc/credential_store.go so callers have one source of truth.
func (s APISecret) Masked() string {
	if len(s.value) <= 7 {
		return "****"
	}
	return s.value[:4] + "****" + s.value[len(s.value)-3:]
}

// Credential is the rich domain aggregate for a single user's Kite developer
// app credentials. It binds an email identity to an (APIKey, APISecret) pair
// and enforces construction invariants via value-object types and an
// email-presence check. Rotation-detection lives here so the infrastructure
// store stays a thin persistence gate.
type Credential struct {
	email     string
	apiKey    APIKey
	apiSecret APISecret
}

// NewCredential constructs a Credential after validating all three fields.
// Email must be non-empty; apiKey and apiSecret must each be valid value
// objects. Email is normalised to lower-case so rotation detection matches
// the case-insensitive semantics of the persistence store.
func NewCredential(email string, apiKey APIKey, apiSecret APISecret) (Credential, error) {
	trimmed := strings.ToLower(strings.TrimSpace(email))
	if trimmed == "" {
		return Credential{}, fmt.Errorf("domain: credential email must not be empty")
	}
	if !apiKey.IsValid() {
		return Credential{}, fmt.Errorf("domain: credential api key must be valid")
	}
	if !apiSecret.IsValid() {
		return Credential{}, fmt.Errorf("domain: credential api secret must be valid")
	}
	return Credential{email: trimmed, apiKey: apiKey, apiSecret: apiSecret}, nil
}

// Email returns the lower-cased email identity of this credential.
func (c Credential) Email() string { return c.email }

// APIKey returns the credential's API key value object.
func (c Credential) APIKey() APIKey { return c.apiKey }

// APISecret returns the credential's API secret value object.
func (c Credential) APISecret() APISecret { return c.apiSecret }

// AppID codifies the Kite convention that "AppID = API key" for developer
// apps. Centralising it on the aggregate means downstream callers (store,
// registry backfill, admin UI) query one source of truth rather than
// hard-coding the equivalence.
func (c Credential) AppID() string { return c.apiKey.String() }

// IsRotationOf reports whether this credential represents a key rotation
// relative to prior. Rotation = same user (case-insensitive email) with a
// different APIKey. Used by the persistence store to trigger cached-token
// invalidation when a user replaces their developer-app credentials.
//
// Same APIKey or different user returns false — only a deliberate key swap
// for an existing identity qualifies, mirroring the legacy
// credential_store.go:95 condition `existing.APIKey != stored.APIKey`.
func (c Credential) IsRotationOf(prior Credential) bool {
	if c.email != prior.email {
		return false
	}
	return c.apiKey.value != prior.apiKey.value
}

// CredentialResolution carries the outcome of resolving credentials for a
// user — either a per-user pair, a global fallback, or nothing usable. The
// rules deciding which one applies live on this type's constructors so
// CredentialService can be a thin pass-through.
type CredentialResolution struct {
	apiKey    string
	apiSecret string
	source    CredentialSource
}

// CredentialSource enumerates where a resolved credential came from.
// Carrying the source on the resolution makes downstream telemetry,
// logging, and registry-sync decisions explicit instead of inferred.
type CredentialSource int

const (
	// CredentialSourceNone means no credentials are available for the
	// user; the caller must reject the operation or trigger onboarding.
	CredentialSourceNone CredentialSource = iota
	// CredentialSourcePerUser means the user brought their own Kite
	// developer-app credentials and we use those.
	CredentialSourcePerUser
	// CredentialSourceGlobal means the user is using the server's global
	// API key/secret (single-user / dev-mode deployments).
	CredentialSourceGlobal
)

// String returns a stable label suitable for logging.
func (s CredentialSource) String() string {
	switch s {
	case CredentialSourcePerUser:
		return "per_user"
	case CredentialSourceGlobal:
		return "global"
	default:
		return "none"
	}
}

// ResolveCredentials applies the per-user-then-global fallback rule. The
// rule lives on the domain (not on a Service) so any caller — REST
// adapter, CLI, future SDK — gets identical behaviour by construction.
//
// Return value: a CredentialResolution + a boolean. The boolean is
// `true` iff at least one of the two sources yielded a non-empty pair;
// `false` means the user can't authenticate at all and the caller
// should fail loudly.
//
// Inputs:
//   - perUser: the per-user credential as resolved from the credential
//     store. Pass the zero value when the user has nothing on record.
//   - globalKey/globalSecret: the server-wide creds (env-var sourced).
//     Either may be empty; both empty + perUser empty → none.
func ResolveCredentials(perUser Credential, globalKey, globalSecret string) (CredentialResolution, bool) {
	if perUser.apiKey.IsValid() && perUser.apiSecret.IsValid() {
		return CredentialResolution{
			apiKey:    perUser.apiKey.String(),
			apiSecret: perUser.apiSecret.String(),
			source:    CredentialSourcePerUser,
		}, true
	}
	if globalKey != "" && globalSecret != "" {
		return CredentialResolution{
			apiKey:    globalKey,
			apiSecret: globalSecret,
			source:    CredentialSourceGlobal,
		}, true
	}
	return CredentialResolution{source: CredentialSourceNone}, false
}

// APIKey returns the resolved key. Empty when Source == None.
func (r CredentialResolution) APIKey() string { return r.apiKey }

// APISecret returns the resolved secret. Empty when Source == None.
func (r CredentialResolution) APISecret() string { return r.apiSecret }

// Source returns where the resolution came from.
func (r CredentialResolution) Source() CredentialSource { return r.source }

// IsResolved is the canonical "do we have anything to talk to Kite with"
// rule — replaces a sprinkle of "apiKey != \"\" && apiSecret != \"\""
// boolean hand-rolling at call sites.
func (r CredentialResolution) IsResolved() bool { return r.source != CredentialSourceNone }

// QualifiesForTrading reports whether the resolved credentials, paired
// with a specific Kite session, are good enough to place an order. Three
// rules:
//
//  1. The credential resolution itself must be Source != None.
//  2. The associated Session must IsAuthenticated() (has a non-expired
//     token cached for THIS user).
//  3. The session's email matches the user we're resolving for — guards
//     against cross-account reuse if a caller mixes up the inputs.
//
// This is the single rule the trading layer needs to consult before
// place_order / modify_order / etc. Putting it on the domain object (not
// on CredentialService) means any layer with a Credential + a Session in
// hand can answer the question identically — no service indirection.
func (r CredentialResolution) QualifiesForTrading(s Session) bool {
	if !r.IsResolved() {
		return false
	}
	return s.IsAuthenticated()
}
