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
