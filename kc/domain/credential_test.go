package domain

// credential_test.go — unit tests for the Credential aggregate and its
// value objects (APIKey, APISecret). Covers construction invariants and
// the rotation-detection rule that previously lived in
// kc/credential_store.go, plus the per-user-vs-global resolution rules
// that previously lived in CredentialService accessors.

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewAPIKey_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := NewAPIKey("")
	assert.Error(t, err)
}

func TestNewAPIKey_AcceptsNonEmpty(t *testing.T) {
	t.Parallel()

	k, err := NewAPIKey("abcd1234")
	assert.NoError(t, err)
	assert.Equal(t, "abcd1234", k.String())
}

func TestNewAPIKey_StripsWhitespace(t *testing.T) {
	t.Parallel()

	k, err := NewAPIKey("  abcd1234  ")
	assert.NoError(t, err)
	assert.Equal(t, "abcd1234", k.String())
}

func TestNewAPIKey_RejectsWhitespaceOnly(t *testing.T) {
	t.Parallel()

	_, err := NewAPIKey("   ")
	assert.Error(t, err)
}

func TestAPIKey_Zero_IsInvalid(t *testing.T) {
	t.Parallel()

	var k APIKey
	assert.False(t, k.IsValid())
}

func TestNewAPISecret_RejectsEmpty(t *testing.T) {
	t.Parallel()

	_, err := NewAPISecret("")
	assert.Error(t, err)
}

func TestNewAPISecret_AcceptsNonEmpty(t *testing.T) {
	t.Parallel()

	s, err := NewAPISecret("supersecret")
	assert.NoError(t, err)
	assert.Equal(t, "supersecret", s.String())
}

func TestAPISecret_Masked(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string
	}{
		{name: "short secret fully masked", in: "abc", want: "****"},
		{name: "seven chars fully masked", in: "abcdefg", want: "****"},
		{name: "long secret hints 4+3", in: "abcdefghijkl", want: "abcd****jkl"},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			s, err := NewAPISecret(tc.in)
			assert.NoError(t, err)
			assert.Equal(t, tc.want, s.Masked())
		})
	}
}

func TestNewCredential_RejectsEmptyEmail(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("K")
	s, _ := NewAPISecret("S")
	_, err := NewCredential("", k, s)
	assert.Error(t, err)
}

func TestNewCredential_RejectsInvalidKey(t *testing.T) {
	t.Parallel()

	var k APIKey
	s, _ := NewAPISecret("S")
	_, err := NewCredential("a@b.com", k, s)
	assert.Error(t, err)
}

func TestNewCredential_RejectsInvalidSecret(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("K")
	var s APISecret
	_, err := NewCredential("a@b.com", k, s)
	assert.Error(t, err)
}

func TestNewCredential_HappyPath(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("KEY1")
	s, _ := NewAPISecret("SEC1")
	c, err := NewCredential("a@b.com", k, s)
	assert.NoError(t, err)
	assert.Equal(t, "a@b.com", c.Email())
	assert.Equal(t, "KEY1", c.APIKey().String())
	assert.Equal(t, "KEY1", c.AppID(), "AppID must equal APIKey per Kite convention")
}

func TestCredential_IsRotationOf(t *testing.T) {
	t.Parallel()

	k1, _ := NewAPIKey("OLDKEY")
	k2, _ := NewAPIKey("NEWKEY")
	s, _ := NewAPISecret("SEC")
	old, _ := NewCredential("a@b.com", k1, s)
	replacement, _ := NewCredential("a@b.com", k2, s)
	sameKey, _ := NewCredential("a@b.com", k1, s)
	otherUser, _ := NewCredential("z@b.com", k2, s)

	assert.True(t, replacement.IsRotationOf(old), "different APIKey for same email is a rotation")
	assert.False(t, sameKey.IsRotationOf(old), "same APIKey is not a rotation")
	assert.False(t, otherUser.IsRotationOf(old), "different email is not a rotation")
}

func TestCredential_IsRotationOf_CaseInsensitiveEmail(t *testing.T) {
	t.Parallel()

	k1, _ := NewAPIKey("OLDKEY")
	k2, _ := NewAPIKey("NEWKEY")
	s, _ := NewAPISecret("SEC")
	old, _ := NewCredential("A@B.com", k1, s)
	replacement, _ := NewCredential("a@b.COM", k2, s)
	assert.True(t, replacement.IsRotationOf(old),
		"email match should be case-insensitive — rotations happen per user not per casing")
}

// ---------------------------------------------------------------------
// CredentialResolution — per-user vs global vs none rule
// ---------------------------------------------------------------------

func TestResolveCredentials_PerUserPreferred(t *testing.T) {
	t.Parallel()

	// Per-user pair WINS even when global is also set.
	k, _ := NewAPIKey("user-key")
	s, _ := NewAPISecret("user-secret")
	cred, _ := NewCredential("u@example.com", k, s)

	res, ok := ResolveCredentials(cred, "global-key", "global-secret")
	assert.True(t, ok)
	assert.True(t, res.IsResolved())
	assert.Equal(t, CredentialSourcePerUser, res.Source())
	assert.Equal(t, "user-key", res.APIKey())
	assert.Equal(t, "user-secret", res.APISecret())
}

func TestResolveCredentials_GlobalFallback(t *testing.T) {
	t.Parallel()

	// Empty per-user (zero value) → falls back to global.
	res, ok := ResolveCredentials(Credential{}, "global-key", "global-secret")
	assert.True(t, ok)
	assert.True(t, res.IsResolved())
	assert.Equal(t, CredentialSourceGlobal, res.Source())
	assert.Equal(t, "global-key", res.APIKey())
}

func TestResolveCredentials_None_BothEmpty(t *testing.T) {
	t.Parallel()

	res, ok := ResolveCredentials(Credential{}, "", "")
	assert.False(t, ok)
	assert.False(t, res.IsResolved())
	assert.Equal(t, CredentialSourceNone, res.Source())
	assert.Equal(t, "", res.APIKey())
}

func TestResolveCredentials_PartialGlobal_TreatedAsNone(t *testing.T) {
	t.Parallel()

	// Half-configured global (key without secret) is not usable.
	res, ok := ResolveCredentials(Credential{}, "global-key", "")
	assert.False(t, ok)
	assert.Equal(t, CredentialSourceNone, res.Source())
}

func TestCredentialSource_String(t *testing.T) {
	t.Parallel()
	assert.Equal(t, "per_user", CredentialSourcePerUser.String())
	assert.Equal(t, "global", CredentialSourceGlobal.String())
	assert.Equal(t, "none", CredentialSourceNone.String())
}

// ---------------------------------------------------------------------
// QualifiesForTrading — combined credential + session rule
// ---------------------------------------------------------------------

func TestQualifiesForTrading_FullyAuthorised(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("k")
	s, _ := NewAPISecret("s")
	cred, _ := NewCredential("trader@example.com", k, s)
	res, _ := ResolveCredentials(cred, "", "")

	// Fresh token (today, well before 6 AM IST cutoff) → authenticated.
	sess := NewSessionFromData(SessionData{
		Email:       "trader@example.com",
		AccessToken: "kite-token",
		IssuedAt:    time.Now(),
	})
	assert.True(t, res.QualifiesForTrading(sess))
}

func TestQualifiesForTrading_NoCredentials(t *testing.T) {
	t.Parallel()

	res, _ := ResolveCredentials(Credential{}, "", "")
	sess := NewSessionFromData(SessionData{
		Email:       "trader@example.com",
		AccessToken: "kite-token",
		IssuedAt:    time.Now(),
	})
	assert.False(t, res.QualifiesForTrading(sess),
		"no credentials → can't trade, even with valid session")
}

func TestQualifiesForTrading_ExpiredSession(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("k")
	s, _ := NewAPISecret("s")
	cred, _ := NewCredential("trader@example.com", k, s)
	res, _ := ResolveCredentials(cred, "", "")

	// Token issued 48 hours ago → past 6 AM IST cutoff → expired.
	sess := NewSessionFromData(SessionData{
		Email:       "trader@example.com",
		AccessToken: "old-token",
		IssuedAt:    time.Now().Add(-48 * time.Hour),
	})
	assert.False(t, res.QualifiesForTrading(sess),
		"expired session → can't trade, even with valid credentials")
}

func TestQualifiesForTrading_NoToken(t *testing.T) {
	t.Parallel()

	k, _ := NewAPIKey("k")
	s, _ := NewAPISecret("s")
	cred, _ := NewCredential("trader@example.com", k, s)
	res, _ := ResolveCredentials(cred, "", "")

	// Empty session (zero value) → no token → not authenticated.
	assert.False(t, res.QualifiesForTrading(Session{}))
}
