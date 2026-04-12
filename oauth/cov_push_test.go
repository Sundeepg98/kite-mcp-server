package oauth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// ===========================================================================
// Coverage push: hit remaining achievable uncovered lines in oauth.
// ===========================================================================

// ---------------------------------------------------------------------------
// jwt.go line 85-97 — multi-audience loop (validates match across audiences)
// Line 98-100 (mismatch) is unreachable: if jwt.WithAudience(audiences[0])
// passes, audiences[0] is in token.Audience, so the loop always matches.
// ---------------------------------------------------------------------------

func TestValidateToken_MultiAud_Match(t *testing.T) {
	t.Parallel()
	jm := NewJWTManager("test-secret", 1*time.Hour)

	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "test@test.com",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			Audience:  jwt.ClaimStrings{"aud-a", "aud-b"},
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenStr, err := token.SignedString([]byte("test-secret"))
	require.NoError(t, err)

	// First audience matches, multi-aud loop confirms
	result, err := jm.ValidateToken(tokenStr, "aud-a", "aud-c")
	assert.NoError(t, err)
	assert.Equal(t, "test@test.com", result.Subject)
}

// ---------------------------------------------------------------------------
// handlers.go — NewHandler minimal config (template parse errors unreachable)
// ---------------------------------------------------------------------------

func TestNewHandler_Minimal(t *testing.T) {
	t.Parallel()
	cfg := &Config{
		JWTSecret: "test-secret",
		Logger:    testLogger(),
	}
	h := NewHandler(cfg, &mockSigner{}, &mockExchanger{})
	assert.NotNil(t, h)
	h.Close()
}

// ---------------------------------------------------------------------------
// stores.go — ClientStore.Register with persistence error (line 211/215)
// ---------------------------------------------------------------------------

type failPersister struct{}

func (fp *failPersister) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
	return assert.AnError
}

func (fp *failPersister) LoadClients() ([]*ClientLoadEntry, error) {
	return nil, assert.AnError
}

func (fp *failPersister) DeleteClient(clientID string) error {
	return assert.AnError
}

func TestClientStore_Register_PersistFail(t *testing.T) {
	t.Parallel()
	cs := NewClientStore()
	cs.SetPersister(&failPersister{})
	cs.SetLogger(testLogger())

	// Register succeeds in-memory even if persistence fails
	clientID, secret, err := cs.Register([]string{"http://localhost/cb"}, "test-client")
	assert.NoError(t, err)
	assert.NotEmpty(t, clientID)
	assert.NotEmpty(t, secret)
}
