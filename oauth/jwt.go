package oauth

import (
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Claims represents the JWT claims for an MCP access token.
type Claims struct {
	jwt.RegisteredClaims
}

// JWTManager handles token generation and validation.
//
// Dual-key rotation: secret signs new tokens; previousSecret is accepted
// during verification only. To rotate without invalidating live sessions:
//
//  1. Set OAUTH_JWT_SECRET_PREVIOUS = current secret
//  2. Set OAUTH_JWT_SECRET = freshly generated new secret
//  3. Restart. Existing JWTs (signed with the now-previous key) verify
//     via the fallback. New tokens sign with the new key.
//  4. After all live JWTs have expired (default 24h MCP / 7d dashboard),
//     unset OAUTH_JWT_SECRET_PREVIOUS. The rotation is complete.
//
// previousSecret may be empty — in which case there is no fallback and
// rotation = invalidation, the pre-PR-DR behaviour.
type JWTManager struct {
	secret         []byte
	previousSecret []byte // accepted during verify only; never signs
	tokenExpiry    time.Duration
}

// NewJWTManager creates a new JWT manager. previousSecret is optional —
// pass empty string when no rotation is in progress.
func NewJWTManager(secret string, expiry time.Duration) *JWTManager {
	return &JWTManager{
		secret:      []byte(secret),
		tokenExpiry: expiry,
	}
}

// SetPreviousSecret installs a second-chance verify key for graceful
// rotation. Tokens signed with this key validate; new tokens still sign
// with the primary secret. Pass empty to clear the rotation slot once
// the migration window has elapsed.
func (j *JWTManager) SetPreviousSecret(previous string) {
	if previous == "" {
		j.previousSecret = nil
		return
	}
	j.previousSecret = []byte(previous)
}

// GenerateToken creates a signed JWT for the given email and client.
func (j *JWTManager) GenerateToken(email, clientID string) (string, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(j.tokenExpiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "kite-mcp-server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// GenerateTokenWithExpiry creates a signed JWT with a custom expiry duration.
func (j *JWTManager) GenerateTokenWithExpiry(email, clientID string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := &Claims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   email,
			Audience:  jwt.ClaimStrings{clientID},
			ExpiresAt: jwt.NewNumericDate(now.Add(expiry)),
			IssuedAt:  jwt.NewNumericDate(now),
			Issuer:    "kite-mcp-server",
		},
	}
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(j.secret)
}

// ValidateToken parses and validates the JWT, returning claims if valid.
// If audiences are provided, validates that the token's audience matches
// at least one.
//
// Dual-key behaviour: tries the primary secret first. On signature
// failure, retries with previousSecret if set. Lets graceful rotations
// keep live sessions alive across a secret swap. Verifications that
// succeed via the previous key still pass — there is no warning header
// or claim flag, since reading already-issued tokens is precisely what
// the fallback exists for.
func (j *JWTManager) ValidateToken(tokenString string, audiences ...string) (*Claims, error) {
	opts := []jwt.ParserOption{
		jwt.WithValidMethods([]string{"HS256"}),
	}
	if len(audiences) > 0 {
		// Validate that the token was issued for one of the expected audiences
		opts = append(opts, jwt.WithAudience(audiences[0]))
	}
	claims, err := j.parseWithKey(tokenString, j.secret, opts)
	if err != nil && len(j.previousSecret) > 0 {
		// Try the previous key. Any error here surfaces the original
		// primary-key failure to the caller — operators see the real
		// reason the token was rejected, not the post-rotation noise.
		if c2, err2 := j.parseWithKey(tokenString, j.previousSecret, opts); err2 == nil {
			claims = c2
			err = nil
		}
	}
	if err != nil {
		return nil, err
	}
	// Check additional audiences if more than one was provided
	if len(audiences) > 1 {
		matched := false
		for _, aud := range audiences {
			for _, tokenAud := range claims.Audience {
				if tokenAud == aud {
					matched = true
					break
				}
			}
			if matched {
				break
			}
		}
		if !matched {
			return nil, fmt.Errorf("token audience mismatch")
		}
	}
	return claims, nil
}

// parseWithKey is a single-key verify that returns the parsed claims.
// Splitting it out keeps ValidateToken's dual-key flow readable.
func (j *JWTManager) parseWithKey(tokenString string, key []byte, opts []jwt.ParserOption) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return key, nil
	}, opts...)
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
