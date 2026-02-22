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
type JWTManager struct {
	secret      []byte
	tokenExpiry time.Duration
}

// NewJWTManager creates a new JWT manager.
func NewJWTManager(secret string, expiry time.Duration) *JWTManager {
	return &JWTManager{
		secret:      []byte(secret),
		tokenExpiry: expiry,
	}
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

// ValidateToken parses and validates the JWT, returning claims if valid.
func (j *JWTManager) ValidateToken(tokenString string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return j.secret, nil
	})
	if err != nil {
		return nil, err
	}
	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, fmt.Errorf("invalid token")
	}
	return claims, nil
}
