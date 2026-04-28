package users

import (
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateTOTPSecret_Format ensures freshly generated secrets are
// base32-encoded with no padding (the form authenticator apps expect)
// and exactly the documented number of bytes after decoding.
func TestGenerateTOTPSecret_Format(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	require.NotEmpty(t, secret)
	// 20 bytes -> 32 base32 chars without padding.
	assert.Len(t, secret, 32)
	assert.False(t, strings.Contains(secret, "="), "secret must be unpadded")
	// Confirms it is decodable by the very routine that consumes it.
	key, err := decodeTOTPSecret(secret)
	require.NoError(t, err)
	assert.Len(t, key, TOTPSecretBytes)
}

// TestGenerateTOTPSecret_Uniqueness — two calls must not collide. This is
// not strictly a deterministic test but with 160 bits of entropy a collision
// is statistically impossible in any reasonable test horizon.
func TestGenerateTOTPSecret_Uniqueness(t *testing.T) {
	t.Parallel()
	a, errA := GenerateTOTPSecret()
	b, errB := GenerateTOTPSecret()
	require.NoError(t, errA)
	require.NoError(t, errB)
	assert.NotEqual(t, a, b)
}

// TestGenerateTOTPCode_AtFixedTime verifies that the produced code has
// the correct format (6 digits, zero-padded numeric).
func TestGenerateTOTPCode_AtFixedTime(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)

	now := time.Date(2026, 4, 28, 10, 0, 0, 0, time.UTC)
	code, err := GenerateTOTPCode(secret, now)
	require.NoError(t, err)
	assert.Len(t, code, TOTPDigits)
	for _, c := range code {
		assert.True(t, c >= '0' && c <= '9', "code must be all digits, got %q", code)
	}
}

// TestGenerateTOTPCode_StableWithinStep — codes within the same 30-second
// time step must be identical. Codes across step boundaries must differ.
func TestGenerateTOTPCode_StableWithinStep(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)

	t1 := time.Date(2026, 4, 28, 10, 0, 5, 0, time.UTC)  // step N at second 5.
	t2 := time.Date(2026, 4, 28, 10, 0, 25, 0, time.UTC) // same step N at second 25.
	t3 := time.Date(2026, 4, 28, 10, 0, 35, 0, time.UTC) // step N+1 at second 35.

	c1, err := GenerateTOTPCode(secret, t1)
	require.NoError(t, err)
	c2, err := GenerateTOTPCode(secret, t2)
	require.NoError(t, err)
	c3, err := GenerateTOTPCode(secret, t3)
	require.NoError(t, err)

	assert.Equal(t, c1, c2, "codes within same 30s step must match")
	assert.NotEqual(t, c1, c3, "codes across step boundary must differ")
}

// TestGenerateTOTPCode_RFC6238Vector checks one concrete vector from RFC 6238
// Appendix B. The test secret is "12345678901234567890" (ASCII), not random.
// Expected codes from the spec verify the implementation is the canonical one
// every authenticator app uses.
func TestGenerateTOTPCode_RFC6238Vector(t *testing.T) {
	t.Parallel()
	// "12345678901234567890" base32-encoded (no padding) is GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ.
	secret := "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
	// RFC 6238 Appendix B references different SHA variants per row. The
	// SHA-1 row at unix=59 yields code 94287082. With our 6-digit truncation
	// the lower 6 digits are "287082".
	at := time.Unix(59, 0)
	code, err := GenerateTOTPCode(secret, at)
	require.NoError(t, err)
	assert.Equal(t, "287082", code)
}

// TestVerifyTOTPCode_HappyPath — a code produced just now must validate.
func TestVerifyTOTPCode_HappyPath(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)

	now := time.Now()
	code, err := GenerateTOTPCode(secret, now)
	require.NoError(t, err)

	assert.True(t, VerifyTOTPCode(secret, code, now, TOTPSkewSteps))
}

// TestVerifyTOTPCode_AcceptsSkew — codes from one step earlier or later
// must validate when skew=1, simulating routine ±30s clock drift.
func TestVerifyTOTPCode_AcceptsSkew(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)

	now := time.Date(2026, 4, 28, 10, 5, 15, 0, time.UTC)
	earlier := now.Add(-TOTPPeriodSeconds * time.Second)
	later := now.Add(TOTPPeriodSeconds * time.Second)

	earlierCode, _ := GenerateTOTPCode(secret, earlier)
	laterCode, _ := GenerateTOTPCode(secret, later)

	assert.True(t, VerifyTOTPCode(secret, earlierCode, now, 1), "code from t-30s must verify with skew=1")
	assert.True(t, VerifyTOTPCode(secret, laterCode, now, 1), "code from t+30s must verify with skew=1")
}

// TestVerifyTOTPCode_RejectsTooOld — codes outside the skew window are
// rejected.
func TestVerifyTOTPCode_RejectsTooOld(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)

	now := time.Date(2026, 4, 28, 10, 5, 15, 0, time.UTC)
	wayEarlier := now.Add(-5 * TOTPPeriodSeconds * time.Second)
	staleCode, _ := GenerateTOTPCode(secret, wayEarlier)

	assert.False(t, VerifyTOTPCode(secret, staleCode, now, 1), "stale code must be rejected with skew=1")
}

// TestVerifyTOTPCode_WrongCode — random-looking 6-digit code must not
// validate.
func TestVerifyTOTPCode_WrongCode(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	assert.False(t, VerifyTOTPCode(secret, "000000", time.Now(), TOTPSkewSteps))
}

// TestVerifyTOTPCode_EmptyInputs — empty secret or empty code must return
// false (gates can be expressed as a single-line check).
func TestVerifyTOTPCode_EmptyInputs(t *testing.T) {
	t.Parallel()
	now := time.Now()
	assert.False(t, VerifyTOTPCode("", "123456", now, 1))
	assert.False(t, VerifyTOTPCode("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", "", now, 1))
	assert.False(t, VerifyTOTPCode("", "", now, 1))
}

// TestVerifyTOTPCode_BogusSecret — an invalid base32 secret cannot decode
// and must return false (never panic).
func TestVerifyTOTPCode_BogusSecret(t *testing.T) {
	t.Parallel()
	// '1' is not a valid base32 character (alphabet is A-Z, 2-7).
	assert.False(t, VerifyTOTPCode("1111111111111111", "123456", time.Now(), 1))
}

// TestVerifyTOTPCode_NegativeSkewClampedToZero — negative skew must be
// treated as 0 (defensive coding) so a misuse doesn't produce a wider
// window than intended.
func TestVerifyTOTPCode_NegativeSkewClampedToZero(t *testing.T) {
	t.Parallel()
	secret, err := GenerateTOTPSecret()
	require.NoError(t, err)
	now := time.Now()
	code, _ := GenerateTOTPCode(secret, now)
	// skew=-5 should behave like skew=0 (still accept the live code).
	assert.True(t, VerifyTOTPCode(secret, code, now, -5))
	// And reject one-step-stale.
	stale, _ := GenerateTOTPCode(secret, now.Add(-TOTPPeriodSeconds*time.Second))
	assert.False(t, VerifyTOTPCode(secret, stale, now, -5))
}

// TestProvisioningURI_Format — the otpauth URI must contain every field
// authenticator apps need.
func TestProvisioningURI_Format(t *testing.T) {
	t.Parallel()
	uri := ProvisioningURI("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567", "kite-mcp-server", "admin@example.com")
	assert.True(t, strings.HasPrefix(uri, "otpauth://totp/"))
	assert.Contains(t, uri, "secret=ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
	assert.Contains(t, uri, "issuer=kite-mcp-server")
	assert.Contains(t, uri, "algorithm=SHA1")
	assert.Contains(t, uri, "digits=6")
	assert.Contains(t, uri, "period=30")
	// Label is path-escaped issuer:account — not query-escaped.
	assert.Contains(t, uri, "kite-mcp-server:admin@example.com")
}

// TestDecodeTOTPSecret_AcceptsPaddedAndUnpadded — both forms decode to
// the same key. Authenticator apps differ on whether they emit padding.
func TestDecodeTOTPSecret_AcceptsPaddedAndUnpadded(t *testing.T) {
	t.Parallel()
	// "Hello!" base32-encoded.
	unpadded := "JBSWY3DPEE"
	padded := "JBSWY3DPEE======"
	a, errA := decodeTOTPSecret(unpadded)
	b, errB := decodeTOTPSecret(padded)
	require.NoError(t, errA)
	require.NoError(t, errB)
	assert.Equal(t, a, b)
}
