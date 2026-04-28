// Package users — TOTP (Time-based One-Time Password) per RFC 6238.
//
// Pure Go implementation built on HOTP (RFC 4226) with a 30-second time step
// and SHA-1 HMAC. SHA-1 is the spec-mandated default for TOTP and is used
// by every authenticator app (Google Authenticator, Authy, 1Password, etc.).
// The keyspace lives outside SHA-1's collision-relevant input domain — TOTP
// uses HMAC-SHA1, not bare SHA-1, so the SHA-1 collision history does not
// degrade the HOTP/TOTP security argument (NIST SP 800-63B §5.1.4 / RFC 6238 §5.1).
//
// Validation accepts a ±1 step skew window (the call site can override) to
// tolerate clock drift between the authenticator app and the server. The
// 30-second step gives a 90-second total accept window with skew=1.
//
// Provisioning URI follows the otpauth:// format documented at
// https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// and is consumed unchanged by every popular authenticator app.
package users

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1" // #nosec G505 -- SHA-1 in HMAC is mandated by RFC 6238 §5.1; not a hash collision context.
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"net/url"
	"strings"
	"time"
)

// TOTP parameters per RFC 6238 — the values every authenticator app expects.
const (
	// TOTPDigits is the number of digits in a TOTP code. RFC 6238 §5.3 specifies 6.
	TOTPDigits = 6
	// TOTPPeriodSeconds is the time step in seconds. RFC 6238 §5.2 default is 30.
	TOTPPeriodSeconds = 30
	// TOTPSecretBytes is the length of a freshly generated TOTP secret in bytes.
	// 20 bytes = 160 bits — RFC 4226 §4 minimum is 128 bits; 160 is the SHA-1
	// block-aligned value used by Google Authenticator.
	TOTPSecretBytes = 20
	// TOTPSkewSteps is the default ± window of accepted time steps.
	// 1 step = ±30s = 90s total accept window. Tolerates routine clock drift.
	TOTPSkewSteps = 1
)

// GenerateTOTPSecret produces a fresh 160-bit secret suitable for TOTP
// enrollment. The returned string is the base32-encoded, no-padding form
// that authenticator apps expect.
func GenerateTOTPSecret() (string, error) {
	buf := make([]byte, TOTPSecretBytes)
	if _, err := rand.Read(buf); err != nil { // COVERAGE: unreachable — Go 1.25 crypto/rand.Read is fatal on failure.
		return "", fmt.Errorf("totp: random read: %w", err)
	}
	return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(buf), nil
}

// GenerateTOTPCode returns the TOTP code for the given secret at time t.
// The secret must be base32-encoded (the form returned by GenerateTOTPSecret
// and stored in the database). Empty / invalid secrets return an error
// rather than a zero code so call sites cannot silently miss enrollment.
func GenerateTOTPCode(secret string, t time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	step := uint64(t.Unix() / TOTPPeriodSeconds) // #nosec G115 -- non-negative Unix time fits uint64 well past year 2100.
	return hotp(key, step), nil
}

// VerifyTOTPCode returns true if the supplied code matches the TOTP for
// the given secret at time t, allowing ± skewSteps of clock drift.
// The comparison is constant-time. An empty code or empty secret returns
// false without erroring, so call sites can use this as a single-line gate.
func VerifyTOTPCode(secret, code string, t time.Time, skewSteps int) bool {
	if secret == "" || code == "" {
		return false
	}
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return false
	}
	if skewSteps < 0 {
		skewSteps = 0
	}
	currentStep := uint64(t.Unix() / TOTPPeriodSeconds) // #nosec G115 -- same reasoning as GenerateTOTPCode.
	for i := -skewSteps; i <= skewSteps; i++ {
		step := currentStep
		switch {
		case i < 0:
			step -= uint64(-i) // #nosec G115 -- bounded by skewSteps loop.
		case i > 0:
			step += uint64(i) // #nosec G115 -- bounded by skewSteps loop.
		}
		candidate := hotp(key, step)
		// Constant-time compare. subtle.ConstantTimeCompare returns 0 on
		// length mismatch — accept only on exact length match (TOTPDigits)
		// to keep the success path single-shaped.
		if len(candidate) == len(code) && subtle.ConstantTimeCompare([]byte(candidate), []byte(code)) == 1 {
			return true
		}
	}
	return false
}

// ProvisioningURI returns an otpauth:// URI for QR-code enrollment.
// issuer is the project name shown in the authenticator app; account is
// usually the user's email. The URI format is the de-facto standard
// documented at https://github.com/google/google-authenticator/wiki/Key-Uri-Format
// — every popular authenticator app (Google Authenticator, Authy, 1Password,
// Microsoft Authenticator, Bitwarden) consumes it unchanged.
func ProvisioningURI(secret, issuer, account string) string {
	// Spec: otpauth://totp/<issuer>:<account>?secret=<secret>&issuer=<issuer>&...
	// The issuer prefix on the path is double-claimed in the query string so
	// authenticator apps that respect only one of the two still attribute
	// the entry correctly.
	label := url.PathEscape(issuer + ":" + account)
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", fmt.Sprintf("%d", TOTPDigits))
	q.Set("period", fmt.Sprintf("%d", TOTPPeriodSeconds))
	return "otpauth://totp/" + label + "?" + q.Encode()
}

// decodeTOTPSecret accepts base32 with or without padding (Google Authenticator
// strips padding; some other apps include it). Returns the decoded bytes.
func decodeTOTPSecret(secret string) ([]byte, error) {
	clean := strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	if clean == "" {
		return nil, fmt.Errorf("totp: empty secret")
	}
	// Try no-padding first (the form GenerateTOTPSecret returns).
	if key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(clean); err == nil {
		return key, nil
	}
	// Fall back to padded decoding for compatibility with other tools.
	key, err := base32.StdEncoding.DecodeString(clean)
	if err != nil {
		return nil, fmt.Errorf("totp: decode secret: %w", err)
	}
	return key, nil
}

// hotp returns the HOTP value for key + counter per RFC 4226. The output is
// always a TOTPDigits-digit zero-padded decimal string.
func hotp(key []byte, counter uint64) string {
	var ctrBuf [8]byte
	binary.BigEndian.PutUint64(ctrBuf[:], counter)
	mac := hmac.New(sha1.New, key)
	mac.Write(ctrBuf[:])
	digest := mac.Sum(nil)
	// Dynamic truncation per RFC 4226 §5.3.
	offset := digest[len(digest)-1] & 0x0F
	binCode := (uint32(digest[offset])&0x7F)<<24 |
		uint32(digest[offset+1])<<16 |
		uint32(digest[offset+2])<<8 |
		uint32(digest[offset+3])
	mod := uint32(1)
	for i := 0; i < TOTPDigits; i++ {
		mod *= 10
	}
	return fmt.Sprintf("%0*d", TOTPDigits, binCode%mod)
}
