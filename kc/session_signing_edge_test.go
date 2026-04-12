package kc

// This file provides session_signing tests WITHOUT the goexperiment.synctest build
// tag so they contribute to normal coverage runs. The original session_signing_test.go
// is gated behind synctest and excluded from `go test`.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"hash"
	"strings"
	"testing"
	"time"
)

// hmacSHA256 computes HMAC-SHA256 and returns base64url encoded string.
func hmacSHA256(key []byte, payload string) string {
	var h hash.Hash = hmac.New(sha256.New, key)
	h.Write([]byte(payload))
	return base64.URLEncoding.EncodeToString(h.Sum(nil))
}

func TestSS_Cov_NewSigner(t *testing.T) {
	t.Parallel()
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("NewSessionSigner error: %v", err)
	}
	if len(signer.secretKey) != 32 {
		t.Errorf("Expected secret key length 32, got %d", len(signer.secretKey))
	}
	if signer.signatureExpiry != DefaultSignatureExpiry {
		t.Errorf("wrong expiry")
	}
}

func TestSS_Cov_WithKey(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, err := NewSessionSignerWithKey(key)
	if err != nil {
		t.Fatal(err)
	}
	_ = signer

	// Empty key
	_, err = NewSessionSignerWithKey(nil)
	if err != ErrEmptySecretKey {
		t.Errorf("expected ErrEmptySecretKey, got %v", err)
	}
	_, err = NewSessionSignerWithKey([]byte{})
	if err != ErrEmptySecretKey {
		t.Errorf("expected ErrEmptySecretKey, got %v", err)
	}
}

func TestSS_Cov_SignVerifyRoundTrip(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	sessionID := "kitemcp-550e8400-e29b-41d4-a716-446655440000"
	signed := signer.SignSessionID(sessionID)

	verifiedID, err := signer.VerifySessionID(signed)
	if err != nil {
		t.Fatalf("VerifySessionID error: %v", err)
	}
	if verifiedID != sessionID {
		t.Errorf("got %q, want %q", verifiedID, sessionID)
	}
}

func TestSS_Cov_NoDotSeparator(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	_, err := signer.VerifySessionID("no-dot-here")
	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}
}

func TestSS_Cov_MultipleDots(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	_, err := signer.VerifySessionID("a.b.c")
	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat for multiple dots, got %v", err)
	}
}

func TestSS_Cov_InvalidBase64(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	_, err := signer.VerifySessionID("sessionid|12345.!!!invalid!!!")
	if err == nil || !strings.Contains(err.Error(), ErrInvalidSignature.Error()) {
		t.Errorf("expected ErrInvalidSignature, got %v", err)
	}
}

func TestSS_Cov_TamperedSignature(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	sessionID := "kitemcp-550e8400-e29b-41d4-a716-446655440000"
	signed := signer.SignSessionID(sessionID)

	tampered := strings.Replace(signed, sessionID, "kitemcp-aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", 1)
	_, err := signer.VerifySessionID(tampered)
	if err != ErrTamperedSession {
		t.Errorf("expected ErrTamperedSession, got %v", err)
	}
}

// TestSS_Cov_NoPipeInPayload — after sig passes, payloadParts != 2 (line 117)
func TestSS_Cov_NoPipeInPayload(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, _ := NewSessionSignerWithKey(key)

	payload := "nopipe-payload"
	sig := hmacSHA256(key, payload)
	signed := payload + "." + sig

	_, err := signer.VerifySessionID(signed)
	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat for no-pipe payload, got %v", err)
	}
}

// TestSS_Cov_InvalidTimestamp — after sig passes, non-numeric timestamp (line 126)
func TestSS_Cov_InvalidTimestamp(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, _ := NewSessionSignerWithKey(key)

	payload := "kitemcp-550e8400-e29b-41d4-a716-446655440000|notanumber"
	sig := hmacSHA256(key, payload)
	signed := payload + "." + sig

	_, err := signer.VerifySessionID(signed)
	if err == nil || !strings.Contains(err.Error(), "invalid timestamp") {
		t.Errorf("expected 'invalid timestamp' error, got %v", err)
	}
}

// TestSS_Cov_FutureTimestamp — timestamp far in the future beyond MaxClockSkew (line 139)
func TestSS_Cov_FutureTimestamp(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, _ := NewSessionSignerWithKey(key)

	payload := fmt.Sprintf("kitemcp-550e8400-e29b-41d4-a716-446655440000|%d", 9999999999)
	sig := hmacSHA256(key, payload)
	signed := payload + "." + sig

	_, err := signer.VerifySessionID(signed)
	if err != ErrInvalidSignature {
		t.Errorf("expected ErrInvalidSignature for future timestamp, got %v", err)
	}
}

func TestSS_Cov_DifferentSigners(t *testing.T) {
	t.Parallel()
	signer1, _ := NewSessionSigner()
	signer2, _ := NewSessionSigner()

	sessionID := "kitemcp-550e8400-e29b-41d4-a716-446655440000"
	signed := signer1.SignSessionID(sessionID)

	_, err := signer2.VerifySessionID(signed)
	if err != ErrTamperedSession {
		t.Errorf("expected ErrTamperedSession, got %v", err)
	}
}

func TestSS_Cov_RedirectParams(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	sessionID := "kitemcp-550e8400-e29b-41d4-a716-446655440000"
	params, err := signer.SignRedirectParams(sessionID)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(params, "session_id=") {
		t.Errorf("expected session_id= prefix")
	}

	verified, err := signer.VerifyRedirectParams(params)
	if err != nil {
		t.Fatal(err)
	}
	if verified != sessionID {
		t.Errorf("got %q, want %q", verified, sessionID)
	}

	// Bad prefix
	_, err = signer.VerifyRedirectParams("invalid=xxx")
	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}

	// Empty value
	_, err = signer.VerifyRedirectParams("session_id=")
	if err != ErrInvalidFormat {
		t.Errorf("expected ErrInvalidFormat, got %v", err)
	}

	// Invalid session ID for sign
	_, err = signer.SignRedirectParams("bad-id")
	if err == nil {
		t.Error("expected error for bad session ID")
	}
}

func TestSS_Cov_GetSecretKey(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, _ := NewSessionSignerWithKey(key)

	got := signer.getSecretKey()
	if string(got) != string(key) {
		t.Error("content mismatch")
	}
	got[0] = 0xFF
	got2 := signer.getSecretKey()
	if got2[0] == 0xFF {
		t.Error("should be a copy")
	}
}

func TestSS_Cov_ValidateSessionID(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	tests := []struct {
		id        string
		expectErr bool
	}{
		{"kitemcp-550e8400-e29b-41d4-a716-446655440000", false},
		{"invalid-550e8400-e29b-41d4-a716-446655440000", true},
		{"kitemcp-invalid-uuid", true},
		{"", true},
	}
	for _, tc := range tests {
		err := signer.ValidateSessionID(tc.id)
		if tc.expectErr && err == nil {
			t.Errorf("expected error for %q", tc.id)
		}
		if !tc.expectErr && err != nil {
			t.Errorf("unexpected error for %q: %v", tc.id, err)
		}
	}
}

// TestSS_Cov_ExpiredTimestamp — timestamp in the past beyond signatureExpiry+MaxClockSkew (line 134)
func TestSS_Cov_ExpiredTimestamp(t *testing.T) {
	t.Parallel()
	key := []byte("abcdefghijklmnopqrstuvwxyz012345")
	signer, _ := NewSessionSignerWithKey(key)
	// Use a very short expiry so a past timestamp is guaranteed expired
	signer.SetSignatureExpiry(1 * time.Second)

	// Timestamp 1 hour in the past — well beyond 1s expiry + 5m clock skew
	pastTS := time.Now().Add(-1 * time.Hour).Unix()
	payload := fmt.Sprintf("kitemcp-550e8400-e29b-41d4-a716-446655440000|%d", pastTS)
	sig := hmacSHA256(key, payload)
	signed := payload + "." + sig

	_, err := signer.VerifySessionID(signed)
	if err != ErrExpiredSignature {
		t.Errorf("expected ErrExpiredSignature, got %v", err)
	}
}

func TestSS_Cov_SetSignatureExpiry(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()
	signer.SetSignatureExpiry(42)
	if signer.signatureExpiry != 42 {
		t.Errorf("expected 42, got %v", signer.signatureExpiry)
	}
}

func TestSS_Cov_Format(t *testing.T) {
	t.Parallel()
	signer, _ := NewSessionSigner()

	sessionID := "kitemcp-550e8400-e29b-41d4-a716-446655440000"
	signed := signer.SignSessionID(sessionID)

	parts := strings.Split(signed, ".")
	if len(parts) != 2 {
		t.Fatalf("expected 2 parts, got %d", len(parts))
	}
	pp := strings.Split(parts[0], "|")
	if len(pp) != 2 {
		t.Fatalf("expected 2 payload parts, got %d", len(pp))
	}
	if pp[0] != sessionID {
		t.Errorf("got %q, want %q", pp[0], sessionID)
	}
}
