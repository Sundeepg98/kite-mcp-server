package kc

import (
	"strings"
	"testing"
)

func TestNewSessionSigner(t *testing.T) {
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("Expected no error creating session signer, got: %v", err)
	}

	if len(signer.secretKey) != 32 {
		t.Errorf("Expected secret key length 32, got %d", len(signer.secretKey))
	}

	if signer.signatureExpiry != DefaultSignatureExpiry {
		t.Errorf("Expected default expiry %v, got %v", DefaultSignatureExpiry, signer.signatureExpiry)
	}
}

func TestSignAndVerifySessionID(t *testing.T) {
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("Expected no error creating session signer, got: %v", err)
	}

	testSessionID := "test-session-12345"

	// Sign the session ID
	signedParam := signer.SignSessionID(testSessionID)
	if signedParam == "" {
		t.Error("Expected non-empty signed parameter")
	}

	// Should contain session ID and timestamp
	if !strings.Contains(signedParam, testSessionID) {
		t.Error("Expected signed parameter to contain session ID")
	}

	// Should have format: payload.signature
	parts := strings.Split(signedParam, ".")
	if len(parts) != 2 {
		t.Errorf("Expected signed parameter to have format 'payload.signature', got %s", signedParam)
	}

	// Verify the signed parameter
	verifiedSessionID, err := signer.VerifySessionID(signedParam)
	if err != nil {
		t.Errorf("Expected no error verifying session ID, got: %v", err)
	}

	if verifiedSessionID != testSessionID {
		t.Errorf("Expected verified session ID %s, got %s", testSessionID, verifiedSessionID)
	}
}

func TestVerifySessionIDErrors(t *testing.T) {
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("Expected no error creating session signer, got: %v", err)
	}

	// Test invalid format (no dot)
	_, err = signer.VerifySessionID("invalid-format")
	if err != ErrInvalidFormat {
		t.Errorf("Expected ErrInvalidFormat for invalid format, got: %v", err)
	}

	// Test invalid base64 signature
	_, err = signer.VerifySessionID("test|123.invalid-base64!")
	if err == nil || !strings.Contains(err.Error(), "invalid base64") {
		t.Errorf("Expected base64 error, got: %v", err)
	}

	// Test tampered signature
	validSigned := signer.SignSessionID("test-session")
	tamperedSigned := strings.Replace(validSigned, "test", "hack", 1)
	_, err = signer.VerifySessionID(tamperedSigned)
	if err != ErrTamperedSession {
		t.Errorf("Expected ErrTamperedSession for tampered signature, got: %v", err)
	}
}

func TestSignAndVerifyRedirectParams(t *testing.T) {
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("Expected no error creating session signer, got: %v", err)
	}

	testSessionID := "test-session-redirect"

	// Sign redirect params
	redirectParams, err := signer.SignRedirectParams(testSessionID)
	if err != nil {
		t.Errorf("Expected no error signing redirect params, got: %v", err)
	}

	if redirectParams == "" {
		t.Error("Expected non-empty redirect params")
	}

	// Should have format: session_id=signed_value
	if !strings.HasPrefix(redirectParams, "session_id=") {
		t.Errorf("Expected redirect params to start with 'session_id=', got %s", redirectParams)
	}

	// Verify redirect params
	verifiedSessionID, err := signer.VerifyRedirectParams(redirectParams)
	if err != nil {
		t.Errorf("Expected no error verifying redirect params, got: %v", err)
	}

	if verifiedSessionID != testSessionID {
		t.Errorf("Expected verified session ID %s, got %s", testSessionID, verifiedSessionID)
	}
}

func TestVerifyRedirectParamsErrors(t *testing.T) {
	signer, err := NewSessionSigner()
	if err != nil {
		t.Fatalf("Expected no error creating session signer, got: %v", err)
	}

	// Test invalid format (no session_id prefix)
	_, err = signer.VerifyRedirectParams("invalid=format")
	if err != ErrInvalidFormat {
		t.Errorf("Expected ErrInvalidFormat for invalid format, got: %v", err)
	}

	// Test empty session_id value
	_, err = signer.VerifyRedirectParams("session_id=")
	if err != ErrInvalidFormat {
		t.Errorf("Expected ErrInvalidFormat for empty session_id, got: %v", err)
	}
}
