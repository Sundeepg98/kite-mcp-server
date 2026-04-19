package oauth

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ===========================================================================
// HandleGoogleLogin
// ===========================================================================



// ===========================================================================
// fetchGoogleUserInfo — tested with httptest server
// ===========================================================================
func TestFetchGoogleUserInfo_EmptyToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// Empty access token will fail at Google's API
	_, err := fetchGoogleUserInfo(ctx, "", nil, "")
	if err == nil {
		t.Error("Expected error with empty access token")
	}
}


func TestFetchGoogleUserInfo_InvalidToken(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	// This will make a real HTTP call that returns 401
	_, err := fetchGoogleUserInfo(ctx, "definitely-invalid-token-xyz123", nil, "")
	if err == nil {
		t.Error("Expected error with invalid access token")
	}
}


func TestFetchGoogleUserInfo_MockSuccess(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify auth header is set
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token-123" {
			t.Errorf("Expected Bearer test-token-123, got %q", auth)
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "user@example.com",
			"verified_email": true,
		})
	}))
	defer srv.Close()

	ctx := context.Background()
	email, err := fetchGoogleUserInfo(ctx, "test-token-123", nil, srv.URL)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("Email = %q, want user@example.com", email)
	}
}


func TestFetchGoogleUserInfo_MockWithCustomClient(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "custom@example.com",
			"verified_email": true,
		})
	}))
	defer srv.Close()

	ctx := context.Background()
	email, err := fetchGoogleUserInfo(ctx, "tok", srv.Client(), srv.URL)
	if err != nil {
		t.Fatalf("Expected no error, got: %v", err)
	}
	if email != "custom@example.com" {
		t.Errorf("Email = %q, want custom@example.com", email)
	}
}


func TestFetchGoogleUserInfo_UnverifiedEmail(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"email":          "unverified@example.com",
			"verified_email": false,
		})
	}))
	defer srv.Close()

	ctx := context.Background()
	_, err := fetchGoogleUserInfo(ctx, "tok", nil, srv.URL)
	if err == nil {
		t.Error("Expected error for unverified email")
	}
	if !strings.Contains(err.Error(), "email not verified") {
		t.Errorf("Expected 'email not verified' error, got: %v", err)
	}
}


func TestFetchGoogleUserInfo_ServerError(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "internal error", http.StatusInternalServerError)
	}))
	defer srv.Close()

	ctx := context.Background()
	_, err := fetchGoogleUserInfo(ctx, "tok", nil, srv.URL)
	if err == nil {
		t.Error("Expected error for server error response")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("Expected error to mention 500, got: %v", err)
	}
}


func TestFetchGoogleUserInfo_InvalidJSON(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte("not-json"))
	}))
	defer srv.Close()

	ctx := context.Background()
	_, err := fetchGoogleUserInfo(ctx, "tok", nil, srv.URL)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}
