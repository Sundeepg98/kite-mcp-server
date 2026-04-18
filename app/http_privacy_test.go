package app

// http_privacy_test.go — tests for /privacy and /terms HTTP endpoints.
// These endpoints render markdown (kc/legaldocs/PRIVACY.md, kc/legaldocs/TERMS.md)
// to HTML via goldmark, wrap them in the legal template, and serve as public pages.
//
// Added as part of the feature switching from hardcoded HTML constants to
// markdown-based rendering with optional ?format=md for raw markdown.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPrivacyHandler_ServesHTML verifies GET /privacy returns 200 with an
// HTML content-type and a body containing "Privacy" (title/heading).
func TestPrivacyHandler_ServesHTML(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/privacy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Header().Get("Content-Type"), "charset=utf-8")
	// Body must mention Privacy (either "Privacy Policy" or "Privacy Notice").
	body := rec.Body.String()
	snippet := body
	if len(snippet) > 400 {
		snippet = snippet[:400]
	}
	assert.True(t,
		strings.Contains(body, "Privacy Policy") || strings.Contains(body, "Privacy Notice"),
		"body should contain 'Privacy Policy' or 'Privacy Notice'; got: %s", snippet,
	)
}

// TestTermsHandler_ServesHTML verifies GET /terms returns 200 with an HTML
// content-type and a body containing "Terms of Service".
func TestTermsHandler_ServesHTML(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/terms", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/html")
	assert.Contains(t, rec.Header().Get("Content-Type"), "charset=utf-8")
	assert.Contains(t, rec.Body.String(), "Terms of Service")
}

// TestPrivacyHandler_FormatMd verifies GET /privacy?format=md returns 200
// with a markdown content-type and a body containing the raw markdown
// (identifiable by a Markdown heading "# Privacy" which HTML would render
// as <h1>).
func TestPrivacyHandler_FormatMd(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/privacy?format=md", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/markdown")

	body := rec.Body.String()
	// Raw markdown should contain a "# " heading, not <h1>
	assert.Contains(t, body, "# ")
	assert.NotContains(t, body, "<h1>")
	assert.NotContains(t, body, "<html")
}

// TestTermsHandler_FormatMd verifies the same ?format=md behaviour for /terms.
func TestTermsHandler_FormatMd(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/terms?format=md", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Header().Get("Content-Type"), "text/markdown")
	body := rec.Body.String()
	assert.Contains(t, body, "# ")
	assert.NotContains(t, body, "<h1>")
}

// TestPrivacyHandler_CacheHeader verifies the response carries
// Cache-Control: public, max-age=3600.
func TestPrivacyHandler_CacheHeader(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	// HTML response
	req := httptest.NewRequest(http.MethodGet, "/privacy", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))

	// Markdown response also gets the cache header
	reqMd := httptest.NewRequest(http.MethodGet, "/privacy?format=md", nil)
	recMd := httptest.NewRecorder()
	mux.ServeHTTP(recMd, reqMd)
	assert.Equal(t, http.StatusOK, recMd.Code)
	assert.Equal(t, "public, max-age=3600", recMd.Header().Get("Cache-Control"))
}

// TestTermsHandler_CacheHeader verifies the same cache behaviour for /terms.
func TestTermsHandler_CacheHeader(t *testing.T) {
	app := NewApp(testLogger())
	require.NoError(t, app.initStatusPageTemplate())

	mux := http.NewServeMux()
	app.serveLegalPages(mux)

	req := httptest.NewRequest(http.MethodGet, "/terms", nil)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "public, max-age=3600", rec.Header().Get("Cache-Control"))
}
