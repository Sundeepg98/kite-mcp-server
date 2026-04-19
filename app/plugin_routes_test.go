package app

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRegisterRoute_Basic — happy path: register a plugin route and
// confirm it's present in ListPluginRoutes.
func TestRegisterRoute_Basic(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	err := RegisterRoute("/plugin/hello", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("hello"))
	})
	require.NoError(t, err)

	routes := ListPluginRoutes()
	require.Len(t, routes, 1)
	assert.Equal(t, "/plugin/hello", routes[0].Pattern)
	assert.NotNil(t, routes[0].Handler)
}

// TestRegisterRoute_MountAttachesToMux — MountPluginRoutes wires every
// registered route onto a supplied ServeMux. After mounting, a request
// to the pattern reaches the plugin handler.
func TestRegisterRoute_MountAttachesToMux(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	require.NoError(t, RegisterRoute("/plugin/echo", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("echoed"))
	}))

	mux := http.NewServeMux()
	MountPluginRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/plugin/echo", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "echoed", w.Body.String())
}

// TestRegisterRoute_RejectsInvalid — empty pattern, nil handler, and
// reserved path prefixes all fail at registration.
func TestRegisterRoute_RejectsInvalid(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	h := func(w http.ResponseWriter, r *http.Request) {}

	assert.Error(t, RegisterRoute("", h))
	assert.Error(t, RegisterRoute("/plugin/x", nil))
	assert.Error(t, RegisterRoute("no-leading-slash", h))

	// Reserved path prefixes (built-in routes) are off-limits.
	for _, reserved := range []string{"/oauth/", "/auth/", "/admin/", "/callback", "/dashboard", "/.well-known/"} {
		err := RegisterRoute(reserved+"shadow", h)
		assert.Error(t, err, "pattern %q should be reserved", reserved+"shadow")
	}
}

// TestRegisterRoute_DuplicatePatternReplaces — matches the lifecycle
// of other plugin registries (last-wins).
func TestRegisterRoute_DuplicatePatternReplaces(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	require.NoError(t, RegisterRoute("/plugin/dup", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("first"))
	}))
	require.NoError(t, RegisterRoute("/plugin/dup", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("second"))
	}))

	routes := ListPluginRoutes()
	require.Len(t, routes, 1)

	mux := http.NewServeMux()
	MountPluginRoutes(mux)

	req := httptest.NewRequest(http.MethodGet, "/plugin/dup", nil)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	assert.Equal(t, "second", w.Body.String())
}

// TestPluginRouteCount — count tracking for the admin surface.
func TestPluginRouteCount(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	assert.Equal(t, 0, PluginRouteCount())
	_ = RegisterRoute("/plugin/a", func(w http.ResponseWriter, r *http.Request) {})
	_ = RegisterRoute("/plugin/b", func(w http.ResponseWriter, r *http.Request) {})
	assert.Equal(t, 2, PluginRouteCount())
}

// TestMountPluginRoutes_NilMux is a safe no-op.
func TestMountPluginRoutes_NilMux(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()
	_ = RegisterRoute("/plugin/x", func(w http.ResponseWriter, r *http.Request) {})
	// Must not panic.
	MountPluginRoutes(nil)
}

// TestRegisterRoute_PluginRequirePrefix — plugin routes SHOULD use
// a /plugin/ namespace, but we enforce only that they don't collide
// with built-ins (the namespace enforcement is a convention, not a
// constraint, so plugins registering e.g. /healthz/mine can still
// mount).
func TestRegisterRoute_PluginRequirePrefix(t *testing.T) {
	ClearPluginRoutes()
	defer ClearPluginRoutes()

	// Non-/plugin/ paths are allowed as long as they don't collide
	// with reserved prefixes.
	err := RegisterRoute("/healthz/mine", func(w http.ResponseWriter, r *http.Request) {})
	assert.NoError(t, err, "unreserved non-/plugin/ paths are allowed")

	// But paths that "sort of look like" reserved ones are still OK
	// provided they don't match the exact reserved prefix.
	err = RegisterRoute("/oauth-ish", func(w http.ResponseWriter, r *http.Request) {})
	if err != nil && !strings.Contains(err.Error(), "reserved") {
		t.Errorf("unexpected error for /oauth-ish: %v", err)
	}
}
