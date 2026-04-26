package riskguard

import (
	"errors"
	"log/slog"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestDiscoverPlugins_HappyPath_RegistersExecutableManifest verifies that
// DiscoverPlugins reads a plugin manifest from a directory and registers
// each named subprocess plugin via the supplied registrar callback.
//
// Doesn't actually launch subprocesses — the registrar only validates
// config (executable path exists). Subprocess launch is lazy at first
// Evaluate time anyway, so discovery is a pure config-loading concern.
func TestDiscoverPlugins_HappyPath_RegistersExecutableManifest(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	// Create a fake plugin executable on disk so config validation passes.
	exePath := filepath.Join(dir, "myplugin")
	if runtime.GOOS == "windows" {
		exePath += ".exe"
	}
	if err := os.WriteFile(exePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}

	manifest := `[
	{"name":"my_check","executable":"` + filepath.ToSlash(exePath) + `","order":2500}
]`
	mfPath := filepath.Join(dir, "plugins.json")
	if err := os.WriteFile(mfPath, []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	var registered []string
	registrar := func(name, executable string, order int) error {
		registered = append(registered, name)
		return nil
	}

	if err := DiscoverPlugins(dir, registrar, slog.Default()); err != nil {
		t.Fatalf("DiscoverPlugins: %v", err)
	}
	if len(registered) != 1 || registered[0] != "my_check" {
		t.Errorf("expected [my_check] registered, got %v", registered)
	}
}

// TestDiscoverPlugins_MissingDir_NoError verifies that a missing plugin
// directory is treated as a no-op (no plugins to register), not an
// error. This matches the production case: most operators don't have a
// plugin directory configured.
func TestDiscoverPlugins_MissingDir_NoError(t *testing.T) {
	t.Parallel()

	registrar := func(name, executable string, order int) error {
		t.Fatalf("registrar should not be called for missing dir")
		return nil
	}
	if err := DiscoverPlugins(filepath.Join(t.TempDir(), "does-not-exist"), registrar, nil); err != nil {
		t.Errorf("expected nil error for missing dir, got %v", err)
	}
}

// TestDiscoverPlugins_NoManifest_NoError verifies that an existing plugin
// directory without a manifest file is also a no-op.
func TestDiscoverPlugins_NoManifest_NoError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	registrar := func(name, executable string, order int) error {
		t.Fatalf("registrar should not be called when manifest absent")
		return nil
	}
	if err := DiscoverPlugins(dir, registrar, nil); err != nil {
		t.Errorf("expected nil error for empty dir, got %v", err)
	}
}

// TestDiscoverPlugins_MalformedManifest_Errors verifies that a manifest
// containing invalid JSON returns an error. The error wraps the parse
// failure with the manifest path so operators can find the culprit.
func TestDiscoverPlugins_MalformedManifest_Errors(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte("{not json"), 0o644); err != nil {
		t.Fatalf("write bad manifest: %v", err)
	}
	registrar := func(name, executable string, order int) error {
		t.Fatalf("registrar should not be called for malformed manifest")
		return nil
	}
	err := DiscoverPlugins(dir, registrar, nil)
	if err == nil {
		t.Fatalf("expected error for malformed manifest")
	}
}

// TestDiscoverPlugins_RegistrarError_PropagatedAfterAll verifies that
// when one plugin's registration fails, DiscoverPlugins continues to
// the remaining plugins (best-effort), then returns an aggregated
// error. This matches the operator expectation: a broken plugin should
// not silently block other plugins from loading.
func TestDiscoverPlugins_RegistrarError_PropagatedAfterAll(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe1 := filepath.Join(dir, "p1")
	exe2 := filepath.Join(dir, "p2")
	if runtime.GOOS == "windows" {
		exe1 += ".exe"
		exe2 += ".exe"
	}
	for _, p := range []string{exe1, exe2} {
		if err := os.WriteFile(p, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}

	manifest := `[
	{"name":"p1","executable":"` + filepath.ToSlash(exe1) + `","order":2500},
	{"name":"p2","executable":"` + filepath.ToSlash(exe2) + `","order":2600}
]`
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}

	failBoom := errors.New("registrar boom")
	var seen []string
	registrar := func(name, executable string, order int) error {
		seen = append(seen, name)
		if name == "p1" {
			return failBoom
		}
		return nil
	}
	err := DiscoverPlugins(dir, registrar, slog.Default())
	if err == nil {
		t.Fatalf("expected aggregated error, got nil")
	}
	// Both plugins should have been ATTEMPTED, even though p1 failed.
	if len(seen) != 2 {
		t.Errorf("expected both plugins attempted, got %v", seen)
	}
	if !errors.Is(err, failBoom) {
		t.Errorf("expected errors.Is(err, failBoom), got %v", err)
	}
}

// TestDiscoverPlugins_DuplicateName_LastWins documents the duplicate-
// name semantics: if the manifest has two entries with the same name,
// the second registration call wins (subject to whatever the registrar
// does). DiscoverPlugins itself does not de-duplicate — that's the
// registrar's responsibility (Guard.RegisterSubprocessCheck calls
// Guard.RegisterCheck which sorts by Order and tolerates duplicates
// in input).
func TestDiscoverPlugins_DuplicateName_LastWins(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	exe := filepath.Join(dir, "p")
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	if err := os.WriteFile(exe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("write exe: %v", err)
	}
	manifest := `[
	{"name":"p","executable":"` + filepath.ToSlash(exe) + `","order":2500},
	{"name":"p","executable":"` + filepath.ToSlash(exe) + `","order":2600}
]`
	if err := os.WriteFile(filepath.Join(dir, "plugins.json"), []byte(manifest), 0o644); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	calls := 0
	registrar := func(name, executable string, order int) error {
		calls++
		return nil
	}
	if err := DiscoverPlugins(dir, registrar, nil); err != nil {
		t.Fatalf("DiscoverPlugins: %v", err)
	}
	if calls != 2 {
		t.Errorf("expected registrar called twice (last-wins), got %d", calls)
	}
}
