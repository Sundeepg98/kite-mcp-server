package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Tests of pure-logic helpers (parseLogLevel, initLogger, memoryLimit)
// migrated to github.com/algo2go/kite-mcp-bootstrap/bootstrap_test.go
// as part of the 2026-05-16 bootstrap-relocation. The tests below cover
// only deploy-repo concerns: build-time version injection and binary
// behaviour with --version / no-args.

func TestVersionVariables(t *testing.T) {
	// Package-level variables should have default values when not injected by ldflags.
	assert.Equal(t, "v0.0.0", MCP_SERVER_VERSION)
	assert.Equal(t, "dev build", buildString)
}

func TestBinary_VersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary test in short mode")
	}

	tmpDir := t.TempDir()
	binaryName := "kite-mcp-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	// Build the binary with a known version injected via ldflags.
	buildCmd := exec.Command("go", "build",
		"-ldflags", "-X main.MCP_SERVER_VERSION=v9.8.7 -X 'main.buildString=test-build-123'",
		"-o", binaryPath,
		".",
	)
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, buildOut)
	}

	out, err := exec.Command(binaryPath, "--version").CombinedOutput()
	require.NoError(t, err, "binary --version should exit 0")
	output := string(out)
	assert.Contains(t, output, "v9.8.7", "should contain injected version")
	assert.Contains(t, output, "test-build-123", "should contain injected build string")
}

func TestBinary_ShortVersionFlag(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary test in short mode")
	}

	tmpDir := t.TempDir()
	binaryName := "kite-mcp-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, buildOut)
	}

	out, err := exec.Command(binaryPath, "-v").CombinedOutput()
	require.NoError(t, err, "binary -v should exit 0")
	output := string(out)
	assert.Contains(t, output, "Kite MCP Server")
	assert.Contains(t, output, "Build:")
}

func TestBinary_NoArgsExitsNonZero(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping binary test in short mode")
	}

	tmpDir := t.TempDir()
	binaryName := "kite-mcp-test"
	if runtime.GOOS == "windows" {
		binaryName += ".exe"
	}
	binaryPath := filepath.Join(tmpDir, binaryName)

	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, buildOut)
	}

	cmd := exec.Command(binaryPath)
	// Clear all Kite/OAuth env vars so LoadConfig fails.
	cmd.Env = append(os.Environ(),
		"KITE_API_KEY=",
		"KITE_API_SECRET=",
		"OAUTH_JWT_SECRET=",
	)
	err = cmd.Run()
	assert.Error(t, err, "binary with no config should exit non-zero")
}
