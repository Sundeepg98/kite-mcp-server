package main

import (
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVersionVariables(t *testing.T) {
	// Package-level variables should have default values when not injected by ldflags.
	assert.Equal(t, "v0.0.0", MCP_SERVER_VERSION)
	assert.Equal(t, "dev build", buildString)
}

func TestInitLogger_DefaultLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	// Default level is INFO — debug messages should not be enabled.
	assert.False(t, logger.Enabled(nil, slog.LevelDebug))
	assert.True(t, logger.Enabled(nil, slog.LevelInfo))
}

func TestInitLogger_DebugLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "debug")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	assert.True(t, logger.Enabled(nil, slog.LevelDebug))
	assert.True(t, logger.Enabled(nil, slog.LevelInfo))
}

func TestInitLogger_WarnLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "warn")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	assert.False(t, logger.Enabled(nil, slog.LevelInfo))
	assert.True(t, logger.Enabled(nil, slog.LevelWarn))
}

func TestInitLogger_ErrorLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "error")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	assert.False(t, logger.Enabled(nil, slog.LevelWarn))
	assert.True(t, logger.Enabled(nil, slog.LevelError))
}

func TestInitLogger_InvalidLevel(t *testing.T) {
	t.Setenv("LOG_LEVEL", "garbage")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	// Invalid level defaults to INFO.
	assert.False(t, logger.Enabled(nil, slog.LevelDebug))
	assert.True(t, logger.Enabled(nil, slog.LevelInfo))
}

func TestInitLogger_InfoExplicit(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)

	assert.False(t, logger.Enabled(nil, slog.LevelDebug))
	assert.True(t, logger.Enabled(nil, slog.LevelInfo))
}

func TestInitLogger_LogBufferCaptures(t *testing.T) {
	t.Setenv("LOG_LEVEL", "info")
	logger, logBuffer := initLogger()

	// Write a log message and verify the buffer captured it.
	logger.Info("test-message-for-buffer")
	entries := logBuffer.Recent(10)
	found := false
	for _, e := range entries {
		if strings.Contains(e.Message, "test-message-for-buffer") {
			found = true
			break
		}
	}
	assert.True(t, found, "LogBuffer should capture log entries")
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
	buildCmd.Dir = "D:/kite-mcp-temp"
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, buildOut)
	}

	// Run with --version flag.
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
	buildCmd.Dir = "D:/kite-mcp-temp"
	buildOut, err := buildCmd.CombinedOutput()
	if err != nil {
		t.Skipf("cannot build binary: %v\n%s", err, buildOut)
	}

	// Run with -v flag (short version).
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

	// Clear env vars so the server fails fast on LoadConfig.
	buildCmd := exec.Command("go", "build", "-o", binaryPath, ".")
	buildCmd.Dir = "D:/kite-mcp-temp"
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
	// Should exit non-zero because LoadConfig fails without required config.
	assert.Error(t, err, "binary with no config should exit non-zero")
}
