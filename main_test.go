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

// TestParseLogLevel covers the pure parser that initLogger delegates to.
// Migrated from TestInitLogger_* (7 t.Setenv tests) to a single table-driven
// parallel test — the env-reading code (initLogger calling os.Getenv) is
// covered by the one TestInitLogger_EnvIntegration adapter test below;
// every behaviour branch lives here against string literals.
func TestParseLogLevel(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want slog.Level
	}{
		{"empty defaults to info", "", slog.LevelInfo},
		{"info explicit", "info", slog.LevelInfo},
		{"debug", "debug", slog.LevelDebug},
		{"warn", "warn", slog.LevelWarn},
		{"error", "error", slog.LevelError},
		{"garbage defaults to info (fail-open)", "garbage", slog.LevelInfo},
		{"uppercase NOT recognised (fail-open to info)", "DEBUG", slog.LevelInfo},
		{"whitespace NOT trimmed (current contract)", " info", slog.LevelInfo},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assert.Equal(t, tc.want, parseLogLevel(tc.raw))
		})
	}
}

// TestInitLogger_EnvIntegration is the single adapter test that verifies
// initLogger reads LOG_LEVEL from the environment and feeds it to
// parseLogLevel. Behaviour-per-value is covered by TestParseLogLevel above;
// this test only proves the os.Getenv → parser chain wiring. Cannot run
// in parallel because t.Setenv mutates process-wide env.
func TestInitLogger_EnvIntegration(t *testing.T) {
	t.Setenv("LOG_LEVEL", "debug")
	logger, logBuffer := initLogger()
	require.NotNil(t, logger)
	require.NotNil(t, logBuffer)
	// Wiring proof: env="debug" → parser returns LevelDebug → logger
	// enabled at debug. If parseLogLevel were called with the wrong env
	// value, the assertion below would fail.
	assert.True(t, logger.Enabled(nil, slog.LevelDebug))
}

// TestInitLogger_LogBufferCaptures verifies the LogBuffer side-effect of
// initLogger (separate from level parsing). Doesn't depend on env reading
// — the level is whatever ambient env says, the test only asserts the
// buffer captures any log line.
func TestInitLogger_LogBufferCaptures(t *testing.T) {
	t.Parallel()
	logger, logBuffer := initLogger()
	// Force an info-level write regardless of ambient LOG_LEVEL by using
	// the lowest level that always fires. If the ambient env set
	// LOG_LEVEL=error this Info call would be filtered, so emit Error
	// to be safe across all ambient configurations.
	logger.Error("test-message-for-buffer")
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
