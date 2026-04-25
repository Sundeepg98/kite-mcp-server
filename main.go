// Kite MCP Server implements the Model Context Protocol for the Kite Connect trading API
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sync/atomic"

	"github.com/zerodha/kite-mcp-server/app"
	"github.com/zerodha/kite-mcp-server/kc/ops"
)

var (
	// MCP_SERVER_VERSION will be injected during the build process by the justfile
	// Use 'just build-version VERSION' to set a specific version
	MCP_SERVER_VERSION = "v0.0.0"

	// buildString will be injected during the build process with build time and git info
	buildString = "dev build"
)

// parseLogLevel maps a raw LOG_LEVEL env value to a slog.Level. Empty string
// or unrecognised values default to LevelInfo. Pure function so tests can
// drive every branch with string literals — no t.Setenv, parallel-safe.
//
// Valid input values: "debug", "info", "warn", "error", "" (empty defaults
// to info). Anything else also defaults to info; the "default to INFO if
// invalid" branch is fail-open: a typo'd LOG_LEVEL must not silence logs.
func parseLogLevel(raw string) slog.Level {
	switch raw {
	case "debug":
		return slog.LevelDebug
	case "info", "":
		return slog.LevelInfo
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

func initLogger() (*slog.Logger, *ops.LogBuffer) {
	// LOG_LEVEL env override; parseLogLevel is the pure parser and is
	// covered by parallel TestParseLogLevel_* table tests in main_test.go.
	level := parseLogLevel(os.Getenv("LOG_LEVEL"))

	opts := &slog.HandlerOptions{
		Level: level,
	}
	logBuffer := ops.NewLogBuffer(500)
	inner := slog.NewTextHandler(os.Stderr, opts)
	tee := ops.NewTeeHandler(inner, logBuffer)
	return slog.New(tee), logBuffer
}

func main() {
	// Check for version flag
	if len(os.Args) > 1 && (os.Args[1] == "--version" || os.Args[1] == "-v") {
		fmt.Printf("Kite MCP Server %s\n", MCP_SERVER_VERSION)
		fmt.Printf("Build: %s\n", buildString)
		os.Exit(0)
	}

	// Initialize logger with tee handler for ops dashboard log streaming
	logger, logBuffer := initLogger()

	// Create a new application instance
	application := app.NewApp(logger)
	application.SetLogBuffer(logBuffer)

	// Load configuration from environment
	if err := application.LoadConfig(); err != nil {
		logger.Error("Failed to load configuration", "error", err)
		os.Exit(1)
	}

	// Set the server version
	application.SetVersion(MCP_SERVER_VERSION)

	// Wire SIGUSR2 graceful-restart (unix) / stub (windows). Safe to
	// call unconditionally: the windows stub is a no-op logger.
	// The listener auto-exits when the ctx is cancelled (never in
	// practice — main blocks on RunServer; process exit cancels the
	// listener goroutine indirectly via OS teardown).
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var activeRequests atomic.Int32
	app.StartGracefulRestartListener(ctx,
		app.GracefulRestartConfig{}.WithDefaults(),
		&activeRequests,
		logger,
		func() { application.TriggerShutdown() })

	// Run the server (blocks until shutdown)
	logger.Info("Starting Kite MCP Server...", "version", MCP_SERVER_VERSION, "build", buildString)
	if err := application.RunServer(); err != nil {
		logger.Error("Server failed to start", "error", err)
		os.Exit(1)
	}
}
