package riskguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// PluginDiscoveryEntry is one row of the plugin manifest. It maps a
// human-readable name to the binary that implements the
// checkrpc.CheckRPC interface for the host's hashicorp/go-plugin
// transport.
//
// The manifest is intentionally minimal: name, executable, order. SBOM
// emission, RecordOnRejection, and Args are deferred to the runtime
// configuration that wraps DiscoverPlugins (operator can call
// RegisterSubprocessCheckWithSBOM directly for those concerns). The
// 99% case is "I have a plugin binary at /path; load it" — that's
// what this surface optimises for.
type PluginDiscoveryEntry struct {
	Name       string `json:"name"`
	Executable string `json:"executable"`
	Order      int    `json:"order"`
}

// PluginRegistrar is the callback that DiscoverPlugins invokes for
// each manifest entry. The host typically passes
// Guard.RegisterSubprocessCheck — that signature matches.
type PluginRegistrar func(name, executable string, order int) error

// DiscoverPlugins reads `<dir>/plugins.json` and invokes registrar
// for each entry. Provides the runtime "discovery" half of the
// already-shipped subprocess plugin framework: operators drop a
// manifest file in dir, restart the server, and their plugins load
// without source-code changes.
//
// Failure modes:
//   - dir does not exist → no-op, returns nil. (Most operators have
//     no plugin directory; treating that as an error would be noisy.)
//   - dir exists but no plugins.json → no-op, returns nil.
//   - plugins.json is malformed → returns wrapped JSON parse error.
//   - registrar returns an error for one entry → DiscoverPlugins
//     continues to the remaining entries (best-effort), then returns
//     an aggregated error via errors.Join. This matches the operator
//     expectation that one broken plugin should not silently block
//     other plugins from loading.
//
// Logger is optional; when non-nil, each successful registration is
// logged at Info level so operators can confirm what loaded.
//
// Concurrency: not safe for concurrent calls against the same
// registrar. The expected usage is "called once at app startup,
// before tool handlers begin serving" — same lifecycle as the rest
// of the riskguard registration surface.
func DiscoverPlugins(dir string, registrar PluginRegistrar, logger *slog.Logger) error {
	if registrar == nil {
		return errors.New("riskguard: DiscoverPlugins requires a non-nil registrar")
	}
	// Wave D Phase 3 Package 2: convert at the boundary. Public
	// signature retains *slog.Logger for caller compatibility
	// (app/providers/riskguard.go:194); internal log calls use the
	// kc/logger.Logger port. ctx is context.Background() because
	// DiscoverPlugins is a one-shot startup function with no
	// request context in scope — same pattern as audit.StartHashPublisher.
	ctx := context.Background()
	var l logport.Logger
	if logger != nil {
		l = logport.NewSlog(logger)
	}
	manifestPath := filepath.Join(dir, "plugins.json")
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			// Treat missing-dir / missing-manifest as no-op — most
			// operators don't run with a plugin directory.
			return nil
		}
		return fmt.Errorf("riskguard: read manifest %s: %w", manifestPath, err)
	}

	var entries []PluginDiscoveryEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		return fmt.Errorf("riskguard: parse manifest %s: %w", manifestPath, err)
	}

	var aggregated []error
	for _, e := range entries {
		if err := registrar(e.Name, e.Executable, e.Order); err != nil {
			if l != nil {
				l.Warn(ctx, "riskguard: plugin discovery failed for entry",
					"name", e.Name, "executable", e.Executable, "order", e.Order, "error", err)
			}
			aggregated = append(aggregated, fmt.Errorf("plugin %q: %w", e.Name, err))
			continue
		}
		if l != nil {
			l.Info(ctx, "riskguard: plugin discovered + registered",
				"name", e.Name, "executable", e.Executable, "order", e.Order)
		}
	}
	if len(aggregated) > 0 {
		return errors.Join(aggregated...)
	}
	return nil
}
