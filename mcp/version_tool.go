package mcp

import (
	"context"
	"os"
	"runtime"
	"runtime/debug"
	"strings"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
)

// ServerVersionTool exposes build + runtime identity of the running process:
// git SHA, build time, deployment region, Go version, uptime, and selected
// public env flags. It intentionally reveals no secrets — operators and users
// need it to answer "which deployment / which commit am I actually talking
// to?" when debugging across local, staging, and Fly.io environments.
//
// The sibling tool `server_metrics` covers per-tool latency and error rates;
// `server_version` is the complementary "what am I running?" tool.
type ServerVersionTool struct{}

func (*ServerVersionTool) Tool() mcp.Tool {
	return mcp.NewTool("server_version",
		mcp.WithDescription("Returns the running server's build SHA, build time, deployment region, and Go version. For debugging which deployment you're connected to."),
		mcp.WithTitleAnnotation("Server Version"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

// serverVersionResponse is the structured payload for server_version. All
// fields are safe for public display — we explicitly do NOT include secret
// env vars (OAUTH_JWT_SECRET, KITE_API_SECRET, TELEGRAM_BOT_TOKEN, etc.), DB
// paths, or user/IP identifiers.
type serverVersionResponse struct {
	GitSHA        string          `json:"git_sha"`
	BuildTime     string          `json:"build_time"`
	Region        string          `json:"region"`
	GoVersion     string          `json:"go_version"`
	UptimeSeconds int64           `json:"uptime_s"`
	EnvFlags      map[string]bool `json:"env_flags"`
}

// versionInfo is computed once at first call and cached. Build-time metadata
// is immutable for the life of the process, so we do the (cheap) reflection
// on BuildInfo exactly once.
var (
	versionInfoOnce sync.Once
	cachedGitSHA    string
	cachedBuildTime string
	cachedRegion    string
)

// resolveVersionInfo fills the cached build-info fields on first call.
//
// Git SHA resolution order:
//  1. `-ldflags "-X main.gitSHA=<sha>"` style override — not used today
//     (main.MCP_SERVER_VERSION / main.buildString ldflags exist in main.go,
//     but pulling those across the mcp→main import boundary would invert
//     the package graph, so we use runtime/debug.ReadBuildInfo instead).
//  2. Go 1.18+ auto-embedded VCS settings via debug.ReadBuildInfo(); we look
//     for vcs.revision (the full SHA) and truncate to 7 chars.
//  3. Fallback "unknown" if the build was produced without VCS info (e.g.
//     `go build -buildvcs=false` or from a dirty tarball).
//
// Build time uses vcs.time from BuildInfo (last commit time) — this is the
// closest thing to "build time" we can get reliably from a stripped Go
// binary. Callers wanting strict build timestamps can add a ldflags inject
// in main.go later without changing this file's contract.
func resolveVersionInfo() {
	sha := "unknown"
	buildTime := "unknown"
	if info, ok := debug.ReadBuildInfo(); ok {
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				if s.Value != "" {
					// Short SHA (first 7 chars), matches `git rev-parse --short HEAD`.
					if len(s.Value) >= 7 {
						sha = s.Value[:7]
					} else {
						sha = s.Value
					}
				}
			case "vcs.time":
				if s.Value != "" {
					buildTime = s.Value
				}
			}
		}
	}
	cachedGitSHA = sha
	cachedBuildTime = buildTime

	// FLY_REGION is set by Fly.io at runtime (e.g. "bom"). Empty on local dev.
	region := strings.TrimSpace(os.Getenv("FLY_REGION"))
	if region == "" {
		region = "local"
	}
	cachedRegion = region
}

// readEnableTradingFlag returns whether ENABLE_TRADING env var is truthy.
// Uses the same truthy set as SafeAssertBool for consistency with the rest
// of the codebase ("true"/"1"/"yes"/"on" — case-insensitive).
// Extracted so tests can pin behaviour without spinning up the whole handler.
func readEnableTradingFlag() bool {
	return parseEnableTradingFlag(os.Getenv("ENABLE_TRADING"))
}

// parseEnableTradingFlag is the pure truthy-check over a raw value.
// Callers pass os.Getenv("ENABLE_TRADING") explicitly so tests can exercise
// the parser without t.Setenv and run in parallel.
func parseEnableTradingFlag(raw string) bool {
	return SafeAssertBool(raw, false)
}

func (*ServerVersionTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "server_version")

		versionInfoOnce.Do(resolveVersionInfo)

		resp := &serverVersionResponse{
			GitSHA:        cachedGitSHA,
			BuildTime:     cachedBuildTime,
			Region:        cachedRegion,
			GoVersion:     runtime.Version(),
			UptimeSeconds: int64(time.Since(serverStartTime).Seconds()),
			EnvFlags: map[string]bool{
				"enable_trading": readEnableTradingFlag(),
			},
		}
		return handler.MarshalResponse(resp, "server_version")
	}
}
