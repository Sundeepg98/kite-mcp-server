package mcp

import (
	"context"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/mcp/common"
	"github.com/zerodha/kite-mcp-server/mcp/paper"
)

// aliases.go — Anchor 1 PR 1.1 (Option B per .research/anchor-1-pr-1-1-
// redesign.md commit 34e5a23). Backward-compatibility shims for the
// types, functions, and constants that moved into mcp/common.
//
// After this PR, mcp/common is the canonical home for the shared MCP
// kernel: Tool interface, ToolHandler / ToolHandlerDeps, ArgParser,
// ToolCache, integrity manifest, elicitation primitives, response
// sanitiser, and the per-context dependency builders (newSessionDeps,
// newAlertDeps, newOrderDeps, newAdminDeps, newReadDeps).
//
// The aliases below preserve the legacy mcp.X reference path for the
// 81 in-tree mcp/ files + 8 external callers (in app/, kc/, plugins/)
// without forcing a touch-everywhere rewrite. Future per-domain
// PRs (1.2-1.10) can incrementally migrate consumers to common.X
// directly; this file is the safety net during the transition.
//
// Type aliases (`type X = common.X`) are not new types, so struct-
// literal construction (`mcp.ToolHandler{...}`), method-set
// satisfaction (a type implementing common.Tool also satisfies
// mcp.Tool), and slice-element identity (`[]mcp.Tool` and
// []common.Tool) are interchangeable at every call site.

// ---------------------------------------------------------------------
// Type aliases — exported symbols from common, re-exposed under mcp.X
// ---------------------------------------------------------------------

type (
	ToolHandler          = common.ToolHandler
	ToolHandlerDeps      = common.ToolHandlerDeps
	ArgParser            = common.ArgParser
	ValidationError      = common.ValidationError
	ToolCache            = common.ToolCache
	PaginationParams     = common.PaginationParams
	PaginatedResponse    = common.PaginatedResponse
	MismatchKind         = common.MismatchKind
	Mismatch             = common.Mismatch
	ToolManifest         = common.ToolManifest
	SessionDepsFields    = common.SessionDepsFields
	AlertDepsFields      = common.AlertDepsFields
	OrderDepsFields      = common.OrderDepsFields
	AdminDepsFields      = common.AdminDepsFields
	ReadDepsFields       = common.ReadDepsFields

	// Anchor 1 PR 1.9 closure: TradingContext moved into mcp/paper alongside
	// BuildTradingContext. The alias preserves *TradingContext as the bridge
	// return type for the existing buildTradingContextFromMap test fixture
	// in helpers_test.go.
	TradingContext = paper.TradingContext
)

// ---------------------------------------------------------------------
// Constants — re-exported via Go const aliasing (declared as const)
// ---------------------------------------------------------------------

const (
	SessionTypeSSE     = common.SessionTypeSSE
	SessionTypeMCP     = common.SessionTypeMCP
	SessionTypeStdio   = common.SessionTypeStdio
	SessionTypeUnknown = common.SessionTypeUnknown

	MaxPaginationLimit = common.MaxPaginationLimit

	ErrAuthRequired        = common.ErrAuthRequired
	ErrAdminRequired       = common.ErrAdminRequired
	ErrUserStoreNA         = common.ErrUserStoreNA
	ErrTargetEmailRequired = common.ErrTargetEmailRequired
	ErrSelfAction          = common.ErrSelfAction
	ErrLastAdmin           = common.ErrLastAdmin
	ErrRiskGuardNA         = common.ErrRiskGuardNA
	ErrConfirmRequired     = common.ErrConfirmRequired
	ErrInvitationStoreNA   = common.ErrInvitationStoreNA

	MismatchDescriptionChanged = common.MismatchDescriptionChanged
	MismatchAdded              = common.MismatchAdded
	MismatchRemoved            = common.MismatchRemoved
)

// ---------------------------------------------------------------------
// Function passthroughs — Go does not support function aliases, so
// these are thin one-line wrappers. Inlined by the compiler.
// ---------------------------------------------------------------------

// NewToolHandler constructs the unified per-request tool dependency
// container. Backward-compat passthrough for mcp.NewToolHandler;
// new code may call common.NewToolHandler directly.
func NewToolHandler(manager *kc.Manager) *ToolHandler {
	return common.NewToolHandler(manager)
}

// NewArgParser wraps a tool-call arg map for fluent extraction.
// Passthrough to common.NewArgParser.
func NewArgParser(args map[string]any) *ArgParser {
	return common.NewArgParser(args)
}

// ValidateRequired checks that the named keys exist and are non-empty.
// Passthrough to common.ValidateRequired.
func ValidateRequired(args map[string]any, required ...string) error {
	return common.ValidateRequired(args, required...)
}

// SafeAssertString returns the string from any with a fallback.
func SafeAssertString(v any, fallback string) string { return common.SafeAssertString(v, fallback) }

// SafeAssertInt returns the int from any with a fallback.
func SafeAssertInt(v any, fallback int) int { return common.SafeAssertInt(v, fallback) }

// SafeAssertFloat64 returns the float64 from any with a fallback.
func SafeAssertFloat64(v any, fallback float64) float64 { return common.SafeAssertFloat64(v, fallback) }

// SafeAssertBool returns the bool from any with a fallback.
func SafeAssertBool(v any, fallback bool) bool { return common.SafeAssertBool(v, fallback) }

// SafeAssertStringArray returns the []string from any.
func SafeAssertStringArray(v any) []string { return common.SafeAssertStringArray(v) }

// ParsePaginationParams extracts from/limit pagination args.
func ParsePaginationParams(args map[string]any) PaginationParams {
	return common.ParsePaginationParams(args)
}

// CreatePaginatedResponse wraps paginated data with metadata.
func CreatePaginatedResponse(originalData any, paginatedData any, params PaginationParams, originalLength int) *PaginatedResponse {
	return common.CreatePaginatedResponse(originalData, paginatedData, params, originalLength)
}

// CacheKey builds a cache key from tool name + email + suffix.
func CacheKey(toolName, email, suffix string) string {
	return common.CacheKey(toolName, email, suffix)
}

// NewToolCache constructs an unbounded TTL cache.
func NewToolCache(ttl time.Duration) *ToolCache { return common.NewToolCache(ttl) }

// NewBoundedToolCache constructs a bounded TTL/LRU cache.
func NewBoundedToolCache(ttl time.Duration, maxEntries int) *ToolCache {
	return common.NewBoundedToolCache(ttl, maxEntries)
}

// WithSessionType decorates ctx with a session-type label.
func WithSessionType(ctx context.Context, sessionType string) context.Context {
	return common.WithSessionType(ctx, sessionType)
}

// SessionTypeFromContext reads the session-type label off ctx.
func SessionTypeFromContext(ctx context.Context) string {
	return common.SessionTypeFromContext(ctx)
}

// ComputeToolManifest hashes each tool's description for tamper detection.
func ComputeToolManifest(tools []Tool) ToolManifest {
	return common.ComputeToolManifest(tools)
}

// GetToolManifest returns the last-stored manifest snapshot.
func GetToolManifest() ToolManifest {
	return common.GetToolManifest()
}

// SanitizeData returns a tree-walked copy with all string values
// passed through SanitizeForLLM.
func SanitizeData(data any) any { return common.SanitizeData(data) }

// SanitizeForLLM neutralises injection-prone characters in a string.
func SanitizeForLLM(s string) string { return common.SanitizeForLLM(s) }

// requestConfirmation is the backward-compat lowercase wrapper that
// preserves the pre-PR-1.1 call sites in mcp/admin_risk_tools.go,
// mcp/admin_user_tools.go, mcp/exit_tools.go, mcp/gtt_tools.go,
// mcp/mf_tools.go, mcp/native_alert_tools.go, mcp/post_tools.go.
// New code should call common.RequestConfirmation directly.
func requestConfirmation(ctx context.Context, mcpServerRef any, message string) error {
	return common.RequestConfirmation(ctx, mcpServerRef, message)
}

// buildOrderConfirmMessage is the backward-compat lowercase wrapper.
func buildOrderConfirmMessage(toolName string, args map[string]any) string {
	return common.BuildOrderConfirmMessage(toolName, args)
}

// isConfirmableTool is the backward-compat lowercase wrapper.
func isConfirmableTool(toolName string) bool {
	return common.IsConfirmableTool(toolName)
}

// WriteToolsSnapshot returns a copy of the current write-tools map,
// lazy-initialising via GetAllTools() on first call. Test fixtures in
// package mcp use this entry point in preference to
// common.WriteToolsSnapshot() because the former drives the lazy
// initialisation; calling common's variant directly would see an
// empty map until SetWriteTools has been invoked.
func WriteToolsSnapshot() map[string]bool {
	ensureWriteToolsInit()
	return common.WriteToolsSnapshot()
}

// isWriteTool is the backward-compat lowercase wrapper for the
// pre-PR-1.1 test fixtures + the plugins/rolegate consumer. The
// canonical implementation now lives in common; this wrapper
// transparently lazy-initialises the write-tools set via
// ensureWriteToolsInit so test fixtures that exercise isWriteTool
// without going through RegisterToolsForRegistry continue to work.
//
// Note for plugins/rolegate/plugin.go: that file declares its OWN
// isWriteTool by hardcoding the trading-tool name set, separate
// from the common-package version. No change needed there.
func isWriteTool(name string) bool {
	ensureWriteToolsInit()
	return common.IsWriteTool(name)
}

// ensureWriteToolsInit lazy-pushes the write-tools set into common
// on first access. Anchor 1 PR 1.1 Phase 3: bridges the cycle-broken
// design (common no longer calls GetAllTools() directly) to the
// pre-PR test ergonomic where `isWriteTool(name)` and
// `common.WriteToolsSnapshot()` were assumed to "just work" without
// an explicit setup call. RegisterToolsForRegistry also calls
// SetWriteTools at production startup; the once-guard inside
// SetWriteTools makes both paths idempotent.
//
// init() can't perform this snapshot because Go init order runs
// aliases.go (alphabetically early) BEFORE the *_tools.go init()s
// that call RegisterInternalTool. By deferring to first-call we
// guarantee internalToolRegistry is fully populated.
var writeToolsLazyOnce sync.Once

func ensureWriteToolsInit() {
	writeToolsLazyOnce.Do(func() {
		common.SetWriteTools(GetAllTools())
	})
}
