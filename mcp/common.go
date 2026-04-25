package mcp

import (
	"context"
	"fmt"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/users"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// Context key for session type
type contextKey string

const (
	sessionTypeKey contextKey = "session_type"
)

// Session type constants
const (
	SessionTypeSSE     = "sse"
	SessionTypeMCP     = "mcp"
	SessionTypeStdio   = "stdio"
	SessionTypeUnknown = "unknown"
)

// WithSessionType adds session type to context
func WithSessionType(ctx context.Context, sessionType string) context.Context {
	return context.WithValue(ctx, sessionTypeKey, sessionType)
}

// SessionTypeFromContext extracts session type from context
func SessionTypeFromContext(ctx context.Context) string {
	if sessionType, ok := ctx.Value(sessionTypeKey).(string); ok {
		return sessionType
	}
	return SessionTypeUnknown // default fallback for undetermined sessions
}

// writeTools is derived from tool annotations at init time.
// A tool is a "write tool" if ReadOnlyHint is not explicitly true.
// Users with the "viewer" role are blocked from calling these tools.
var writeTools map[string]bool

func init() {
	writeTools = make(map[string]bool)
	for _, t := range GetAllTools() {
		tool := t.Tool()
		if tool.Annotations.ReadOnlyHint == nil || !*tool.Annotations.ReadOnlyHint {
			writeTools[tool.Name] = true
		}
	}
}

// WithViewerBlock enforces the viewer role: blocks write tools for read-only users.
// Returns a non-nil result if the user is blocked, nil otherwise.
func (h *ToolHandler) WithViewerBlock(ctx context.Context, toolName string) *mcp.CallToolResult {
	email := oauth.EmailFromContext(ctx)
	if email == "" || !writeTools[toolName] {
		return nil
	}
	if uStore := h.deps.UserStore; uStore != nil {
		if uStore.GetRole(email) == users.RoleViewer {
			return mcp.NewToolResultError("Read-only access: your account has viewer role. Contact admin for trader access.")
		}
	}
	return nil
}

// WithTokenRefresh checks if a Kite token has likely expired (~6 AM IST daily)
// and verifies it with the Kite API. Returns a non-nil result if expired, nil otherwise.
//
// Not a CQRS violation: this is a pre-dispatch session-validation step that
// runs inside WithSession's composition, before the handler closure is
// invoked. The broker probe here is the session's OWN validity check — the
// "is this Kite token still valid?" question is a property of the session,
// not a read query over broker data. Queries routed through QueryBus are
// business-value reads (GetProfile for the *profile tool*, get_orders for
// the orders tool, etc.). A session-validity probe is infrastructure,
// scoped to the session boundary, and returns a nil-or-error rather than a
// value. Architecturally analogous to circuit breaker or auth middleware —
// those sit outside CQRS too.
//
// If a future refactor moves session validation out of WithSession into a
// dedicated SessionValidator middleware, the profile probe moves with it
// (still not CQRS-bound). This function's form is deliberate, not legacy.
func (h *ToolHandler) WithTokenRefresh(ctx context.Context, toolName string, session *kc.KiteSessionData, sessionID, email string) *mcp.CallToolResult {
	if email == "" {
		return nil
	}
	entry, ok := h.deps.TokenStore.Get(email)
	isExpired := kc.IsKiteTokenExpired
	if h.IsTokenExpiredFn != nil {
		isExpired = h.IsTokenExpiredFn
	}
	if !ok || !isExpired(entry.StoredAt) {
		return nil
	}
	profileUC := usecases.NewGetProfileUseCase(
		&sessionBrokerResolver{client: session.Broker},
		h.deps.Logger,
	)
	if _, err := profileUC.Execute(ctx, cqrs.GetProfileQuery{Email: email}); err != nil {
		h.deps.Logger.Warn("Kite token expired on existing session", "tool", toolName, "session_id", sessionID, "error", err)
		h.deps.TokenStore.Delete(email)
		h.trackToolError(ctx, toolName, "token_expired")
		return mcp.NewToolResultError(fmt.Sprintf("Your Kite session has expired: %s. Please use the login tool to re-authenticate.", err.Error()))
	}
	return nil
}

// WithSession validates session and executes the provided function with a valid Kite session.
// Composes WithViewerBlock (RBAC) and WithTokenRefresh (expiry detection) as middleware steps.
// Extracts email from OAuth context (if available) to enable per-user token caching.
func (h *ToolHandler) WithSession(ctx context.Context, toolName string, fn func(*kc.KiteSessionData) (*mcp.CallToolResult, error)) (*mcp.CallToolResult, error) {
	// Step 1: RBAC — block viewer role from write tools.
	if block := h.WithViewerBlock(ctx, toolName); block != nil {
		return block, nil
	}

	sess := server.ClientSessionFromContext(ctx)
	sessionID := sess.SessionID()
	email := oauth.EmailFromContext(ctx)

	h.deps.Logger.Debug("Tool request with session", "tool", toolName, "session_id", sessionID, "email", email)

	// Step 2: Session lookup/creation.
	kiteSession, isNew, err := h.deps.Sessions.GetOrCreateSessionWithEmail(sessionID, email)
	if err != nil {
		h.deps.Logger.Error("Failed to establish session", "tool", toolName, "session_id", sessionID, "error", err)
		h.trackToolError(ctx, toolName, "session_error")
		return mcp.NewToolResultError(fmt.Sprintf("Failed to establish a session: %s", err.Error())), nil
	}

	// DEV_MODE: mock broker session — skip all token/auth checks.
	// The stub Kite client (non-nil, dead base URI) lets handler bodies execute
	// and return API errors instead of panicking on nil dereference.
	if h.deps.Config.DevMode() {
		h.deps.Logger.Debug("DEV_MODE session (mock broker), skipping auth checks", "tool", toolName, "session_id", sessionID)
		return fn(kiteSession)
	}

	if isNew {
		// Check if a cached token was applied (per-email cache hit)
		if email != "" && h.deps.Credentials.HasCachedToken(email) {
			// Verify the cached token is still valid
			_, err := kiteSession.Kite.Client.GetUserProfile()
			if err != nil {
				h.deps.Logger.Warn("Cached Kite token expired", "email", email, "error", err)
				h.deps.TokenStore.Delete(email)
				h.trackToolError(ctx, toolName, "auth_required")
				return mcp.NewToolResultError(fmt.Sprintf("Your Kite session has expired: %s. Please use the login tool to re-authenticate.", err.Error())), nil
			}
			h.deps.Logger.Info("Auto-authenticated via cached token", "tool", toolName, "email", email)
			h.deps.Metrics.TrackDailyUser(email)
		} else if !h.deps.Credentials.HasPreAuth() {
			h.deps.Logger.Info("New session created, login required", "tool", toolName, "session_id", sessionID)
			h.trackToolError(ctx, toolName, "auth_required")
			return mcp.NewToolResultError("Please log in first using the login tool"), nil
		} else {
			h.deps.Logger.Info("New session with pre-auth token", "tool", toolName, "session_id", sessionID)
		}
	}

	// Step 3: Token refresh — check if existing session's token expired.
	if !isNew {
		if block := h.WithTokenRefresh(ctx, toolName, kiteSession, sessionID, email); block != nil {
			return block, nil
		}
	}

	h.deps.Logger.Debug("Session validated successfully", "tool", toolName, "session_id", sessionID)
	return fn(kiteSession)
}

// callWithNilKiteGuard runs the tool handler fn with a deferred recover.
// In DEV_MODE session.Kite is nil, so any tool that dereferences session.Kite.Client
// will panic.  The recover catches this and returns a descriptive error instead.
func (h *ToolHandler) callWithNilKiteGuard(toolName string, session *kc.KiteSessionData, fn func(*kc.KiteSessionData) (*mcp.CallToolResult, error)) (result *mcp.CallToolResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			h.deps.Logger.Warn("DEV_MODE: tool panicked (likely accessed session.Kite.Client)", "tool", toolName, "panic", r)
			result = mcp.NewToolResultError(fmt.Sprintf("This tool (%s) requires a real Kite connection and is not available in DEV_MODE. Disable DEV_MODE to use it.", toolName))
			err = nil
		}
	}()
	return fn(session)
}

// ValidationError represents a parameter validation error
type ValidationError struct {
	Parameter string
	Message   string
}

func (e ValidationError) Error() string {
	return fmt.Sprintf("parameter '%s': %s", e.Parameter, e.Message)
}

// ValidateRequired checks if required parameters are present and non-empty
func ValidateRequired(args map[string]any, required ...string) error {
	for _, param := range required {
		value := args[param]
		if value == nil {
			return ValidationError{Parameter: param, Message: "is required"}
		}

		// Check for empty strings
		if str, ok := value.(string); ok && str == "" {
			return ValidationError{Parameter: param, Message: "cannot be empty"}
		}

		// Check for empty arrays/slices using reflection
		if arr, ok := value.([]any); ok && len(arr) == 0 {
			return ValidationError{Parameter: param, Message: "cannot be empty"}
		}

		// Check for other slice types
		switch v := value.(type) {
		case []string:
			if len(v) == 0 {
				return ValidationError{Parameter: param, Message: "cannot be empty"}
			}
		case []int:
			if len(v) == 0 {
				return ValidationError{Parameter: param, Message: "cannot be empty"}
			}
		}
	}
	return nil
}

// ArgParser provides declarative argument extraction from MCP tool requests.
// Eliminates repetitive SafeAssertString/Int/Float chains.
type ArgParser struct {
	args map[string]any
}

// NewArgParser wraps tool request arguments for fluent extraction.
func NewArgParser(args map[string]any) *ArgParser {
	return &ArgParser{args: args}
}

// String extracts a string argument with default.
func (p *ArgParser) String(key, defaultVal string) string {
	return SafeAssertString(p.args[key], defaultVal)
}

// Int extracts an integer argument with default.
func (p *ArgParser) Int(key string, defaultVal int) int {
	return SafeAssertInt(p.args[key], defaultVal)
}

// Float extracts a float64 argument with default.
func (p *ArgParser) Float(key string, defaultVal float64) float64 {
	return SafeAssertFloat64(p.args[key], defaultVal)
}

// Bool extracts a boolean argument with default.
func (p *ArgParser) Bool(key string, defaultVal bool) bool {
	return SafeAssertBool(p.args[key], defaultVal)
}

// StringArray extracts a string array argument.
func (p *ArgParser) StringArray(key string) []string {
	return SafeAssertStringArray(p.args[key])
}

// Required checks that required keys exist and are non-empty.
func (p *ArgParser) Required(keys ...string) error {
	return ValidateRequired(p.args, keys...)
}

// Raw returns the underlying args map.
func (p *ArgParser) Raw() map[string]any {
	return p.args
}

// SafeAssertString safely converts any to string with fallback
func SafeAssertString(v any, fallback string) string {
	if v == nil {
		return fallback
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// SafeAssertInt safely converts any to int with fallback
func SafeAssertInt(v any, fallback int) int {
	if v == nil {
		return fallback
	}
	if i, ok := v.(int); ok {
		return i
	}
	if f, ok := v.(float64); ok {
		return int(f)
	}
	return fallback
}

// SafeAssertFloat64 safely converts any to float64 with fallback
func SafeAssertFloat64(v any, fallback float64) float64 {
	if v == nil {
		return fallback
	}
	if f, ok := v.(float64); ok {
		return f
	}
	if i, ok := v.(int); ok {
		return float64(i)
	}
	return fallback
}

// SafeAssertBool safely converts any to bool with fallback
func SafeAssertBool(v any, fallback bool) bool {
	if v == nil {
		return fallback
	}
	if b, ok := v.(bool); ok {
		return b
	}
	if s, ok := v.(string); ok {
		switch s {
		case "true", "True", "TRUE", "1", "yes", "Yes", "YES", "on", "On", "ON":
			return true
		case "false", "False", "FALSE", "0", "no", "No", "NO", "off", "Off", "OFF":
			return false
		}
	}
	return fallback
}

// SafeAssertStringArray safely converts any to []string with fallback.
// Handles both []any (normal) and single string (wraps into slice).
func SafeAssertStringArray(v any) []string {
	if v == nil {
		return nil
	}

	// Handle single string — wrap into slice
	if s, ok := v.(string); ok && s != "" {
		return []string{s}
	}

	arr, ok := v.([]any)
	if !ok {
		return nil
	}

	result := make([]string, 0, len(arr))
	for _, item := range arr {
		str := SafeAssertString(item, "")
		if str != "" {
			result = append(result, str)
		}
	}
	return result
}

// Common error messages for tool handlers.
const (
	ErrAuthRequired        = "Authentication required. Please log in first."
	ErrAdminRequired       = "Admin access required. This tool is restricted to server administrators."
	ErrUserStoreNA         = "User store not available."
	ErrTargetEmailRequired = "target_email is required."
	ErrSelfAction          = "Cannot perform this action on yourself."
	ErrLastAdmin           = "Cannot demote/suspend the last active admin."
	ErrRiskGuardNA         = "RiskGuard not available on this server."
	ErrConfirmRequired     = "confirm must be true to execute this action."
	ErrInvitationStoreNA   = "Invitation store not available."
)

// MaxPaginationLimit caps the maximum number of items returned per page.
const MaxPaginationLimit = 500

// PaginationParams holds pagination parameters
type PaginationParams struct {
	From  int
	Limit int
}

// ParsePaginationParams extracts pagination parameters from arguments
func ParsePaginationParams(args map[string]any) PaginationParams {
	p := NewArgParser(args)
	limit := p.Int("limit", 0)
	if limit > MaxPaginationLimit {
		limit = MaxPaginationLimit
	}
	return PaginationParams{
		From:  p.Int("from", 0),
		Limit: limit,
	}
}

// ApplyPagination applies pagination to any slice using reflection-like approach
func ApplyPagination[T any](data []T, params PaginationParams) []T {
	// If empty data, return empty slice
	if len(data) == 0 {
		return data
	}

	// Ensure from is within bounds
	from := min(max(params.From, 0), len(data))

	// If no limit specified, return from offset to end
	if params.Limit <= 0 {
		return data[from:]
	}

	// Calculate end index (from + limit) but don't exceed data length
	end := min(from+params.Limit, len(data))

	// Return paginated slice
	return data[from:end]
}

// PaginatedResponse wraps a response with pagination metadata
type PaginatedResponse struct {
	Data       any `json:"data"`
	Pagination struct {
		From     int  `json:"from"`
		Limit    int  `json:"limit"`
		Total    int  `json:"total"`
		HasMore  bool `json:"has_more"`
		Returned int  `json:"returned"`
	} `json:"pagination"`
}

// CreatePaginatedResponse creates a paginated response with metadata
func CreatePaginatedResponse(originalData any, paginatedData any, params PaginationParams, originalLength int) *PaginatedResponse {
	response := &PaginatedResponse{
		Data: paginatedData,
	}

	response.Pagination.From = params.From
	response.Pagination.Limit = params.Limit
	response.Pagination.Total = originalLength

	// Calculate returned count based on actual paginated data
	returnedCount := 0
	if paginatedData != nil {
		switch data := paginatedData.(type) {
		case []any:
			returnedCount = len(data)
		default:
			// For other types, calculate based on parameters with bounds checking
			from := max(0, min(params.From, originalLength))
			if params.Limit > 0 {
				returnedCount = min(params.Limit, max(0, originalLength-from))
			} else {
				returnedCount = max(0, originalLength-from)
			}
		}
	} else {
		// Handle nil paginated data by calculating from parameters
		from := max(0, min(params.From, originalLength))
		if params.Limit > 0 {
			returnedCount = min(params.Limit, max(0, originalLength-from))
		} else {
			returnedCount = max(0, originalLength-from)
		}
	}

	response.Pagination.Returned = returnedCount
	response.Pagination.HasMore = params.From+returnedCount < originalLength

	return response
}

// SimpleToolHandler creates a handler function for simple GET endpoints.
// The apiCall closure receives the request context so dispatches inherit
// cancellation and X-Request-ID values rather than rooting via context.Background().
func SimpleToolHandler(manager *kc.Manager, toolName string, apiCall func(context.Context, *kc.KiteSessionData) (any, error)) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Track the tool call at the handler level
		handler.trackToolCall(ctx, toolName)
		result, err := handler.HandleAPICall(ctx, toolName, apiCall)
		if err != nil {
			handler.trackToolError(ctx, toolName, "execution_error")
		} else if result != nil && result.IsError {
			handler.trackToolError(ctx, toolName, "api_error")
		}
		return result, err
	}
}

// PaginatedToolHandler creates a handler function for endpoints that support pagination.
// The apiCall closure receives the request context for ctx-aware bus dispatch.
func PaginatedToolHandler[T any](manager *kc.Manager, toolName string, apiCall func(context.Context, *kc.KiteSessionData) ([]T, error)) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		// Track the tool call at the handler level
		handler.trackToolCall(ctx, toolName)
		result, err := handler.WithSession(ctx, toolName, func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			// Get the data
			data, err := apiCall(ctx, session)
			if err != nil {
				handler.deps.Logger.Error("API call failed", "tool", toolName, "error", err)
				handler.trackToolError(ctx, toolName, "api_error")
				return mcp.NewToolResultError(fmt.Sprintf("%s: %s", toolName, err.Error())), nil
			}

			// Parse pagination parameters
			args := request.GetArguments()
			params := ParsePaginationParams(args)

			// Apply pagination if limit is specified
			originalLength := len(data)
			paginatedData := ApplyPagination(data, params)

			// Create response with pagination metadata if pagination was applied
			var responseData any
			if params.Limit > 0 {
				responseData = CreatePaginatedResponse(data, paginatedData, params, originalLength)
			} else {
				responseData = paginatedData
			}

			return handler.MarshalResponse(responseData, toolName)
		})

		if err != nil {
			handler.trackToolError(ctx, toolName, "execution_error")
		} else if result != nil && result.IsError {
			handler.trackToolError(ctx, toolName, "api_error")
		}
		return result, err
	}
}

// PaginatedToolHandlerWithArgs is like PaginatedToolHandler but passes
// the request arguments to the API call function, allowing tool-specific
// parameters (e.g., position_type) to influence which data is returned.
// The apiCall closure receives the request context for ctx-aware bus dispatch.
func PaginatedToolHandlerWithArgs[T any](manager *kc.Manager, toolName string, apiCall func(context.Context, *kc.KiteSessionData, map[string]any) ([]T, error)) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, toolName)
		result, err := handler.WithSession(ctx, toolName, func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
			args := request.GetArguments()
			data, err := apiCall(ctx, session, args)
			if err != nil {
				handler.deps.Logger.Error("API call failed", "tool", toolName, "error", err)
				handler.trackToolError(ctx, toolName, "api_error")
				return mcp.NewToolResultError(fmt.Sprintf("%s: %s", toolName, err.Error())), nil
			}

			params := ParsePaginationParams(args)
			originalLength := len(data)
			paginatedData := ApplyPagination(data, params)

			var responseData any
			if params.Limit > 0 {
				responseData = CreatePaginatedResponse(data, paginatedData, params, originalLength)
			} else {
				responseData = paginatedData
			}

			return handler.MarshalResponse(responseData, toolName)
		})

		if err != nil {
			handler.trackToolError(ctx, toolName, "execution_error")
		} else if result != nil && result.IsError {
			handler.trackToolError(ctx, toolName, "api_error")
		}
		return result, err
	}
}
