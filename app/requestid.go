package app

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/google/uuid"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Request-ID propagation
//
// Standardize on the X-Request-ID header for cross-system correlation. The
// middleware accepts a client-supplied ID when it is well-formed, otherwise
// it generates a fresh UUIDv7 (time-ordered, sortable by insertion time).
// The chosen ID is:
//
//   - stored in the request context under requestIDCtxKey so downstream
//     handlers, audit middleware and slog loggers can read it via
//     RequestIDFromCtx;
//   - echoed back in the response X-Request-ID header so clients can link
//     logs on their side without parsing bodies.
//
// Design notes:
//
//   - Validation is permissive (alphanumerics + -._~) but strict enough to
//     block CRLF-based response splitting and other header smuggling
//     attacks. IDs longer than 512 characters are rejected — a sanity cap
//     well above the 36 bytes a UUID needs and the typical 64 bytes used
//     by W3C traceparent.
//   - UUIDv7 is preferred over v4 because entries in logs and the audit
//     table sort naturally by time when indexed on the CallID / request
//     ID columns, which matters for forensics.
//   - Fallback to uuid.NewString() preserves liveness if the system
//     entropy source is briefly unavailable during UUIDv7 generation.

// requestIDHeader is the canonical HTTP header used for the correlation ID.
const requestIDHeader = "X-Request-ID"

// requestIDMaxLen is a conservative upper bound on accepted request IDs.
// Well above the 36 bytes a UUID needs and the typical 64 bytes a W3C
// traceparent header occupies — defends against memory-pressure payloads
// without cutting off realistic client identifiers.
const requestIDMaxLen = 512

// ctxKey is a package-local type used as a context key — prevents
// collisions with string-typed keys defined in other packages.
type ctxKey string

const requestIDCtxKey ctxKey = "request_id"

// withRequestID returns middleware that:
//  1. Uses the client-provided X-Request-ID header when it passes
//     isValidRequestID;
//  2. Otherwise generates a fresh UUIDv7;
//  3. Stores the chosen ID in the request context and echoes it back in
//     the response header so the client can correlate logs.
func withRequestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get(requestIDHeader)
		if !isValidRequestID(id) {
			id = newRequestID()
		}
		// Echo back so the client can link their logs to ours.
		w.Header().Set(requestIDHeader, id)
		ctx := context.WithValue(r.Context(), requestIDCtxKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// RequestIDFromCtx extracts the request ID set by withRequestID.
// Returns the empty string when no ID is present.
func RequestIDFromCtx(ctx context.Context) string {
	if id, ok := ctx.Value(requestIDCtxKey).(string); ok {
		return id
	}
	return ""
}

// LoggerWithRequestID enriches an slog.Logger with the request ID from
// the context (if any). Callers who pre-build a request-scoped logger
// should prefer this over re-extracting the ID at each log site.
func LoggerWithRequestID(logger *slog.Logger, ctx context.Context) *slog.Logger {
	if logger == nil {
		return nil
	}
	if id := RequestIDFromCtx(ctx); id != "" {
		return logger.With("request_id", id)
	}
	return logger
}

// LoggerPortWithRequestID is the kc/logger.Logger port-typed sibling
// of LoggerWithRequestID. New call sites that already depend on the
// port should reach for this one rather than wrap-then-unwrap through
// AsSlog. Behavior is identical — when no request ID is in the
// context, the original logger is returned unchanged.
func LoggerPortWithRequestID(l logport.Logger, ctx context.Context) logport.Logger {
	if l == nil {
		return nil
	}
	if id := RequestIDFromCtx(ctx); id != "" {
		return l.With("request_id", id)
	}
	return l
}

// isValidRequestID gates the client-supplied X-Request-ID header.
//
// Accepted: non-empty, no longer than requestIDMaxLen, and each byte is
// either alphanumeric or one of the unreserved URI characters [-._~].
// Rejected: empty, overlong, whitespace, control characters (CR/LF/NUL),
// or anything that could enable response splitting / log injection.
func isValidRequestID(s string) bool {
	if s == "" || len(s) > requestIDMaxLen {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '~':
		default:
			return false
		}
	}
	return true
}

// newRequestID returns a fresh UUIDv7, falling back to a v4 random UUID
// if the v7 generator fails (very rare — only when the system random
// source is unavailable).
func newRequestID() string {
	if id, err := uuid.NewV7(); err == nil {
		return id.String()
	}
	return uuid.NewString()
}
