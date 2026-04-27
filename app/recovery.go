package app

import (
	"log/slog"
	"net/http"
	"runtime/debug"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Panic recovery
//
// recoverPanic is installed as the OUTERMOST HTTP middleware so it catches
// panics from any inner middleware or handler, including withRequestID and
// securityHeaders. Without this layer, a panic in a handler crashes the
// net/http per-connection goroutine, which logs a stack trace to stderr
// but leaves the client with no response (just a closed connection) — no
// structured audit entry, no correlation ID in the response, no chance
// for the reverse proxy to return a clean 500.
//
// Design:
//
//   - Outermost means recoverPanic runs BEFORE withRequestID. If a panic
//     happens after withRequestID successfully sets the context, we can
//     read the request ID back via RequestIDFromCtx and echo it in the
//     response X-Request-ID header so the client can correlate with logs.
//     If the panic happens before RequestID runs (very rare — only in
//     recoverPanic's own deferred teardown), we log "" for request_id.
//   - The log entry includes the full stack trace via runtime/debug.Stack()
//     at Error level so ops alerting (log-based alerts on level=Error) fires.
//   - The response body is a small JSON envelope including the correlation
//     ID so an end user pasting the response into a bug report gives ops
//     enough to find the exact log line.
//   - http.ErrAbortHandler is a Go sentinel meaning "end the connection
//     without a response" — servers use it to force RST on clients. It
//     must be re-raised, not swallowed; otherwise well-behaved server
//     code (e.g. a WebSocket upgrade that detects a bad handshake and
//     calls panic(http.ErrAbortHandler)) would silently turn into an
//     HTTP 500 and break clients that rely on the RST semantics.
// Deprecated: use recoverPanicWithPort. This shim wraps the supplied
// *slog.Logger via logport.NewSlog and exists for the Wave D Phase 3
// Logger sweep migration window (Package 7) only. Will be removed in
// Package 8 cleanup. Existing callers (app/http.go) compile unchanged.
func recoverPanic(logger *slog.Logger, next http.Handler) http.Handler {
	return recoverPanicWithPort(logport.NewSlog(logger), next)
}

// recoverPanicWithPort is the canonical Wave D Phase 3 implementation.
// Takes a logport.Logger directly; the request ctx (r.Context()) is
// already available as the natural ctx for the recovered-panic log
// call — no service-ctx fallback needed at this seam.
func recoverPanicWithPort(logger logport.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			rec := recover()
			if rec == nil {
				return
			}
			// Re-raise the abort sentinel — net/http uses it to force
			// RST on the connection and any swallow here would
			// silently degrade that signal into a 500.
			if rec == http.ErrAbortHandler {
				panic(rec)
			}

			// Prefer the response header for the correlation ID: the inner
			// withRequestID middleware writes it to w.Header() BEFORE
			// handing the request downstream, so it is observable here
			// even though the context-mutated request never propagated
			// back up to this outer frame. Fall back to the request
			// context in case a future middleware writes the ID to the
			// context without also setting the header.
			requestID := w.Header().Get(requestIDHeader)
			if requestID == "" {
				requestID = RequestIDFromCtx(r.Context())
			}
			if logger != nil {
				// Recovered panic value isn't a typed error (it's any),
				// so the err parameter is nil and the panic value lands
				// in the args field. Request ctx travels through the
				// logger.Error first parameter for trace correlation.
				logger.Error(r.Context(), "panic recovered in HTTP handler", nil,
					"request_id", requestID,
					"panic", rec,
					"method", r.Method,
					"path", r.URL.Path,
					"remote_addr", r.RemoteAddr,
					"stack", string(debug.Stack()),
				)
			}

			// If a downstream handler already wrote a status + body, we
			// cannot rewrite the response — headers are already on the
			// wire. Best-effort write: if WriteHeader was never called,
			// Go sets StatusOK the first time Write is invoked, so our
			// explicit 500 wins. If it was called, the 500 here is a
			// no-op and the client sees whatever the handler partially
			// wrote — the audit-log entry still captures the incident.
			w.Header().Set("Content-Type", "application/json")
			if requestID != "" {
				w.Header().Set(requestIDHeader, requestID)
			}
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"error":"internal_server_error","request_id":"` + jsonEscape(requestID) + `"}`))
		}()
		next.ServeHTTP(w, r)
	})
}

// jsonEscape handles the narrow case of sanitizing a request ID for
// embedding in the error-response JSON. The ID itself is already
// validated by isValidRequestID to contain only [A-Za-z0-9-._~], so
// nothing in it requires escaping — but we strip to empty on any
// unexpected byte as a belt-and-suspenders measure against a future
// code-path that bypasses validation.
func jsonEscape(s string) string {
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z':
		case c >= 'A' && c <= 'Z':
		case c >= '0' && c <= '9':
		case c == '-' || c == '_' || c == '.' || c == '~':
		default:
			return ""
		}
	}
	return s
}
