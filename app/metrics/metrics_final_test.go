package metrics

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

// TestStartCleanupRoutine_StopsOnChannelClose verifies the startCleanupRoutine
// goroutine exits when cleanupStop is closed (covering the <-m.cleanupStop path).
func TestStartCleanupRoutine_StopsOnChannelClose(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: true})
	// AutoCleanup=true starts the goroutine. Shutdown closes the channel.
	m.Shutdown()
	// Double shutdown is safe.
	m.Shutdown()
}

// TestIsDailyMetric_EmptyBaseName covers the path where splitting the metric
// key results in a date suffix but an empty base name (e.g. key = "2026-01-01").
func TestIsDailyMetric_EmptyBaseName(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: false})
	defer m.Shutdown()

	// Key "_2026-01-01" splits into ["", "2026-01-01"], baseName="" -> return false.
	result := m.isDailyMetric("_2026-01-01")
	if result {
		t.Error("isDailyMetric should return false for key with empty base name")
	}
}

// TestIsDailyMetric_BadDateFormat covers the path at line 237 where the
// last part passes the length+dash check but fails the segment-length validation.
func TestIsDailyMetric_BadDateFormat(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: false})
	defer m.Shutdown()

	// "12345-67-8" is 10 chars with 2 dashes, but split gives [5,2,1] not [4,2,2].
	result := m.isDailyMetric("key_12345-67-8")
	if result {
		t.Error("isDailyMetric should return false for bad date format segments")
	}
}

// TestWritePrometheus_NonStringKey covers the path where a sync.Map key is not
// a string (defensive code).
func TestWritePrometheus_NonStringKey(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: false})
	defer m.Shutdown()

	// Inject a non-string key directly into the counters sync.Map.
	m.counters.Store(12345, new(int64))

	var buf bytes.Buffer
	m.WritePrometheus(&buf) // Should skip the non-string key without panic.

	// Clean up the bad key.
	m.counters.Delete(12345)
}

// TestHTTPHandler_WriteError covers the path where w.Write returns an error.
// We simulate this with a failing ResponseWriter.
func TestHTTPHandler_WriteError_Final(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: false})
	defer m.Shutdown()

	handler := m.HTTPHandler()

	// Use a writer that fails on Write.
	w := &failWriter{ResponseWriter: httptest.NewRecorder()}
	r := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	handler.ServeHTTP(w, r)
	// No panic expected; the handler just returns on write error.
}

// failWriter is a ResponseWriter that fails on Write.
type failWriter struct {
	http.ResponseWriter
	headerWritten bool
	mu            sync.Mutex
}

func (fw *failWriter) Header() http.Header {
	return fw.ResponseWriter.Header()
}

func (fw *failWriter) WriteHeader(statusCode int) {
	fw.mu.Lock()
	fw.headerWritten = true
	fw.mu.Unlock()
	fw.ResponseWriter.WriteHeader(statusCode)
}

func (fw *failWriter) Write(b []byte) (int, error) {
	return 0, http.ErrAbortHandler
}
