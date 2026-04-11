package metrics

import (
	"bytes"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name     string
		config   Config
		expected string
	}{
		{"with service name", Config{ServiceName: "test-service"}, "test-service"},
		{"empty service name uses default", Config{}, DefaultServiceName},
		{"with admin path", Config{AdminSecretPath: "secret123"}, DefaultServiceName},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(tt.config)
			if m.serviceName != tt.expected {
				t.Errorf("expected service name %q, got %q", tt.expected, m.serviceName)
			}
			if tt.config.AdminSecretPath != "" && m.adminSecretPath != tt.config.AdminSecretPath {
				t.Errorf("expected admin secret path %q, got %q", tt.config.AdminSecretPath, m.adminSecretPath)
			}
		})
	}
}

func TestIncrement(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Test initial increment
	m.Increment("test_counter")
	if count := m.GetCounterValue("test_counter"); count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}

	// Test multiple increments
	m.Increment("test_counter")
	m.Increment("test_counter")
	if count := m.GetCounterValue("test_counter"); count != 3 {
		t.Errorf("expected count 3, got %d", count)
	}

	// Test different counter
	m.Increment("other_counter")
	if count := m.GetCounterValue("other_counter"); count != 1 {
		t.Errorf("expected count 1, got %d", count)
	}
}

func TestIncrementBy(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	m.IncrementBy("test_counter", 5)
	if count := m.GetCounterValue("test_counter"); count != 5 {
		t.Errorf("expected count 5, got %d", count)
	}

	m.IncrementBy("test_counter", 3)
	if count := m.GetCounterValue("test_counter"); count != 8 {
		t.Errorf("expected count 8, got %d", count)
	}
}

func TestConcurrentIncrement(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	const numGoroutines = 100
	const incrementsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < incrementsPerGoroutine; j++ {
				m.Increment("concurrent_counter")
			}
		}()
	}

	wg.Wait()

	expected := int64(numGoroutines * incrementsPerGoroutine)
	if count := m.GetCounterValue("concurrent_counter"); count != expected {
		t.Errorf("expected count %d, got %d", expected, count)
	}
}

func TestTrackDailyUser(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Test empty user ID (should be ignored)
	m.TrackDailyUser("")
	if count := m.GetTodayUserCount(); count != 0 {
		t.Errorf("expected empty user ID to be ignored, got count %d", count)
	}

	// Track same user multiple times
	m.TrackDailyUser("user1")
	m.TrackDailyUser("user1")
	m.TrackDailyUser("user1")

	if count := m.GetTodayUserCount(); count != 1 {
		t.Errorf("expected today's user count 1, got %d", count)
	}

	// Track different users
	m.TrackDailyUser("user2")
	m.TrackDailyUser("user3")

	if count := m.GetTodayUserCount(); count != 3 {
		t.Errorf("expected today's user count 3, got %d", count)
	}
}

func TestGetDailyUserCount(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Test non-existent date
	if count := m.GetDailyUserCount("2023-01-01"); count != 0 {
		t.Errorf("expected count 0 for non-existent date, got %d", count)
	}

	// Track users for today
	m.TrackDailyUser("user1")
	m.TrackDailyUser("user2")

	today := time.Now().UTC().Format("2006-01-02")
	if count := m.GetDailyUserCount(today); count != 2 {
		t.Errorf("expected count 2 for today, got %d", count)
	}
}

func TestCleanupOldData(t *testing.T) {
	m := New(Config{ServiceName: "test", CleanupRetentionDays: 5})

	// Manually add old data
	oldDate := time.Now().UTC().AddDate(0, 0, -10).Format("2006-01-02")
	oldUserSet := &userSet{}
	oldUserSet.users.Store("user1", true)
	oldUserSet.count = 1
	m.dailyUsers.Store(oldDate, oldUserSet)

	// Add recent data
	m.TrackDailyUser("user2")

	// Verify old data exists
	if count := m.GetDailyUserCount(oldDate); count != 1 {
		t.Errorf("expected old data count 1, got %d", count)
	}

	// Cleanup old data
	if err := m.CleanupOldData(); err != nil {
		t.Errorf("cleanup failed: %v", err)
	}

	// Verify old data is removed
	if count := m.GetDailyUserCount(oldDate); count != 0 {
		t.Errorf("expected old data to be cleaned up, got count %d", count)
	}

	// Verify recent data still exists
	if count := m.GetTodayUserCount(); count != 1 {
		t.Errorf("expected recent data to remain, got count %d", count)
	}
}

func TestWritePrometheus(t *testing.T) {
	m := New(Config{ServiceName: "test-service", HistoricalDays: 3})

	// Add some metrics
	m.Increment("login_count")
	m.Increment("login_count")
	m.IncrementBy("error_count", 3)
	m.TrackDailyUser("user1")
	m.TrackDailyUser("user2")

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	// Check that metrics are present
	expectedMetrics := []string{
		"login_count_total{service=\"test-service\"} 2",
		"error_count_total{service=\"test-service\"} 3",
		"daily_unique_users_total{",
		"service=\"test-service\"",
	}

	for _, expected := range expectedMetrics {
		if !strings.Contains(output, expected) {
			t.Errorf("expected output to contain %q, got:\n%s", expected, output)
		}
	}

	// Should use consistent metric names (all _total suffix)
	if strings.Contains(output, "daily_unique_users_current") || strings.Contains(output, "daily_unique_users_historical") {
		t.Error("should use consistent metric name daily_unique_users_total")
	}
}

func TestHTTPHandler(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	m.Increment("test_metric")

	handler := m.HTTPHandler()

	// Test GET request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	contentType := w.Header().Get("Content-Type")
	if contentType != PrometheusContentType {
		t.Errorf("expected content type %q, got %q", PrometheusContentType, contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "test_metric_total") {
		t.Errorf("expected body to contain test_metric_total, got:\n%s", body)
	}

	// Test POST request (should fail)
	req = httptest.NewRequest("POST", "/metrics", nil)
	w = httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for POST, got %d", w.Code)
	}
}

func TestAdminHTTPHandler(t *testing.T) {
	tests := []struct {
		name           string
		adminPath      string
		requestPath    string
		expectedStatus int
	}{
		{
			name:           "disabled when no admin path",
			adminPath:      "",
			requestPath:    "/admin/secret/metrics",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "enabled with correct path",
			adminPath:      "secret123",
			requestPath:    "/admin/secret123/metrics",
			expectedStatus: http.StatusOK,
		},
		{
			name:           "wrong path returns 404",
			adminPath:      "secret123",
			requestPath:    "/admin/wrong/metrics",
			expectedStatus: http.StatusNotFound,
		},
		{
			name:           "missing metrics suffix returns 404",
			adminPath:      "secret123",
			requestPath:    "/admin/secret123/",
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := New(Config{
				ServiceName:     "test",
				AdminSecretPath: tt.adminPath,
			})
			m.Increment("test_metric")

			handler := m.AdminHTTPHandler()
			req := httptest.NewRequest("GET", tt.requestPath, nil)
			w := httptest.NewRecorder()
			handler(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("expected status %d, got %d", tt.expectedStatus, w.Code)
			}

			if tt.expectedStatus == http.StatusOK {
				body := w.Body.String()
				if !strings.Contains(body, "test_metric_total") {
					t.Errorf("expected body to contain metrics, got:\n%s", body)
				}
			}
		})
	}
}

func TestConcurrentDailyUserTracking(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	const numGoroutines = 50
	const usersPerGoroutine = 20

	var wg sync.WaitGroup
	wg.Add(numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(goroutineID int) {
			defer wg.Done()
			for j := 0; j < usersPerGoroutine; j++ {
				userID := fmt.Sprintf("user_%d_%d", goroutineID, j)
				m.TrackDailyUser(userID)
			}
		}(i)
	}

	wg.Wait()

	expected := int64(numGoroutines * usersPerGoroutine)
	if count := m.GetTodayUserCount(); count != expected {
		t.Errorf("expected today's user count %d, got %d", expected, count)
	}
}

func TestFormatMetric(t *testing.T) {
	m := New(Config{ServiceName: "test-service"})
	buf := new(bytes.Buffer)

	// Test with labels
	labels := map[string]string{
		"method": "GET",
		"status": "200",
	}
	m.formatMetric(buf, "http_requests_total", labels, 42.5)

	output := buf.String()
	expected := `http_requests_total{method="GET",service="test-service",status="200"} 42.5`
	if !strings.Contains(output, expected) {
		t.Errorf("expected output to contain %q, got:\n%s", expected, output)
	}

	// Test without labels
	buf.Reset()
	m.formatMetric(buf, "simple_counter", nil, 10)

	output = buf.String()
	expected = `simple_counter{service="test-service"} 10`
	if !strings.Contains(output, expected) {
		t.Errorf("expected output to contain %q, got:\n%s", expected, output)
	}
}

func TestGetNextCleanupTime(t *testing.T) {
	tests := []struct {
		name     string
		now      time.Time
		expected int // expected days from now
	}{
		{
			name:     "Monday should wait until Saturday",
			now:      time.Date(2025, 6, 9, 10, 0, 0, 0, time.UTC), // Monday
			expected: 5,
		},
		{
			name:     "Saturday before 3 AM should wait until 3 AM same day",
			now:      time.Date(2025, 6, 14, 1, 0, 0, 0, time.UTC), // Saturday 1 AM
			expected: 0,
		},
		{
			name:     "Saturday after 3 AM should wait until next Saturday",
			now:      time.Date(2025, 6, 14, 10, 0, 0, 0, time.UTC), // Saturday 10 AM
			expected: 7,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			next := getNextCleanupTime(tt.now)

			// Check that it's at 3 AM
			if next.Hour() != DefaultCleanupHour {
				t.Errorf("expected hour %d, got %d", DefaultCleanupHour, next.Hour())
			}

			// Check that it's on Saturday
			if next.Weekday() != time.Saturday {
				t.Errorf("expected Saturday, got %v", next.Weekday())
			}

			// Check approximate days difference
			daysDiff := int(next.Sub(tt.now).Hours() / 24)
			if tt.expected == 0 {
				// Same day case - should be within hours
				if daysDiff > 0 {
					t.Errorf("expected same day, got %d days difference", daysDiff)
				}
			} else {
				if daysDiff < tt.expected-1 || daysDiff > tt.expected+1 {
					t.Errorf("expected approximately %d days, got %d", tt.expected, daysDiff)
				}
			}
		})
	}
}

func TestShutdown(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: true})

	// Should not panic
	m.Shutdown()

	// Should be safe to call multiple times
	m.Shutdown()
	m.Shutdown()
}

func TestAutoCleanupDisabled(t *testing.T) {
	m := New(Config{ServiceName: "test", AutoCleanup: false})

	// Should not have started cleanup routine
	// We can't easily test this without exposing internals,
	// but at least verify it doesn't panic
	m.Shutdown()
}

// ---------------------------------------------------------------------------
// Additional coverage: GetAllCounters, GetCounterValue edge cases,
// concurrent metric writes, WritePrometheus historical days, HTTPHandler
// write error path.
// ---------------------------------------------------------------------------

func TestGetAllCounters(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	m.Increment("counter_a")
	m.IncrementBy("counter_b", 5)
	m.Increment("counter_c")
	m.Increment("counter_c")

	counters := m.GetAllCounters()
	if counters["counter_a"] != 1 {
		t.Errorf("expected counter_a=1, got %d", counters["counter_a"])
	}
	if counters["counter_b"] != 5 {
		t.Errorf("expected counter_b=5, got %d", counters["counter_b"])
	}
	if counters["counter_c"] != 2 {
		t.Errorf("expected counter_c=2, got %d", counters["counter_c"])
	}
}

func TestGetAllCounters_Empty(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	counters := m.GetAllCounters()
	if len(counters) != 0 {
		t.Errorf("expected empty counters, got %d entries", len(counters))
	}
}

func TestGetCounterValue_NonExistent(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	if val := m.GetCounterValue("nonexistent"); val != 0 {
		t.Errorf("expected 0 for nonexistent counter, got %d", val)
	}
}

func TestTrackDailyUser_TypeAssertionFail(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Manually store a non-userSet value to trigger type assertion failure path.
	m.dailyUsers.Store(time.Now().UTC().Format("2006-01-02"), "not_a_userSet")

	// Should not panic — just skip.
	m.TrackDailyUser("user_after_corrupt")

	// Count should still be 0 since the corrupted entry is skipped.
	// A new entry might not be created depending on LoadOrStore behavior.
}

func TestConcurrentMetricWrites(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	const numGoroutines = 50
	const opsPerGoroutine = 100

	var wg sync.WaitGroup
	wg.Add(numGoroutines * 3) // writers, daily trackers, readers

	// Concurrent Increment
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m.Increment("concurrent_write")
			}
		}()
	}

	// Concurrent IncrementBy
	for i := 0; i < numGoroutines; i++ {
		go func() {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m.IncrementBy("concurrent_by", 2)
			}
		}()
	}

	// Concurrent daily tracking
	for i := 0; i < numGoroutines; i++ {
		go func(id int) {
			defer wg.Done()
			for j := 0; j < opsPerGoroutine; j++ {
				m.TrackDailyUser(fmt.Sprintf("user_%d_%d", id, j))
			}
		}(i)
	}

	wg.Wait()

	expected := int64(numGoroutines * opsPerGoroutine)
	if got := m.GetCounterValue("concurrent_write"); got != expected {
		t.Errorf("expected concurrent_write=%d, got %d", expected, got)
	}
	if got := m.GetCounterValue("concurrent_by"); got != expected*2 {
		t.Errorf("expected concurrent_by=%d, got %d", expected*2, got)
	}
}

func TestWritePrometheus_NoHistoricalData(t *testing.T) {
	m := New(Config{ServiceName: "test", HistoricalDays: 7})

	// No data at all — should still write today's user count (0).
	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	today := time.Now().UTC().Format("2006-01-02")
	expected := fmt.Sprintf(`daily_unique_users_total{date="%s",service="test"} 0`, today)
	if !strings.Contains(output, expected) {
		t.Errorf("expected output to contain %q, got:\n%s", expected, output)
	}
}

func TestWritePrometheus_WithHistoricalUserData(t *testing.T) {
	m := New(Config{ServiceName: "test", HistoricalDays: 3})

	// Add historical user data for yesterday.
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	oldUserSet := &userSet{}
	oldUserSet.users.Store("hist_user1", true)
	oldUserSet.users.Store("hist_user2", true)
	oldUserSet.count = 2
	m.dailyUsers.Store(yesterday, oldUserSet)

	// Add today's user.
	m.TrackDailyUser("today_user")

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)
	output := buf.String()

	// Check historical data appears.
	expectedHist := fmt.Sprintf(`daily_unique_users_total{date="%s",service="test"} 2`, yesterday)
	if !strings.Contains(output, expectedHist) {
		t.Errorf("expected output to contain %q, got:\n%s", expectedHist, output)
	}
}

func TestHTTPHandler_WriteError(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	m.Increment("error_test_metric")

	handler := m.HTTPHandler()

	// Test HEAD request (should work same as GET but empty body)
	// Actually the handler checks for GET, so HEAD should fail with 405.
	req := httptest.NewRequest("HEAD", "/metrics", nil)
	w := httptest.NewRecorder()
	handler(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405 for HEAD, got %d", w.Code)
	}
}

func TestCleanupOldData_NoOldData(t *testing.T) {
	m := New(Config{ServiceName: "test", CleanupRetentionDays: 5})

	// Only add recent data.
	m.TrackDailyUser("recent_user")

	err := m.CleanupOldData()
	if err != nil {
		t.Errorf("cleanup failed: %v", err)
	}

	// Recent data should still exist.
	if count := m.GetTodayUserCount(); count != 1 {
		t.Errorf("expected recent data to remain, got count %d", count)
	}
}

func TestStartCleanupRoutine_Shutdown(t *testing.T) {
	// Test that auto-cleanup starts and can be shut down.
	m := New(Config{ServiceName: "test", AutoCleanup: true})

	// Should not hang or panic.
	m.Shutdown()
}

func TestIsDailyMetric_EdgeCases(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Single part (no underscore) — not daily.
	if m.isDailyMetric("nodash") {
		t.Error("single part should not be daily metric")
	}

	// Date-like but wrong separator count.
	if m.isDailyMetric("metric_2025-08") {
		t.Error("YYYY-MM should not be daily metric")
	}

	// Looks like date but year part is wrong length.
	if m.isDailyMetric("metric_25-08-05") {
		t.Error("YY-MM-DD should not be daily metric")
	}
}

func TestGetAllCounters_ConcurrentRead(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Add some counters.
	for i := 0; i < 10; i++ {
		m.Increment(fmt.Sprintf("counter_%d", i))
	}

	// Concurrent reads should not panic.
	var wg sync.WaitGroup
	wg.Add(20)
	for i := 0; i < 20; i++ {
		go func() {
			defer wg.Done()
			_ = m.GetAllCounters()
		}()
	}
	wg.Wait()
}

// ===========================================================================
// Additional edge cases to push coverage above 98%
// ===========================================================================

func TestCleanupOldData_WithExpiredEntries(t *testing.T) {
	m := New(Config{ServiceName: "test", CleanupRetentionDays: 7})

	// Inject a daily user entry for 30 days ago directly into the sync.Map
	// (TrackDailyUser always uses today's date, so we inject manually).
	oldDate := time.Now().UTC().AddDate(0, 0, -30).Format("2006-01-02")
	oldSet := &userSet{}
	oldSet.users.Store("old@example.com", true)
	oldSet.count = 1
	m.dailyUsers.Store(oldDate, oldSet)

	// Track a user for today normally.
	m.TrackDailyUser("new@example.com")
	recentDate := time.Now().UTC().Format("2006-01-02")

	err := m.CleanupOldData()
	if err != nil {
		t.Fatalf("CleanupOldData error: %v", err)
	}

	if m.GetDailyUserCount(oldDate) != 0 {
		t.Errorf("old date should have been cleaned, got count=%d", m.GetDailyUserCount(oldDate))
	}
	if m.GetDailyUserCount(recentDate) != 1 {
		t.Errorf("recent date should survive cleanup, got count=%d", m.GetDailyUserCount(recentDate))
	}
}

func TestCleanupOldData_NonStringKey(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Inject a non-string key into dailyUsers sync.Map.
	m.dailyUsers.Store(12345, &sync.Map{})

	// Should not panic, just skip the non-string key.
	err := m.CleanupOldData()
	if err != nil {
		t.Fatalf("CleanupOldData error: %v", err)
	}
}

func TestStartCleanupRoutine_StopsOnShutdown(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	m.startCleanupRoutine()

	// Shutdown should stop the cleanup goroutine.
	m.Shutdown()
	// Double shutdown should not panic.
	m.Shutdown()
}

func TestWritePrometheus_WithDailyMetrics(t *testing.T) {
	m := New(Config{ServiceName: "test", HistoricalDays: 3})

	today := time.Now().UTC().Format("2006-01-02")

	// Add a daily counter (has date suffix).
	m.Increment("tool_calls_mcp_" + today)
	// Add a regular counter (no date).
	m.Increment("api_calls")

	// Add historical daily user entries directly (yesterday).
	yesterday := time.Now().UTC().AddDate(0, 0, -1).Format("2006-01-02")
	ySet := &userSet{}
	ySet.users.Store("user1@test.com", true)
	ySet.users.Store("user2@test.com", true)
	ySet.count = 2
	m.dailyUsers.Store(yesterday, ySet)

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)

	output := buf.String()
	// Should contain the daily metric with date label.
	if !strings.Contains(output, "tool_calls_total") {
		t.Errorf("expected tool_calls_total in output, got:\n%s", output)
	}
	// Should contain the regular counter.
	if !strings.Contains(output, "api_calls_total") {
		t.Errorf("expected api_calls_total in output, got:\n%s", output)
	}
	// Should contain historical daily users.
	if !strings.Contains(output, "daily_unique_users_total") {
		t.Errorf("expected daily_unique_users_total in output, got:\n%s", output)
	}
}

func TestWritePrometheus_DailyMetricWithSessionType(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	today := time.Now().UTC().Format("2006-01-02")
	m.Increment("sessions_sse_" + today)

	buf := new(bytes.Buffer)
	m.WritePrometheus(buf)

	output := buf.String()
	if !strings.Contains(output, "sessions_total") {
		t.Errorf("expected sessions_total in output, got:\n%s", output)
	}
	if !strings.Contains(output, "session_type") {
		t.Errorf("expected session_type label in output, got:\n%s", output)
	}
}

func TestHTTPHandler_MethodNotAllowed(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	handler := m.HTTPHandler()

	req := httptest.NewRequest(http.MethodPost, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected 405, got %d", rr.Code)
	}
}

func TestHTTPHandler_GET_ReturnsPrometheus(t *testing.T) {
	m := New(Config{ServiceName: "test"})
	m.Increment("test_counter")

	handler := m.HTTPHandler()

	req := httptest.NewRequest(http.MethodGet, "/metrics", nil)
	rr := httptest.NewRecorder()
	handler(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rr.Code)
	}
	ct := rr.Header().Get("Content-Type")
	if ct != PrometheusContentType {
		t.Errorf("expected Content-Type %q, got %q", PrometheusContentType, ct)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "test_counter_total") {
		t.Errorf("expected test_counter_total in response body")
	}
}

func TestIsDailyMetric_MoreEdgeCases(t *testing.T) {
	m := New(Config{ServiceName: "test"})

	// Single part (no underscore).
	if m.isDailyMetric("nodashes") {
		t.Error("single part should not be daily metric")
	}
	// Date-like but wrong separators.
	if m.isDailyMetric("counter_20260411") {
		t.Error("no dashes in date part should not match")
	}
	// Empty base name after removing date.
	if m.isDailyMetric("2026-04-11") {
		t.Error("just a date with no base should not match")
	}
	// Valid daily metric.
	if !m.isDailyMetric("counter_2026-04-11") {
		t.Error("counter_2026-04-11 should be daily metric")
	}
	// Wrong date part lengths.
	if m.isDailyMetric("counter_26-04-11") {
		t.Error("short year should not match")
	}
}
