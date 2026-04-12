package usecases

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zerodha/kite-mcp-server/kc/audit"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// --- Mock audit store ---

type mockAuditStore struct {
	stats        *audit.Stats
	statsErr     error
	toolMetrics  []audit.ToolMetric
	toolErr      error
	topErrors    []audit.UserErrorCount
	topErrorsErr error
}

func (m *mockAuditStore) GetGlobalStats(since time.Time) (*audit.Stats, error) {
	return m.stats, m.statsErr
}
func (m *mockAuditStore) GetToolMetrics(since time.Time) ([]audit.ToolMetric, error) {
	return m.toolMetrics, m.toolErr
}
func (m *mockAuditStore) GetTopErrorUsers(since time.Time, limit int) ([]audit.UserErrorCount, error) {
	return m.topErrors, m.topErrorsErr
}

func TestServerMetrics_Success_24h(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{
		stats:       &audit.Stats{TotalCalls: 100, ErrorCount: 5},
		toolMetrics: []audit.ToolMetric{{ToolName: "get_holdings", CallCount: 50}},
		topErrors:   []audit.UserErrorCount{{Email: "user@test.com", ErrorCount: 3}},
	}
	uc := NewServerMetricsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com", Period: "24h",
	})
	require.NoError(t, err)
	assert.Equal(t, "24h", result.Period)
	assert.Equal(t, 100, result.Stats.TotalCalls)
	assert.Len(t, result.ToolMetrics, 1)
	assert.Len(t, result.TopErrorUsers, 1)
}

func TestServerMetrics_Periods(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}}
	uc := NewServerMetricsUseCase(store, testLogger())

	for _, period := range []string{"1h", "24h", "7d", "30d", "unknown", ""} {
		result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
			AdminEmail: "admin@test.com", Period: period,
		})
		require.NoError(t, err, "period=%q", period)
		if period == "" || period == "unknown" {
			assert.Equal(t, "24h", result.Period, "period=%q should default to 24h", period)
		} else {
			assert.Equal(t, period, result.Period)
		}
	}
}

func TestServerMetrics_EmptyEmail(t *testing.T) {
	t.Parallel()
	uc := NewServerMetricsUseCase(&mockAuditStore{}, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{})
	assert.ErrorContains(t, err, "admin_email is required")
}

func TestServerMetrics_StatsError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{statsErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "get global stats")
}

func TestServerMetrics_ToolMetricsError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}, toolErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	_, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	assert.ErrorContains(t, err, "get tool metrics")
}

func TestServerMetrics_TopErrorUsersError(t *testing.T) {
	t.Parallel()
	store := &mockAuditStore{stats: &audit.Stats{}, topErrorsErr: errors.New("db fail")}
	uc := NewServerMetricsUseCase(store, testLogger())
	result, err := uc.Execute(context.Background(), cqrs.ServerMetricsQuery{
		AdminEmail: "admin@test.com",
	})
	require.NoError(t, err) // topErrorUsers error is silently ignored
	assert.Nil(t, result.TopErrorUsers)
}
