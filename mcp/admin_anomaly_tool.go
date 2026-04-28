package mcp

import (
	"context"
	"encoding/json"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/audit"
)

// ─────────────────────────────────────────────────────────────────────────────
// Tool: admin_list_anomaly_flags (read-only, admin-only)
//
// Operator dashboard for riskguard's anomaly-block events. Surfaces every
// order that was flagged by the rolling μ+3σ + 10×μ anomaly check within a
// configurable time window, grouped by user, with enough context to triage
// the alert (timestamp, reason code, order value, blocked flag).
//
// Data source: the audit-trail `tool_calls` table. When the riskguard
// middleware rejects an order, the audit middleware records an error row
// whose `error_message` column carries the exact string
// `ERROR: ORDER BLOCKED [anomaly_high]: ...`. We scan errored rows for
// that substring, extract the reason, and reconstruct the order value from
// the stored params JSON.
//
// Today anomaly is a strict hard-block — every flagged order is also blocked.
// The response schema carries a `blocked` boolean so that if/when riskguard
// adds a "warn, don't block" soft-flag tier the shape can carry both.
//
// Intentionally read-only: no writes, no state mutation, capped event count,
// and decoupled from riskguard internals (we scrape the audit trail rather
// than reaching into the guard's in-memory state). This keeps the operator
// tool side-effect-free even under concurrent trading load.
// ─────────────────────────────────────────────────────────────────────────────

const (
	// adminAnomalyDefaultHours is the default lookback window when the caller
	// does not supply an `hours` argument. 24h = one full trading cycle; long
	// enough to catch overnight / off-hours anomaly activity, short enough to
	// keep the query fast even on active tenants.
	adminAnomalyDefaultHours = 24
	// adminAnomalyMaxUsers caps how many top-error users we probe before
	// building the response. Much larger than the typical distinct-user count
	// over a 24-48h window but bounded so a runaway audit table can't make
	// the tool pathological.
	adminAnomalyMaxUsers = 100
	// adminAnomalyMaxEventsTotal caps the total number of anomaly rows surfaced
	// across all users in a single response. MCP payloads are token-sensitive;
	// operators viewing 100+ events per window should export via a dedicated
	// pipeline, not a conversational tool.
	adminAnomalyMaxEventsTotal = 100
	// adminAnomalyMaxEventsPerUser bounds a single user's event list so a
	// hyperactive account cannot crowd out other users from the response.
	adminAnomalyMaxEventsPerUser = 20
)

// anomalyReasonRegexp pulls the rejection reason code out of the audit
// error_message text. The riskguard middleware formats every block as
// `ORDER BLOCKED [<reason>]: <details>` — we only want events whose reason
// starts with `anomaly` (i.e. `anomaly_high` today, plus any future
// `anomaly_*` soft-flag tiers).
//
// Compiled once at package load; regex panics surface at init time rather
// than on a hot path.
var anomalyReasonRegexp = regexp.MustCompile(`ORDER BLOCKED \[(anomaly[a-z_]*)\]`)

// AdminListAnomalyFlagsTool lists recent orders flagged by riskguard's
// anomaly check, for operator triage.
type AdminListAnomalyFlagsTool struct{}

func (*AdminListAnomalyFlagsTool) Tool() mcp.Tool {
	return mcp.NewTool("admin_list_anomaly_flags",
		mcp.WithDescription(
			"List recent orders flagged by riskguard's anomaly check (μ+3σ + 10×mean). "+
				"Groups by user with event details: timestamp, reason code, order value, "+
				"and whether the order was hard-blocked. Defaults to the last 24 hours. "+
				"Read-only, admin-only.",
		),
		mcp.WithTitleAnnotation("Admin: List Anomaly Flags"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithNumber("hours",
			mcp.Description("Lookback window in hours (default 24). Non-positive values fall back to the default."),
		),
	)
}

// adminAnomalyEvent is a single surfaced anomaly flag.
type adminAnomalyEvent struct {
	// Timestamp is the UTC time the order was evaluated by riskguard
	// (i.e. the audit row's started_at).
	Timestamp time.Time `json:"timestamp"`
	// Reason is the riskguard rejection reason code, e.g. "anomaly_high".
	// Always starts with "anomaly" since we filter on that prefix.
	Reason string `json:"reason"`
	// OrderValue is the attempted order value (quantity * price) in INR,
	// parsed from the audit row's input_params JSON. Zero when we cannot
	// reconstruct it (missing price, MARKET order, non-standard params).
	OrderValue float64 `json:"order_value"`
	// Blocked reports whether the order was actually rejected. True today
	// for every anomaly event; kept as a field so future "warn, don't block"
	// soft-flag tiers can be distinguished without a schema break.
	Blocked bool `json:"blocked"`
	// CallID is the audit row's call_id — lets an operator jump from this
	// summary into the full audit-timeline view for forensic detail.
	CallID string `json:"call_id,omitempty"`
	// Tool is the MCP tool the caller invoked (place_order / modify_order).
	Tool string `json:"tool,omitempty"`
}

// adminAnomalyUserAgg groups a single user's anomaly events.
type adminAnomalyUserAgg struct {
	Email     string              `json:"email"`
	FlagCount int                 `json:"flag_count"`
	Events    []adminAnomalyEvent `json:"events"`
}

// adminAnomalyFlagsResponse is the structured payload returned by the tool.
type adminAnomalyFlagsResponse struct {
	WindowHours int                    `json:"window_hours"`
	Since       time.Time              `json:"since"`
	TotalFlags  int                    `json:"total_flags"`
	ByUser      []adminAnomalyUserAgg  `json:"by_user"`
	// Truncated reports whether the response was capped (either per-user or
	// total). Operators seeing this flag should rerun with a narrower window.
	Truncated bool `json:"truncated,omitempty"`
}

func (*AdminListAnomalyFlagsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return withAdminCheck(manager, func(ctx context.Context, _ string, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "admin_list_anomaly_flags")

		p := NewArgParser(request.GetArguments())
		hours := p.Int("hours", adminAnomalyDefaultHours)
		if hours <= 0 {
			hours = adminAnomalyDefaultHours
		}

		// Route through the AuditStoreProvider port: GetTopErrorUsers and
		// List are both on AuditStoreInterface. Phase 3a Batch 1 dropped
		// the prior manager.AuditStoreConcrete() leak — the older comment
		// (now removed) was empirically stale.
		auditStore := handler.AuditStore()
		if auditStore == nil {
			return mcp.NewToolResultError(
				"Audit store not available — anomaly flag history requires database persistence.",
			), nil
		}

		since := time.Now().UTC().Add(-time.Duration(hours) * time.Hour)
		resp := buildAnomalyFlagResponse(auditStore, since, hours)
		return handler.MarshalResponse(resp, "admin_list_anomaly_flags")
	})
}

// buildAnomalyFlagResponse does the aggregation off the MCP hot path so it
// can be unit-tested in isolation. Takes the AuditStoreInterface port —
// GetTopErrorUsers + List are both on AuditReader, no concrete-only methods
// needed — and returns a fully populated structured payload.
//
// Flow:
//  1. Pull top-error users within the window (bounded).
//  2. For each, pull their error rows via List(OnlyErrors) within the window.
//  3. Filter rows whose error_message carries an "ORDER BLOCKED [anomaly…]"
//     tag, parse reason + order value, append to the aggregate.
//  4. Cap per-user and total event counts; sort users by flag count desc
//     for a stable, operator-friendly ordering.
func buildAnomalyFlagResponse(auditStore kc.AuditStoreInterface, since time.Time, windowHours int) *adminAnomalyFlagsResponse {
	resp := &adminAnomalyFlagsResponse{
		WindowHours: windowHours,
		Since:       since,
		ByUser:      []adminAnomalyUserAgg{},
	}

	// Step 1: find candidate users. GetTopErrorUsers returns decrypted emails.
	errorUsers, err := auditStore.GetTopErrorUsers(since, adminAnomalyMaxUsers)
	if err != nil || len(errorUsers) == 0 {
		return resp
	}

	// Step 2+3: for each user, scan error rows in the window for anomaly events.
	totalEvents := 0
	for _, u := range errorUsers {
		if u.Email == "" {
			continue
		}
		rows, _, listErr := auditStore.List(u.Email, audit.ListOptions{
			OnlyErrors: true,
			Since:      since,
			// Bound the per-user fetch — we cap user events below anyway,
			// and List without a limit could otherwise return a huge set
			// for a spammy account.
			Limit: adminAnomalyMaxEventsPerUser * 3,
		})
		if listErr != nil {
			continue
		}

		events := make([]adminAnomalyEvent, 0, len(rows))
		for _, row := range rows {
			reason, ok := anomalyReasonFromMessage(row.ErrorMessage)
			if !ok {
				continue
			}
			events = append(events, adminAnomalyEvent{
				Timestamp:  row.StartedAt.UTC(),
				Reason:     reason,
				OrderValue: orderValueFromAuditParams(row.InputParams),
				// Today every anomaly event is a hard-block — the riskguard
				// middleware returns a ToolResultError which is what drives
				// IsError=1 on the audit row. We surface the IsError flag
				// directly so a future "warn-only" soft tier would flow
				// through unchanged.
				Blocked: row.IsError,
				CallID:  row.CallID,
				Tool:    row.ToolName,
			})
		}
		if len(events) == 0 {
			continue
		}
		if len(events) > adminAnomalyMaxEventsPerUser {
			events = events[:adminAnomalyMaxEventsPerUser]
			resp.Truncated = true
		}
		resp.ByUser = append(resp.ByUser, adminAnomalyUserAgg{
			Email:     strings.ToLower(u.Email),
			FlagCount: len(events),
			Events:    events,
		})
		totalEvents += len(events)
		if totalEvents >= adminAnomalyMaxEventsTotal {
			resp.Truncated = true
			break
		}
	}

	// Stable ordering: most-flagged users first, then alphabetical as a
	// tiebreaker so the response is deterministic for snapshot-style tests
	// and operator-eye diffs.
	sort.SliceStable(resp.ByUser, func(i, j int) bool {
		if resp.ByUser[i].FlagCount != resp.ByUser[j].FlagCount {
			return resp.ByUser[i].FlagCount > resp.ByUser[j].FlagCount
		}
		return resp.ByUser[i].Email < resp.ByUser[j].Email
	})

	resp.TotalFlags = totalEvents
	return resp
}

// anomalyReasonFromMessage extracts an `anomaly_*` reason code from the
// audit error_message text. Returns ("", false) when the message is not an
// anomaly-class block (including generic caps, rate limits, etc., which
// must not pollute the anomaly-flag operator view).
func anomalyReasonFromMessage(msg string) (string, bool) {
	if msg == "" {
		return "", false
	}
	m := anomalyReasonRegexp.FindStringSubmatch(msg)
	if len(m) != 2 {
		return "", false
	}
	return m[1], true
}

// orderValueFromAuditParams reconstructs the attempted order value (INR)
// from the audit row's input_params JSON. Mirrors the semantics of
// kc/audit/anomaly.go's orderValueFromParams: (qty * price), skipping rows
// where either side is missing/zero (MARKET orders have no submission-time
// price). Returns 0 when the value cannot be recovered — callers render
// that as "unknown" in the UI rather than silently showing zero-value
// orders as real zeros.
func orderValueFromAuditParams(paramsJSON string) float64 {
	if paramsJSON == "" {
		return 0
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(paramsJSON), &raw); err != nil {
		return 0
	}
	qty := numericAnomalyField(raw, "quantity")
	price := numericAnomalyField(raw, "price")
	if qty <= 0 || price <= 0 {
		return 0
	}
	return qty * price
}

// numericAnomalyField extracts a numeric value from a decoded JSON map,
// tolerating both native float64 and string-encoded numerics. Kept local
// to this tool rather than reaching into kc/audit's unexported helper so
// the tool has no compile-time coupling to audit internals.
func numericAnomalyField(m map[string]any, key string) float64 {
	v, ok := m[key]
	if !ok || v == nil {
		return 0
	}
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case int64:
		return float64(n)
	case string:
		// json.Unmarshal never produces a string for a numeric literal, but
		// some clients hand-serialise quantities as strings ("10"). Tolerate.
		if f, err := strconv.ParseFloat(n, 64); err == nil {
			return f
		}
	}
	return 0
}

func init() { RegisterInternalTool(&AdminListAnomalyFlagsTool{}) }
