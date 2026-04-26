package mcp

import (
	"context"
	"fmt"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// CompositeAlertTool creates an alert that fires when multiple conditions
// across different instruments are satisfied (AND) or when any single
// condition fires (ANY/OR). Each leg targets a different instrument with
// its own operator (above/below/drop_pct/rise_pct) and threshold.
//
// Typical use case: a day-trader watching for a correlated market move,
// e.g. "NIFTY drops 0.5% AND INDIA VIX rises 15% from reference".
//
// Persistence is implemented per Option B: composite alerts share the
// `alerts` table with single-leg alerts and are distinguished by
// alert_type='composite' with a JSON-encoded conditions payload. See
// kc/alerts/db.go for the schema and kc/usecases/create_composite_alert.go
// for the validation + write use case.
//
// Evaluator integration (walking legs on every tick and triggering only
// when the logic is satisfied) is handled in a follow-up PR — for now
// composite alerts persist correctly but the ticker evaluator treats the
// anchor leg as a regular alert. This is flagged in the tool's response
// note so callers are not surprised.
type CompositeAlertTool struct{}

// compositeLogicAnd / compositeLogicAny are the two supported combination
// modes. Kept as constants so callers (and future evaluator code) can
// reference the same spelling the schema enum enforces.
const (
	compositeLogicAnd = "AND"
	compositeLogicAny = "ANY"
)

// compositeMinConditions / compositeMaxConditions bound the number of
// legs a single composite alert can reference. 2 is the floor because a
// single-leg composite would just be a regular alert; 5 is a pragmatic
// ceiling — beyond that the UX (and evaluator cost) degrades sharply.
const (
	compositeMinConditions = 2
	compositeMaxConditions = 5
)

// compositeCondition is the parsed, validated form of one leg of the
// composite alert. Mirrors the shape of `alerts.Alert` so a future
// persistence layer can map 1:1 without re-parsing.
type compositeCondition struct {
	Exchange       string  `json:"exchange"`
	Tradingsymbol  string  `json:"tradingsymbol"`
	Operator       string  `json:"operator"`
	Value          float64 `json:"value"`
	ReferencePrice float64 `json:"reference_price,omitempty"`
	// InstrumentToken is resolved from the instruments store on intake so
	// the evaluator (once wired) doesn't need to re-resolve per tick.
	InstrumentToken uint32 `json:"instrument_token"`
}

// compositeAlertResponse is the structured payload returned to the
// caller. `status` is "created" on success; `alert_id` carries the
// newly-minted persistence ID. Retained as the SCAFFOLD-era field set
// (plus AlertID) so callers that already key off the shape continue to
// work.
type compositeAlertResponse struct {
	Status     string               `json:"status"`
	Message    string               `json:"message"`
	AlertID    string               `json:"alert_id,omitempty"`
	Name       string               `json:"name"`
	Logic      string               `json:"logic"`
	Conditions []compositeCondition `json:"conditions"`
	Note       string               `json:"note,omitempty"`
}

func (*CompositeAlertTool) Tool() mcp.Tool {
	return mcp.NewTool("composite_alert",
		mcp.WithDescription("Create a composite alert that fires when multiple conditions are met together (AND) or any of them are met (ANY). Each condition can target a different instrument, price, OR percentage change. Returns the alert ID on creation. Not investment advice."),
		mcp.WithTitleAnnotation("Composite Alert"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("name",
			mcp.Description("Label for the alert (e.g. 'nifty_vix_correlation'). Used in notifications."),
			mcp.Required(),
		),
		mcp.WithString("logic",
			mcp.Description("How legs combine: 'AND' = every condition must fire simultaneously; 'ANY' = any single condition fires the alert."),
			mcp.Required(),
			mcp.Enum(compositeLogicAnd, compositeLogicAny),
		),
		mcp.WithArray("conditions",
			mcp.Description("Array of 2-5 condition legs. Each leg targets a different instrument with its own operator and threshold."),
			mcp.Required(),
			mcp.MinItems(compositeMinConditions),
			mcp.MaxItems(compositeMaxConditions),
			mcp.Items(map[string]any{
				"type": "object",
				"properties": map[string]any{
					"exchange": map[string]any{
						"type":        "string",
						"description": "Exchange code (NSE, NFO, BSE, BFO, MCX)",
					},
					"tradingsymbol": map[string]any{
						"type":        "string",
						"description": "Trading symbol (e.g. 'RELIANCE', 'NIFTY 50')",
					},
					"operator": map[string]any{
						"type":        "string",
						"enum":        []string{"above", "below", "drop_pct", "rise_pct"},
						"description": "Trigger direction for this leg",
					},
					"value": map[string]any{
						"type":        "number",
						"description": "Price for above/below; percentage (e.g. 5.0 for 5%) for drop_pct/rise_pct",
					},
					"reference_price": map[string]any{
						"type":        "number",
						"description": "Baseline price for drop_pct/rise_pct. Required for those operators.",
					},
				},
				"required": []string{"exchange", "tradingsymbol", "operator", "value"},
			}),
		),
		mcp.WithString("note",
			mcp.Description("Optional freeform description stored alongside the alert."),
		),
	)
}

func (*CompositeAlertTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "composite_alert")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "name", "logic", "conditions"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		name := strings.TrimSpace(p.String("name", ""))
		if name == "" {
			return mcp.NewToolResultError("name cannot be empty"), nil
		}

		logic := strings.ToUpper(strings.TrimSpace(p.String("logic", "")))
		if logic != compositeLogicAnd && logic != compositeLogicAny {
			return mcp.NewToolResultError("logic must be 'AND' or 'ANY'"), nil
		}

		rawConds, ok := args["conditions"].([]any)
		if !ok {
			return mcp.NewToolResultError("conditions must be an array of objects"), nil
		}
		if len(rawConds) < compositeMinConditions {
			return mcp.NewToolResultError(fmt.Sprintf("conditions must contain at least %d legs", compositeMinConditions)), nil
		}
		if len(rawConds) > compositeMaxConditions {
			return mcp.NewToolResultError(fmt.Sprintf("conditions must contain at most %d legs", compositeMaxConditions)), nil
		}

		// Parse + validate each leg. We fail fast on the first bad leg
		// with an explicit index in the error so the caller knows which
		// object in their payload was rejected.
		conds := make([]compositeCondition, 0, len(rawConds))
		for i, rc := range rawConds {
			cond, err := parseCompositeCondition(i, rc)
			if err != nil {
				handler.trackToolError(ctx, "composite_alert", "invalid_condition")
				return mcp.NewToolResultError(err.Error()), nil
			}

			// Resolve instrument token via the shared instruments store.
			// We do this at intake (not at evaluator time) so the stored
			// alert carries a stable instrument_token.
			instMgr := handler.deps.Instruments.InstrumentsManager()
			if instMgr == nil {
				return mcp.NewToolResultError("Instruments store not available"), nil
			}
			inst, err := instMgr.GetByTradingsymbol(cond.Exchange, cond.Tradingsymbol)
			if err != nil {
				handler.trackToolError(ctx, "composite_alert", "instrument_not_found")
				return mcp.NewToolResultError(fmt.Sprintf("conditions[%d]: instrument %s:%s not found", i, cond.Exchange, cond.Tradingsymbol)), nil
			}
			cond.InstrumentToken = inst.InstrumentToken
			conds = append(conds, cond)
		}

		note := strings.TrimSpace(p.String("note", ""))

		// Dispatch to the use case via the CQRS command bus. The tool
		// handler has already normalized exchange casing, operator casing
		// and resolved instrument tokens for echo purposes; the use case
		// re-validates and re-resolves to keep a single source of truth
		// for business rules (defense in depth — admin or scripted
		// callers bypass the tool).
		specs := make([]cqrs.CompositeConditionSpec, len(conds))
		for i, c := range conds {
			specs[i] = cqrs.CompositeConditionSpec{
				Exchange:       c.Exchange,
				Tradingsymbol:  c.Tradingsymbol,
				Operator:       c.Operator,
				Value:          c.Value,
				ReferencePrice: c.ReferencePrice,
			}
		}

		raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.CreateCompositeAlertCommand{
			Email:      email,
			Name:       name,
			Logic:      logic,
			Conditions: specs,
		})
		if err != nil {
			handler.trackToolError(ctx, "composite_alert", "persistence_error")
			return mcp.NewToolResultError(fmt.Sprintf("Failed to create composite alert: %s", err)), nil
		}
		alertID, _ := raw.(string)

		message := "Composite alert created."
		// Appended note is informational; the evaluator-side integration
		// lands in a follow-up PR, so callers should know their composite
		// persists but the anchor leg is what the current evaluator walks.
		responseNote := note
		if responseNote == "" {
			responseNote = "Composite alert persisted. Ticker evaluator will trigger on the anchor leg until composite evaluator lands."
		}

		resp := &compositeAlertResponse{
			Status:     "created",
			Message:    message,
			AlertID:    alertID,
			Name:       name,
			Logic:      logic,
			Conditions: conds,
			Note:       responseNote,
		}

		handler.deps.Logger.Info("composite_alert created",
			"email", email,
			"alert_id", alertID,
			"name", name,
			"logic", logic,
			"conditions", len(conds))

		return handler.MarshalResponse(resp, "composite_alert")
	}
}

// parseCompositeCondition turns a single entry from the user-supplied
// `conditions` array into a validated compositeCondition. The `idx`
// parameter is echoed into error messages so the caller can pinpoint
// which leg was rejected.
func parseCompositeCondition(idx int, raw any) (compositeCondition, error) {
	var zero compositeCondition

	obj, ok := raw.(map[string]any)
	if !ok {
		return zero, fmt.Errorf("conditions[%d]: expected an object, got %T", idx, raw)
	}

	exchange := strings.ToUpper(strings.TrimSpace(SafeAssertString(obj["exchange"], "")))
	if exchange == "" {
		return zero, fmt.Errorf("conditions[%d]: exchange is required", idx)
	}
	if !validCompositeExchange(exchange) {
		return zero, fmt.Errorf("conditions[%d]: exchange %q not supported (use NSE, NFO, BSE, BFO, MCX)", idx, exchange)
	}

	symbol := strings.TrimSpace(SafeAssertString(obj["tradingsymbol"], ""))
	if symbol == "" {
		return zero, fmt.Errorf("conditions[%d]: tradingsymbol is required", idx)
	}

	operator := strings.ToLower(strings.TrimSpace(SafeAssertString(obj["operator"], "")))
	if operator == "" {
		return zero, fmt.Errorf("conditions[%d]: operator is required", idx)
	}
	if !alerts.ValidDirections[alerts.Direction(operator)] {
		return zero, fmt.Errorf("conditions[%d]: operator %q must be one of above, below, drop_pct, rise_pct", idx, operator)
	}

	value := SafeAssertFloat64(obj["value"], 0)
	if value <= 0 {
		return zero, fmt.Errorf("conditions[%d]: value must be > 0", idx)
	}

	refPrice := SafeAssertFloat64(obj["reference_price"], 0)
	if alerts.IsPercentageDirection(alerts.Direction(operator)) {
		if refPrice <= 0 {
			return zero, fmt.Errorf("conditions[%d]: reference_price is required (and > 0) for %s", idx, operator)
		}
		if value > 100 {
			return zero, fmt.Errorf("conditions[%d]: percentage value cannot exceed 100", idx)
		}
	}

	return compositeCondition{
		Exchange:       exchange,
		Tradingsymbol:  symbol,
		Operator:       operator,
		Value:          value,
		ReferencePrice: refPrice,
	}, nil
}

// validCompositeExchange mirrors the enum documented in the tool
// description. Kept as a small helper so the allowlist lives next to
// the code that rejects unknown values.
func validCompositeExchange(exchange string) bool {
	switch exchange {
	case "NSE", "NFO", "BSE", "BFO", "MCX", "CDS", "BCD":
		return true
	}
	return false
}

func init() { RegisterInternalTool(&CompositeAlertTool{}) }
