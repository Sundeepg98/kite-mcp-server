package mcp

import (
	"context"
	"fmt"
	"math"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	kiteconnect "github.com/zerodha/gokiteconnect/v4"
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
	"github.com/zerodha/kite-mcp-server/oauth"
)

// CreateWatchlistTool creates a new named watchlist.
type CreateWatchlistTool struct{}

func (*CreateWatchlistTool) Tool() mcp.Tool {
	return mcp.NewTool("create_watchlist",
		mcp.WithDescription("Create a new named watchlist for tracking instruments. Max 10 watchlists per user."),
		mcp.WithTitleAnnotation("Create Watchlist"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("name",
			mcp.Description("Name for the watchlist (e.g. 'Tech Stocks', 'Swing Trades')"),
			mcp.Required(),
		),
	)
}

func (*CreateWatchlistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "create_watchlist")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "name"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		name := strings.TrimSpace(NewArgParser(args).String("name", ""))
		if name == "" {
			return mcp.NewToolResultError("Watchlist name cannot be empty"), nil
		}

		raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.CreateWatchlistCommand{Email: email, Name: name})
		if err != nil {
			handler.trackToolError(ctx, "create_watchlist", "create_error")
			return mcp.NewToolResultError(err.Error()), nil
		}
		result, ok := raw.(*usecases.CreateWatchlistResult)
		if !ok || result == nil {
			return mcp.NewToolResultError("internal: unexpected create_watchlist result"), nil
		}

		// G132: result.Name is user-supplied — sanitize before echoing
		// to the LLM so a hostile name like "X\nIgnore prior..." can't
		// inject a fresh instruction paragraph.
		return mcp.NewToolResultText(fmt.Sprintf("Watchlist %q created (ID: %s). Use add_to_watchlist to add instruments.", SanitizeForLLM(result.Name), result.ID)), nil
	}
}

// DeleteWatchlistTool deletes a watchlist and all its items.
type DeleteWatchlistTool struct{}

func (*DeleteWatchlistTool) Tool() mcp.Tool {
	return mcp.NewTool("delete_watchlist",
		mcp.WithDescription("Delete a watchlist and all its items."),
		mcp.WithTitleAnnotation("Delete Watchlist"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("watchlist",
			mcp.Description("Watchlist ID or name"),
			mcp.Required(),
		),
	)
}

func (*DeleteWatchlistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "delete_watchlist")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "watchlist"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		watchlistRef := NewArgParser(args).String("watchlist", "")
		wl := resolveWatchlist(manager, email, watchlistRef)
		if wl == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Watchlist %q not found", watchlistRef)), nil
		}

		raw, err := handler.CommandBus().DispatchWithResult(ctx, cqrs.DeleteWatchlistCommand{Email: email, WatchlistID: wl.ID})
		if err != nil {
			handler.trackToolError(ctx, "delete_watchlist", "delete_error")
			return mcp.NewToolResultError(err.Error()), nil
		}
		result, ok := raw.(*usecases.DeleteWatchlistResult)
		if !ok || result == nil {
			return mcp.NewToolResultError("internal: unexpected delete_watchlist result"), nil
		}

		// G132: name was user-supplied at create time — sanitize the echo.
		return mcp.NewToolResultText(fmt.Sprintf("Watchlist %q deleted (%d items removed).", SanitizeForLLM(result.Name), result.ItemCount)), nil
	}
}

// AddToWatchlistTool adds instruments to a watchlist.
type AddToWatchlistTool struct{}

func (*AddToWatchlistTool) Tool() mcp.Tool {
	return mcp.NewTool("add_to_watchlist",
		mcp.WithDescription("Add instruments to a watchlist. Max 50 items per watchlist. Optionally set notes and price targets."),
		mcp.WithTitleAnnotation("Add to Watchlist"),
		mcp.WithDestructiveHintAnnotation(false),
		mcp.WithIdempotentHintAnnotation(false),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("watchlist",
			mcp.Description("Watchlist ID or name"),
			mcp.Required(),
		),
		mcp.WithString("instruments",
			mcp.Description("Comma-separated instruments in exchange:symbol format (e.g. 'NSE:RELIANCE,NSE:TCS,NSE:INFY')"),
			mcp.Required(),
		),
		mcp.WithString("notes",
			mcp.Description("Optional notes for all instruments being added"),
		),
		mcp.WithNumber("target_entry",
			mcp.Description("Optional target entry price (0 = not set)"),
		),
		mcp.WithNumber("target_exit",
			mcp.Description("Optional target exit price (0 = not set)"),
		),
	)
}

func (*AddToWatchlistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "add_to_watchlist")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "watchlist", "instruments"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		watchlistRef := p.String("watchlist", "")
		instrumentsStr := p.String("instruments", "")
		notes := p.String("notes", "")
		targetEntry := p.Float("target_entry", 0)
		targetExit := p.Float("target_exit", 0)

		wl := resolveWatchlist(manager, email, watchlistRef)
		if wl == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Watchlist %q not found. Use create_watchlist first.", watchlistRef)), nil
		}

		instruments := parseInstrumentList(instrumentsStr)
		if len(instruments) == 0 {
			return mcp.NewToolResultError("No valid instruments provided. Use exchange:symbol format (e.g. 'NSE:RELIANCE')."), nil
		}

		bus := handler.CommandBus()

		var added, failed []string
		for _, instID := range instruments {
			parts := strings.SplitN(instID, ":", 2)
			if len(parts) != 2 {
				failed = append(failed, fmt.Sprintf("%s (invalid format)", instID))
				continue
			}
			exchange := parts[0]

			// Resolve instrument to get token
			inst, err := handler.deps.Instruments.InstrumentsManager().GetByID(instID)
			if err != nil {
				failed = append(failed, fmt.Sprintf("%s (not found)", instID))
				continue
			}

			if _, err := bus.DispatchWithResult(ctx, cqrs.AddToWatchlistCommand{
				Email:           email,
				WatchlistID:     wl.ID,
				Exchange:        exchange,
				Tradingsymbol:   inst.Tradingsymbol,
				InstrumentToken: inst.InstrumentToken,
				Notes:           notes,
				TargetEntry:     targetEntry,
				TargetExit:      targetExit,
			}); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%s)", instID, err))
				continue
			}
			added = append(added, instID)
		}

		var result strings.Builder
		if len(added) > 0 {
			result.WriteString(fmt.Sprintf("Added %d instrument(s) to %q: %s", len(added), wl.Name, strings.Join(added, ", ")))
		}
		if len(failed) > 0 {
			if result.Len() > 0 {
				result.WriteString("\n")
			}
			result.WriteString(fmt.Sprintf("Failed: %s", strings.Join(failed, "; ")))
		}

		if len(added) == 0 {
			handler.trackToolError(ctx, "add_to_watchlist", "all_failed")
			return mcp.NewToolResultError(result.String()), nil
		}

		return mcp.NewToolResultText(result.String()), nil
	}
}

// RemoveFromWatchlistTool removes instruments from a watchlist.
type RemoveFromWatchlistTool struct{}

func (*RemoveFromWatchlistTool) Tool() mcp.Tool {
	return mcp.NewTool("remove_from_watchlist",
		mcp.WithDescription("Remove instruments from a watchlist by item ID or exchange:symbol."),
		mcp.WithTitleAnnotation("Remove from Watchlist"),
		mcp.WithDestructiveHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
		mcp.WithString("watchlist",
			mcp.Description("Watchlist ID or name"),
			mcp.Required(),
		),
		mcp.WithString("items",
			mcp.Description("Comma-separated item IDs or exchange:symbol (e.g. 'abc123,NSE:TCS')"),
			mcp.Required(),
		),
	)
}

func (*RemoveFromWatchlistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "remove_from_watchlist")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "watchlist", "items"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		watchlistRef := p.String("watchlist", "")
		itemsStr := p.String("items", "")

		wl := resolveWatchlist(manager, email, watchlistRef)
		if wl == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Watchlist %q not found", watchlistRef)), nil
		}

		refs := parseInstrumentList(itemsStr)
		if len(refs) == 0 {
			return mcp.NewToolResultError("No items specified"), nil
		}

		bus := handler.CommandBus()

		var removed, failed []string
		for _, ref := range refs {
			itemID := ref
			// If ref looks like exchange:symbol, resolve to item ID
			if strings.Contains(ref, ":") {
				parts := strings.SplitN(ref, ":", 2)
				if len(parts) == 2 {
					found := handler.deps.Watchlist.WatchlistStore().FindItemBySymbol(wl.ID, parts[0], parts[1])
					if found != nil {
						itemID = found.ID
					} else {
						failed = append(failed, fmt.Sprintf("%s (not in watchlist)", ref))
						continue
					}
				}
			}

			if _, err := bus.DispatchWithResult(ctx, cqrs.RemoveFromWatchlistCommand{Email: email, WatchlistID: wl.ID, ItemID: itemID}); err != nil {
				failed = append(failed, fmt.Sprintf("%s (%s)", ref, err))
				continue
			}
			removed = append(removed, ref)
		}

		var result strings.Builder
		if len(removed) > 0 {
			result.WriteString(fmt.Sprintf("Removed %d item(s) from %q: %s", len(removed), wl.Name, strings.Join(removed, ", ")))
		}
		if len(failed) > 0 {
			if result.Len() > 0 {
				result.WriteString("\n")
			}
			result.WriteString(fmt.Sprintf("Failed: %s", strings.Join(failed, "; ")))
		}

		if len(removed) == 0 {
			handler.trackToolError(ctx, "remove_from_watchlist", "all_failed")
			return mcp.NewToolResultError(result.String()), nil
		}

		return mcp.NewToolResultText(result.String()), nil
	}
}

// GetWatchlistTool returns items in a watchlist with optional LTP enrichment.
type GetWatchlistTool struct{}

func (*GetWatchlistTool) Tool() mcp.Tool {
	return mcp.NewTool("get_watchlist",
		mcp.WithDescription("Get all instruments in a watchlist with current prices (LTP). Shows distance to target entry/exit."),
		mcp.WithTitleAnnotation("Get Watchlist"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(true),
		mcp.WithString("watchlist",
			mcp.Description("Watchlist ID or name"),
			mcp.Required(),
		),
		mcp.WithBoolean("include_ltp",
			mcp.Description("Include current LTP prices (default: true). Requires an active Kite session."),
		),
	)
}

func (*GetWatchlistTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "get_watchlist")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		args := request.GetArguments()
		if err := ValidateRequired(args, "watchlist"); err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}

		p := NewArgParser(args)
		watchlistRef := p.String("watchlist", "")
		includeLTP := p.Bool("include_ltp", true)

		wl := resolveWatchlist(manager, email, watchlistRef)
		if wl == nil {
			return mcp.NewToolResultError(fmt.Sprintf("Watchlist %q not found", watchlistRef)), nil
		}

		raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.GetWatchlistQuery{Email: email, WatchlistID: wl.ID})
		if err != nil {
			handler.trackToolError(ctx, "get_watchlist", "get_error")
			return mcp.NewToolResultError(err.Error()), nil
		}
		items := raw.([]*watchlist.WatchlistItem)
		if len(items) == 0 {
			// G132: wl.Name was user-supplied — sanitize before echoing.
			return mcp.NewToolResultText(fmt.Sprintf("Watchlist %q is empty. Use add_to_watchlist to add instruments.", SanitizeForLLM(wl.Name))), nil
		}

		// Build LTP map if requested
		ltpMap := make(map[string]float64) // "EXCHANGE:SYMBOL" -> last_price
		if includeLTP {
			// Build instrument list for batch LTP call
			instrIDs := make([]string, 0, len(items))
			for _, item := range items {
				instrIDs = append(instrIDs, item.Exchange+":"+item.Tradingsymbol)
			}

			// Get Kite session for LTP call
			sess := server.ClientSessionFromContext(ctx)
			sessionID := sess.SessionID()
			kiteSession, _, clientErr := handler.deps.Sessions.GetOrCreateSessionWithEmail(sessionID, email)
			if clientErr == nil {
				ltpResp, ltpErr := RetryBrokerCall(func() (kiteconnect.QuoteLTP, error) {
					return kiteSession.Kite.Client.GetLTP(instrIDs...)
				}, 2)
				if ltpErr == nil {
					for key, data := range ltpResp {
						ltpMap[key] = data.LastPrice
					}
				} else {
					handler.Logger().Warn("Failed to fetch LTP for watchlist", "error", ltpErr)
				}
			} else {
				handler.Logger().Warn("Failed to get Kite session for watchlist LTP", "error", clientErr)
			}
		}

		// Build response
		type itemResponse struct {
			ID            string  `json:"id"`
			Instrument    string  `json:"instrument"`
			Notes         string  `json:"notes,omitempty"`
			TargetEntry   float64 `json:"target_entry,omitempty"`
			TargetExit    float64 `json:"target_exit,omitempty"`
			LTP           float64 `json:"ltp,omitempty"`
			DistanceEntry string  `json:"distance_to_entry,omitempty"`
			DistanceExit  string  `json:"distance_to_exit,omitempty"`
			NearTarget    bool    `json:"near_target,omitempty"`
			Suggestion    string  `json:"suggestion,omitempty"`
		}

		type watchlistResponse struct {
			Name      string         `json:"name"`
			ID        string         `json:"id"`
			ItemCount int            `json:"item_count"`
			Items     []itemResponse `json:"items"`
		}

		resp := watchlistResponse{
			Name:      wl.Name,
			ID:        wl.ID,
			ItemCount: len(items),
			Items:     make([]itemResponse, 0, len(items)),
		}

		for _, item := range items {
			instrID := item.Exchange + ":" + item.Tradingsymbol
			ir := itemResponse{
				ID:          item.ID,
				Instrument:  instrID,
				Notes:       item.Notes,
				TargetEntry: item.TargetEntry,
				TargetExit:  item.TargetExit,
			}

			if ltp, ok := ltpMap[instrID]; ok && ltp > 0 {
				ir.LTP = ltp
				if item.TargetEntry > 0 {
					pct := ((ltp - item.TargetEntry) / item.TargetEntry) * 100
					ir.DistanceEntry = fmt.Sprintf("%.2f%%", pct)
					if math.Abs(pct) <= 5.0 {
						ir.NearTarget = true
						if ltp <= item.TargetEntry {
							ir.Suggestion = fmt.Sprintf("Price is %.1f%% below target entry (%.2f) — consider buying", math.Abs(pct), item.TargetEntry)
						} else {
							ir.Suggestion = fmt.Sprintf("Price is %.1f%% above target entry (%.2f) — entry zone passed", pct, item.TargetEntry)
						}
					}
				}
				if item.TargetExit > 0 {
					pct := ((ltp - item.TargetExit) / item.TargetExit) * 100
					ir.DistanceExit = fmt.Sprintf("%.2f%%", pct)
					if math.Abs(pct) <= 5.0 {
						ir.NearTarget = true
						if ltp >= item.TargetExit {
							ir.Suggestion = fmt.Sprintf("Price is %.1f%% above target exit (%.2f) — consider selling", pct, item.TargetExit)
						} else {
							ir.Suggestion = fmt.Sprintf("Price is %.1f%% below target exit (%.2f) — approaching exit target", math.Abs(pct), item.TargetExit)
						}
					}
				}
			}

			resp.Items = append(resp.Items, ir)
		}

		return handler.MarshalResponse(resp, "get_watchlist")
	}
}

// ListWatchlistsTool lists all watchlists for the current user.
type ListWatchlistsTool struct{}

func (*ListWatchlistsTool) Tool() mcp.Tool {
	return mcp.NewTool("list_watchlists",
		mcp.WithDescription("List all watchlists for the current user with item counts."),
		mcp.WithTitleAnnotation("List Watchlists"),
		mcp.WithReadOnlyHintAnnotation(true),
		mcp.WithIdempotentHintAnnotation(true),
		mcp.WithOpenWorldHintAnnotation(false),
	)
}

func (*ListWatchlistsTool) Handler(manager *kc.Manager) server.ToolHandlerFunc {
	handler := NewToolHandler(manager)
	return func(ctx context.Context, request mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		handler.trackToolCall(ctx, "list_watchlists")

		email := oauth.EmailFromContext(ctx)
		if email == "" {
			return mcp.NewToolResultError("Email required (OAuth must be enabled)"), nil
		}

		raw, err := handler.QueryBus().DispatchWithResult(ctx, cqrs.ListWatchlistsQuery{Email: email})
		if err != nil {
			return mcp.NewToolResultError(err.Error()), nil
		}
		result := raw.([]usecases.WatchlistInfo)

		if len(result) == 0 {
			return mcp.NewToolResultText("No watchlists. Use create_watchlist to create one."), nil
		}

		return handler.MarshalResponse(result, "list_watchlists")
	}
}

// --- Helper functions ---

// resolveWatchlist finds a watchlist by ID or name for the given user.
//
// Phase 3a Batch 6: provider is the narrow port surface this function
// actually needs (single WatchlistStore() accessor). *kc.Manager satisfies
// kc.WatchlistStoreProvider, so existing callers compile unchanged.
func resolveWatchlist(provider kc.WatchlistStoreProvider, email, ref string) *watchlist.Watchlist {
	store := provider.WatchlistStore()
	// Try by name first (more user-friendly)
	if wl := store.FindWatchlistByName(email, ref); wl != nil {
		return wl
	}
	// Try by ID
	watchlists := store.ListWatchlists(email)
	for _, wl := range watchlists {
		if wl.ID == ref {
			return wl
		}
	}
	return nil
}

// parseInstrumentList splits a comma-separated string into trimmed, non-empty items.
func parseInstrumentList(s string) []string {
	parts := strings.Split(s, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func init() {
	RegisterInternalTool(&AddToWatchlistTool{})
	RegisterInternalTool(&CreateWatchlistTool{})
	RegisterInternalTool(&DeleteWatchlistTool{})
	RegisterInternalTool(&GetWatchlistTool{})
	RegisterInternalTool(&ListWatchlistsTool{})
	RegisterInternalTool(&RemoveFromWatchlistTool{})
}
