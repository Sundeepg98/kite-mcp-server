package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	"github.com/zerodha/kite-mcp-server/kc/watchlist"
)

// WatchlistStore abstracts watchlist persistence for use cases.
type WatchlistStore interface {
	CreateWatchlist(email, name string) (string, error)
	DeleteWatchlist(email, watchlistID string) error
	DeleteByEmail(email string)
	ListWatchlists(email string) []*watchlist.Watchlist
	FindWatchlistByName(email, name string) *watchlist.Watchlist
	ItemCount(watchlistID string) int
	AddItem(email, watchlistID string, item *watchlist.WatchlistItem) error
	RemoveItem(email, watchlistID, itemID string) error
	GetItems(watchlistID string) []*watchlist.WatchlistItem
	FindItemBySymbol(watchlistID, exchange, tradingsymbol string) *watchlist.WatchlistItem
}

// --- Create Watchlist ---

// CreateWatchlistUseCase creates a new named watchlist.
type CreateWatchlistUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewCreateWatchlistUseCase creates a CreateWatchlistUseCase with dependencies injected.
func NewCreateWatchlistUseCase(store WatchlistStore, logger *slog.Logger) *CreateWatchlistUseCase {
	return &CreateWatchlistUseCase{store: store, logger: logger}
}

// CreateWatchlistResult holds the result of creating a watchlist.
type CreateWatchlistResult struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// Execute creates a new watchlist, checking for duplicates.
func (uc *CreateWatchlistUseCase) Execute(ctx context.Context, cmd cqrs.CreateWatchlistCommand) (*CreateWatchlistResult, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if cmd.Name == "" {
		return nil, fmt.Errorf("usecases: watchlist name is required")
	}

	if existing := uc.store.FindWatchlistByName(cmd.Email, cmd.Name); existing != nil {
		return nil, fmt.Errorf("usecases: watchlist %q already exists (ID: %s)", cmd.Name, existing.ID)
	}

	id, err := uc.store.CreateWatchlist(cmd.Email, cmd.Name)
	if err != nil {
		uc.logger.Error("Failed to create watchlist", "email", cmd.Email, "name", cmd.Name, "error", err)
		return nil, fmt.Errorf("usecases: create watchlist: %w", err)
	}

	return &CreateWatchlistResult{ID: id, Name: cmd.Name}, nil
}

// --- Delete Watchlist ---

// DeleteWatchlistUseCase deletes a watchlist and all its items.
type DeleteWatchlistUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewDeleteWatchlistUseCase creates a DeleteWatchlistUseCase with dependencies injected.
func NewDeleteWatchlistUseCase(store WatchlistStore, logger *slog.Logger) *DeleteWatchlistUseCase {
	return &DeleteWatchlistUseCase{store: store, logger: logger}
}

// DeleteWatchlistResult holds the result of deleting a watchlist.
type DeleteWatchlistResult struct {
	Name      string `json:"name"`
	ItemCount int    `json:"item_count"`
}

// Execute deletes a watchlist by ID.
func (uc *DeleteWatchlistUseCase) Execute(ctx context.Context, cmd cqrs.DeleteWatchlistCommand) (*DeleteWatchlistResult, error) {
	if cmd.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if cmd.WatchlistID == "" {
		return nil, fmt.Errorf("usecases: watchlist_id is required")
	}

	// Get watchlist name and item count before deleting.
	watchlists := uc.store.ListWatchlists(cmd.Email)
	var wlName string
	for _, wl := range watchlists {
		if wl.ID == cmd.WatchlistID {
			wlName = wl.Name
			break
		}
	}

	itemCount := uc.store.ItemCount(cmd.WatchlistID)

	if err := uc.store.DeleteWatchlist(cmd.Email, cmd.WatchlistID); err != nil {
		uc.logger.Error("Failed to delete watchlist", "email", cmd.Email, "id", cmd.WatchlistID, "error", err)
		return nil, fmt.Errorf("usecases: delete watchlist: %w", err)
	}

	return &DeleteWatchlistResult{Name: wlName, ItemCount: itemCount}, nil
}

// --- List Watchlists ---

// ListWatchlistsUseCase retrieves all watchlists for a user.
type ListWatchlistsUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewListWatchlistsUseCase creates a ListWatchlistsUseCase with dependencies injected.
func NewListWatchlistsUseCase(store WatchlistStore, logger *slog.Logger) *ListWatchlistsUseCase {
	return &ListWatchlistsUseCase{store: store, logger: logger}
}

// WatchlistInfo holds summary information about a watchlist.
type WatchlistInfo struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	ItemCount int    `json:"item_count"`
	UpdatedAt string `json:"updated_at"`
}

// Execute retrieves all watchlists for the given user.
func (uc *ListWatchlistsUseCase) Execute(ctx context.Context, query cqrs.ListWatchlistsQuery) ([]WatchlistInfo, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}

	watchlists := uc.store.ListWatchlists(query.Email)
	result := make([]WatchlistInfo, 0, len(watchlists))
	for _, wl := range watchlists {
		result = append(result, WatchlistInfo{
			ID:        wl.ID,
			Name:      wl.Name,
			ItemCount: uc.store.ItemCount(wl.ID),
			UpdatedAt: wl.UpdatedAt.Format("2006-01-02 15:04"),
		})
	}

	return result, nil
}

// --- Add To Watchlist ---

// AddToWatchlistUseCase adds an instrument to a watchlist.
type AddToWatchlistUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewAddToWatchlistUseCase creates an AddToWatchlistUseCase with dependencies injected.
func NewAddToWatchlistUseCase(store WatchlistStore, logger *slog.Logger) *AddToWatchlistUseCase {
	return &AddToWatchlistUseCase{store: store, logger: logger}
}

// Execute adds an instrument to a watchlist.
func (uc *AddToWatchlistUseCase) Execute(ctx context.Context, cmd cqrs.AddToWatchlistCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.WatchlistID == "" {
		return fmt.Errorf("usecases: watchlist_id is required")
	}

	item := &watchlist.WatchlistItem{
		Exchange:        cmd.Exchange,
		Tradingsymbol:   cmd.Tradingsymbol,
		InstrumentToken: cmd.InstrumentToken,
		Notes:           cmd.Notes,
		TargetEntry:     cmd.TargetEntry,
		TargetExit:      cmd.TargetExit,
	}

	if err := uc.store.AddItem(cmd.Email, cmd.WatchlistID, item); err != nil {
		uc.logger.Error("Failed to add to watchlist", "email", cmd.Email, "watchlist_id", cmd.WatchlistID, "error", err)
		return fmt.Errorf("usecases: add to watchlist: %w", err)
	}

	return nil
}

// --- Get Watchlist ---

// GetWatchlistUseCase retrieves items in a watchlist.
type GetWatchlistUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewGetWatchlistUseCase creates a GetWatchlistUseCase with dependencies injected.
func NewGetWatchlistUseCase(store WatchlistStore, logger *slog.Logger) *GetWatchlistUseCase {
	return &GetWatchlistUseCase{store: store, logger: logger}
}

// Execute retrieves all items in a watchlist.
func (uc *GetWatchlistUseCase) Execute(ctx context.Context, query cqrs.GetWatchlistQuery) ([]*watchlist.WatchlistItem, error) {
	if query.Email == "" {
		return nil, fmt.Errorf("usecases: email is required")
	}
	if query.WatchlistID == "" {
		return nil, fmt.Errorf("usecases: watchlist_id is required")
	}

	return uc.store.GetItems(query.WatchlistID), nil
}

// --- Remove From Watchlist ---

// RemoveFromWatchlistUseCase removes an instrument from a watchlist.
type RemoveFromWatchlistUseCase struct {
	store  WatchlistStore
	logger *slog.Logger
}

// NewRemoveFromWatchlistUseCase creates a RemoveFromWatchlistUseCase with dependencies injected.
func NewRemoveFromWatchlistUseCase(store WatchlistStore, logger *slog.Logger) *RemoveFromWatchlistUseCase {
	return &RemoveFromWatchlistUseCase{store: store, logger: logger}
}

// Execute removes an item from a watchlist.
func (uc *RemoveFromWatchlistUseCase) Execute(ctx context.Context, cmd cqrs.RemoveFromWatchlistCommand) error {
	if cmd.Email == "" {
		return fmt.Errorf("usecases: email is required")
	}
	if cmd.WatchlistID == "" {
		return fmt.Errorf("usecases: watchlist_id is required")
	}
	if cmd.ItemID == "" {
		return fmt.Errorf("usecases: item_id is required")
	}

	if err := uc.store.RemoveItem(cmd.Email, cmd.WatchlistID, cmd.ItemID); err != nil {
		uc.logger.Error("Failed to remove from watchlist", "email", cmd.Email, "watchlist_id", cmd.WatchlistID, "item_id", cmd.ItemID, "error", err)
		return fmt.Errorf("usecases: remove from watchlist: %w", err)
	}

	return nil
}
