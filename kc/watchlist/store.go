package watchlist

import (
	"database/sql"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
)

const (
	// MaxWatchlistsPerUser is the maximum number of watchlists a single user can have.
	MaxWatchlistsPerUser = 10
	// MaxItemsPerWatchlist is the maximum number of items in a single watchlist.
	MaxItemsPerWatchlist = 50
)

// Watchlist represents a named group of instruments.
type Watchlist struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Name      string    `json:"name"`
	SortOrder int       `json:"sort_order"`
	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// WatchlistItem represents a single instrument in a watchlist.
type WatchlistItem struct {
	ID              string    `json:"id"`
	WatchlistID     string    `json:"watchlist_id"`
	Email           string    `json:"email"`
	Exchange        string    `json:"exchange"`
	Tradingsymbol   string    `json:"tradingsymbol"`
	InstrumentToken uint32    `json:"instrument_token"`
	Notes           string    `json:"notes,omitempty"`
	TargetEntry     float64   `json:"target_entry,omitempty"` // 0 = not set
	TargetExit      float64   `json:"target_exit,omitempty"`  // 0 = not set
	SortOrder       int       `json:"sort_order"`
	AddedAt         time.Time `json:"added_at"`
}

// WatchlistDB is an optional persistence backend for watchlists.
// Implemented by alerts.DB to avoid circular imports (same pattern as SessionDB).
type WatchlistDB interface {
	ExecDDL(ddl string) error
	ExecInsert(query string, args ...any) error
	RawQuery(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
}

// Store is a thread-safe in-memory store for watchlists and their items.
// Optionally backed by SQLite for persistence via SetDB.
type Store struct {
	mu         sync.RWMutex
	watchlists map[string]*Watchlist       // id -> watchlist
	items      map[string][]*WatchlistItem // watchlist_id -> items
	db         WatchlistDB
	logger     *slog.Logger
}

// NewStore creates a new watchlist store.
func NewStore() *Store {
	return &Store{
		watchlists: make(map[string]*Watchlist),
		items:      make(map[string][]*WatchlistItem),
		logger:     slog.Default(),
	}
}

// SetLogger sets the logger for DB error reporting.
func (s *Store) SetLogger(logger *slog.Logger) {
	s.logger = logger
}

// SetDB enables write-through persistence to the given SQLite database.
func (s *Store) SetDB(db WatchlistDB) {
	s.db = db
}

// LoadFromDB populates the in-memory store from the database.
func (s *Store) LoadFromDB() error {
	if s.db == nil {
		return nil
	}
	watchlists, err := loadWatchlists(s.db)
	if err != nil {
		return fmt.Errorf("load watchlists: %w", err)
	}
	items, err := loadItems(s.db)
	if err != nil {
		return fmt.Errorf("load watchlist items: %w", err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, w := range watchlists {
		s.watchlists[w.ID] = w
	}
	for _, item := range items {
		s.items[item.WatchlistID] = append(s.items[item.WatchlistID], item)
	}
	return nil
}

// CreateWatchlist creates a new named watchlist for the user.
// Returns the watchlist ID. Returns error if user already has MaxWatchlistsPerUser.
func (s *Store) CreateWatchlist(email, name string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Count existing watchlists for this user
	count := 0
	for _, w := range s.watchlists {
		if w.Email == email {
			count++
		}
	}
	if count >= MaxWatchlistsPerUser {
		return "", fmt.Errorf("maximum number of watchlists (%d) reached for this user", MaxWatchlistsPerUser)
	}

	now := time.Now()
	w := &Watchlist{
		ID:        uuid.New().String()[:8],
		Email:     email,
		Name:      name,
		SortOrder: count, // append at end
		CreatedAt: now,
		UpdatedAt: now,
	}

	s.watchlists[w.ID] = w
	if s.db != nil {
		if err := saveWatchlist(s.db, w); err != nil {
			s.logger.Error("Failed to persist watchlist", "id", w.ID, "error", err)
		}
	}
	return w.ID, nil
}

// DeleteWatchlist removes a watchlist and all its items.
func (s *Store) DeleteWatchlist(email, watchlistID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.watchlists[watchlistID]
	if !ok {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}
	if w.Email != email {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}

	delete(s.watchlists, watchlistID)
	delete(s.items, watchlistID)

	if s.db != nil {
		if err := deleteWatchlist(s.db, email, watchlistID); err != nil {
			s.logger.Error("Failed to delete watchlist from DB", "id", watchlistID, "error", err)
		}
	}
	return nil
}

// ListWatchlists returns all watchlists for the given email.
// Returns deep copies to prevent callers from mutating shared state.
func (s *Store) ListWatchlists(email string) []*Watchlist {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*Watchlist
	for _, w := range s.watchlists {
		if w.Email == email {
			cp := *w
			result = append(result, &cp)
		}
	}
	return result
}

// ItemCount returns the number of items in a watchlist.
func (s *Store) ItemCount(watchlistID string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.items[watchlistID])
}

// AddItem adds an instrument to a watchlist.
// Returns error if the watchlist has MaxItemsPerWatchlist items.
func (s *Store) AddItem(email, watchlistID string, item *WatchlistItem) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.watchlists[watchlistID]
	if !ok {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}
	if w.Email != email {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}

	existing := s.items[watchlistID]
	if len(existing) >= MaxItemsPerWatchlist {
		return fmt.Errorf("maximum number of items (%d) reached for this watchlist", MaxItemsPerWatchlist)
	}

	// Check for duplicates (same exchange:tradingsymbol)
	for _, it := range existing {
		if it.Exchange == item.Exchange && it.Tradingsymbol == item.Tradingsymbol {
			return fmt.Errorf("%s:%s already in watchlist", item.Exchange, item.Tradingsymbol)
		}
	}

	item.ID = uuid.New().String()[:8]
	item.WatchlistID = watchlistID
	item.Email = email
	item.SortOrder = len(existing)
	item.AddedAt = time.Now()

	s.items[watchlistID] = append(s.items[watchlistID], item)

	// Update watchlist timestamp
	w.UpdatedAt = time.Now()

	if s.db != nil {
		if err := saveItem(s.db, item); err != nil {
			s.logger.Error("Failed to persist watchlist item", "id", item.ID, "error", err)
		}
		if err := updateWatchlistTimestamp(s.db, watchlistID, w.UpdatedAt); err != nil {
			s.logger.Error("Failed to update watchlist timestamp", "id", watchlistID, "error", err)
		}
	}
	return nil
}

// RemoveItem removes an instrument from a watchlist by item ID.
func (s *Store) RemoveItem(email, watchlistID, itemID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	w, ok := s.watchlists[watchlistID]
	if !ok {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}
	if w.Email != email {
		return fmt.Errorf("watchlist %s not found", watchlistID)
	}

	items := s.items[watchlistID]
	for i, it := range items {
		if it.ID == itemID {
			s.items[watchlistID] = append(items[:i], items[i+1:]...)
			w.UpdatedAt = time.Now()
			if s.db != nil {
				if err := deleteItem(s.db, email, itemID); err != nil {
					s.logger.Error("Failed to delete watchlist item from DB", "id", itemID, "error", err)
				}
				if err := updateWatchlistTimestamp(s.db, watchlistID, w.UpdatedAt); err != nil {
					s.logger.Error("Failed to update watchlist timestamp", "id", watchlistID, "error", err)
				}
			}
			return nil
		}
	}
	return fmt.Errorf("item %s not found in watchlist %s", itemID, watchlistID)
}

// GetItems returns copies of all items in a watchlist.
func (s *Store) GetItems(watchlistID string) []*WatchlistItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	items := s.items[watchlistID]
	result := make([]*WatchlistItem, len(items))
	for i, it := range items {
		cp := *it
		result[i] = &cp
	}
	return result
}

// GetAllItems returns all items across all watchlists for a user (for batch LTP).
func (s *Store) GetAllItems(email string) []*WatchlistItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	var result []*WatchlistItem
	for wlID, items := range s.items {
		w, ok := s.watchlists[wlID]
		if !ok || w.Email != email {
			continue
		}
		for _, it := range items {
			cp := *it
			result = append(result, &cp)
		}
	}
	return result
}

// FindWatchlistByName returns the watchlist with the given name for the user.
// Returns nil if not found.
func (s *Store) FindWatchlistByName(email, name string) *Watchlist {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, w := range s.watchlists {
		if w.Email == email && w.Name == name {
			cp := *w
			return &cp
		}
	}
	return nil
}

// FindItemBySymbol finds an item by exchange:tradingsymbol in a watchlist.
// Returns nil if not found.
func (s *Store) FindItemBySymbol(watchlistID, exchange, tradingsymbol string) *WatchlistItem {
	s.mu.RLock()
	defer s.mu.RUnlock()

	for _, it := range s.items[watchlistID] {
		if it.Exchange == exchange && it.Tradingsymbol == tradingsymbol {
			cp := *it
			return &cp
		}
	}
	return nil
}
