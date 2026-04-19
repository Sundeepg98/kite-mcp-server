package watchlist

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWatchlistStore_CreateAndGet(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, err := s.CreateWatchlist("alice@example.com", "Tech Stocks")
	require.NoError(t, err)
	assert.NotEmpty(t, id)

	// List should contain the watchlist.
	wls := s.ListWatchlists("alice@example.com")
	require.Len(t, wls, 1)
	assert.Equal(t, "Tech Stocks", wls[0].Name)
	assert.Equal(t, "alice@example.com", wls[0].Email)
	assert.Equal(t, id, wls[0].ID)
}

func TestWatchlistStore_List(t *testing.T) {
	t.Parallel()
	s := NewStore()

	_, err := s.CreateWatchlist("bob@example.com", "Watchlist A")
	require.NoError(t, err)
	_, err = s.CreateWatchlist("bob@example.com", "Watchlist B")
	require.NoError(t, err)
	_, err = s.CreateWatchlist("other@example.com", "Other User")
	require.NoError(t, err)

	bobs := s.ListWatchlists("bob@example.com")
	assert.Len(t, bobs, 2)

	others := s.ListWatchlists("other@example.com")
	assert.Len(t, others, 1)

	nobodys := s.ListWatchlists("nobody@example.com")
	assert.Len(t, nobodys, 0)
}

func TestWatchlistStore_Delete(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, err := s.CreateWatchlist("alice@example.com", "To Delete")
	require.NoError(t, err)

	err = s.DeleteWatchlist("alice@example.com", id)
	require.NoError(t, err)

	wls := s.ListWatchlists("alice@example.com")
	assert.Len(t, wls, 0)
}

func TestWatchlistStore_DeleteWrongUser(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, err := s.CreateWatchlist("alice@example.com", "Alice's List")
	require.NoError(t, err)

	err = s.DeleteWatchlist("bob@example.com", id)
	assert.Error(t, err, "deleting another user's watchlist should fail")

	// Alice should still see it.
	wls := s.ListWatchlists("alice@example.com")
	assert.Len(t, wls, 1)
}

func TestWatchlistStore_DeleteNonExistent(t *testing.T) {
	t.Parallel()
	s := NewStore()

	err := s.DeleteWatchlist("alice@example.com", "nonexistent")
	assert.Error(t, err)
}

func TestWatchlistStore_MaxWatchlists(t *testing.T) {
	t.Parallel()
	s := NewStore()

	for i := 0; i < MaxWatchlistsPerUser; i++ {
		_, err := s.CreateWatchlist("alice@example.com", "WL")
		require.NoError(t, err)
	}

	_, err := s.CreateWatchlist("alice@example.com", "One More")
	assert.Error(t, err, "should reject when at MaxWatchlistsPerUser")
	assert.Contains(t, err.Error(), "maximum")
}

func TestWatchlistStore_AddItem(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, err := s.CreateWatchlist("alice@example.com", "Tech")
	require.NoError(t, err)

	err = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	require.NoError(t, err)

	items := s.GetItems(id)
	require.Len(t, items, 1)
	assert.Equal(t, "NSE", items[0].Exchange)
	assert.Equal(t, "RELIANCE", items[0].Tradingsymbol)
	assert.NotEmpty(t, items[0].ID)
	assert.Equal(t, id, items[0].WatchlistID)
	assert.Equal(t, "alice@example.com", items[0].Email)
}

func TestWatchlistStore_AddItem_Duplicate(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Dup Test")

	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})

	err := s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})
	assert.Error(t, err, "duplicate symbol should be rejected")
	assert.Contains(t, err.Error(), "already in watchlist")
}

func TestWatchlistStore_AddItem_WrongUser(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Alice's List")

	err := s.AddItem("bob@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "TCS",
	})
	assert.Error(t, err, "wrong user should be rejected")
}

func TestWatchlistStore_AddItem_NonExistentWatchlist(t *testing.T) {
	t.Parallel()
	s := NewStore()

	err := s.AddItem("alice@example.com", "nonexistent", &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "TCS",
	})
	assert.Error(t, err)
}

func TestWatchlistStore_AddItem_MaxItems(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Full")

	for i := 0; i < MaxItemsPerWatchlist; i++ {
		err := s.AddItem("alice@example.com", id, &WatchlistItem{
			Exchange:      "NSE",
			Tradingsymbol: "SYM" + string(rune('A'+i%26)) + string(rune('0'+i/26)),
		})
		require.NoError(t, err)
	}

	err := s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "OVERFLOW",
	})
	assert.Error(t, err, "should reject when at MaxItemsPerWatchlist")
	assert.Contains(t, err.Error(), "maximum")
}

func TestWatchlistStore_RemoveItem(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Remove Test")

	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})

	items := s.GetItems(id)
	require.Len(t, items, 2)

	err := s.RemoveItem("alice@example.com", id, items[0].ID)
	require.NoError(t, err)

	items = s.GetItems(id)
	assert.Len(t, items, 1)
	assert.Equal(t, "INFY", items[0].Tradingsymbol)
}

func TestWatchlistStore_RemoveItem_WrongUser(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Protected")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "TCS",
	})
	items := s.GetItems(id)
	require.Len(t, items, 1)

	err := s.RemoveItem("bob@example.com", id, items[0].ID)
	assert.Error(t, err, "wrong user should be rejected")

	// Item should still exist.
	assert.Len(t, s.GetItems(id), 1)
}

func TestWatchlistStore_RemoveItem_NotFound(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Test")

	err := s.RemoveItem("alice@example.com", id, "nonexistent-item")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not found")
}

func TestWatchlistStore_FindByName(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.CreateWatchlist("alice@example.com", "Tech Stocks")
	s.CreateWatchlist("alice@example.com", "Pharma")

	found := s.FindWatchlistByName("alice@example.com", "Tech Stocks")
	require.NotNil(t, found)
	assert.Equal(t, "Tech Stocks", found.Name)

	notFound := s.FindWatchlistByName("alice@example.com", "Nonexistent")
	assert.Nil(t, notFound)

	wrongUser := s.FindWatchlistByName("bob@example.com", "Tech Stocks")
	assert.Nil(t, wrongUser)
}

func TestWatchlistStore_FindItemBySymbol(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Test")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})

	found := s.FindItemBySymbol(id, "NSE", "RELIANCE")
	require.NotNil(t, found)
	assert.Equal(t, "RELIANCE", found.Tradingsymbol)

	notFound := s.FindItemBySymbol(id, "NSE", "INFY")
	assert.Nil(t, notFound)

	notFound2 := s.FindItemBySymbol("nonexistent", "NSE", "RELIANCE")
	assert.Nil(t, notFound2)
}

func TestWatchlistStore_GetAllItems(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id1, _ := s.CreateWatchlist("alice@example.com", "WL1")
	id2, _ := s.CreateWatchlist("alice@example.com", "WL2")
	s.CreateWatchlist("bob@example.com", "Bob's WL")

	_ = s.AddItem("alice@example.com", id1, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	_ = s.AddItem("alice@example.com", id2, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})

	allAlice := s.GetAllItems("alice@example.com")
	assert.Len(t, allAlice, 2)

	allBob := s.GetAllItems("bob@example.com")
	assert.Len(t, allBob, 0)
}

func TestWatchlistStore_ItemCount(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Count Test")
	assert.Equal(t, 0, s.ItemCount(id))

	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})
	assert.Equal(t, 1, s.ItemCount(id))

	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "INFY",
	})
	assert.Equal(t, 2, s.ItemCount(id))
}

func TestWatchlistStore_DeleteByEmail(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.CreateWatchlist("alice@example.com", "WL1")
	s.CreateWatchlist("alice@example.com", "WL2")
	s.CreateWatchlist("bob@example.com", "Bob's WL")

	s.DeleteByEmail("alice@example.com")

	assert.Len(t, s.ListWatchlists("alice@example.com"), 0)
	assert.Len(t, s.ListWatchlists("bob@example.com"), 1, "bob's watchlist should survive")
}

func TestWatchlistStore_DeepCopy(t *testing.T) {
	t.Parallel()
	s := NewStore()

	id, _ := s.CreateWatchlist("alice@example.com", "Copy Test")
	_ = s.AddItem("alice@example.com", id, &WatchlistItem{
		Exchange:      "NSE",
		Tradingsymbol: "RELIANCE",
	})

	// Mutating returned items should NOT affect the store.
	items := s.GetItems(id)
	items[0].Tradingsymbol = "MUTATED"

	freshItems := s.GetItems(id)
	assert.Equal(t, "RELIANCE", freshItems[0].Tradingsymbol,
		"store should return deep copies, not shared references")
}

func TestWatchlistStore_ListDeepCopy(t *testing.T) {
	t.Parallel()
	s := NewStore()

	s.CreateWatchlist("alice@example.com", "Original")

	wls := s.ListWatchlists("alice@example.com")
	wls[0].Name = "MUTATED"

	fresh := s.ListWatchlists("alice@example.com")
	assert.Equal(t, "Original", fresh[0].Name,
		"ListWatchlists should return deep copies")
}
