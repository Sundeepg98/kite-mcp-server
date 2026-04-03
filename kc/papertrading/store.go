package papertrading

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
)

// Account represents a paper trading account for a user.
type Account struct {
	Email       string
	Enabled     bool
	InitialCash float64
	CashBalance float64
	CreatedAt   time.Time
	ResetAt     time.Time
}

// Order represents a paper trading order.
type Order struct {
	OrderID         string
	Email           string
	Exchange        string
	Tradingsymbol   string
	TransactionType string // BUY/SELL
	OrderType       string // MARKET/LIMIT/SL/SL-M
	Product         string // CNC/MIS/NRML
	Variety         string
	Quantity        int
	Price           float64
	TriggerPrice    float64
	Status          string // OPEN/COMPLETE/CANCELLED/REJECTED
	FilledQuantity  int
	AveragePrice    float64
	PlacedAt        time.Time
	FilledAt        time.Time
	Tag             string
}

// Position represents an open paper trading position.
type Position struct {
	Email         string
	Exchange      string
	Tradingsymbol string
	Product       string
	Quantity      int // positive=long, negative=short
	AveragePrice  float64
	LastPrice     float64
	PnL           float64
}

// Holding represents a paper trading CNC holding.
type Holding struct {
	Email         string
	Exchange      string
	Tradingsymbol string
	Quantity      int
	AveragePrice  float64
	LastPrice     float64
	PnL           float64
}

// Store provides SQLite persistence for paper trading data.
type Store struct {
	db     *alerts.DB
	logger *slog.Logger
}

// NewStore creates a new paper trading store backed by the given alerts DB.
func NewStore(db *alerts.DB, logger *slog.Logger) *Store {
	return &Store{db: db, logger: logger}
}

// InitTables creates the paper trading tables if they don't already exist.
func (s *Store) InitTables() error {
	ddl := `
CREATE TABLE IF NOT EXISTS paper_accounts (
    email        TEXT PRIMARY KEY,
    enabled      INTEGER NOT NULL DEFAULT 1,
    initial_cash REAL NOT NULL,
    cash_balance REAL NOT NULL,
    created_at   TEXT NOT NULL,
    reset_at     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS paper_orders (
    order_id         TEXT PRIMARY KEY,
    email            TEXT NOT NULL,
    exchange         TEXT NOT NULL,
    tradingsymbol    TEXT NOT NULL,
    transaction_type TEXT NOT NULL CHECK(transaction_type IN ('BUY','SELL')),
    order_type       TEXT NOT NULL,
    product          TEXT NOT NULL,
    variety          TEXT NOT NULL DEFAULT 'regular',
    quantity         INTEGER NOT NULL,
    price            REAL NOT NULL DEFAULT 0,
    trigger_price    REAL NOT NULL DEFAULT 0,
    status           TEXT NOT NULL CHECK(status IN ('OPEN','COMPLETE','CANCELLED','REJECTED')),
    filled_quantity  INTEGER NOT NULL DEFAULT 0,
    average_price    REAL NOT NULL DEFAULT 0,
    placed_at        TEXT NOT NULL,
    filled_at        TEXT,
    tag              TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_paper_orders_email ON paper_orders(email);
CREATE INDEX IF NOT EXISTS idx_paper_orders_status ON paper_orders(status);

CREATE TABLE IF NOT EXISTS paper_positions (
    email         TEXT NOT NULL,
    exchange      TEXT NOT NULL,
    tradingsymbol TEXT NOT NULL,
    product       TEXT NOT NULL,
    quantity      INTEGER NOT NULL,
    average_price REAL NOT NULL,
    last_price    REAL NOT NULL DEFAULT 0,
    pnl           REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (email, exchange, tradingsymbol, product)
);

CREATE TABLE IF NOT EXISTS paper_holdings (
    email         TEXT NOT NULL,
    exchange      TEXT NOT NULL,
    tradingsymbol TEXT NOT NULL,
    quantity      INTEGER NOT NULL,
    average_price REAL NOT NULL,
    last_price    REAL NOT NULL DEFAULT 0,
    pnl           REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (email, exchange, tradingsymbol)
);`
	return s.db.ExecDDL(ddl)
}

// GetAccount retrieves the paper trading account for the given email.
// Returns nil, nil if no account exists.
func (s *Store) GetAccount(email string) (*Account, error) {
	row := s.db.QueryRow(
		`SELECT email, enabled, initial_cash, cash_balance, created_at, reset_at
		 FROM paper_accounts WHERE email = ?`, email)

	var a Account
	var enabled int
	var createdAt, resetAt string
	err := row.Scan(&a.Email, &enabled, &a.InitialCash, &a.CashBalance, &createdAt, &resetAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	a.Enabled = enabled == 1
	a.CreatedAt, _ = time.Parse(time.RFC3339, createdAt)
	a.ResetAt, _ = time.Parse(time.RFC3339, resetAt)
	return &a, nil
}

// EnableAccount creates or updates a paper trading account with the given initial cash.
func (s *Store) EnableAccount(email string, initialCash float64) error {
	now := time.Now().UTC().Format(time.RFC3339)
	return s.db.ExecInsert(
		`INSERT INTO paper_accounts (email, enabled, initial_cash, cash_balance, created_at, reset_at)
		 VALUES (?, 1, ?, ?, ?, ?)
		 ON CONFLICT(email) DO UPDATE SET enabled = 1, initial_cash = ?, cash_balance = ?, reset_at = ?`,
		email, initialCash, initialCash, now, now,
		initialCash, initialCash, now)
}

// DisableAccount disables paper trading for the given email.
func (s *Store) DisableAccount(email string) error {
	return s.db.ExecInsert(
		`UPDATE paper_accounts SET enabled = 0 WHERE email = ?`, email)
}

// UpdateCashBalance updates the cash balance for the given account.
func (s *Store) UpdateCashBalance(email string, balance float64) error {
	return s.db.ExecInsert(
		`UPDATE paper_accounts SET cash_balance = ? WHERE email = ?`, balance, email)
}

// InsertOrder inserts a new paper trading order.
func (s *Store) InsertOrder(o *Order) error {
	filledAt := ""
	if !o.FilledAt.IsZero() {
		filledAt = o.FilledAt.UTC().Format(time.RFC3339)
	}
	return s.db.ExecInsert(
		`INSERT INTO paper_orders (order_id, email, exchange, tradingsymbol, transaction_type,
		 order_type, product, variety, quantity, price, trigger_price, status,
		 filled_quantity, average_price, placed_at, filled_at, tag)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.OrderID, o.Email, o.Exchange, o.Tradingsymbol, o.TransactionType,
		o.OrderType, o.Product, o.Variety, o.Quantity, o.Price, o.TriggerPrice, o.Status,
		o.FilledQuantity, o.AveragePrice,
		o.PlacedAt.UTC().Format(time.RFC3339), filledAt, o.Tag)
}

// UpdateOrderStatus updates the status, filled quantity, and average price of an order.
func (s *Store) UpdateOrderStatus(orderID, status string, filledQty int, avgPrice float64) error {
	filledAt := ""
	if status == "COMPLETE" || status == "CANCELLED" || status == "REJECTED" {
		filledAt = time.Now().UTC().Format(time.RFC3339)
	}
	return s.db.ExecInsert(
		`UPDATE paper_orders SET status = ?, filled_quantity = ?, average_price = ?, filled_at = ?
		 WHERE order_id = ?`,
		status, filledQty, avgPrice, filledAt, orderID)
}

// GetOrders returns all paper orders for the given email, most recent first.
func (s *Store) GetOrders(email string) ([]*Order, error) {
	rows, err := s.db.RawQuery(
		`SELECT order_id, email, exchange, tradingsymbol, transaction_type,
		 order_type, product, variety, quantity, price, trigger_price, status,
		 filled_quantity, average_price, placed_at, filled_at, tag
		 FROM paper_orders WHERE email = ? ORDER BY placed_at DESC`, email)
	if err != nil {
		return nil, fmt.Errorf("get orders: %w", err)
	}
	defer rows.Close()
	return scanOrders(rows)
}

// GetOpenOrders returns all OPEN paper orders for the given email.
func (s *Store) GetOpenOrders(email string) ([]*Order, error) {
	rows, err := s.db.RawQuery(
		`SELECT order_id, email, exchange, tradingsymbol, transaction_type,
		 order_type, product, variety, quantity, price, trigger_price, status,
		 filled_quantity, average_price, placed_at, filled_at, tag
		 FROM paper_orders WHERE email = ? AND status = 'OPEN' ORDER BY placed_at DESC`, email)
	if err != nil {
		return nil, fmt.Errorf("get open orders: %w", err)
	}
	defer rows.Close()
	return scanOrders(rows)
}

// GetOrder returns a single order by ID.
func (s *Store) GetOrder(orderID string) (*Order, error) {
	rows, err := s.db.RawQuery(
		`SELECT order_id, email, exchange, tradingsymbol, transaction_type,
		 order_type, product, variety, quantity, price, trigger_price, status,
		 filled_quantity, average_price, placed_at, filled_at, tag
		 FROM paper_orders WHERE order_id = ?`, orderID)
	if err != nil {
		return nil, fmt.Errorf("get order: %w", err)
	}
	defer rows.Close()

	orders, err := scanOrders(rows)
	if err != nil {
		return nil, err
	}
	if len(orders) == 0 {
		return nil, fmt.Errorf("order %s not found", orderID)
	}
	return orders[0], nil
}

// scanOrders scans rows into a slice of Order pointers.
func scanOrders(rows *sql.Rows) ([]*Order, error) {
	var orders []*Order
	for rows.Next() {
		var o Order
		var placedAt, filledAt, tag string
		if err := rows.Scan(
			&o.OrderID, &o.Email, &o.Exchange, &o.Tradingsymbol, &o.TransactionType,
			&o.OrderType, &o.Product, &o.Variety, &o.Quantity, &o.Price, &o.TriggerPrice,
			&o.Status, &o.FilledQuantity, &o.AveragePrice, &placedAt, &filledAt, &tag,
		); err != nil {
			return nil, fmt.Errorf("scan order: %w", err)
		}
		o.PlacedAt, _ = time.Parse(time.RFC3339, placedAt)
		if filledAt != "" {
			o.FilledAt, _ = time.Parse(time.RFC3339, filledAt)
		}
		o.Tag = tag
		orders = append(orders, &o)
	}
	return orders, rows.Err()
}

// UpsertPosition inserts or updates a paper position.
func (s *Store) UpsertPosition(p *Position) error {
	return s.db.ExecInsert(
		`INSERT INTO paper_positions (email, exchange, tradingsymbol, product, quantity, average_price, last_price, pnl)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email, exchange, tradingsymbol, product)
		 DO UPDATE SET quantity = ?, average_price = ?, last_price = ?, pnl = ?`,
		p.Email, p.Exchange, p.Tradingsymbol, p.Product, p.Quantity, p.AveragePrice, p.LastPrice, p.PnL,
		p.Quantity, p.AveragePrice, p.LastPrice, p.PnL)
}

// GetPositions returns all paper positions for the given email.
func (s *Store) GetPositions(email string) ([]*Position, error) {
	rows, err := s.db.RawQuery(
		`SELECT email, exchange, tradingsymbol, product, quantity, average_price, last_price, pnl
		 FROM paper_positions WHERE email = ?`, email)
	if err != nil {
		return nil, fmt.Errorf("get positions: %w", err)
	}
	defer rows.Close()

	var positions []*Position
	for rows.Next() {
		var p Position
		if err := rows.Scan(&p.Email, &p.Exchange, &p.Tradingsymbol, &p.Product,
			&p.Quantity, &p.AveragePrice, &p.LastPrice, &p.PnL); err != nil {
			return nil, fmt.Errorf("scan position: %w", err)
		}
		positions = append(positions, &p)
	}
	return positions, rows.Err()
}

// DeletePosition removes a paper position.
func (s *Store) DeletePosition(email, exchange, symbol, product string) error {
	return s.db.ExecInsert(
		`DELETE FROM paper_positions WHERE email = ? AND exchange = ? AND tradingsymbol = ? AND product = ?`,
		email, exchange, symbol, product)
}

// UpsertHolding inserts or updates a paper holding.
func (s *Store) UpsertHolding(h *Holding) error {
	return s.db.ExecInsert(
		`INSERT INTO paper_holdings (email, exchange, tradingsymbol, quantity, average_price, last_price, pnl)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email, exchange, tradingsymbol)
		 DO UPDATE SET quantity = ?, average_price = ?, last_price = ?, pnl = ?`,
		h.Email, h.Exchange, h.Tradingsymbol, h.Quantity, h.AveragePrice, h.LastPrice, h.PnL,
		h.Quantity, h.AveragePrice, h.LastPrice, h.PnL)
}

// GetHoldings returns all paper holdings for the given email.
func (s *Store) GetHoldings(email string) ([]*Holding, error) {
	rows, err := s.db.RawQuery(
		`SELECT email, exchange, tradingsymbol, quantity, average_price, last_price, pnl
		 FROM paper_holdings WHERE email = ?`, email)
	if err != nil {
		return nil, fmt.Errorf("get holdings: %w", err)
	}
	defer rows.Close()

	var holdings []*Holding
	for rows.Next() {
		var h Holding
		if err := rows.Scan(&h.Email, &h.Exchange, &h.Tradingsymbol,
			&h.Quantity, &h.AveragePrice, &h.LastPrice, &h.PnL); err != nil {
			return nil, fmt.Errorf("scan holding: %w", err)
		}
		holdings = append(holdings, &h)
	}
	return holdings, rows.Err()
}

// GetAllOpenOrders returns all OPEN paper orders across all users.
func (s *Store) GetAllOpenOrders() ([]*Order, error) {
	rows, err := s.db.RawQuery(
		`SELECT order_id, email, exchange, tradingsymbol, transaction_type,
		 order_type, product, variety, quantity, price, trigger_price, status,
		 filled_quantity, average_price, placed_at, filled_at, tag
		 FROM paper_orders WHERE status = 'OPEN' ORDER BY placed_at ASC`)
	if err != nil {
		return nil, fmt.Errorf("get all open orders: %w", err)
	}
	defer rows.Close()
	return scanOrders(rows)
}

// ResetAccount deletes all orders, positions, and holdings for the given email
// and resets the cash balance to the initial amount.
func (s *Store) ResetAccount(email string) error {
	// Delete orders
	if err := s.db.ExecInsert(`DELETE FROM paper_orders WHERE email = ?`, email); err != nil {
		return fmt.Errorf("reset orders: %w", err)
	}
	// Delete positions
	if err := s.db.ExecInsert(`DELETE FROM paper_positions WHERE email = ?`, email); err != nil {
		return fmt.Errorf("reset positions: %w", err)
	}
	// Delete holdings
	if err := s.db.ExecInsert(`DELETE FROM paper_holdings WHERE email = ?`, email); err != nil {
		return fmt.Errorf("reset holdings: %w", err)
	}
	// Reset cash to initial amount
	now := time.Now().UTC().Format(time.RFC3339)
	return s.db.ExecInsert(
		`UPDATE paper_accounts SET cash_balance = initial_cash, reset_at = ? WHERE email = ?`,
		now, email)
}
