package papertrading

import (
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/domain"
)

// Account represents a paper trading account for a user.
//
// InitialCash and CashBalance use the domain.Money value object so the
// engine fails fast on cross-currency comparisons rather than silently
// coercing — same Slice 1 pattern as UserLimits.Max*INR. The zero Money
// (Amount=0, Currency="") is the "empty / not yet funded" sentinel; once
// EnableAccount runs, both fields hold an INR Money. SQLite REAL columns
// stay; we bind via .Float64() and rehydrate via domain.NewINR(scanned)
// on Scan so the wire / persistence shape is unchanged.
type Account struct {
	Email       string
	Enabled     bool
	InitialCash domain.Money
	CashBalance domain.Money
	CreatedAt   time.Time
	ResetAt     time.Time
}

// Order represents a paper trading order.
//
// Price + AveragePrice use domain.Money (Slice 6b) to align the Order
// aggregate with the rest of the papertrading Money sweep:
//   - Price: user-supplied LIMIT/SL limit price; zero Money is the
//     "MARKET / no price set" sentinel (Slice 2 OrderCheckRequest.Price
//     pattern).
//   - AveragePrice: broker-reported fill price; zero Money is the
//     "unfilled" sentinel matching the Slice 6a Position.LastPrice
//     pre-refresh shape.
//
// TriggerPrice stays float64 for now — it's a comparison-only field
// (shouldFill / determineFillPrice predicates in monitor.go) and a
// separate slice can elevate it without coupling to this commit.
//
// SQLite REAL columns unchanged; bind via .Float64(), scan via
// domain.NewINR. JSON wire format unchanged at the orderToMap +
// trades-list seams (.Float64() at the boundary).
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
	Price           domain.Money
	TriggerPrice    float64
	Status          string // OPEN/COMPLETE/CANCELLED/REJECTED
	FilledQuantity  int
	AveragePrice    domain.Money
	PlacedAt        time.Time
	FilledAt        time.Time
	Tag             string
}

// Position represents an open paper trading position.
//
// All monetary fields are domain.Money (Slice 6a complete):
//   - AveragePrice (commit 2): weighted-average via Money.Multiply / Add chains;
//     resets to fillPrice on side-flip.
//   - LastPrice (commit 1): LTP refreshed from the LTPProvider.
//   - PnL (commit 3): derived value = Quantity * (LastPrice - AveragePrice).
//     Negative for losing trades; sign preserved through Money.Sub +
//     Money.Multiply.
//
// SQLite REAL columns unchanged; bind via .Float64(), scan via domain.NewINR.
type Position struct {
	Email         string
	Exchange      string
	Tradingsymbol string
	Product       string
	Quantity      int // positive=long, negative=short
	AveragePrice  domain.Money
	LastPrice     domain.Money
	PnL           domain.Money
}

// Holding represents a paper trading CNC holding.
//
// All monetary fields are domain.Money (Slice 6a). Same semantic as
// Position; weighted-average on additional buys via the Money pipeline.
type Holding struct {
	Email         string
	Exchange      string
	Tradingsymbol string
	Quantity      int
	AveragePrice  domain.Money
	LastPrice     domain.Money
	PnL           domain.Money
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
//
// Foreign-key invariant (DDD aggregate boundary): paper_orders, paper_positions,
// and paper_holdings are children of the paper_accounts aggregate root. Each
// child row's email MUST reference an existing paper_accounts(email). The
// constraint is enforced by SQLite when foreign_keys=ON (set per-connection
// via the DSN _pragma=foreign_keys(1) — see kc/alerts/db.go:dsnWithFKPragma).
//
// ON DELETE CASCADE: deleting an account row purges all dependent orders /
// positions / holdings atomically. In practice the application never hard-
// deletes paper_accounts (DeleteMyAccountUseCase calls Reset+Disable, which
// preserves the row with enabled=0); the cascade is a defence-in-depth
// invariant against schema-bypassing DELETEs.
//
// CREATE TABLE IF NOT EXISTS is idempotent only on a fresh schema — existing
// pre-FK databases (Fly.io prod) keep their old constraint-less tables.
// New environments and all tests get the FK-enforced schema. Schema-as-truth
// going forward.
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
    tag              TEXT NOT NULL DEFAULT '',
    FOREIGN KEY (email) REFERENCES paper_accounts(email) ON DELETE CASCADE
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
    PRIMARY KEY (email, exchange, tradingsymbol, product),
    FOREIGN KEY (email) REFERENCES paper_accounts(email) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS paper_holdings (
    email         TEXT NOT NULL,
    exchange      TEXT NOT NULL,
    tradingsymbol TEXT NOT NULL,
    quantity      INTEGER NOT NULL,
    average_price REAL NOT NULL,
    last_price    REAL NOT NULL DEFAULT 0,
    pnl           REAL NOT NULL DEFAULT 0,
    PRIMARY KEY (email, exchange, tradingsymbol),
    FOREIGN KEY (email) REFERENCES paper_accounts(email) ON DELETE CASCADE
);`
	return s.db.ExecDDL(ddl)
}

// GetAccount retrieves the paper trading account for the given email.
// Returns nil, nil if no account exists.
//
// SQLite REAL → domain.Money rehydration: the underlying column type is
// REAL (float64); we scan into local floats and wrap with domain.NewINR
// so the returned Account presents Money values to engine code. Boundary
// pattern matches kc/riskguard/limits.go LoadLimits (Slice 1).
func (s *Store) GetAccount(email string) (*Account, error) {
	row := s.db.QueryRow(
		`SELECT email, enabled, initial_cash, cash_balance, created_at, reset_at
		 FROM paper_accounts WHERE email = ?`, email)

	var a Account
	var enabled int
	var createdAt, resetAt string
	var initialCash, cashBalance float64
	err := row.Scan(&a.Email, &enabled, &initialCash, &cashBalance, &createdAt, &resetAt)
	if err == sql.ErrNoRows {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("get account: %w", err)
	}
	a.Enabled = enabled == 1
	a.InitialCash = domain.NewINR(initialCash)
	a.CashBalance = domain.NewINR(cashBalance)
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
//
// SQLite REAL boundary: Order.Price + Order.AveragePrice are domain.Money;
// bind via .Float64() at the SQL parameter sites so column types stay REAL.
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
		o.OrderType, o.Product, o.Variety, o.Quantity, o.Price.Float64(), o.TriggerPrice, o.Status,
		o.FilledQuantity, o.AveragePrice.Float64(),
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
//
// SQLite REAL → domain.Money rehydration: scan into local floats and
// wrap with domain.NewINR. Mirrors the Slice 6a Position / Holding
// scan pattern.
func scanOrders(rows *sql.Rows) ([]*Order, error) {
	var orders []*Order
	for rows.Next() {
		var o Order
		var placedAt, filledAt, tag string
		var price, avgPrice float64
		if err := rows.Scan(
			&o.OrderID, &o.Email, &o.Exchange, &o.Tradingsymbol, &o.TransactionType,
			&o.OrderType, &o.Product, &o.Variety, &o.Quantity, &price, &o.TriggerPrice,
			&o.Status, &o.FilledQuantity, &avgPrice, &placedAt, &filledAt, &tag,
		); err != nil {
			return nil, fmt.Errorf("scan order: %w", err)
		}
		o.Price = domain.NewINR(price)
		o.AveragePrice = domain.NewINR(avgPrice)
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
//
// SQLite REAL boundary: AveragePrice, LastPrice, PnL are all domain.Money;
// bind via .Float64() at the SQL parameter sites so column types stay REAL.
func (s *Store) UpsertPosition(p *Position) error {
	return s.db.ExecInsert(
		`INSERT INTO paper_positions (email, exchange, tradingsymbol, product, quantity, average_price, last_price, pnl)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email, exchange, tradingsymbol, product)
		 DO UPDATE SET quantity = ?, average_price = ?, last_price = ?, pnl = ?`,
		p.Email, p.Exchange, p.Tradingsymbol, p.Product, p.Quantity, p.AveragePrice.Float64(), p.LastPrice.Float64(), p.PnL.Float64(),
		p.Quantity, p.AveragePrice.Float64(), p.LastPrice.Float64(), p.PnL.Float64())
}

// GetPositions returns all paper positions for the given email.
//
// SQLite REAL → domain.Money rehydration for AveragePrice, LastPrice, PnL.
// Mirrors the GetAccount pattern from Slice 5.
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
		var avgPrice, lastPrice, pnl float64
		if err := rows.Scan(&p.Email, &p.Exchange, &p.Tradingsymbol, &p.Product,
			&p.Quantity, &avgPrice, &lastPrice, &pnl); err != nil {
			return nil, fmt.Errorf("scan position: %w", err)
		}
		p.AveragePrice = domain.NewINR(avgPrice)
		p.LastPrice = domain.NewINR(lastPrice)
		p.PnL = domain.NewINR(pnl)
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
//
// SQLite REAL boundary: AveragePrice, LastPrice, PnL are all domain.Money;
// bind via .Float64() at the SQL parameter sites.
func (s *Store) UpsertHolding(h *Holding) error {
	return s.db.ExecInsert(
		`INSERT INTO paper_holdings (email, exchange, tradingsymbol, quantity, average_price, last_price, pnl)
		 VALUES (?, ?, ?, ?, ?, ?, ?)
		 ON CONFLICT(email, exchange, tradingsymbol)
		 DO UPDATE SET quantity = ?, average_price = ?, last_price = ?, pnl = ?`,
		h.Email, h.Exchange, h.Tradingsymbol, h.Quantity, h.AveragePrice.Float64(), h.LastPrice.Float64(), h.PnL.Float64(),
		h.Quantity, h.AveragePrice.Float64(), h.LastPrice.Float64(), h.PnL.Float64())
}

// GetHoldings returns all paper holdings for the given email.
//
// SQLite REAL → domain.Money rehydration mirrors GetPositions.
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
		var avgPrice, lastPrice, pnl float64
		if err := rows.Scan(&h.Email, &h.Exchange, &h.Tradingsymbol,
			&h.Quantity, &avgPrice, &lastPrice, &pnl); err != nil {
			return nil, fmt.Errorf("scan holding: %w", err)
		}
		h.AveragePrice = domain.NewINR(avgPrice)
		h.LastPrice = domain.NewINR(lastPrice)
		h.PnL = domain.NewINR(pnl)
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
