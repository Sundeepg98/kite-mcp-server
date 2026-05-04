package ticker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/gokiteconnect/v4/models"

	brokerticker "github.com/zerodha/kite-mcp-server/broker/ticker"
	"github.com/zerodha/kite-mcp-server/broker/zerodha"
)

// Mode aliases the broker-agnostic broker/ticker.Mode so external
// consumers (mcp/ticker_tools.go, mcp/alert_tools.go, mcp/trailing_
// tools.go) keep using kc/ticker.Mode unchanged. Migration target for
// post-launch cleanup: callsites import broker/ticker directly.
type Mode = brokerticker.Mode

// Mode aliases for the broker-agnostic mode constants. Same byte
// values as kiteticker.ModeLTP/ModeQuote/ModeFull (typed string
// "ltp"/"quote"/"full"); existing kc/ticker.ModeLTP callsites
// continue to work unchanged.
const (
	ModeLTP   = brokerticker.ModeLTP
	ModeQuote = brokerticker.ModeQuote
	ModeFull  = brokerticker.ModeFull
)

// TickCallback is invoked on each incoming tick for a user. Carries
// gokiteconnect models.Tick because kc/alerts.Evaluator.Evaluate
// takes that signature today; the broker/ticker.Tick translation
// happens INSIDE wireCallbacks so the kiteticker dependency stays
// hidden from anything outside this package + kc/alerts.
//
// Future cleanup (out of scope for the multi-broker port-adapter
// commit): kc/alerts.Evaluator.Evaluate accepts broker/ticker.Tick;
// this signature swaps too; the round-trip translation in
// wireCallbacks is dropped.
type TickCallback func(email string, tick models.Tick)

// Config holds configuration for creating a new ticker Service.
type Config struct {
	Logger *slog.Logger
	OnTick TickCallback // optional: global tick handler (e.g. alert evaluator)
}

// UserTicker holds a single user's WebSocket ticker connection.
//
// Ticker holds a broker/ticker.Ticker port — production wires
// *zerodha.TickerAdapter (which wraps *kiteticker.Ticker); future
// non-Zerodha adapters slot in here without touching this struct.
type UserTicker struct {
	Email       string
	APIKey      string
	AccessToken string
	Ticker      brokerticker.Ticker
	Cancel      context.CancelFunc
	Connected   bool
	StartedAt   time.Time
	Subscribed  map[uint32]brokerticker.Mode // token -> mode
	conn        tickerConn                   // mockable subscribe/unsubscribe/setmode ops
	mu          sync.RWMutex
}

// Service manages per-user WebSocket ticker connections.
type Service struct {
	tickers map[string]*UserTicker // email -> ticker
	mu      sync.RWMutex
	logger    *slog.Logger
	onTick    TickCallback
}

// New creates a new ticker Service.
func New(cfg Config) *Service {
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}
	return &Service{
		tickers: make(map[string]*UserTicker),
		logger:  logger,
		onTick:  cfg.OnTick,
	}
}

// Start creates and starts a WebSocket ticker for the given user.
// If a ticker is already running for this email, it returns an error.
func (s *Service) Start(email, apiKey, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if email == "" {
		return fmt.Errorf("email is required")
	}

	// Check for existing running ticker
	if ut, ok := s.tickers[email]; ok {
		ut.mu.RLock()
		connected := ut.Connected
		ut.mu.RUnlock()
		if connected {
			return fmt.Errorf("ticker already running for %s", email)
		}
	}

	// Create a new broker-agnostic ticker via the Zerodha adapter.
	// Production today is Zerodha-only; future broker support swaps
	// the factory here without touching the UserTicker struct or the
	// callback wiring.
	t := zerodha.NewTickerAdapter(apiKey, accessToken)

	ctx, cancel := context.WithCancel(context.Background())

	ut := &UserTicker{
		Email:       email,
		APIKey:      apiKey,
		AccessToken: accessToken,
		Ticker:      t,
		conn:        t,
		Cancel:      cancel,
		StartedAt:   time.Now(),
		Subscribed:  make(map[uint32]brokerticker.Mode),
	}

	// Wire callbacks
	s.wireCallbacks(ut, t)

	s.tickers[email] = ut

	// Start serving in a goroutine (blocking call)
	go func() {
		s.logger.Info("Starting ticker", "email", email)
		t.Serve(ctx)
		s.logger.Info("Ticker serve exited", "email", email)
	}()

	return nil
}

// tickerSubscriber is the subset of broker/ticker.Ticker used by onConnect to
// resubscribe tokens after a WebSocket reconnection. Extracted as an interface
// so callback logic can be unit-tested without a real WebSocket.
type tickerSubscriber interface {
	Subscribe(tokens []uint32) error
	SetMode(mode brokerticker.Mode, tokens []uint32) error
}

// tickerConn abstracts the subscribe/unsubscribe/mode operations on a ticker
// connection. *zerodha.TickerAdapter (and any future broker adapter) satisfies
// this. Stored on UserTicker so tests can inject a mock without a WebSocket.
type tickerConn interface {
	Subscribe(tokens []uint32) error
	Unsubscribe(tokens []uint32) error
	SetMode(mode brokerticker.Mode, tokens []uint32) error
}

// callbackRegistrar abstracts the On* methods used by wireCallbacks to register
// event handlers. *zerodha.TickerAdapter satisfies this via the broker/ticker.
// Ticker port. We use a local subset rather than embedding broker/ticker.Ticker
// directly because OnTick on the port takes broker/ticker.TickHandler (Tick
// payload) while we want to wire to onTickReceived which takes models.Tick
// today (kc/alerts.Evaluator boundary). The translation happens INSIDE
// wireCallbacks via brokerToModelsTick.
type callbackRegistrar interface {
	OnConnect(f func())
	OnTick(handler brokerticker.TickHandler)
	OnError(f func(error))
	OnClose(f func(int, string))
	OnReconnect(f func(int, time.Duration))
	OnNoReconnect(f func(int))
}

// brokerToModelsTick translates a broker-agnostic broker/ticker.Tick back
// to gokiteconnect models.Tick for compatibility with kc/alerts.Evaluator
// (which takes models.Tick today). Round-trip is loss-free for the
// Zerodha adapter because translateTick at broker/zerodha/ticker_adapter.go
// fills every field this function reads.
//
// Future cleanup (out of scope for the multi-broker port-adapter commit):
// kc/alerts.Evaluator accepts broker/ticker.Tick; this function disappears
// alongside the TickCallback signature change.
func brokerToModelsTick(tk brokerticker.Tick) models.Tick {
	return models.Tick{
		InstrumentToken:    tk.InstrumentToken,
		LastPrice:          tk.LastPrice,
		LastTradedQuantity: tk.LastQuantity,
		AverageTradePrice:  tk.AverageTradePrice,
		VolumeTraded:       tk.Volume,
		TotalBuyQuantity:   tk.BuyQuantity,
		TotalSellQuantity:  tk.SellQuantity,
		NetChange:          tk.ChangePercent,
		Mode:               string(tk.Mode),
		OHLC: models.OHLC{
			Open:  tk.OHLC.Open,
			High:  tk.OHLC.High,
			Low:   tk.OHLC.Low,
			Close: tk.OHLC.Close,
		},
	}
}

// wireCallbacks sets up all WebSocket event handlers (OnConnect, OnClose,
// OnError, OnTick, OnReconnect, OnNoReconnect) on the given callbackRegistrar,
// binding them to the provided UserTicker. This is shared between Start and
// UpdateToken to eliminate callback-wiring duplication.
func (s *Service) wireCallbacks(ut *UserTicker, t callbackRegistrar) {
	t.OnConnect(func() { s.onConnect(ut, ut.conn) })
	t.OnTick(func(tk brokerticker.Tick) { s.onTickReceived(ut.Email, brokerToModelsTick(tk)) })
	t.OnError(func(err error) { s.onError(ut.Email, err) })
	t.OnClose(func(code int, reason string) { s.onClose(ut, code, reason) })
	t.OnReconnect(func(attempt int, delay time.Duration) { s.onReconnect(ut.Email, attempt, delay) })
	t.OnNoReconnect(func(attempt int) { s.onNoReconnect(ut, attempt) })
}

// onConnect handles the WebSocket connected event: marks the UserTicker as
// connected and resubscribes any previously subscribed tokens.
func (s *Service) onConnect(ut *UserTicker, sub tickerSubscriber) {
	email := ut.Email

	ut.mu.Lock()
	ut.Connected = true
	ut.mu.Unlock()
	s.logger.Info("Ticker connected", "email", email)

	// Resubscribe to previously subscribed tokens on reconnect
	ut.mu.RLock()
	tokens := make([]uint32, 0, len(ut.Subscribed))
	for token := range ut.Subscribed {
		tokens = append(tokens, token)
	}
	ut.mu.RUnlock()

	if len(tokens) > 0 {
		if err := sub.Subscribe(tokens); err != nil {
			s.logger.Error("Failed to resubscribe on connect", "email", email, "error", err)
		}
		// Restore modes per-token group
		modeTokens := make(map[brokerticker.Mode][]uint32)
		ut.mu.RLock()
		for token, mode := range ut.Subscribed {
			modeTokens[mode] = append(modeTokens[mode], token)
		}
		ut.mu.RUnlock()
		for mode, toks := range modeTokens {
			if err := sub.SetMode(mode, toks); err != nil {
				s.logger.Error("Failed to restore mode on connect", "email", email, "mode", mode, "error", err)
			}
		}
	}
}

// onTickReceived dispatches an incoming tick to the global OnTick callback.
func (s *Service) onTickReceived(email string, tick models.Tick) {
	if s.onTick != nil {
		s.onTick(email, tick)
	}
}

// onError logs a WebSocket error.
func (s *Service) onError(email string, err error) {
	s.logger.Error("Ticker error", "email", email, "error", err)
}

// onClose handles the WebSocket closed event.
func (s *Service) onClose(ut *UserTicker, code int, reason string) {
	ut.mu.Lock()
	ut.Connected = false
	ut.mu.Unlock()
	s.logger.Info("Ticker closed", "email", ut.Email, "code", code, "reason", reason)
}

// onReconnect logs a WebSocket reconnection attempt.
func (s *Service) onReconnect(email string, attempt int, delay time.Duration) {
	s.logger.Info("Ticker reconnecting", "email", email, "attempt", attempt, "delay", delay)
}

// onNoReconnect handles the event when the ticker gives up reconnecting.
func (s *Service) onNoReconnect(ut *UserTicker, attempt int) {
	s.logger.Warn("Ticker gave up reconnecting", "email", ut.Email, "attempts", attempt)
	ut.mu.Lock()
	ut.Connected = false
	ut.mu.Unlock()
}

// Stop stops the ticker for the given user.
func (s *Service) Stop(email string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	ut, ok := s.tickers[email]
	if !ok {
		return fmt.Errorf("no ticker found for %s", email)
	}

	ut.Cancel()
	delete(s.tickers, email)
	s.logger.Info("Ticker stopped", "email", email)
	return nil
}

// UpdateToken stops the existing ticker and starts a new one with the fresh token.
// Preserves subscriptions across the restart.
// The entire operation is serialized under s.mu to prevent concurrent callers from
// seeing inconsistent state between stop and start.
func (s *Service) UpdateToken(email, apiKey, accessToken string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	oldUT, ok := s.tickers[email]
	if !ok {
		return fmt.Errorf("no ticker found for %s", email)
	}

	// Capture current subscriptions before stopping
	oldUT.mu.RLock()
	subs := make(map[uint32]brokerticker.Mode, len(oldUT.Subscribed))
	for token, mode := range oldUT.Subscribed {
		subs[token] = mode
	}
	oldUT.mu.RUnlock()

	// Stop the old ticker directly (not via s.Stop which would re-acquire s.mu)
	oldUT.Cancel()
	delete(s.tickers, email)
	s.logger.Info("Ticker stopped for token update", "email", email)

	// Create a new broker-agnostic ticker via the Zerodha adapter.
	t := zerodha.NewTickerAdapter(apiKey, accessToken)

	ctx, cancel := context.WithCancel(context.Background())

	newUT := &UserTicker{
		Email:       email,
		APIKey:      apiKey,
		AccessToken: accessToken,
		Ticker:      t,
		conn:        t,
		Cancel:      cancel,
		StartedAt:   time.Now(),
		Subscribed:  subs, // Set subscriptions BEFORE wiring OnConnect
	}

	// Wire callbacks
	s.wireCallbacks(newUT, t)

	s.tickers[email] = newUT

	// Start serving in a goroutine (blocking call)
	go func() {
		s.logger.Info("Starting ticker", "email", email)
		t.Serve(ctx)
		s.logger.Info("Ticker serve exited", "email", email)
	}()

	s.logger.Info("Ticker token updated", "email", email, "subscriptions_preserved", len(subs))
	return nil
}

// Subscribe subscribes the user's ticker to the given instrument tokens with the specified mode.
func (s *Service) Subscribe(email string, tokens []uint32, mode brokerticker.Mode) error {
	s.mu.RLock()
	ut, ok := s.tickers[email]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no ticker found for %s — call start_ticker first", email)
	}

	// Store subscriptions
	ut.mu.Lock()
	for _, token := range tokens {
		ut.Subscribed[token] = mode
	}
	ut.mu.Unlock()

	// If connected, subscribe immediately
	ut.mu.RLock()
	connected := ut.Connected
	ut.mu.RUnlock()

	if connected {
		if err := ut.conn.Subscribe(tokens); err != nil {
			return fmt.Errorf("subscribe failed: %w", err)
		}
		if err := ut.conn.SetMode(mode, tokens); err != nil {
			return fmt.Errorf("set mode failed: %w", err)
		}
	}
	// If not yet connected, subscriptions will be applied in OnConnect callback

	s.logger.Info("Subscribed instruments", "email", email, "tokens", tokens, "mode", mode)
	return nil
}

// Unsubscribe removes instrument tokens from the user's ticker.
func (s *Service) Unsubscribe(email string, tokens []uint32) error {
	s.mu.RLock()
	ut, ok := s.tickers[email]
	s.mu.RUnlock()

	if !ok {
		return fmt.Errorf("no ticker found for %s", email)
	}

	// Remove from stored subscriptions
	ut.mu.Lock()
	for _, token := range tokens {
		delete(ut.Subscribed, token)
	}
	ut.mu.Unlock()

	// If connected, unsubscribe immediately
	ut.mu.RLock()
	connected := ut.Connected
	ut.mu.RUnlock()

	if connected {
		if err := ut.conn.Unsubscribe(tokens); err != nil {
			return fmt.Errorf("unsubscribe failed: %w", err)
		}
	}

	s.logger.Info("Unsubscribed instruments", "email", email, "tokens", tokens)
	return nil
}

// GetStatus returns the current status of a user's ticker.
func (s *Service) GetStatus(email string) (*Status, error) {
	s.mu.RLock()
	ut, ok := s.tickers[email]
	s.mu.RUnlock()

	if !ok {
		return &Status{Running: false}, nil
	}

	ut.mu.RLock()
	defer ut.mu.RUnlock()

	subs := make([]SubscriptionInfo, 0, len(ut.Subscribed))
	for token, mode := range ut.Subscribed {
		subs = append(subs, SubscriptionInfo{
			InstrumentToken: token,
			Mode:            string(mode),
		})
	}

	return &Status{
		Running:       true,
		Connected:     ut.Connected,
		StartedAt:     ut.StartedAt,
		Uptime:        time.Since(ut.StartedAt).String(),
		Subscriptions: subs,
	}, nil
}

// IsRunning returns true if a ticker is active for the given email.
func (s *Service) IsRunning(email string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	_, ok := s.tickers[email]
	return ok
}

// UserTickerInfo is a summary of a user's ticker connection for admin display.
type UserTickerInfo struct {
	Email         string    `json:"email"`
	Connected     bool      `json:"connected"`
	StartedAt     time.Time `json:"started_at"`
	Subscriptions int       `json:"subscriptions"`
}

// ListAll returns a summary of all active ticker connections.
func (s *Service) ListAll() []UserTickerInfo {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]UserTickerInfo, 0, len(s.tickers))
	for _, ut := range s.tickers {
		ut.mu.RLock()
		info := UserTickerInfo{
			Email:         ut.Email,
			Connected:     ut.Connected,
			StartedAt:     ut.StartedAt,
			Subscriptions: len(ut.Subscribed),
		}
		ut.mu.RUnlock()
		out = append(out, info)
	}
	return out
}

// Shutdown stops all running tickers.
func (s *Service) Shutdown() {
	s.mu.Lock()
	defer s.mu.Unlock()

	for email, ut := range s.tickers {
		ut.Cancel()
		s.logger.Info("Ticker stopped during shutdown", "email", email)
	}
	s.tickers = make(map[string]*UserTicker)
	s.logger.Info("Ticker service shutdown complete")
}
