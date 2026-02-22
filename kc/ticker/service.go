package ticker

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	kiteticker "github.com/zerodha/gokiteconnect/v4/ticker"
	"github.com/zerodha/gokiteconnect/v4/models"
)

// Mode is an alias for kiteticker.Mode.
type Mode = kiteticker.Mode

// Mode aliases for kiteticker modes.
const (
	ModeLTP   = kiteticker.ModeLTP
	ModeQuote = kiteticker.ModeQuote
	ModeFull  = kiteticker.ModeFull
)

// TickCallback is invoked on each incoming tick for a user.
type TickCallback func(email string, tick models.Tick)

// TickListener is a per-stream tick handler (e.g. SSE dashboard stream).
type TickListener func(tick models.Tick)

// Config holds configuration for creating a new ticker Service.
type Config struct {
	Logger *slog.Logger
	OnTick TickCallback // optional: global tick handler (e.g. alert evaluator)
}

// UserTicker holds a single user's WebSocket ticker connection.
type UserTicker struct {
	Email       string
	APIKey      string
	AccessToken string
	Ticker      *kiteticker.Ticker
	Cancel      context.CancelFunc
	Connected   bool
	StartedAt   time.Time
	Subscribed  map[uint32]kiteticker.Mode // token -> mode
	mu          sync.RWMutex
}

// Service manages per-user WebSocket ticker connections.
type Service struct {
	tickers   map[string]*UserTicker                    // email -> ticker
	listeners map[string]map[string]TickListener        // email -> listenerID -> callback
	mu        sync.RWMutex
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
		tickers:   make(map[string]*UserTicker),
		listeners: make(map[string]map[string]TickListener),
		logger:    logger,
		onTick:    cfg.OnTick,
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
	if ut, ok := s.tickers[email]; ok && ut.Connected {
		return fmt.Errorf("ticker already running for %s", email)
	}

	// Create a new Kite Ticker
	t := kiteticker.New(apiKey, accessToken)
	t.SetAutoReconnect(true)
	t.SetReconnectMaxRetries(300)

	ctx, cancel := context.WithCancel(context.Background())

	ut := &UserTicker{
		Email:       email,
		APIKey:      apiKey,
		AccessToken: accessToken,
		Ticker:      t,
		Cancel:      cancel,
		StartedAt:   time.Now(),
		Subscribed:  make(map[uint32]kiteticker.Mode),
	}

	// Wire callbacks
	t.OnConnect(func() {
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
			if err := t.Subscribe(tokens); err != nil {
				s.logger.Error("Failed to resubscribe on connect", "email", email, "error", err)
			}
			// Restore modes per-token group
			modeTokens := make(map[kiteticker.Mode][]uint32)
			ut.mu.RLock()
			for token, mode := range ut.Subscribed {
				modeTokens[mode] = append(modeTokens[mode], token)
			}
			ut.mu.RUnlock()
			for mode, toks := range modeTokens {
				if err := t.SetMode(mode, toks); err != nil {
					s.logger.Error("Failed to restore mode on connect", "email", email, "mode", mode, "error", err)
				}
			}
		}
	})

	t.OnTick(func(tick models.Tick) {
		// Global tick handler (alert evaluator)
		if s.onTick != nil {
			s.onTick(email, tick)
		}
		// Per-stream listeners (SSE dashboard streams)
		s.mu.RLock()
		if emailListeners, ok := s.listeners[email]; ok {
			for _, listener := range emailListeners {
				listener(tick)
			}
		}
		s.mu.RUnlock()
	})

	t.OnError(func(err error) {
		s.logger.Error("Ticker error", "email", email, "error", err)
	})

	t.OnClose(func(code int, reason string) {
		ut.mu.Lock()
		ut.Connected = false
		ut.mu.Unlock()
		s.logger.Info("Ticker closed", "email", email, "code", code, "reason", reason)
	})

	t.OnReconnect(func(attempt int, delay time.Duration) {
		s.logger.Info("Ticker reconnecting", "email", email, "attempt", attempt, "delay", delay)
	})

	t.OnNoReconnect(func(attempt int) {
		s.logger.Warn("Ticker gave up reconnecting", "email", email, "attempts", attempt)
		ut.mu.Lock()
		ut.Connected = false
		ut.mu.Unlock()
	})

	s.tickers[email] = ut

	// Start serving in a goroutine (blocking call)
	go func() {
		s.logger.Info("Starting ticker", "email", email)
		t.ServeWithContext(ctx)
		s.logger.Info("Ticker serve exited", "email", email)
	}()

	return nil
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
func (s *Service) UpdateToken(email, apiKey, accessToken string) error {
	s.mu.Lock()
	ut, ok := s.tickers[email]
	s.mu.Unlock()

	if !ok {
		return fmt.Errorf("no ticker found for %s", email)
	}

	// Capture current subscriptions before stopping
	ut.mu.RLock()
	subs := make(map[uint32]kiteticker.Mode, len(ut.Subscribed))
	for token, mode := range ut.Subscribed {
		subs[token] = mode
	}
	ut.mu.RUnlock()

	// Stop the existing ticker
	if err := s.Stop(email); err != nil {
		return fmt.Errorf("failed to stop existing ticker: %w", err)
	}

	// Start a new ticker with the fresh token
	if err := s.Start(email, apiKey, accessToken); err != nil {
		return fmt.Errorf("failed to start ticker with new token: %w", err)
	}

	// Restore subscriptions (they'll be applied on connect callback)
	s.mu.RLock()
	newUT, ok := s.tickers[email]
	s.mu.RUnlock()
	if ok {
		newUT.mu.Lock()
		newUT.Subscribed = subs
		newUT.mu.Unlock()
	}

	s.logger.Info("Ticker token updated", "email", email, "subscriptions_preserved", len(subs))
	return nil
}

// Subscribe subscribes the user's ticker to the given instrument tokens with the specified mode.
func (s *Service) Subscribe(email string, tokens []uint32, mode kiteticker.Mode) error {
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
		if err := ut.Ticker.Subscribe(tokens); err != nil {
			return fmt.Errorf("subscribe failed: %w", err)
		}
		if err := ut.Ticker.SetMode(mode, tokens); err != nil {
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
		if err := ut.Ticker.Unsubscribe(tokens); err != nil {
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

// AddListener registers a per-stream tick listener for the given user.
func (s *Service) AddListener(email, listenerID string, fn TickListener) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.listeners[email]; !ok {
		s.listeners[email] = make(map[string]TickListener)
	}
	s.listeners[email][listenerID] = fn
	s.logger.Debug("Tick listener added", "email", email, "listener_id", listenerID)
}

// RemoveListener removes a per-stream tick listener.
func (s *Service) RemoveListener(email, listenerID string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if emailListeners, ok := s.listeners[email]; ok {
		delete(emailListeners, listenerID)
		if len(emailListeners) == 0 {
			delete(s.listeners, email)
		}
	}
	s.logger.Debug("Tick listener removed", "email", email, "listener_id", listenerID)
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
