package alerts

import (
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"time"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
)

// BotAPI abstracts the Telegram bot client for testability.
// *tgbotapi.BotAPI satisfies this interface.
type BotAPI interface {
	Send(c tgbotapi.Chattable) (tgbotapi.Message, error)
	Request(c tgbotapi.Chattable) (*tgbotapi.APIResponse, error)
}

// BotFactory constructs a BotAPI from a token. Used by
// NewTelegramNotifierWithFactory to inject per-call bot creation —
// the t.Parallel-safe alternative to the package-level newBotFunc
// global mutated via OverrideNewBotFunc.
type BotFactory func(token string) (BotAPI, error)

// newBotFunc is the function used to create a BotAPI instance.
// Protected by newBotFuncMu to allow safe override in tests.
var (
	newBotFuncMu sync.Mutex
	newBotFunc   = func(token string) (BotAPI, error) {
		return tgbotapi.NewBotAPI(token)
	}
)

// escapeTelegramMarkdown escapes special Markdown characters for Telegram messages.
func escapeTelegramMarkdown(s string) string {
	for _, ch := range []string{"_", "*", "[", "]", "(", ")", "~", "`", ">", "#", "+", "-", "=", "|", "{", "}", ".", "!"} {
		s = strings.ReplaceAll(s, ch, "\\"+ch)
	}
	return s
}

// TelegramNotifier sends alert notifications via Telegram.
type TelegramNotifier struct {
	bot    BotAPI
	store  *Store
	logger *slog.Logger
}

// NewTelegramNotifier creates a new Telegram notifier using the package-level
// newBotFunc factory. Returns nil if botToken is empty (Telegram notifications
// disabled).
//
// Prefer NewTelegramNotifierWithFactory when wiring tests that need a fake
// Telegram server — the per-call factory bypasses the global mutex on
// newBotFunc and is t.Parallel-safe.
func NewTelegramNotifier(botToken string, store *Store, logger *slog.Logger) (*TelegramNotifier, error) {
	newBotFuncMu.Lock()
	createBot := newBotFunc
	newBotFuncMu.Unlock()
	return NewTelegramNotifierWithFactory(botToken, store, logger, createBot)
}

// NewTelegramNotifierWithFactory creates a Telegram notifier using a
// caller-supplied BotFactory instead of the package-level newBotFunc global.
// Returns nil if botToken is empty (Telegram notifications disabled).
//
// Tests inject a fake-server-backed factory here to keep the kc/alerts
// global state untouched — multiple parallel tests can each carry their
// own factory without racing on newBotFuncMu.
func NewTelegramNotifierWithFactory(botToken string, store *Store, logger *slog.Logger, factory BotFactory) (*TelegramNotifier, error) {
	if botToken == "" {
		logger.Info("Telegram bot token not configured, notifications disabled")
		return nil, nil
	}
	if factory == nil {
		return nil, fmt.Errorf("alerts: BotFactory required (nil factory passed)")
	}

	bot, err := factory(botToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
	}

	logger.Info("Telegram bot initialized")

	return &TelegramNotifier{
		bot:    bot,
		store:  store,
		logger: logger,
	}, nil
}

// SendMessage sends an arbitrary MarkdownV2 message to a specific chat.
// Returns an error if the send fails. Callers are responsible for escaping
// user-supplied text with EscapeMarkdown before embedding it.
func (t *TelegramNotifier) SendMessage(chatID int64, text string) error {
	if t == nil || t.bot == nil {
		return fmt.Errorf("telegram notifier not initialized")
	}
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeMarkdownV2
	_, err := t.bot.Send(msg)
	return err
}

// SendHTMLMessage sends an arbitrary HTML-formatted message to a specific chat.
func (t *TelegramNotifier) SendHTMLMessage(chatID int64, text string) error {
	if t == nil || t.bot == nil {
		return fmt.Errorf("telegram notifier not initialized")
	}
	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeHTML
	_, err := t.bot.Send(msg)
	return err
}

// EscapeMarkdown escapes special MarkdownV2 characters for Telegram messages.
// This is the exported version of escapeTelegramMarkdown.
func EscapeMarkdown(s string) string {
	return escapeTelegramMarkdown(s)
}

// Bot returns the underlying Telegram bot API instance.
func (t *TelegramNotifier) Bot() BotAPI {
	if t == nil {
		return nil
	}
	return t.bot
}

// Store returns the underlying alert store (used by briefing to iterate users).
func (t *TelegramNotifier) Store() *Store {
	return t.store
}

// Logger returns the notifier's logger.
func (t *TelegramNotifier) Logger() *slog.Logger {
	return t.logger
}

// Notify sends a price alert notification to the user's Telegram.
func (t *TelegramNotifier) Notify(alert *Alert, currentPrice float64) {
	if t == nil || t.bot == nil {
		return
	}

	chatID, ok := t.store.GetTelegramChatID(alert.Email)
	if !ok {
		t.logger.Warn("No Telegram chat ID for user, skipping notification", "email", alert.Email)
		return
	}

	var emoji string
	switch alert.Direction {
	case DirectionAbove, DirectionRisePct:
		emoji = "\U0001F4C8" // chart increasing
	default:
		emoji = "\U0001F4C9" // chart decreasing
	}

	var text string
	if alert.IsPercentageAlert() {
		var dirLabel string
		if alert.Direction == DirectionDropPct {
			dirLabel = "dropped"
		} else {
			dirLabel = "risen"
		}
		actualPct := 0.0
		if alert.ReferencePrice > 0 {
			actualPct = (currentPrice - alert.ReferencePrice) / alert.ReferencePrice * 100
		}
		text = fmt.Sprintf(
			"%s *%s:%s* has %s by %s%% from ref %s\nCurrent: %s \\(%s%%\\)\nThreshold: %s%%",
			emoji,
			escapeTelegramMarkdown(alert.Exchange),
			escapeTelegramMarkdown(alert.Tradingsymbol),
			escapeTelegramMarkdown(dirLabel),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", alert.TargetPrice)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", alert.ReferencePrice)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", currentPrice)),
			escapeTelegramMarkdown(fmt.Sprintf("%+.2f", actualPct)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", alert.TargetPrice)),
		)
	} else {
		text = fmt.Sprintf(
			"%s *%s:%s* crossed %s %s\nCurrent: %s\nTarget: %s \\(%s\\)",
			emoji,
			escapeTelegramMarkdown(alert.Exchange),
			escapeTelegramMarkdown(alert.Tradingsymbol),
			escapeTelegramMarkdown(string(alert.Direction)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", alert.TargetPrice)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", currentPrice)),
			escapeTelegramMarkdown(fmt.Sprintf("%.2f", alert.TargetPrice)),
			escapeTelegramMarkdown(string(alert.Direction)),
		)
	}

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeMarkdownV2

	if _, err := t.bot.Send(msg); err != nil {
		t.logger.Error("Failed to send Telegram notification",
			"email", alert.Email,
			"chat_id", chatID,
			"error", err,
		)
	} else {
		t.logger.Info("Telegram notification sent",
			"email", alert.Email,
			"instrument", alert.Exchange+":"+alert.Tradingsymbol,
		)
		// Record when the notification was sent.
		t.store.MarkNotificationSent(alert.ID, time.Now())
	}
}
