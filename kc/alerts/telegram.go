package alerts

import (
	"fmt"
	"log/slog"
	"strings"

	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api/v5"
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
	bot    *tgbotapi.BotAPI
	store  *Store
	logger *slog.Logger
}

// NewTelegramNotifier creates a new Telegram notifier.
// Returns nil if botToken is empty (Telegram notifications disabled).
func NewTelegramNotifier(botToken string, store *Store, logger *slog.Logger) (*TelegramNotifier, error) {
	if botToken == "" {
		logger.Info("Telegram bot token not configured, notifications disabled")
		return nil, nil
	}

	bot, err := tgbotapi.NewBotAPI(botToken)
	if err != nil {
		return nil, fmt.Errorf("failed to create Telegram bot: %w", err)
	}

	logger.Info("Telegram bot initialized", "bot_name", bot.Self.UserName)

	return &TelegramNotifier{
		bot:    bot,
		store:  store,
		logger: logger,
	}, nil
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
	if alert.Direction == DirectionAbove {
		emoji = "\U0001F4C8" // chart increasing
	} else {
		emoji = "\U0001F4C9" // chart decreasing
	}

	text := fmt.Sprintf(
		"%s *%s:%s* crossed %s %.2f\nCurrent: %.2f\nTarget: %.2f (%s)",
		emoji,
		escapeTelegramMarkdown(alert.Exchange),
		escapeTelegramMarkdown(alert.Tradingsymbol),
		string(alert.Direction),
		alert.TargetPrice,
		currentPrice,
		alert.TargetPrice,
		string(alert.Direction),
	)

	msg := tgbotapi.NewMessage(chatID, text)
	msg.ParseMode = tgbotapi.ModeMarkdown

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
	}
}
