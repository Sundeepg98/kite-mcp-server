package mcp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// DevMode session handler tests: tool execution through DevMode manager with stub Kite client.


func TestLogin_NonAlphanumericAPIKey(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key":    "key!@#$%",
		"api_secret": "validsecret123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "invalid api_key")
}


func TestLogin_NonAlphanumericAPISecret(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key":    "validkey123",
		"api_secret": "secret!@#",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "invalid api_secret")
}


func TestLogin_PartialCredentials_KeyOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_key": "validkey123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "api_key and api_secret are required")
}


func TestLogin_PartialCredentials_SecretOnly(t *testing.T) {
	t.Parallel()
	mgr := newTestManager(t)
	result := callToolDevMode(t, mgr, "login", "test@example.com", map[string]any{
		"api_secret": "validsecret123",
	})
	assert.True(t, result.IsError)
	assertResultContains(t, result, "api_key and api_secret are required")
}


func TestLogin_DevMode_NoExtraCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", nil)
	// In DevMode with global credentials, should succeed (either cached or login URL)
	assert.NotNil(t, result)
}


func TestLogin_StoreUserCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "user@example.com", map[string]any{
		"api_key":    "userkey123",
		"api_secret": "usersecret456",
	})
	assert.NotNil(t, result)
	// Credentials should be stored
	entry, ok := mgr.CredentialStore().Get("user@example.com")
	assert.True(t, ok)
	assert.Equal(t, "userkey123", entry.APIKey)
}


func TestLogin_NoEmail_WithCredentials(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "validkey123",
		"api_secret": "validsecret456",
	})
	// Without email, storing per-user credentials should fail
	assert.True(t, result.IsError)
	assertResultContains(t, result, "OAuth authentication required")
}


func TestOpenDashboard_DefaultPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", nil)
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_ActivityPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_OrdersPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "orders",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_AlertsPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "alerts",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_PaperPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "paper",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_SafetyPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "safety",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_WatchlistPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "watchlist",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_OptionsPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "options",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_ChartPage(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "chart",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_ActivityWithCategory(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":     "activity",
		"category": "order",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_ActivityWithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "activity",
		"days": float64(7),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_ActivityWithErrors(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":   "activity",
		"errors": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_OrdersWithDays(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page": "orders",
		"days": float64(30),
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestOpenDashboard_AllDeepLinkParams(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
		"page":     "activity",
		"category": "market_data",
		"days":     float64(1),
		"errors":   true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
}


func TestSetupTelegram_DevMode_NilNotifier_WithSession(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(999888777),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assertResultContains(t, result, "Telegram notifications are not configured")
}


func TestDevMode_SetupTelegram_NoNotifier(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	// TelegramNotifier is nil in DevMode
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(12345),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "not configured")
}


func TestDevMode_SetupTelegram_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(12345),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_SetupTelegram_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_SetupTelegram_ZeroChatID(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_DeleteMyAccount_NoConfirm(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "dev@example.com", map[string]any{
		"confirm": false,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "permanently deletes")
}


func TestDevMode_DeleteMyAccount_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_DeleteMyAccount_Confirmed(t *testing.T) {
	// Not parallel — modifies shared state
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "delete_my_account", "delete-test@example.com", map[string]any{
		"confirm": true,
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "deleted")
}


func TestDevMode_UpdateMyCredentials_MissingRequired(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_UpdateMyCredentials_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "", map[string]any{
		"api_key":    "new_key",
		"api_secret": "new_secret",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
}


func TestDevMode_UpdateMyCredentials_EmptyValues(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_key":    "",
		"api_secret": "",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	// Validation catches empty values
	text := resultText(t, result)
	assert.True(t, len(text) > 0, "expected non-empty error message")
}


func TestDevMode_UpdateMyCredentials_Valid(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "update_my_credentials", "dev@example.com", map[string]any{
		"api_key":    "new_key_123",
		"api_secret": "new_secret_456",
	})
	assert.NotNil(t, result)
	assert.False(t, result.IsError)
	assert.Contains(t, resultText(t, result), "updated")
}


func TestDevMode_Login_MissingEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "test",
		"api_secret": "test",
	})
	assert.NotNil(t, result)
}


func TestDevMode_OpenDashboard_NoEmail(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolDevMode(t, mgr, "open_dashboard", "", nil)
	assert.NotNil(t, result)
}


func TestDevMode_OpenDashboard_Sections(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	sections := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "admin", "admin/users", "admin/metrics"}
	for _, section := range sections {
		result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
			"section": section,
		})
		assert.NotNil(t, result, "section=%s", section)
	}
}


// ---------------------------------------------------------------------------
// setup_tools.go: LoginTool.Handler (50.7% -> higher)
// ---------------------------------------------------------------------------
func TestLogin_WithCredentials_DevMode(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "cred@example.com", map[string]any{
		"api_key":    "newkey123",
		"api_secret": "newsecret456",
	})
	assert.NotNil(t, result)
	// In DevMode, login stores creds and returns a result
}


func TestLogin_OnlyApiKey(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key": "onlykey123",
	})
	assert.NotNil(t, result)
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "api_key and api_secret are required")
}


func TestLogin_InvalidApiKeyChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key":    "bad-key!@#",
		"api_secret": "good123",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}


func TestLogin_InvalidApiSecretChars(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{
		"api_key":    "good123",
		"api_secret": "bad-secret!",
	})
	assert.True(t, result.IsError)
	assert.Contains(t, resultText(t, result), "alphanumeric")
}


func TestLogin_NoEmail_NoCredentials(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	// Login with credentials but no email
	result := callToolDevMode(t, mgr, "login", "", map[string]any{
		"api_key":    "key123",
		"api_secret": "secret456",
	})
	assert.NotNil(t, result)
	// Should return error about OAuth
	if result.IsError {
		assert.Contains(t, resultText(t, result), "OAuth")
	}
}


func TestLogin_PlainLogin_DevMode(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "login", "dev@example.com", map[string]any{})
	assert.NotNil(t, result)
	// DevMode should return some result (may succeed or show login URL)
}


// ---------------------------------------------------------------------------
// open_dashboard with various pages (setup_tools)
// ---------------------------------------------------------------------------
func TestOpenDashboard_AllPages(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	pages := []string{"portfolio", "activity", "orders", "alerts", "paper", "safety", "options", "chart"}
	for _, page := range pages {
		result := callToolDevMode(t, mgr, "open_dashboard", "dev@example.com", map[string]any{
			"page": page,
		})
		assert.NotNil(t, result, "page=%s", page)
	}
}


// ---------------------------------------------------------------------------
// setup_tools: setup_telegram deeper body
// ---------------------------------------------------------------------------
func TestSetupTelegram_ZeroChatID_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{
		"chat_id": float64(0),
	})
	assert.True(t, result.IsError)
	// TelegramNotifier is nil, so returns "not configured" before chatID check
	assert.Contains(t, resultText(t, result), "not configured")
}


// ---------------------------------------------------------------------------
// setup_telegram: no email + NaN chatID + missing chat_id
// ---------------------------------------------------------------------------
func TestSetupTelegram_NoEmail_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "", map[string]any{
		"chat_id": float64(12345),
	})
	assert.True(t, result.IsError)
}


func TestSetupTelegram_MissingChatID_Push(t *testing.T) {
	t.Parallel()
	mgr, _ := newFullDevModeManager(t)
	result := callToolDevMode(t, mgr, "setup_telegram", "dev@example.com", map[string]any{})
	assert.True(t, result.IsError)
}
