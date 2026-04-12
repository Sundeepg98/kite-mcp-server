package alerts

// SetNewBotFuncForTest replaces the bot creation function for cross-package
// testing. Callers must defer RestoreNewBotFunc to avoid leaking state.
func SetNewBotFuncForTest(fn func(string) (BotAPI, error)) {
	newBotFuncMu.Lock()
	newBotFunc = fn
	newBotFuncMu.Unlock()
}

// RestoreNewBotFunc is a no-op placeholder: the original factory cannot be
// captured generically across tests. Instead, use OverrideNewBotFunc which
// returns a restore function.
//
// Deprecated: Use OverrideNewBotFunc instead.
func RestoreNewBotFunc() {
	// no-op — callers should use OverrideNewBotFunc
}

// OverrideNewBotFunc replaces the bot creation function and returns a cleanup
// function that restores the original. Safe for concurrent tests.
func OverrideNewBotFunc(fn func(string) (BotAPI, error)) func() {
	newBotFuncMu.Lock()
	orig := newBotFunc
	newBotFunc = fn
	newBotFuncMu.Unlock()
	return func() {
		newBotFuncMu.Lock()
		newBotFunc = orig
		newBotFuncMu.Unlock()
	}
}
