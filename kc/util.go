package kc

// truncKey safely returns the first n characters of a string, or the whole string if shorter.
//
// Anchor 6 PR 6.15 relocated this helper from kc/manager.go so manager.go
// can stay focused on the constructors. Used by kc/credential_service.go
// for log-friendly registry IDs ("migrated-{email}-{first-8-of-key}").
func truncKey(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
