package kc

// ManagedSessionService wraps session operations for cleaner access.
// Extracted from Manager to reduce god-object coupling.
type ManagedSessionService struct {
	registry *SessionRegistry
}

// NewManagedSessionService creates a new ManagedSessionService.
func NewManagedSessionService(reg *SessionRegistry) *ManagedSessionService {
	return &ManagedSessionService{registry: reg}
}

// ActiveCount returns the number of non-terminated, non-expired sessions.
func (s *ManagedSessionService) ActiveCount() int {
	if s.registry == nil {
		return 0
	}
	return len(s.registry.ListActiveSessions())
}

// TerminateByEmail terminates all active sessions belonging to the given email.
func (s *ManagedSessionService) TerminateByEmail(email string) int {
	if s.registry == nil {
		return 0
	}
	return s.registry.TerminateByEmail(email)
}

// Registry returns the underlying SessionRegistry.
func (s *ManagedSessionService) Registry() *SessionRegistry {
	return s.registry
}
