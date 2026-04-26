package mcp

import "github.com/zerodha/kite-mcp-server/kc"

// AdminDepsFields is the admin/observability-context subset of
// ToolHandlerDeps: registry of MCP-tool clients, audit log retention,
// billing-tier admin, and the embedded MCP server handle (admin tools
// inspect server state). Adding new admin/forensics ports here does
// NOT collide with session, alert, or order agent edits.
//
// Investment K — see session_deps.go for rationale.
type AdminDepsFields struct {
	Registry  kc.RegistryStoreProvider
	Audit     kc.AuditStoreProvider
	Billing   kc.BillingStoreProvider
	MCPServer kc.MCPServerProvider
}

func newAdminDeps(manager *kc.Manager) AdminDepsFields {
	return AdminDepsFields{
		Registry:  manager,
		Audit:     manager,
		Billing:   manager,
		MCPServer: manager,
	}
}
