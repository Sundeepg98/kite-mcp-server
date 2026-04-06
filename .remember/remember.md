# Handoff

## State
18 research agents completed across 6 rounds. Design spec committed at docs/superpowers/specs/2026-04-06-admin-mcp-billing-design.md (afa7d97). ALL conflicts resolved. NOTHING built yet — purely research. CI green (930d0bb), 80 tools, 11 widgets, 330+ tests.

## Next
1. Build Phase 1: 10 admin MCP tools in mcp/admin_tools.go + mcp.go registration + tiers.go (TierFree) + guard.go GlobalFreezeStatus + common_test.go unmapped list update. Use direct requestConfirmation() calls, NOT confirmableTools map. Suspend must Freeze+UpdateStatus+TerminateByEmail.
2. Build Phase 2: Billing refactor — store.go PK rebuild (BEGIN/COMMIT transaction, pragma_table_info idempotency check), middleware.go adminEmailFn, webhook.go userStore+max_users, users/store.go AdminEmail field, interfaces.go, app.go wiring.
3. Build Phases 3-5: oauth/google_sso.go registry lookup (h.registry already wired), pricing.html+checkout.go, 4 admin widget templates in ext_apps.go.

## Context
- Codebase at D:\kite-mcp-temp — ALWAYS tell agents this path with specific file paths
- Tool names from SPEC not research agents: admin_list_users, admin_get_user, admin_server_status, admin_get_risk_status, admin_suspend_user, admin_activate_user, admin_change_role, admin_freeze_user, admin_unfreeze_user, admin_freeze_global (10 total, skip admin_unfreeze_global)
- guard.go needs globalFrozenReason field added (FreezeGlobal stores reason in log only, not field)
- Admin tools stay UNMAPPED from toolDashboardPage; update common_test.go unmapped list instead
- Migration safe: SQLite WAL + Litestream unaffected by BEGIN/COMMIT table rebuild
- manager.MCPServer() returns server ref for elicitation (stored as `any`)
- h.registry KeyRegistry field already exists on oauth Handler — no new wiring for family linkage
- User must re-login after admin registers app (no event system on Register())
