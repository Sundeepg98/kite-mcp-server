# Admin MCP Tools + Billing Refactor — Combined Design Spec

## Commercial Model: Admin Pays for Family (Model A)

Admin (dad) pays ₹349-699/mo. Family members get access via admin's subscription.
Pricing: Free ₹0/1user, Pro ₹349/5users, Premium ₹699/20users.

---

## Part 1: Billing Refactor

### Schema Changes

billing table (rebuild migration):
```sql
CREATE TABLE billing (
    admin_email        TEXT PRIMARY KEY,
    tier               INTEGER NOT NULL DEFAULT 0,
    stripe_customer_id TEXT DEFAULT '',
    stripe_sub_id      TEXT DEFAULT '',
    status             TEXT NOT NULL DEFAULT 'active',
    expires_at         TEXT DEFAULT '',
    updated_at         TEXT NOT NULL,
    max_users          INTEGER NOT NULL DEFAULT 1
);
```

users table (add column):
```sql
ALTER TABLE users ADD COLUMN admin_email TEXT DEFAULT '';
```

### Tier Resolution

```go
func (s *Store) GetTierForUser(email string, adminEmailFn func(string) string) Tier {
    key := strings.ToLower(email)
    if tier := s.GetTier(key); tier > TierFree { return tier }
    adminEmail := adminEmailFn(key)
    if adminEmail != "" && adminEmail != key { return s.GetTier(strings.ToLower(adminEmail)) }
    return TierFree
}
```

### Middleware Change

```go
func Middleware(store *Store, adminEmailFn func(string) string) server.ToolHandlerMiddleware
```

In app.go:
```go
adminEmailFn := func(email string) string {
    u, ok := kcManager.UserStore().Get(email)
    if !ok || u.AdminEmail == "" { return "" }
    return u.AdminEmail
}
```

### Webhook Change

handleCheckoutCompleted: extract max_users from session.Metadata, upgrade payer to admin role.

### Migration

Existing billing rows: email → admin_email (table rebuild). Existing users: admin_email="" (solo).

### Files Changed

1. kc/billing/store.go — MaxUsers field, GetTierForUser, schema migration
2. kc/billing/middleware.go — accept adminEmailFn
3. kc/billing/webhook.go — max_users extraction, admin role upgrade
4. kc/users/store.go — AdminEmail field, SetAdminEmail method
5. app/app.go — wire adminEmailFn, capture admin linkage at provisioning
6. kc/interfaces.go — add SetAdminEmail + GetTierForUser

---

## Part 2: Admin MCP Tools (10 tools)

All in mcp/admin_tools.go. Register in mcp/mcp.go after ServerMetricsTool.

### Read-Only (Tier 0)

1. admin_list_users — manager.UserStore().List()
2. admin_get_user — manager.UserStore().Get(email) + RiskGuard().GetUserStatus(email)
3. admin_server_status — global freeze, sessions, user count (needs GlobalFreezeStatus() getter on guard.go)
4. admin_get_risk_status — RiskGuard().GetUserStatus(email) per-user

### Reversible Write (Tier 2 — elicitation)

5. admin_suspend_user — Freeze + UpdateStatus(suspended) + TerminateByEmail. Self-action guard.
6. admin_activate_user — UpdateStatus(active). No elicitation (restorative).
7. admin_change_role — UpdateRole. Last-admin guard. Elicitation for all changes.
8. admin_freeze_user — guard.Freeze(email, admin, reason). Self-action guard.
9. admin_unfreeze_user — guard.Unfreeze(email). No elicitation (restorative).

### Global (double elicitation)

10. admin_freeze_global — guard.FreezeGlobal(admin, reason). Critical warning message.

### Companion: admin_unfreeze_global (11th tool if needed)

### Guards (port from handler.go)

- Admin check: manager.UserStore().IsAdmin(email) — same as server_metrics
- Self-action: strings.EqualFold(targetEmail, adminEmail)
- Last-admin: count active admins, reject if count <= 1 and demoting

### Elicitation (extend elicit.go)

Add to confirmableTools: admin_suspend_user, admin_change_role, admin_freeze_user, admin_freeze_global.
Add cases to buildOrderConfirmMessage (or call requestConfirmation directly with custom message).

### Gotchas

- guard.go: globalFrozenBy/At unexported → add GlobalFreezeStatus() method
- RiskGuard() returns *riskguard.Guard (concrete, not interface)
- SessionManager().TerminateByEmail returns int
- users package constants needed: StatusSuspended, StatusActive, RoleAdmin etc.
- Audit logging handled automatically by MCP middleware (no manual logAdminAction needed)
- HTTP suspend handler ONLY calls UpdateStatus — MCP tool should also Freeze + TerminateByEmail

---

## Part 3: Admin Widgets (4 widgets)

1. admin_overview_app.html — stat grid (sessions, tokens, RAM, goroutines, DB, freeze state)
2. admin_users_app.html — user table with action buttons (suspend/activate/role)
3. admin_metrics_app.html — tool performance + error rates
4. admin_registry_app.html — Kite app registry with status badges

Each needs: appResource entry in ext_apps.go, DataFunc with admin check, toolDashboardPage entries.

---

## Part 4: Pricing Page + Stripe Checkout

New handler: POST /billing/checkout?plan=pro
- Protected by RequireAuthBrowser
- Creates Stripe Checkout Session with customer_email, metadata.max_users
- Redirects to Stripe hosted checkout
- Webhook processes checkout.session.completed → creates subscription + upgrades to admin

Pricing page: /pricing — 3 cards (Free/Pro/Premium) with features + Checkout buttons.
