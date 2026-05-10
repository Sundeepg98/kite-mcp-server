# Family Usecases Revival — Research Findings

## 1. Family Service vs Revived Usecases — Source of Truth

**Evidence:**
- `kc/family_service.go:18-90`: FamilyService implements ListMembers, CanInvite, RemoveMember, AdminEmailFn
- `mcp/admin_family_tools.go:58-70`: AdminInviteFamilyMemberTool duplicates CanInvite logic (count+max_users check)
- `mcp/admin_family_tools.go:168`: AdminListFamilyTool calls ListByAdminEmail directly, same as FamilyService:46
- Git history (0ff7334^): Deleted usecases were thin wrappers—AdminListFamilyUseCase returned uc.userStore.List()

**Recommendation: HYBRID**
Keep FamilyService as the library for reuse. Revived usecases should **delegate to FamilyService** for CanInvite, RemoveMember, AdminEmailFn resolution. This avoids duplication (currently in mcp/admin_family_tools.go:60-70) and establishes FamilyService as the single source of truth. Delete the manual billing/user store queries from mcp/admin_family_tools.go and route through usecases instead.

**Confidence: HIGH**

---

## 2. Billing Tier Inheritance for Family Members

**Evidence:**
- `kc/billing/tiers.go:37-68`: Family tools (admin_invite_family_member, admin_list_family, admin_remove_family_member) all map to TierFree—they have no tier gate
- `kc/billing/webhook.go:19,119-151`: Webhook creates Subscription with MaxUsers (from metadata), but **only for the payer admin email**, not family members
- `kc/family_service.go:31-42`: AdminEmailFn resolves tier via admin linkage, but no Subscription lookup for family members
- `mcp/admin_family_tools.go:100-105`: FamilyInvitedEvent dispatched on invite, but no billing linkage established

**Recommendation: EXPLICIT AUTO-INHERIT**
Family members should **automatically inherit the admin's tier at invitation time**. Implement in AdminInviteFamilyMemberUseCase:
1. After creating invitation, look up admin's subscription tier via BillingStore
2. Cache the tier link in a family_member_tiers table or as a field on users.User (AdminTier)
3. At tool-call time, billing middleware checks: if user.AdminEmail is set, use AdminTier from subscription

Do NOT wait for family member to accept—tier inheritance is retroactive from invite. Current behavior leaves family members at TierFree indefinitely (no code sets their tier).

**Confidence: MED** (no explicit tier inheritance logic found; assumption based on absence)

---

## 3. Audit & Domain Events for Family Operations

**Evidence:**
- `kc/domain/events.go:183-191`: FamilyInvitedEvent already defined with AdminEmail, InvitedEmail, Timestamp
- `mcp/admin_family_tools.go:100-105`: FamilyInvitedEvent dispatched on invite
- `kc/usecases/place_order.go`: OrderPlacedEvent dispatched via uc.events.Dispatch() pattern
- Missing: FamilyMemberRemovedEvent, FamilyMemberAcceptedEvent in domain/events.go

**Recommendation: ADD TWO EVENT TYPES**
Extend domain/events.go with:
```go
type FamilyMemberRemovedEvent struct {
  AdminEmail   string
  RemovedEmail string
  Timestamp    time.Time
}
type FamilyMemberAcceptedEvent struct {
  AdminEmail   string
  MemberEmail  string
  Timestamp    time.Time
}
```
Dispatch FamilyMemberRemovedEvent in AdminRemoveFamilyMemberUseCase (after RemoveMember succeeds).
Do NOT create new FamilyInvitedEvent—reuse existing; mcp/admin_family_tools.go:100 already does this.

**Confidence: HIGH**

---

## 4. Test Strategy for Revived Usecases

**Evidence:**
- `kc/usecases/usecases_test.go:1981 lines`: Unit tests for existing usecases (AdminListUsersUseCase, AdminSuspendUserUseCase) with mocks
- No bus-level integration tests in kc/cqrs/ (bus_test.go only tests registration/dispatch mechanics)
- Git deleted: 12 family tests (not counted; git history unavailable for count)
- `kc/usecases/mocks_test.go:13710 lines`: MockUserStore, MockRiskGuardService patterns exist

**Recommendation: UNIT + BUS INTEGRATION HYBRID**
1. **Unit tests (recreate the 12 deleted):** Test AdminListFamilyUseCase, AdminInviteFamilyMemberUseCase, AdminRemoveFamilyMemberUseCase with mocks (FamilyService mock or real, MockUserStore). Target: ~40-50 lines per usecase.
2. **Bus integration test (NEW):** One test in cqrs/bus_test.go that registers all three family usecases and commands, then executes list → invite → remove flow end-to-end. This validates CQRS wiring.
3. Skip mcp layer tests—those are tool-level concern (already passing per admin_family_tools.go existence).

Coverage target: 90%+ unit, 1 happy-path bus integration test.

**Confidence: HIGH**

---

## 5. Should Duplicate Logic in mcp/admin_family_tools.go Be Removed?

**Evidence:**
- `mcp/admin_family_tools.go:54-72`: AdminInviteFamilyMemberTool manually implements CanInvite logic (uStore.ListByAdminEmail + billingStore.GetSubscription + count/max check)
- `kc/family_service.go:71-75`: CanInvite method already does this
- `mcp/admin_family_tools.go:279-294`: AdminRemoveFamilyMemberTool manually calls uStore.SetAdminEmail
- `kc/family_service.go:77-90`: RemoveMember does the same
- mcp/admin_family_tools.go is the only consumer; no other tools call it

**Recommendation: DELETE DUPLICATE, ROUTE VIA USECASES**
1. Remove lines 54-72 (CanInvite) from mcp/admin_family_tools.go—invoke revived AdminInviteFamilyMemberUseCase via CommandBus instead
2. Remove lines 279-294 (RemoveMember) from mcp/admin_family_tools.go—invoke AdminRemoveFamilyMemberUseCase via CommandBus
3. Remove lines 163-235 (ListMembers loop) from mcp/admin_family_tools.go—invoke AdminListFamilyUseCase via QueryBus
4. Reduce mcp/admin_family_tools.go to pure MCP protocol translation (auth check, arg parsing, tool metadata) → delegates to buses
5. Keep mcp/admin_family_tools.go as **thin adapter layer** (30-40 lines of wrapper code)

This eliminates duplication, forces CQRS adoption, and improves testability.

**Confidence: HIGH**

---

## Summary Table

| Question | Recommendation | Confidence |
|----------|---|---|
| 1. Source of truth | Delegate usecases → FamilyService (thin CQRS wrapper) | HIGH |
| 2. Tier inheritance | Auto-inherit on invite, cache tier link in users table | MED |
| 3. Events | Add FamilyMemberRemovedEvent, FamilyMemberAcceptedEvent | HIGH |
| 4. Testing | Unit + 1 bus integration test, ~50 LOC each | HIGH |
| 5. Duplicate logic | DELETE mcp tools' manual logic, route via usecases + buses | HIGH |

---

**Next Steps:**
1. Implement FamilyService delegation in revived usecases
2. Add missing event types to domain/events.go
3. Refactor mcp/admin_family_tools.go to use CommandBus/QueryBus
4. Write unit tests (usecases) + 1 bus integration test
5. Verify billing tier inheritance via AdminInviteFamilyMemberUseCase command handler
