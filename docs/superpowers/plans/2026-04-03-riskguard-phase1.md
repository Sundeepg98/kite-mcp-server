# Riskguard Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add server-side financial safety controls that block orders exceeding configurable limits before they reach the Kite API.

**Architecture:** New `kc/riskguard/` package with a Guard struct that runs 4 checks (kill switch, order value, quantity limit, daily count) via a tool handler middleware. Sits between audit middleware and elicitation in the request chain.

**Tech Stack:** Go, mcp-go v0.46.0 middleware, SQLite (existing alerts.DB), existing instruments.Manager for freeze quantities.

---

### Task 1: Create riskguard package — types and Guard skeleton

**Files:**
- Create: `kc/riskguard/guard.go`

- [ ] **Step 1: Create the package with types and constructor**

Create `kc/riskguard/guard.go` with: UserLimits struct, UserTracker struct, Guard struct, NewGuard(), CheckOrder() skeleton that returns allowed, helper for getting effective limits. Include the orderTools map. System defaults as package-level var. The CheckOrder method calls 4 check methods in sequence — implement checkKillSwitch and checkDailyOrderCount (pure in-memory, no external deps). Stub checkOrderValue and checkQuantityLimit to return allowed.

- [ ] **Step 2: Verify build**

Run: `cd D:/kite-mcp-temp && go build ./kc/riskguard/...`

- [ ] **Step 3: Commit**

---

### Task 2: Tests for Guard checks

**Files:**
- Create: `kc/riskguard/guard_test.go`

- [ ] **Step 1: Write tests for all 4 checks**

Tests: TestCheckKillSwitch (frozen blocks, unfrozen passes), TestCheckOrderValue (over blocks, under passes, MARKET skipped), TestCheckQuantityLimit (over blocks, no instrument passes), TestCheckDailyOrderCount (at limit blocks, under passes), TestCheckOrder combined, TestFreeze/Unfreeze, TestDayReset, TestConfigResolution (per-user > default).

- [ ] **Step 2: Run tests — some should fail (stubs)**

- [ ] **Step 3: Implement checkOrderValue and checkQuantityLimit**

checkOrderValue: extract qty/price/order_type from args, compute value, compare to limit. Skip for MARKET (price=0). checkQuantityLimit: look up freeze qty from instruments manager, compare. Skip if no manager or instrument not found.

- [ ] **Step 4: Run tests — all pass**

- [ ] **Step 5: Commit**

---

### Task 3: Middleware + admin freeze/unfreeze

**Files:**
- Create: `kc/riskguard/middleware.go`
- Modify: `kc/ops/handler.go` (add freeze/unfreeze endpoints)

- [ ] **Step 1: Create middleware**

`Middleware(guard *Guard) server.ToolHandlerMiddleware` — checks orderTools map, calls guard.CheckOrder, blocks or passes through. On block: return mcp.NewToolResultError with the rejection message. On allow + successful order: call guard.RecordOrder to increment daily count.

- [ ] **Step 2: Add freeze/unfreeze to ops handler**

Two new endpoints: `POST /admin/ops/api/risk/freeze` (body: email, reason) and `POST /admin/ops/api/risk/unfreeze` (body: email). Both require admin auth. Call guard.Freeze/Unfreeze.

- [ ] **Step 3: Verify build**

- [ ] **Step 4: Commit**

---

### Task 4: SQLite persistence + DB schema

**Files:**
- Modify: `kc/alerts/db.go` (add risk_limits DDL)
- Add to: `kc/riskguard/guard.go` (LoadLimits, SaveLimits methods)

- [ ] **Step 1: Add risk_limits table DDL**

Add `CREATE TABLE IF NOT EXISTS risk_limits (...)` to the init function chain in alerts/db.go.

- [ ] **Step 2: Add LoadLimits/SaveLimits to Guard**

LoadLimits reads all rows from risk_limits into the guard's limits map. SaveLimits persists a single user's limits. Called at startup and on freeze/unfreeze.

- [ ] **Step 3: Verify build + tests**

- [ ] **Step 4: Commit**

---

### Task 5: Wire into app.go + Manager

**Files:**
- Modify: `kc/manager.go` (add riskGuard field)
- Modify: `app/app.go` (init guard, register middleware)

- [ ] **Step 1: Add riskGuard to Manager**

Add `riskGuard *riskguard.Guard` field, `SetRiskGuard()`, `RiskGuard()` accessors.

- [ ] **Step 2: Wire in app.go**

After audit store init: create Guard, set instruments manager, set DB, load limits. Register middleware: `serverOpts = append(serverOpts, server.WithToolHandlerMiddleware(riskguard.Middleware(guard)))`.

- [ ] **Step 3: Full build + test suite**

Run: `cd D:/kite-mcp-temp && go test -ldflags="-s -w" ./... -count=1 -short`

- [ ] **Step 4: Commit, push, deploy**
