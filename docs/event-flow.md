# Domain Event Flow

Auto-generated from `app/providers.CanonicalPersisterSubscriptions` (Wave D Phase 2 Slice P2.4f).
Run `go test ./cmd/event-graph -update` to regenerate after adding/removing subscriptions.

**36 events** persist via the dispatcher → audit-log path; they fan into **17 aggregate streams** for projector queries.

```mermaid
flowchart LR
    agg_Alert["Alert"]
    agg_Billing["Billing"]
    agg_Family["Family"]
    agg_GTT["GTT"]
    agg_Global["Global"]
    agg_MFOrder["MFOrder"]
    agg_MFSIP["MFSIP"]
    agg_NativeAlert["NativeAlert"]
    agg_Order["Order"]
    agg_PaperOrder["PaperOrder"]
    agg_PaperTrading["PaperTrading"]
    agg_Position["Position"]
    agg_RiskGuard["RiskGuard"]
    agg_RiskguardCounters["RiskguardCounters"]
    agg_Session["Session"]
    agg_TrailingStop["TrailingStop"]
    agg_User["User"]

    "order.filled" --> agg_Order
    "position.opened" --> agg_Position
    "position.closed" --> agg_Position
    "alert.triggered" --> agg_Alert
    "user.frozen" --> agg_User
    "user.suspended" --> agg_User
    "global.freeze" --> agg_Global
    "family.invited" --> agg_Family
    "family.member_removed" --> agg_Family
    "risk.limit_breached" --> agg_RiskGuard
    "session.created" --> agg_Session
    "billing.tier_changed" --> agg_Billing
    "riskguard.kill_switch_tripped" --> agg_RiskguardCounters
    "riskguard.daily_counter_reset" --> agg_RiskguardCounters
    "riskguard.rejection_recorded" --> agg_RiskguardCounters
    "order.rejected" --> agg_Order
    "position.converted" --> agg_Position
    "paper.order_rejected" --> agg_PaperOrder
    "mf.order_rejected" --> agg_MFOrder
    "gtt.rejected" --> agg_GTT
    "trailing_stop.triggered" --> agg_TrailingStop
    "mf.order_placed" --> agg_MFOrder
    "mf.order_cancelled" --> agg_MFOrder
    "mf.sip_placed" --> agg_MFSIP
    "mf.sip_cancelled" --> agg_MFSIP
    "gtt.placed" --> agg_GTT
    "gtt.modified" --> agg_GTT
    "gtt.deleted" --> agg_GTT
    "trailing_stop.set" --> agg_TrailingStop
    "trailing_stop.cancelled" --> agg_TrailingStop
    "native_alert.placed" --> agg_NativeAlert
    "native_alert.modified" --> agg_NativeAlert
    "native_alert.deleted" --> agg_NativeAlert
    "paper.enabled" --> agg_PaperTrading
    "paper.disabled" --> agg_PaperTrading
    "paper.reset" --> agg_PaperTrading
```
