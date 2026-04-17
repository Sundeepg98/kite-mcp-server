# Billing Activation Plan

Concrete rollout if we flip Path 4 (empanelled White Box + paid tiers). Infrastructure is dormant-ready; this is the activation sequence.

## Current state

Billing infra is production-ready. What's wired:
- `kc/billing/store.go` — subscription store, tier mapping, Stripe integration
- `kc/billing/checkout.go` — Stripe Checkout Session
- `kc/billing/webhook.go` — full Stripe event handling (idempotent)
- `kc/billing/middleware.go` — tool-call gating
- `kc/billing/portal.go` — Customer Portal redirect
- `/webhooks/stripe` endpoint wired at `app/http.go:384`

**"Flip the switch" means:** set 5 env vars (`STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, 3 price IDs) + register webhook URL in Stripe dashboard. Zero code changes needed.

## Recommended tier design

| Tier | Price | Target | Key features |
|---|---|---|---|
| **Free** | ₹0 | Casual users, learners | Read-only data, paper trading, tech indicators, tax/compliance reports, list alerts |
| **Pro** | ₹799/mo | Ananya + active retail | + Order execution, alerts+Telegram, GTT, trailing stops, MF orders, position analysis, up to 5 family users |
| **Premium** | ₹2,499/mo | Institutional | + Options Greeks, audit exports, up to 20 family users, priority support |

**Benchmark reference:** Streak (previously ₹500-1400 before free), Sensibull Pro ₹1,300, Tickertape ₹299. Agent's ₹799 price sits between.

**Drop SoloPro** — it splits Pro cohort and adds Stripe product overhead for no benefit.

## SEBI-compliant fee disclosure (critical)

Per Spice Route Legal: "Charges must be prominently and completely disclosed."

Placement:
1. **Landing page** — new "Pricing" section with 3 cards + prominent disclosure table (price, cycle, cancellation, cooling-off, SEBI disclaimer)
2. **Dashboard /dashboard/billing** — pre-charge confirmation screen with GST breakdown + cooling-off note
3. **Before first charge** — email + in-app banner 1 day before renewal
4. **7-day cooling-off refund** (Indian Consumer Protection Act 2019)

**Critical disclaimer required:** "This service is not a SEBI-registered Investment Adviser, Research Analyst, or Stock Broker. Charges are for software access only, not investment advice."

## 4-week rollout

- **Week 1:** Ship pricing page (visible but no checkout). SEBI disclosure visible.
- **Week 2:** Stripe TEST mode + 5 friendlies beta test full flow.
- **Week 3:** Tool-tier gating activation (still test mode). Verify free users get upgrade prompt on write tools.
- **Week 4:** Stripe LIVE mode. First real charge. Public announcement.

## Grandfather policy

- **Sundeep:** Auto-Premium, permanent
- **Other early users** (likely 0 today): 3 months free Pro

## Revenue projections (agent's model)

| Users | MRR net | Covers |
|---|---|---|
| 10 Pro | ₹7,750 | Fly.io + R2 |
| 50 Pro + 5 Premium | ₹50,745 | 1 FTE ₹40k/mo |
| 100 Pro + 10 Premium | ₹101,690 | Full-time operator + buffer |
| 500 Pro + 50 Premium | ₹508,450 | Sustainable SaaS, hire support |

**Break-even:** ~50 Pro subscribers (Month 4-6 realistic).

## Tax + regulatory hooks

- **GST trigger:** ₹20L annual turnover. Below that, no registration needed.
- **Entity:** Sole proprietorship until ₹50L revenue; then convert to Pvt Ltd.
- **Stripe fees:** 2.9% + ₹10/txn in India. Negotiable at ₹500k+ MRR.
- **SEBI impact:** None if charges framed as "software access, not advice" — matches Path 4 White Box positioning.

## Risks flagged

- Webhook idempotency (already addressed in code)
- Test/live key swap (separate Fly machines for staging/prod)
- 7-day cooling-off refund API (Stripe supports, needs UI)
- Accidental duplicate charges (monitor Stripe dashboard monthly)

## Decision gate

**Do not activate billing without:**
1. Path 4 empanelment secured OR clear legal opinion from fintech lawyer
2. 5-person beta test passed in Stripe test mode
3. Updated TOS with billing + refund policy
4. Stripe account verified (deposit check received)
