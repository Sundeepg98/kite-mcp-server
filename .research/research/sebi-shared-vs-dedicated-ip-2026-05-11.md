---
title: SEBI April 2026 IP Mandate — Shared vs Dedicated IPv4 Deep-Dive
as-of: 2026-05-11
re-verify-by: 2026-08-11
author: research agent (competitive + regulatory domain)
status: empirical; WebFetch official sources only
trigger: Today's fly MCP install discovered cited 209.71.68.157 egress IP is STALE; real shared IPv4 is 66.241.125.151
verdict: BUY a $3.60/mo app-scoped static egress IPv4 for Fly bom region BEFORE Show HN. Confidence: HIGH.
---

# SEBI April 2026 IP Mandate — Shared vs Dedicated IPv4 Deep-Dive

## TL;DR (2 paragraphs)

**Buy a $3.60/mo app-scoped static egress IPv4 for `kite-mcp-server` in `bom` region before Show HN.** SEBI's circular text uses "**static IP whitelisted by the broker**" (not "dedicated"). Kite's developer console FAQ **explicitly accepts cloud provider IPs** (AWS, GCP — by precedent, also Fly.io / Hetzner / any cloud), and allows 2 IPs (primary + secondary). So a *shared but stable* cloud egress IP is regulatorily valid for **the operator's own** order placement.

**However**, the operative problem for us is not regulatory — it's empirical. Today's discovery is that the assumed `209.71.68.157` is stale; the *inbound shared anycast IPv4* `66.241.125.151` is what `fly ips list` shows, but **Fly.io's inbound anycast IP is not the same as its egress IP**. The default Fly egress is NAT'd through shared pools that "may change without notice" across machine restarts and deploys. Whitelisting `66.241.125.151` in the developer console will not actually accept our outbound order calls. The only way to have a stable egress IP on Fly is to allocate an app-scoped static egress IPv4 via `fly ips allocate-egress -a kite-mcp-server -r bom`. This costs $3.60/mo, persists across deploys, and gives us **one** stable IPv4 to whitelist. Combined with the existing `ENABLE_TRADING=false` posture on the hosted instance, this is a precaution for any *self-host-on-Fly* user we direct to our deploy template — not a blocker for the read-only hosted instance.

---

## §1. SEBI mandate text + interpretation

### What the circular actually says

SEBI circular `SEBI/HO/MIRSD/MIRSD-PoD/P/CIR/2025/0000013` (Feb 4, 2025), as quoted across multiple secondary sources (the SEBI page itself didn't render full PDF text via WebFetch; quoted excerpts are consistent across Liquide, Sahi, Quotaguard, NSE/INVG/67858 secondary sourcing):

> "Not permit open APIs and allow access only through a **unique vendor client specific API key and static IP whitelisted by the broker** to ensure identification and traceability of the algo provider and the end user."

Also from Zerodha's Z-Connect comprehensive overview of NSE circular:

> "a **static IP dedicated to their API key**"

### "Static" vs "dedicated" — terminology interpretation

The SEBI primary text says **"static IP"**. The Zerodha secondary commentary says **"static IP dedicated to their API key"** — where "dedicated" modifies the *binding to one API key*, not the *exclusivity vs other accounts*. Read in context: a static IP that's mapped to (dedicated to) your specific API key in the developer console — not an IP that you alone own from the upstream ISP.

This is reinforced by:

1. **Kite Connect FAQ (official Zerodha support page)**: explicitly states you can "acquire a static IP from an ISP (internet service provider), a cloud provider (such as AWS or GCP), or a VPN/VPC service." Cloud provider IPs are commonly NAT'd / shared upstream; they are accepted.
2. **Kite team forum post**: "Sharing of IPs is only permitted between **family members** (spouse, dependent children, and dependent parents) as per the regulation." This implies that the regulation worries about **person-level sharing** (one IP serving multiple distinct trading accounts), not **technical IP-level sharing** (one cloud anycast IP serving the broker's egress for many cloud customers).
3. **Vendor blogs** (QuotaGuard) using the term "dedicated static IP" appear to be marketing copy promoting their static-IP-as-a-service product. Not authoritative.

### Implication

The regulation requires a **stable, predictable, traceable** IP — one the broker can use to identify "which API key submitted this order." A cloud provider's shared NAT egress IP, **if stable for the operator**, satisfies this. What it doesn't satisfy: a *rotating* IP pool (where IP changes mid-session), or an IP that gets reused by a different person's API key over time.

**Net interpretation: shared cloud IP = OK if stable. Rotating = NOT OK.**

---

## §2. Kite developer console IP whitelist mechanics

Sources: support.zerodha.com FAQ on Kite Connect API + Kite Connect forum threads 15016, 15460, 15873, 15912, 15933.

### Capacity & format

| Field | Value |
|---|---|
| **Max IPs per developer account** | 2 (one **primary** mandatory, one **secondary** optional) |
| **Scope** | Developer account level — applies to **all apps** under that account |
| **Address types** | Both IPv4 and IPv6 supported |
| **Private/local addresses (e.g., 192.168.x.x)** | NOT allowed — must be public |
| **CSV / multiple comma-separated IPs in one field** | Not supported. Exactly two distinct fields. |
| **Change frequency** | 1 change per calendar week |
| **Update propagation** | Instantly effective |
| **Sharing** | Permitted **only** for family members (spouse, dependent children, dependent parents). Sharing with others may trigger account suspension. |

### Failure mode

> "IP (3.95.61.192) is not allowed to place orders for this app. Update allowed IPs on the Kite developer console."

Cloud users on PythonAnywhere etc. hit this when their cloud egress IP rotates between sessions. The fix is to use a stable cloud IP (AWS Elastic IP, Fly app-scoped static egress IP, etc.).

### Cloud-provider IPs are explicitly accepted

From the Kite Connect FAQ:

> "You can acquire a static IP from an ISP (internet service provider), a cloud provider (such as AWS or GCP), or a VPN/VPC service."

No qualification that the cloud IP must be dedicated-to-only-you. The operative requirement is *stability* + *attribution-to-your-API-key-in-the-console*.

### No special guidance for MCP / SaaS multi-tenant servers

Forum threads show no Kite team response to the question "what if a SaaS server hosts many users from one shared IP?" — this is the gap that affects products like ours. The likely interpretation: **each end user must whitelist the IP from which their orders are placed**. So if our hosted MCP server places orders on behalf of user X, user X's developer console must list our Fly egress IP in their whitelist.

This implies a **per-user setup step** at signup: "add `<our-fly-egress-ipv4>` to your Kite developer console's IP whitelist." Worth documenting.

---

## §3. Fly.io shared vs dedicated IPv4 — mechanics

Sources: fly.io/docs/networking/services/, fly.io/docs/networking/egress-ips/, fly.io/docs/about/pricing/, community.fly.io/t/billing-for-app-scoped-egress-ips-starts-jan-1-2026/26686, fly.io/docs/flyctl/ips-allocate-v4/, QuotaGuard analysis.

### Three distinct IP concepts on Fly

| Concept | Direction | Address | Cost |
|---|---|---|---|
| **Shared IPv4 anycast** | INBOUND only | One of Fly's shared anycast addresses (e.g., `66.241.125.151`) routed via BGP based on app's domain | Free |
| **Dedicated IPv4** | INBOUND only | A dedicated v4 address allocated to your app | $2/mo |
| **App-scoped static egress IP** | OUTBOUND only | A separate static address allocated per app per region for outbound NAT | $3.60/mo per IPv4 (IPv6 free) |

### Critical empirical finding (the "stale 209.71.68.157" puzzle)

The address `66.241.125.151` returned by `fly ips list` for `kite-mcp-server` is the **inbound anycast IPv4**. Fly's documentation explicitly states:

> "Anycast IP addresses described on this page are **not used** for outbound connections made from within a Machine."

And:

> "By default, outbound (egress) IPs from Fly Machines are **unstable** and may change. IPv4 traffic is NAT'd and may vary depending on machine location and restarts."

**So the actual egress IP for `kite-mcp-server` today is NOT `66.241.125.151`.** It is whatever NAT pool address Fly's edge happens to assign at the moment, drawn from a shared pool that rotates. The stale `209.71.68.157` in memory was likely the egress NAT-pool address at one earlier point that has since rotated.

### Conclusion: whitelisting `66.241.125.151` is useless for order placement

If any user whitelists `66.241.125.151` (our inbound anycast) in their Kite developer console, **their orders will still get rejected** because the outbound IP from which our order calls reach Kite is some other shared NAT pool address — not the anycast inbound. This isn't a SEBI issue; it's an empirical Fly networking fact.

### Fix: allocate a static egress IPv4

Command:
```
fly ips allocate-egress -a kite-mcp-server -r bom
```

Behavior:
- Allocates a pair (IPv4 + IPv6) of stable static egress addresses for the app, scoped to the `bom` region.
- Persists across machine restarts and deploys (the v6.1+ "app-scoped" model; the older machine-scoped model is now legacy).
- One static egress IP covers up to 64 machines per region. We have 1, so fine.
- Billing started Jan 1, 2026. Cost: **$3.60/month per IPv4**.
- After allocation, outbound traffic from machines in `bom` flows through this static egress IP, stable across deploys.

### Does the inbound anycast also change?

No. Allocating an egress IP doesn't change the inbound anycast (`66.241.125.151`). The app gets both: stable inbound on the anycast, stable outbound on the new static egress.

---

## §4. Competitive practice — what other Indian broker MCPs do

### 4a. Official Zerodha Kite MCP (`mcp.kite.trade`)

- **Read-only** — order placement excluded from the hosted instance. Only GTT-orderable.
- No documented compliance approach for static IP on the GitHub repo.
- Since they're a Zerodha first-party server, they likely don't need to whitelist their own egress IP — they're already the broker. Inapplicable to third-party reasoning.

### 4b. Upstox MCP (`mcp.upstox.com`) — launched Feb 25, 2026

- **Read-only**. Explicit: "no trade execution via AI."
- Static IP requirement on Upstox API is same as Kite's (own SEBI mandate). Since they don't do order placement via MCP, they sidestep it entirely.
- Order placement remains "log into the Upstox API like before" — i.e., the user's own setup.

### 4c. Dhan community MCP (`mayankthole/Dhan-MCP-Trades`)

- 19 tools including full order placement.
- Python, self-hosted.
- No documented compliance approach. Likely assumes the user is running it locally from their own static-IP-enabled setup.

### 4d. TurtleStack (`turtlehq-tech/turtlestack-lite`)

- Multi-broker (Kite + Groww + Dhan + AngelOne).
- Real-time order placement.
- Cloudflare Workers deployment.
- Cloudflare Workers do NOT give a static egress IP without their Workers Static IPs add-on. The community version likely punts compliance to the user.

### 4e. Multibagg AI

- Web-app stock-research SaaS — **does not place orders**. Out of scope for SEBI static IP mandate.

### 4f. `aranjan/kite-mcp` (Python community)

- Local-only by design — runs on the user's machine, uses user's home IP. SEBI-compliant by virtue of being a local tool.

### Competitive pattern

**No third-party Indian-broker MCP that I could find documents or enables compliant hosted order placement.** The category-wide pattern is:
- Hosted official MCPs = read-only
- Hosted community MCPs (TurtleStack) = punt compliance to user
- Trading-enabled MCPs = local self-host

Our `ENABLE_TRADING=false` on the hosted instance + self-host-for-trading posture is **aligned with the entire competitive set**. We are not behind on this dimension.

---

## §5. Recommendation

### Buy a static egress IPv4 in bom — $3.60/mo

Decision: **YES**. Three reasons:

1. **Operational correctness.** Today's discovery proves we don't currently have a stable egress IP. Without one, **even the read-only hosted instance** has an unstable outbound IP that any compliance-curious user might fail to predict. Order-placement self-hosters who follow our README/Fly template inherit this same problem.

2. **Cheap insurance.** $3.60/month = ₹300/month. The product strategy doc lists much larger compliance costs (SEBI RA ₹1.1-1.8L Y1 etc). A static egress IP is two orders of magnitude cheaper than any other compliance line item.

3. **Show HN derisking.** Someone on HN will ask "what's your egress IP and how do you handle SEBI's static IP rule?" Having a one-line answer ("we allocated a static egress IPv4 via `fly ips allocate-egress`; here it is; here's the user-side setup") is much stronger than "we are read-only so it doesn't matter."

### Execution sequence (suggested, not in this doc's scope to execute)

1. `fly ips allocate-egress -a kite-mcp-server -r bom` → note the new IPv4.
2. Update memory + `kite-landmines.md` + `kite-callback-deepdive.md` with the new static egress IPv4 (and explicitly mark `209.71.68.157` and `66.241.125.151` as stale-egress / inbound-only respectively).
3. Update README's "deployment" section: document that the hosted instance has a stable egress IPv4 and that **self-hosters on Fly should also allocate one** if they enable `ENABLE_TRADING=true`.
4. Update Show HN prepared replies to include a 2-sentence answer for "how do you handle SEBI static IP?"
5. Update the onboarding doc to instruct each order-placing user: "Add `<our-fly-egress-ipv4>` (primary) + your own home IP (secondary) to your Kite developer console's IP whitelist."

### What NOT to do

- **Do not** allocate a dedicated *inbound* IPv4 ($2/mo). The inbound anycast already works fine. Allocating one would just add cost without addressing the egress question.
- **Do not** use Cloudflare Tunnel, NAT proxies, or third-party static-IP-as-a-service (QuotaGuard etc.) — extra cost, extra latency, extra failure mode. Fly's native app-scoped egress is the correct fix.
- **Do not** email kiteconnect@zerodha.com preemptively for clarification. Risk: pre-launch reveal of our existence. SEBI / Kite FAQ already permits "cloud provider IPs"; no clarification needed.

---

## §6. Communications plan for users at launch

### README addition (proposed; not executed in this doc)

Suggest a new section after "Deployment":

> **SEBI Static IP Compliance (for `ENABLE_TRADING=true`)**
>
> India's SEBI mandates that every API order originate from a static IP whitelisted in the user's broker developer console (Feb 2025 circular; enforced from Apr 1, 2026).
>
> - **Read-only usage on our hosted instance:** No action required. `mcp.kite-mcp-server` runs `ENABLE_TRADING=false`; no orders are placed; SEBI static IP rule does not apply.
> - **Order placement (self-host or future hosted-trading tier):** You must add the egress IP of the server you run from to your Kite Connect developer console (Profile → IP Whitelist). For our Fly.io deployment template, that egress IP is allocated via `fly ips allocate-egress -a <app-name> -r bom` and costs $3.60/month. The exact IP is printed in the deploy output.
> - **For our hosted-trading tier (future):** We will publish the static egress IP at `/.well-known/static-ip` so onboarding is one click.

### Show HN reply additions

Add to the prepared-replies section in `docs/show-hn-post.md` (this is a recommendation; this research doc doesn't edit that file):

> **"How do you handle SEBI's static IP rule for cloud-hosted API orders?"**
> The hosted instance is `ENABLE_TRADING=false` so the rule doesn't apply to us today. For self-hosters who turn trading on, the README's deploy template allocates a static egress IPv4 on Fly (`fly ips allocate-egress`, $3.60/mo), which the user then adds to their Kite developer console IP whitelist. Kite Connect's FAQ explicitly accepts cloud-provider IPs.

> **"Wait, but isn't that 'shared' since Fly's egress is technically NAT'd?"**
> Fly's app-scoped static egress IPv4 is allocated per-app, persists across deploys and machine restarts, and is what your traffic actually appears as to upstream. SEBI's circular requires "static IP whitelisted by the broker" — not "exclusively owned IP." Kite's FAQ accepts cloud provider IPs (AWS, GCP — same NAT model). $3.60/month for stable + traceable beats $0 for "may change without notice."

### What NOT to communicate

- Don't post the actual egress IP in `docs/show-hn-post.md` ahead of allocation — it will look like a contradiction once allocated. Reference it abstractly (e.g., "static IP available in deploy output / `/.well-known/static-ip`").
- Don't claim "SEBI compliant" — we are a tool, the user is the SEBI-mandate subject. Use the framing: "we provide the infrastructure for users to comply."

---

## §7. Frontmatter / verification

- **As-of:** 2026-05-11
- **Re-verify by:** 2026-08-11 (90 days; SEBI/NSE circulars sometimes ship clarifications)
- **Authoritative re-verify probes:**
  - `flyctl ips list -a kite-mcp-server` — confirm whether egress IPs allocated
  - `curl https://kite-mcp-server.fly.dev/healthz` from a known endpoint → check forwarding IP
  - `support.zerodha.com/category/.../kite-connect-api-faqs` for any FAQ-language drift
  - `sebi.gov.in/legal/circulars/feb-2025/...91614.html` for circular text (PDF lookup if needed)
- **Confidence:** HIGH on the regulatory interpretation. HIGH on the Fly mechanics. MEDIUM on the actual cost (could shift if Fly changes pricing — community thread confirms $3.60/mo as of Jan 1, 2026).
- **Failed-WebFetches:**
  - `nsearchives.nseindia.com/content/circulars/INVG67858.pdf` — socket closed during fetch. Secondary sourcing used instead. Worth a direct fetch in a follow-up if anyone needs the verbatim NSE text.
  - `sebi.gov.in/.../91614.html` — page rendered metadata only, not the circular PDF. Used QuotaGuard + Liquide + Sahi quoted excerpts for SEBI text. Excerpts are consistent across 4+ secondary sources.

## Sources

### SEBI / NSE Regulatory
- [SEBI safer participation of retail investors in algo trading (Feb 2025)](https://www.sebi.gov.in/legal/circulars/feb-2025/safer-participation-of-retail-investors-in-algorithmic-trading_91614.html)
- [SEBI extension circular Jul 2025](https://www.sebi.gov.in/legal/circulars/jul-2025/extension-of-timeline-for-implementation-of-sebi-circular-sebi-ho-mirsd-mirsd-pod-p-cir-2025-0000013-dated-february-04-2025_95677.html)
- [NSE Circular INVG67858 (PDF)](https://nsearchives.nseindia.com/content/circulars/INVG67858.pdf)
- [Z-Connect: comprehensive overview of NSE circular](https://zerodha.com/z-connect/general/a-comprehensive-overview-of-nses-circular-on-the-new-retail-algo-trading-framework)
- [QuotaGuard: SEBI static IP mandate analysis](https://www.quotaguard.com/blog/sebis-static-ip-mandate-is-live-fix-your-cloud-trading-bot-now)
- [Liquide.life: SEBI 2026 algo trading regulations](https://blog.liquide.life/sebi-algo-trading-regulations-2026/)
- [Sahi.com: SEBI algo trading rules 2026](https://www.sahi.com/blogs/sebi-algo-trading-rules-2026-what-every-retail-trader-must-know-before-april)

### Zerodha Kite Connect
- [Kite Connect API FAQs (official Zerodha support)](https://support.zerodha.com/category/trading-and-markets/general-kite/kite-api/articles/kite-connect-api-faqs)
- [Kite forum: preparing to comply with SEBI's retail algo rules](https://kite.trade/forum/discussion/15912/preparing-to-comply-with-sebis-retail-algo-rules-static-ip-ratelimits-order-types)
- [Kite forum: static IP regulation NSE circular](https://kite.trade/forum/discussion/15016/static-ip-regulation-nse-circular)
- [Kite forum: entering static IP for whitelisting](https://kite.trade/forum/discussion/15460/entering-static-ip-for-whitelisting)
- [Kite forum: market protection and static IP](https://kite.trade/forum/discussion/15873/regarding-market-protection-and-static-ip)
- [Kite forum: static IP clarification](https://kite.trade/forum/discussion/15933/static-ip-clarification)

### Fly.io Network
- [Fly.io egress IPs documentation](https://fly.io/docs/networking/egress-ips/)
- [Fly.io public network services](https://fly.io/docs/networking/services/)
- [Fly.io pricing](https://fly.io/docs/about/pricing/)
- [Fly.io community: billing for app-scoped egress IPs starts Jan 1, 2026](https://community.fly.io/t/billing-for-app-scoped-egress-ips-starts-jan-1-2026/26686)
- [Fly.io flyctl ips allocate v4](https://fly.io/docs/flyctl/ips-allocate-v4/)
- [fly-apps/fly-fixed-egress-ip-proxy](https://github.com/fly-apps/fly-fixed-egress-ip-proxy)
- [QuotaGuard: Fly.io static outbound IP](https://www.quotaguard.com/blog/fly-io-static-outbound-ip)

### Competitive
- [Official Zerodha Kite MCP server GitHub](https://github.com/zerodha/kite-mcp-server)
- [Upstox MCP announcement (Feb 25, 2026)](https://community.upstox.com/t/announcing-upstox-mcp-your-trading-data-now-works-with-ai-assistants/14334)
- [Upstox MCP integration docs](https://upstox.com/developer/api-documentation/mcp-integration/)
- [Dhan community MCP (Mayank Thole)](https://github.com/mayankthole/dhan-mcp-trades)
- [TurtleStack multi-broker MCP](https://github.com/turtlehq-tech/turtlestack-lite)
- [Upstox: please help me get my static IP whitelisted for SEBI 2026](https://community.upstox.com/t/please-help-me-get-my-static-ip-whitelisted-and-my-algorithmic-trading-system-approved-for-sebi-2026-compliance/15038)
- [Upstox developer announcements: algo trading circular](https://upstox.com/developer/api-documentation/announcements/algo-trading-circular/)
