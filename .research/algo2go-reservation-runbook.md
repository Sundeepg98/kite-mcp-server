# Algo2Go Brand Reservation Runbook — Saturday Side-Quest

**Date**: 2026-05-03
**HEAD audited**: `1848a96` (`research: multi-repo execute-or-defer`)
**Charter**: Path B from `1848a96`. Reserve the brand only — domain + GitHub org + TM filing + npm/PyPI/social handle namespace squat. **No code migration. No repo rebrand.** kite-mcp-server stays at `Sundeepg98` namespace.
**Total user time**: ~2 hours sequential. **Total cost**: ~₹19-23k one-time + ~₹2k/yr renewal.

**Predecessors**:
- `645c034` (now in `kite-mcp-internal` private) — Algo2Go umbrella product strategy; Phase 6 verdict to RESERVE the brand
- `1848a96` `.research/multi-repo-execute-or-defer.md` — Path A+B as strict dominator (19/21 score)
- `MEMORY.md` `kite-algo2go-rename.md` — TM cost ₹4.5k/class (govt) or ₹9-11k/class (full filing); Class 36 + 42 = ₹18-22k

---

## TL;DR — empirical availability + this-week actions

### Availability check (run 2026-05-03 IST)

| Channel | Result | Source |
|---|---|---|
| `algo2go.com` | **AVAILABLE** | RDAP Verisign HTTP 404 (`https://rdap.verisign.com/com/v1/domain/algo2go.com`) + DNS resolution failure (no nameservers) |
| `algo2go.net` | AVAILABLE | RDAP Verisign 404 |
| `algo2go.org` | AVAILABLE | RDAP PIR 404 |
| `algo2go.io` | AVAILABLE | RDAP Identity Digital 404 |
| `algo2go.dev` | AVAILABLE | RDAP PIR 404 |
| `algo2go` GitHub org | **AVAILABLE** | `GET api.github.com/orgs/algo2go` → 404 |
| `algo2go` GitHub user | AVAILABLE | `GET api.github.com/users/algo2go` → 404 |
| `algo2go` on npm | **AVAILABLE** | `GET registry.npmjs.org/algo2go` → 404 |
| `algo2go` on PyPI | **AVAILABLE** | `GET pypi.org/pypi/algo2go/json` → 404 |
| `@algo2go` on X / Twitter | **LIKELY AVAILABLE** | `https://twitter.com/algo2go` → 301 redirect to x.com (standard for unknown handles); `https://x.com/algo2go` returns the X login wall (HTTP 200) which is the same response served for non-existent handles since X's anti-scraping change |
| `r/algo2go` subreddit | **LIKELY AVAILABLE** | reddit.com responses are anti-bot 403; manual check needed |
| `u/algo2go` Reddit user | **LIKELY AVAILABLE** | same 403 |
| `algo2go.bsky.social` | TAKEN OR PROTECTED | HTTP 200 from bsky.app — ambiguous (could be the platform's catch-all); manual visit needed |

### CRITICAL CORRECTION — Tradarc backup name is NOT clean

Memory `kite-algo2go-rename.md` claimed `tradarc.com` is the documented backup if Algo2Go gets contested. **Empirical RDAP check confirms `tradarc.com` is REGISTERED and held by Server Plan Srl (Italian registrar) since 2001-05-04. Expires 2026-05-04 (literally tomorrow as of this writing).** It may drop on May 5 if the holder doesn't renew, but this is a low-probability gamble — most domains auto-renew. **The Tradarc backup is unreliable as documented.** If user wants a real backup name, fresh research is needed.

Possible alternative backup names (NOT verified — user must check):
- `Algoflow` / `Algowire` / `Algogrid` / `Algogo`
- `Tradarc.io` (verify; .com is taken)
- `GoQuant` / `QuantGo` (likely taken in Indian fintech)

User should NOT spend a TM filing fee on Tradarc without re-checking.

### Three user actions ranked by criticality

| # | Action | Cost | Time | Why this rank |
|---|---|---|---|---|
| 1 | **Buy `algo2go.com`** at Namecheap or GoDaddy | ₹1k/yr | 5 min | Squatter risk is highest here; domains can be claimed any moment by anyone watching expiring/likely-target lists. Once registered, reservation is bulletproof. |
| 2 | **Create `algo2go` GitHub org** | ₹0 | 2 min | Free; 0 risk; protects against another developer creating the same org name and forcing us to negotiate. Same-day. |
| 3 | **File TM Class 36 + 42 via Vakilsearch / LegalWiz** | ₹18-22k | 30 min online | TM examination is 12-18 months but usage allowed immediately as `Algo2Go™`. Locks the legal escape route from any future Zerodha C&D. Filing date establishes priority. |

Actions 4-7 (npm/PyPI/social handles) are quick (~30-60 min total) and free except for the ~10 minute publish steps which need user's auth tokens.

---

## Phase 1 — Empirical availability check (already complete)

### Method

Used five independent signal sources to triangulate availability:

1. **Verisign RDAP** (canonical for .com/.net): `https://rdap.verisign.com/com/v1/domain/<name>` returns 404 for unregistered, full JSON for registered.
2. **GitHub REST API** (public, no auth): `GET https://api.github.com/orgs/<name>` and `/users/<name>` return 404 for unclaimed.
3. **npm registry** (public): `GET https://registry.npmjs.org/<name>` returns 404 for unclaimed.
4. **PyPI JSON API** (public): `GET https://pypi.org/pypi/<name>/json` returns 404 for unclaimed.
5. **HTTP probe** (basic existence): `curl -I https://<host>` for service-level checks (Twitter, Bluesky, Reddit).

### Results detail (2026-05-03 IST)

```
algo2go.com (Verisign RDAP)               → HTTP 404           → AVAILABLE
algo2go.com (DNS resolution)              → "Could not resolve" → AVAILABLE
algo2go.net (Verisign RDAP)               → HTTP 404           → AVAILABLE
algo2go.org (PIR RDAP)                    → HTTP 404           → AVAILABLE
algo2go.io (Identity Digital RDAP)        → HTTP 404           → AVAILABLE
algo2go.dev (PIR RDAP)                    → HTTP 404           → AVAILABLE
github.com/orgs/algo2go (API)             → 404 "Not Found"    → AVAILABLE
github.com/users/algo2go (API)            → 404 "Not Found"    → AVAILABLE
registry.npmjs.org/algo2go                → HTTP 404           → AVAILABLE
pypi.org/pypi/algo2go/json                → HTTP 404           → AVAILABLE
twitter.com/algo2go                       → 301 → x.com/algo2go → ambiguous (X's anti-scrape behavior)
reddit.com/u/algo2go.json                 → HTTP 403            → ambiguous (anti-bot)
reddit.com/r/algo2go.json                 → HTTP 403            → ambiguous
bsky.app/profile/algo2go.bsky.social      → HTTP 200            → ambiguous (Bluesky catch-all)

tradarc.com (Verisign RDAP)               → HTTP 200, registered 2001-05-04, expires 2026-05-04 → TAKEN
```

### Interpretation

**Definitively AVAILABLE** (verified via canonical APIs):
- `algo2go.com`, `algo2go.net`, `algo2go.org`, `algo2go.io`, `algo2go.dev`
- `algo2go` on GitHub (org and user namespace)
- `algo2go` on npm
- `algo2go` on PyPI

**Needs MANUAL check** (anti-bot blocks programmatic checks):
- `@algo2go` on X / Twitter — visit `https://x.com/algo2go` in a logged-in browser; should show "This account doesn't exist"
- `r/algo2go` and `u/algo2go` on Reddit — visit `https://reddit.com/r/algo2go` in a logged-in browser
- `algo2go.bsky.social` on Bluesky — visit `https://bsky.app` and try registering the handle
- `algo2go` on Mastodon (mastodon.social) — visit `https://mastodon.social/@algo2go`
- `algo2go` on Threads — visit `https://threads.net/@algo2go`

**TAKEN** (empirically confirmed):
- `tradarc.com` (Italian registrant; expires 2026-05-04 — possibly drops May 5 but most domains auto-renew, so don't gamble)

---

## Phase 2 — User-do steps with paste-ready content

### A. Buy `algo2go.com` at Namecheap (5 min, ₹1k/yr)

**Why Namecheap over GoDaddy**: Namecheap's WhoisGuard (privacy) is free with `.com`; GoDaddy charges extra. Namecheap UI is also less aggressive on upsells.

**URL**: `https://www.namecheap.com/domains/registration/results/?domain=algo2go.com`

**Form pre-fill checklist**:
- Domain: `algo2go.com`
- Term: 1 year (auto-renew ON; can extend later — no point pre-paying multi-year before TM examination concludes)
- Privacy: WhoisGuard ON (free; hides registrant info from public WHOIS)
- Auto-renew: ON
- Optional addons (DECLINE all): SSL certificate (we use Fly.io's autocert), email hosting, Whois privacy (already free)

**Expected price**: ~$10-13/yr USD (~₹830-1,080/yr INR at current FX) for first year on Namecheap. Renewal ~$15/yr (~₹1,250/yr).

**DNS configuration after purchase**:

For now, leave default Namecheap parking nameservers. **Don't point DNS to Fly.io static IP `209.71.68.157`** — that's the kite-mcp-server's deployed IP; pointing algo2go.com there would conflate the brands prematurely.

When Path B is activated (rebrand triggered per `645c034` Phase 6), DNS will be reconfigured to:
- `algo2go.com` → CNAME `algo2go.fly.dev` (after we create that Fly app) OR redirect to `github.com/algo2go`
- `www.algo2go.com` → CNAME same

For now, use Namecheap's "Redirect URL" feature → forward `algo2go.com` → `https://github.com/algo2go` (the empty org page). One-line config; takes ~2 min after registration.

---

### B. Create `algo2go` GitHub org (2 min, ₹0)

**URL**: `https://github.com/account/organizations/new`

**Form pre-fill**:
- Organization account name: `algo2go`
- Contact email: user's main email (NOT the renusharmafoundation address per user-rule MEMORY)
- Plan: **Free** (private repos limited to 3 collaborators; sufficient for now)
- This organization belongs to: My personal account (so it's owned by `Sundeepg98` user)

**Post-creation settings** (GitHub → algo2go → Settings):
- Display name: `Algo2Go`
- Description: `Trading-AI tooling. Currently anchored on kite-mcp-server.`
- URL: `https://algo2go.com` (after Step A completes)
- Email: hidden
- Verified domains: skip (requires DNS records; do later)
- Member privacy: Private members default
- Two-factor authentication requirement: ON for all members
- Default repository permission: None
- Member repository permission: None (only org-creator can create)

**Profile README** (paste into `algo2go/.github/profile/README.md` after creating a `.github` repo):

```markdown
# Algo2Go

Open-source trading-AI tooling for Indian markets.

Current anchor: [kite-mcp-server](https://github.com/Sundeepg98/kite-mcp-server) — a Model Context Protocol server that turns Claude / ChatGPT into a power-user trading copilot for Zerodha Kite. ~80 tools, 9 pre-trade safety checks, paper trading, Black-Scholes Greeks, backtesting, Telegram alerts.

## Why Algo2Go

We're reserving this org as an umbrella for future trading-AI tooling — a place to spin out shared libraries (riskguard, audit-trail, indicators) when external developer demand justifies the split. No premature multi-repo theater; the lead product stays at [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server) until traction warrants the move.

## What's planned (gated on community demand)

- **kite-mcp-server** (Go, MIT) — the anchor product.
- **algo2go-riskguard** (Go library) — extracted from kite-mcp-server's pre-trade safety checks. Spin-out trigger: 50+ stars on parent OR ≥2 inbound questions about standalone use.
- **algo2go-audit** (Go library) — extracted tamper-evident audit trail for AI tool calls. Spin-out trigger: external AI-agent-builder demand.
- **algo2go-cli** (Go binary) — terminal-first interface. Trigger: Pre-Seed close.

## Contact

Open an issue on [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server) — this org's repos will be cross-linked there as they spin out.

License: MIT (anchor); per-repo as spin-outs land.
```

**(151 words)**

**To publish the profile README** (after creating the org):

```bash
# After org is created, create the .github repo
gh repo create algo2go/.github --public --description "Profile content for algo2go org"

# Clone, add the README, push
git clone https://github.com/algo2go/.github
cd .github
mkdir -p profile
# Save the markdown above as profile/README.md
git add profile/README.md
git commit -m "Initial profile README"
git push
```

The README will then appear at `https://github.com/algo2go`.

---

### C. File TM Class 36 + 42 via Vakilsearch (30 min online, ₹18-22k)

**Recommended platform**: Vakilsearch (vakilsearch.com) or LegalWiz (legalwiz.in). Both handle DPIIT-startup discount eligibility check.

**URL**: `https://vakilsearch.com/online-trademark-registration` OR `https://www.legalwiz.in/trademark-registration`

**Form pre-fill content**:

**Mark Type**: Word Mark
**Mark Text**: `ALGO2GO` (all caps; this is the standard convention for word marks)
**Tagline / Logo**: None for initial filing (logo can be filed as separate device mark later)
**Translation/Transliteration**: None (mark is not in a foreign language)

**Class 36 — Financial Services**

Class 36 description (paste into the application):

```
Financial services, namely, providing a software-as-a-service (SaaS)
platform for stock market analysis, brokerage account integration,
algorithmic trade order placement, portfolio analysis, market data
aggregation, options pricing analytics, paper-trading simulation,
backtesting of trading strategies, and pre-trade risk assessment;
financial information services delivered via Application Programming
Interface (API) and Model Context Protocol (MCP); financial software
for retail self-directed investors trading on Indian recognised stock
exchanges (NSE, BSE) under SEBI's retail trader framework. The mark
is used in connection with self-hosted and hosted financial-software
endpoints exposing trading and analytics tools to AI-assistant clients.
```

**Class 42 — Technology Services / Software-as-a-Service**

Class 42 description (paste into the application):

```
Software-as-a-Service (SaaS) services featuring software for trading-
account integration, market-data analytics, options Greeks computation,
strategy backtesting, paper-trading, audit logging, and pre-trade risk
checks; design and development of computer software, namely, Model
Context Protocol (MCP) servers and client integrations; cloud-hosted
software platforms; software libraries for financial market analysis;
research, design, and development of computer software providing
trading-AI assistant integrations; technology consulting in financial
software systems; computer programming services; software application
development; technical support services for proprietary computer
software; programming and maintenance of computer software for trading-
AI applications.
```

**Applicant Type Decision**:

Three applicant-type options affect government fee:
- **Individual** (Sundeep G — natural person): ₹4,500/class govt fee. Total Class 36 + 42 = ₹9,000 govt + ₹9,000-13,000 agent fee = ₹18-22k.
- **DPIIT-recognized startup** (if Pvt Ltd is DPIIT-certified): ₹4,500/class govt fee (same discount as individual). Total ~same as individual.
- **MSME-registered entity**: ₹4,500/class. Total ~same.
- **Other (LLP / Pvt Ltd without DPIIT)**: ₹9,000/class. Total Class 36 + 42 = ₹18,000 govt + ₹9,000-13,000 agent = ₹27-31k.

**Recommendation**: file as **Individual** (Sundeep G) — cheapest, fastest, no entity-creation prerequisite. Once Pvt Ltd is incorporated post-Pre-Seed, transfer ownership of the mark to the company via TM-P form (₹2-3k separately; takes 2-4 weeks).

**Document checklist** (Vakilsearch will request):
1. PAN card of applicant (individual) — scan
2. Aadhaar card of applicant — scan
3. Address proof (Aadhaar suffices)
4. Email + phone (will get OTP)
5. Logo (if filing combined logo+word; we're filing word only — skip)
6. Power of Attorney signed in favor of the agent (Vakilsearch generates and emails — sign + return scan)
7. **Use date** (when did you first start using `Algo2Go` in commerce): for a brand reservation that hasn't been used yet, leave blank OR file as "Proposed to be used" (this is standard for forward-looking filings).

**Use vs Proposed-to-be-used decision**:
- "Used since": stronger TM rights from registration date (back-dated to first use). Requires documentary proof (invoices, ads, social media posts) showing the date. We have NONE today; this would be perjury if we claimed an earlier date.
- "Proposed to be used": weaker initial rights but legal and clean. Once we activate the brand, proof of use accumulates and at registration time it converts.

**Recommendation**: file as **"Proposed to be used"**. Standard for forward-looking brand reservation.

**Timeline expectations**:
- Filing → official receipt: **same day** (Vakilsearch sends within 24h)
- Application examination: **6-12 months** (TM Office)
- First Examination Report (FER) / objection: **typical** (most marks face one objection requiring counter-statement; Vakilsearch handles)
- Journal publication: **1-3 months after acceptance**
- Opposition window: **4 months from publication**
- Registration certificate: **12-18 months total** if no opposition

**During this period**:
- We can use `Algo2Go™` (the TM symbol) immediately
- We CANNOT use `Algo2Go®` (the registered symbol) until certificate issues
- Filing date establishes priority — even if examination takes 18 months, the rights date back to filing

---

### D. Reserve `@algo2go` on X (Twitter) (5 min, free)

**URL**: `https://twitter.com/i/flow/signup`

**Pre-fill**:
- Name: `Algo2Go`
- Email: user's main email
- Date of birth: user's
- Username: `algo2go` (verify availability at signup; if taken, fall back to `algo2go_in` or `getalgo2go`)
- Bio: `Trading-AI tooling for Indian markets. github.com/algo2go`
- Location: `India`
- Website: `https://algo2go.com` (after Step A)

**Post-signup**:
- Profile photo: temporary geometric placeholder (replace at brand-designer engagement per `team-scaling-cost-benefit-per-axis.md`)
- Header: temporary plain color
- Don't tweet yet (silence is fine until rebrand triggered)

---

### E. Run `npm publish` on Algo2Go placeholder (5 min, free)

Agent has generated the package scaffolding below. User runs publish.

**Directory layout** (create in any parent dir; example `D:\Sundeep\projects\algo2go-npm-stub\`):

```
algo2go-npm-stub/
├── package.json
├── index.js
├── README.md
└── LICENSE
```

**`package.json`** (paste-ready):

```json
{
  "name": "algo2go",
  "version": "0.0.1",
  "description": "Algo2Go umbrella namespace placeholder. See https://github.com/algo2go for active packages.",
  "main": "index.js",
  "keywords": [
    "algo2go",
    "namespace",
    "placeholder",
    "trading",
    "fintech",
    "india"
  ],
  "homepage": "https://github.com/algo2go",
  "repository": {
    "type": "git",
    "url": "https://github.com/algo2go/algo2go-npm-stub"
  },
  "author": "Sundeep G",
  "license": "MIT",
  "engines": {
    "node": ">=18"
  }
}
```

**`index.js`** (paste-ready):

```javascript
// Algo2Go umbrella namespace placeholder.
// See https://github.com/algo2go for active packages.
module.exports = {
  reserved: true,
  namespace: 'algo2go',
  homepage: 'https://github.com/algo2go'
};
```

**`README.md`** (paste-ready):

```markdown
# algo2go

Algo2Go umbrella namespace placeholder.

This package reserves the `algo2go` name on npm. Active Algo2Go packages will be published under `@algo2go/<name>` (scoped) once the umbrella is activated.

For the current anchor product, see [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server).

## License

MIT — Sundeep G
```

**`LICENSE`** (paste-ready):

```
MIT License

Copyright (c) 2026 Sundeep G

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

**Publish commands** (user runs):

```bash
cd algo2go-npm-stub
npm login            # if not already logged in; uses npm credentials
npm publish --access public
```

**Verify**: `https://www.npmjs.com/package/algo2go` should show the placeholder within ~30s.

---

### F. Run `twine upload` on Algo2Go PyPI placeholder (5 min, free)

**Directory layout** (example `D:\Sundeep\projects\algo2go-pypi-stub\`):

```
algo2go-pypi-stub/
├── pyproject.toml
├── algo2go/
│   └── __init__.py
├── README.md
└── LICENSE
```

**`pyproject.toml`** (paste-ready):

```toml
[build-system]
requires = ["setuptools>=64", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "algo2go"
version = "0.0.1"
description = "Algo2Go umbrella namespace placeholder. See https://github.com/algo2go for active packages."
authors = [
  { name = "Sundeep G" }
]
license = { text = "MIT" }
readme = "README.md"
requires-python = ">=3.10"
keywords = ["algo2go", "namespace", "placeholder", "trading", "fintech", "india"]
classifiers = [
  "Development Status :: 1 - Planning",
  "Intended Audience :: Developers",
  "License :: OSI Approved :: MIT License",
  "Operating System :: OS Independent",
  "Programming Language :: Python :: 3",
  "Programming Language :: Python :: 3 :: Only",
  "Topic :: Office/Business :: Financial :: Investment"
]

[project.urls]
Homepage = "https://github.com/algo2go"
Repository = "https://github.com/algo2go/algo2go-pypi-stub"

[tool.setuptools.packages.find]
where = ["."]
include = ["algo2go*"]
```

**`algo2go/__init__.py`** (paste-ready):

```python
"""
Algo2Go umbrella namespace placeholder.
See https://github.com/algo2go for active packages.
"""

RESERVED = True
NAMESPACE = "algo2go"
HOMEPAGE = "https://github.com/algo2go"

__version__ = "0.0.1"
```

**`README.md`** (paste-ready): same as Step E (substitute "PyPI" for "npm" in the first sentence).

**`LICENSE`** (paste-ready): same as Step E.

**Publish commands** (user runs):

```bash
cd algo2go-pypi-stub
python -m pip install --upgrade build twine
python -m build               # generates dist/
python -m twine upload dist/* # prompts for PyPI username/password OR uses ~/.pypirc
```

If user uses PyPI API tokens (recommended): set username `__token__` and password = the API token.

**Verify**: `https://pypi.org/project/algo2go/` should show the placeholder within ~30s.

---

### G. Optional: Reserve more handles (~30 min, free)

In order of value:

| Channel | URL | Notes |
|---|---|---|
| Bluesky | https://bsky.app/ → settings → handle | claim `algo2go.bsky.social`. Bluesky has wide adoption among devs in 2026. |
| Mastodon (mastodon.social) | https://mastodon.social/auth/sign_up | claim `@algo2go@mastodon.social`. Federated; can move servers later. |
| Reddit (subreddit) | https://www.reddit.com/subreddits/create | request `r/algo2go`. Requires user-account in good standing for ~30 days. |
| Reddit (user) | https://www.reddit.com/register | claim `u/algo2go` for cross-posting. Can be done same day. |
| Threads | https://threads.net (Instagram-linked) | claim `@algo2go`. Requires Instagram account. |
| Discord | https://discord.com/servers (no namespace lock; vanity URLs require boost) | NOT critical; defer per `645c034` (low ROI before community exists). |

---

## Phase 3 — Execution order checklist

```
[ ] 1. (5 min)  Buy algo2go.com on Namecheap with WhoisGuard ON, auto-renew ON
[ ] 2. (2 min)  Create algo2go GitHub org (free plan)
[ ] 3. (5 min)  Create algo2go/.github repo and push profile/README.md
[ ] 4. (5 min)  Sign up @algo2go on X / Twitter, set bio
[ ] 5. (10 min) Reserve @algo2go on Bluesky + Mastodon (optional)
[ ] 6. (5 min)  Generate npm stub package; npm login; npm publish
[ ] 7. (5 min)  Generate PyPI stub package; python -m build; twine upload
[ ] 8. (30 min) File TM Class 36+42 on Vakilsearch as Individual, Proposed-to-be-used
[ ] 9. (10 min) Configure Namecheap "Forward URL" → github.com/algo2go
[ ] 10. (3 min) Update algo2go/.github profile description to point to algo2go.com
```

**Total**: ~80 minutes minimum execution; plus ~30 min thinking / typing buffer = **~2 hours sequential**.

**Total cost**: ~₹1k (domain) + ~₹18-22k (TM filing as Individual) + ~₹0 (everything else) = **~₹19-23k one-time**, ~₹1k/yr renewal.

---

## Phase 4 — DON'T-DO checklist

These are explicitly OUT OF SCOPE for this weekend:

| Item | Why deferred | When to revisit |
|---|---|---|
| Rename `Sundeepg98/kite-mcp-server` repo | Defers Show HN, breaks all external links + mcp-remote OAuth caches | Trigger from `645c034` Phase 6 (Zerodha C&D / 50 paid users / multi-broker ships) |
| Migrate to `algo2go/algo2go-mcp` | Same as above | Same trigger |
| Rename Fly.io app `kite-mcp-server` → `algo2go` | Forces all users to re-OAuth | Same trigger |
| Update README hero / landing.html / launch material | Show-HN narrative is "kite-mcp-server"; rebranding mid-stream burns the launch | Post-rebrand-trigger |
| Spin out `algo2go/algo2go-riskguard` | 2-3 dev-weeks of work; no external demand | 50+ stars + ≥2 inbound use-questions per `multi-product-and-repo-structure.md` §5.5 |
| Spin out `algo2go/algo2go-audit` | 3-4 dev-weeks of work; no external demand | Same trigger |
| Set up `algo2go.com` to point to live MCP endpoint | Premature; current endpoint is `kite-mcp-server.fly.dev` | After rebrand triggered |
| Buy `tradarc.com` as backup | Memory was wrong; tradarc.com is held by an Italian registrant since 2001 | If user wants a real backup name, fresh research on alternatives (Algoflow / Algowire / GoQuant etc — all need fresh availability check) |
| Buy multiple TLDs (algo2go.io / .net / .ai) | Defensive cost; not justified at zero-revenue stage | Post-launch + 100 paying users |
| Build algo2go.com landing page | Premature; redirect to GitHub is enough | Post-rebrand-trigger |
| Hire designer for Algo2Go logo | Per `team-scaling-cost-benefit-per-axis.md`, brand designer is Tier-2 hire (post-100-paid-users) | Post-100-paid-users |

---

## Phase 5 — What the agent automated vs deferred to user

### Agent-automated (already done by writing this runbook)

1. **Empirical availability checks** for 12 channels via canonical APIs (Verisign RDAP, GitHub REST, npm registry, PyPI JSON). Results in Phase 1.
2. **Profile README content** for `algo2go/.github` (151 words, paste-ready).
3. **npm placeholder package scaffolding** — package.json, index.js, README.md, LICENSE (all 4 files paste-ready).
4. **PyPI placeholder package scaffolding** — pyproject.toml, __init__.py, README.md, LICENSE (all 4 files paste-ready).
5. **TM filing form pre-fill** — Class 36 + Class 42 word descriptions written in TM-Office-style legalese; applicant-type decision matrix; Use vs Proposed-to-be-used recommendation.
6. **Namecheap registration form pre-fill** — domain, term, privacy, auto-renew, addon-decline list.
7. **GitHub org creation form pre-fill** — name, display name, description, post-creation settings.
8. **Critical correction**: identified that memory's claimed Tradarc backup is unreliable (tradarc.com is held).

### User-do steps (identity-verified or paid)

These require user's own credentials and cannot be automated by an agent without violating standing rules:

- A. Buy `algo2go.com` on Namecheap (requires user payment method)
- B. Create `algo2go` GitHub org (requires user GitHub auth)
- C. File TM Class 36+42 on Vakilsearch (requires user PAN/Aadhaar/payment)
- D. Sign up `@algo2go` on X (requires user phone OTP)
- E. Run `npm publish` (requires user npm token)
- F. Run `twine upload` (requires user PyPI token)
- G. Optional: Bluesky / Mastodon / Reddit (requires user identity)

### Optional auto-able commands the user CAN run after the org is created

```bash
# After Step B (GitHub org created), user can run these from a logged-in shell:

# 1. Create the .github profile repo
gh repo create algo2go/.github --public \
  --description "Profile content for algo2go org"

# 2. Clone, add the README, push
git clone https://github.com/algo2go/.github
cd .github
mkdir -p profile

# Save the README content from Step B above as profile/README.md
# (Use the agent-generated 151-word README)

git add profile/README.md
git commit -m "Initial profile README — umbrella reservation"
git push

# 3. Set 2FA-required for the org
gh api -X PATCH orgs/algo2go \
  --field two_factor_requirement_enabled=true

# 4. Set member privacy to private (defaults are usually fine; confirm)
gh api -X PATCH orgs/algo2go \
  --field default_repository_permission=none
```

---

## Phase 6 — Verification post-execution

After completing Steps 1-10, verify each:

```bash
# Domain
curl -I https://algo2go.com                                # should redirect to github.com/algo2go (per Namecheap forward)
curl -sS https://rdap.verisign.com/com/v1/domain/algo2go.com | head -5  # should show registration

# GitHub org
curl -sS https://api.github.com/orgs/algo2go              # should return 200 + JSON
gh org list                                                # should include algo2go

# Profile README
curl -sS https://github.com/algo2go                        # should render the README

# npm
npm view algo2go                                           # should print the placeholder
curl -sS https://registry.npmjs.org/algo2go | head -10    # should return 200

# PyPI
pip index versions algo2go                                 # should show 0.0.1
curl -sS https://pypi.org/pypi/algo2go/json | head -5     # should return 200

# Twitter / X
curl -I https://x.com/algo2go                              # should return 200 (account exists)

# Vakilsearch — verification email arrives within 24h with TM application receipt
```

---

## Phase 7 — Honest caveats

1. **Tradarc backup memory is stale**. `tradarc.com` is held since 2001-05-04 (Italian registrant, expires 2026-05-04). Don't pursue Tradarc without re-checking; if memory's other data is verified by user (TM availability, GitHub availability), it's also worth re-doing the check the day before filing.

2. **TM filing as Individual is irreversible without a TM-P transfer form** (₹2-3k, 2-4 weeks to assign to Pvt Ltd later). Cleanest path: file as Individual now; transfer to Pvt Ltd post-incorporation. Cost addition is small.

3. **TM examination is 6-12 months minimum**. Even after filing, a competing party can oppose during the 4-month window post-publication. We have NO conflicts identified per memory `kite-algo2go-rename.md` (Class 36/42 clear in IP India DB), but examination outcome is not guaranteed.

4. **DNS forwarding is fragile**. Namecheap's URL Forward uses HTTP 301; if Namecheap's nameservers go down, the forward breaks. For long-term setup, user should use Cloudflare DNS (free) and a Page Rule. **Not urgent** — can be done post-rebrand-trigger.

5. **The `@algo2go` handle on X / Twitter is hardest to verify programmatically** in 2026 due to anti-scraping. Manual visit in a logged-in session is the only reliable check. Twitter / X may also enforce account-age / verified-phone requirements before letting a new account claim a "good" handle.

6. **PyPI namespace squatting policy**: PyPI's `https://pypi.org/help/#name_conflict` policy permits placeholder packages but discourages "name hoarding without intent to develop." Our `0.0.1` placeholder with a clear README pointing to the umbrella + a stated intent to publish scoped packages under it is policy-compliant. If a future maintainer claims the name is being squatted, PyPI may transfer it; we can defend by showing the algo2go GitHub org + active development. **Risk is low but non-zero.**

7. **npm's "Hold an unused package" policy** is similar — placeholders are tolerated; pure squatting is not. Same defense (active GitHub org + intent statement) applies.

8. **GitHub org dormancy**: GitHub does not auto-reclaim inactive orgs. Once `algo2go` is created, it's permanent unless manually deleted.

9. **DPDP Act compliance**: when the user fills in any of these forms with personal data (PAN, Aadhaar, contact info), the recipients (Vakilsearch, Namecheap) become "Data Fiduciaries." Ensure the recipient's privacy policy is acceptable. Vakilsearch and Namecheap both have published India-compliant privacy policies as of 2025-2026.

10. **Fly.io app dormancy**: this runbook does NOT create `algo2go.fly.dev`. Doing so prematurely would consume a Fly.io app slot ($0/month at zero-traffic but visible to other users in `fly apps list -o sundeepg98`). Defer until rebrand triggered.

---

## Sources

- HEAD audited: `1848a96`
- Predecessor: `645c034` (Algo2Go umbrella product strategy, now in `kite-mcp-internal` private repo via `dd8be3a`)
- Predecessor: `1848a96` `.research/multi-repo-execute-or-defer.md` Path A+B verdict
- Memory: `kite-algo2go-rename.md` (TM availability, filing cost — but Tradarc backup data is stale)
- Empirical availability checks: Verisign RDAP (`rdap.verisign.com`), PIR RDAP (`rdap.publicinterestregistry.org`), Identity Digital RDAP, GitHub REST API (`api.github.com`), npm registry (`registry.npmjs.org`), PyPI JSON API (`pypi.org/pypi`), HTTP probes for X/Reddit/Bluesky
- TM filing class scope: derived from kite-mcp-server's empirical capability inventory in `docs/product-definition.md` Section 1, mapped to Nice Classification Class 36 (financial) and Class 42 (software)
- DPIIT-startup discount eligibility: India Startup Recognition guidelines

---

*Generated 2026-05-03, read-only research deliverable. Agent-automated steps are in this doc; user-do steps are paste-ready and ranked by criticality. Total user time: ~2 hours sequential. Total cost: ~₹19-23k one-time + ~₹1k/yr.*

---

## Phase 8 — Playwright execution log (live drive-through, 2026-05-03 IST)

The agent drove each reservation form to its safety boundary. Per-step state and exact user resumption point below.

### STEP A — Namecheap `algo2go.com` purchase

**State**: `PRE-FILLED-CART-WAITING-FOR-USER-LOGIN`

**Confirmed empirically on the page**:
- `algo2go.com` AVAILABLE
- **Price: $11.28/yr regular, $6.79 first-year with promo code `NEWCOM679`** (new customers only). At ₹83/$ = ~₹560 first year, ~₹950/yr renewal.
- Other Namecheap-shown TLDs available: `algo2go.org` $7.48/yr, `algo2go.net` $12.48/yr, `algo2go.ai` $92.98/yr (min 2-yr). All RDAP-confirmed available.

**Agent did**:
1. Navigated to `https://www.namecheap.com/domains/registration/results/?domain=algo2go.com`
2. Clicked "Add to cart" on the primary `algo2go.com` result
3. Clicked "Checkout" → landed on `https://www.namecheap.com/shoppingcart/`
4. Cart shows `algo2go.com` + auto-included "Privacy and Uptime protection" at $0.20

**User resumes here**:
- Visit `https://www.namecheap.com/shoppingcart/` (cart should still have your item if same browser session; if not, redo step 1)
- Click "Sign in" if you have an existing Namecheap account (you may already have one from prior projects); otherwise click "Sign up"
- After login: paste promo code `NEWCOM679` in the "Promo Code" field, click "Apply" — first-year price drops to $6.79
- Verify cart shows: `algo2go.com` (1 yr), `WhoisGuard` ON (free), `Auto-renew` ON
- Click "Confirm Order" → enter payment card → click "Pay"
- Expected total first year: ~$6.99 (~₹580). Renewal ~$15/yr (~₹1,250).

**Total user time at this step**: ~5 min (or ~10 min if creating new Namecheap account).

---

### STEP B — GitHub `algo2go` org creation

**State**: `BLOCKED-AT-GITHUB-LOGIN-REDIRECT`

**Agent did**:
1. Navigated to `https://github.com/account/organizations/new`
2. GitHub redirected to `https://github.com/login?return_to=https%3A%2F%2Fgithub.com%2Faccount%2Forganizations%2Fnew`

**Why blocked**: Playwright runs a fresh browser session with no `Sundeepg98` cookies. Login requires user's password (and likely 2FA TOTP). Per safety gate, agent does NOT enter passwords.

**User resumes here**:
1. Open `https://github.com/account/organizations/new` in a browser where you're already logged into GitHub as `Sundeepg98`
2. **Form pre-fill** (paste from runbook §B above):
   - Organization account name: `algo2go`
   - Contact email: your main personal email (NOT the renusharmafoundation address per user-rule)
   - This organization belongs to: My personal account (radio button)
   - Plan: Free
3. Click "Next" → may ask for billing details (skip if Free plan); click "Create organization"
4. After creation, run the agent-generated commands locally to seed the profile README:

```bash
gh repo create algo2go/.github --public \
  --description "Profile content for algo2go org"
git clone https://github.com/algo2go/.github
cd .github
mkdir -p profile
# Save the 151-word README from runbook §B as profile/README.md
git add profile/README.md
git commit -m "Initial profile README — umbrella reservation"
git push
```

5. Set 2FA-required for the org:

```bash
gh api -X PATCH orgs/algo2go --field two_factor_requirement_enabled=true
```

**Total user time at this step**: ~5 min.

---

### STEP C — Vakilsearch TM filing

**State**: `FORM-NAV-COMPLETE-WAITING-FOR-USER-PII`

**URL correction**: runbook's `https://vakilsearch.com/online-trademark-registration` returns 404 (URL changed since memory `kite-algo2go-rename.md` was written). **Current correct URL: `https://vakilsearch.com/trademark-registration`** (verified via Tavily + direct page load).

**Pricing observed on Vakilsearch (2026-05-03)**:
- **Basic plan: ₹1,499** (Vakilsearch professional fees)
- **Express plan: ₹1,999** (Vakilsearch fees, 6-hour filing)
- **Plus government fees**: ₹4,500/class for Individual/Startup/MSME, or ₹9,000/class for Pvt Ltd/LLP
- **Total Class 36 + 42 as Individual**: ₹1,499 (Vakilsearch) + ₹9,000 (govt 2 classes × ₹4,500) = **~₹10,500 minimum**
- **Express + 2 classes**: ₹1,999 + ₹9,000 = **~₹11,000**
- **Note**: Vakilsearch may add additional class-fees / search-fees during the form flow. Memory's "₹18-22k" estimate is on the high end and may include extras the runbook didn't quote.

**Agent did**:
1. Navigated to `https://vakilsearch.com/trademark-registration`
2. Clicked "Proceed to pay" on the Basic ₹1,499 plan
3. Landed on `https://vakilsearch.com/onboarding-v1/step-1?id=tm-reg`
4. Form step 1 of 3 ("Basic Details") expanded — three fields visible: Email ID, Mobile number, City/Pincode

**Why agent stopped**: These are user PII fields. Agent does not have user's product-context email (renusharmafoundation address explicitly forbidden by user-rule), phone, or city.

**User resumes here**:
1. Open `https://vakilsearch.com/trademark-registration` in your browser
2. Click "Proceed to pay" on Basic ₹1,499 plan (Express ₹1,999 is faster but unnecessary at our stage)
3. Step 1 of 3 — fill:
   - Email ID: your main personal email
   - Mobile number: your Indian mobile (10-digit, no +91)
   - City: your city (e.g. Bangalore / Mumbai / Pune)
4. Click "Next" → step 2 will ask for trademark details. Use:
   - Mark text: `ALGO2GO`
   - Mark type: Word Mark (not logo)
   - Class: select **Class 36** (financial services) — see Class 36 description in runbook §C above; paste their structured fields if asked
   - Add another class: **Class 42** (technology services) — paste Class 42 description from runbook §C
   - Applicant type: **Individual** (cheapest, ₹4,500/class govt fee)
   - Use status: **Proposed to be used** (not Used since X — we have no proof of past use)
5. Step 3 will ask for documents:
   - PAN card (scan/photo of your PAN)
   - Aadhaar card (scan/photo)
   - Address proof (Aadhaar suffices)
6. Pay ₹1,499 (Vakilsearch) → they will collect govt fees ₹9,000 separately or add to invoice. Total: ₹10,500-13,000 depending on plan
7. Vakilsearch sends Power of Attorney form via email — sign + return scan within 48h
8. Receive official TM filing receipt within 24-48h with application numbers (one per class)

**Total user time at this step**: ~30-45 min (including document scanning).

---

### STEP D — `@algo2go` X / Twitter signup

**State**: `LANDING-PAGE-LOADED-WAITING-FOR-USER-OTP-FLOW`

**Agent did**:
1. Navigated to `https://x.com/i/flow/signup`
2. X landing page loaded but the actual signup dialog is a modal that requires interaction (X's anti-bot collapses the dialog content in headless contexts)

**Why agent stopped**: signup requires:
- Phone number with SMS OTP verification, OR email with email OTP
- Date of birth
- A working phone the agent does not have

**User resumes here**:
1. Open `https://x.com/i/flow/signup` in a browser
2. Click "Create account" if a modal hasn't appeared
3. Fill:
   - Name: `Algo2Go`
   - Email: a fresh email (X enforces 1 account per email; if `Sundeepg98@gmail.com` is already on X, use a `+algo2go` alias e.g. `Sundeepg98+algo2go@gmail.com` which Gmail accepts and X typically treats as new)
   - Or Phone: your number
   - Date of birth: your real DOB (X requires 13+; just use yours)
4. Receive OTP via email or SMS, enter it
5. Skip "Customize your experience" prompts
6. **Username step**: type `algo2go` — should be available. Fall back to `algo2go_in` or `getalgo2go` if X claims taken (which would be a surprise; manual visit to `x.com/algo2go` from a logged-in account confirms unclaimed).
7. Bio: `Trading-AI tooling for Indian markets. github.com/algo2go`
8. Profile photo: skip for now (placeholder OK; replace at brand-designer engagement per `team-scaling-cost-benefit-per-axis.md` Tier-2)
9. Header: skip
10. Don't tweet yet (silence is fine until rebrand triggered per `645c034` Phase 6)

**Total user time at this step**: ~5-10 min.

---

### STEPS E + F — npm + PyPI publish

**State**: `NOT-BROWSER-AUTOMATABLE-USER-CLI-COMMANDS`

These are CLI operations that need user's npm and PyPI auth tokens. Agent generated the package scaffolding in runbook §E and §F (8 paste-ready files total: 4 npm + 4 PyPI). User runs:

```bash
# npm placeholder
mkdir -p ~/algo2go-npm-stub && cd ~/algo2go-npm-stub
# Paste the 4 files from runbook §E (package.json, index.js, README.md, LICENSE)
npm login        # if not already logged in
npm publish --access public

# PyPI placeholder
mkdir -p ~/algo2go-pypi-stub && cd ~/algo2go-pypi-stub
# Paste the 4 files from runbook §F (pyproject.toml, algo2go/__init__.py, README.md, LICENSE)
python -m pip install --upgrade build twine
python -m build
python -m twine upload dist/*    # uses ~/.pypirc OR prompts for token
```

Verify post-publish:
```bash
npm view algo2go              # should show 0.0.1 placeholder
pip index versions algo2go    # should show 0.0.1
```

**Total user time at this step**: ~5-10 min.

---

### Per-step resumption summary

| Step | URL to resume at | Auth needed | User time |
|---|---|---|---|
| A. Namecheap | `https://www.namecheap.com/shoppingcart/` | Namecheap login + payment card | ~5-10 min |
| B. GitHub org | `https://github.com/account/organizations/new` | GitHub login (Sundeepg98) + 2FA | ~5 min |
| C. Vakilsearch TM | `https://vakilsearch.com/trademark-registration` (note: URL corrected from runbook §C) | Email + mobile OTP + PAN/Aadhaar + payment | ~30-45 min |
| D. X signup | `https://x.com/i/flow/signup` | Email or phone OTP | ~5-10 min |
| E. npm publish | local CLI | npm token (`npm login`) | ~3 min |
| F. PyPI publish | local CLI | PyPI token (`~/.pypirc`) | ~3 min |
| **TOTAL** | n/a | n/a | **~50-75 min** |

(Slightly faster than the runbook's earlier "~2 hours" estimate because Namecheap and Vakilsearch were already navigated to the post-form-load state by the agent.)

---

### What's pre-filled vs what still needs manual touch

**Pre-filled by agent** (verified live on the actual current pages, 2026-05-03):
- ✅ Namecheap: domain selected, in cart, with WhoisGuard auto-included (~$0.20)
- ✅ Vakilsearch: TM application onboarding step-1 reached; pricing structure confirmed ₹1,499 + ₹9,000 govt = ₹10,500 minimum (NOT ₹18-22k as memory estimated — see correction)
- ✅ Profile README content (151 words) ready to push to `algo2go/.github`
- ✅ npm + PyPI package scaffolding ready (8 files, paste-ready)
- ✅ TM Class 36 + Class 42 word descriptions in TM-Office-style legalese

**Still needs user manual touch**:
- ❌ Namecheap login + promo code paste + payment
- ❌ GitHub login + clicking "Create organization" + running `gh repo create` for profile README
- ❌ Vakilsearch: filling email/mobile/city + applicant details + document upload + payment
- ❌ X signup OTP flow + username confirmation + bio paste
- ❌ npm publish (needs `npm login`)
- ❌ PyPI publish (needs PyPI token)

### Runbook URL corrections (apply to future readers)

| Runbook §C original | Actual current (2026-05-03) | Reason |
|---|---|---|
| `https://vakilsearch.com/online-trademark-registration` | `https://vakilsearch.com/trademark-registration` | Vakilsearch URL slug changed; old URL returns 404 |
| Memory's "₹18-22k" total | **₹10,500-13,000 actual** | Vakilsearch base prices are lower than memory estimated; govt fee ₹4,500/class × 2 = ₹9,000 + ₹1,499-1,999 service = ₹10,500-11,000. Old estimate may have included optional extras (TM search ₹500-1,000, additional service fees). |

### Safety-gate compliance

✅ Did NOT enter any password / 2FA / payment card / phone OTP
✅ Did NOT proceed past any "Pay" / "Confirm Order" / "Submit Application" button
✅ Did NOT log session cookies or auth tokens to chat
✅ Did NOT hit any CAPTCHA blocks (none encountered; reCAPTCHA reference was passive notice only)
✅ Did NOT use the `g.karthick.renusharmafoundation@gmail.com` address per user-rule

---

*Phase 8 added 2026-05-03 IST. Playwright drove each form to its safety boundary; user resumption points are surgical — exact URL + exact field set + exact paste content.*
