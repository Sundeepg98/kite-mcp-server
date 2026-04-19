> **DRAFT — not yet in force.** This notice will replace any prior version at the time of public launch. Placeholders (e.g., `<your product email>`) must be substituted before publication.

> **REPLACE ALL `<your product email>` PLACEHOLDERS WITH A DEDICATED PRODUCT EMAIL BEFORE PUBLISHING. Do NOT use any Foundation-context email.**

# Terms of Service — kite-mcp-server (Hosted Instance)

**Last updated:** `<YYYY-MM-DD>`

These Terms govern your use of the hosted instance of **kite-mcp-server** at `https://kite-mcp-server.fly.dev` (the "Service"), operated by **Sundeep Govarthinam**, a sole proprietorship based in India ("Operator", "we"). Self-hosted deployments of the open-source code are governed by the MIT licence only and are outside these Terms.

---

## 1. Acceptance

By accessing or using the Service, you agree to these Terms. If you do not agree, do not use the Service.

---

## 2. Service description

The Service is a **Model Context Protocol (MCP) server** that lets your chosen AI client (e.g., Claude, an MCP-capable chat UI) communicate with **your own** Zerodha Kite account. It is a **software tool**, not a financial adviser, broker, research analyst, or portfolio manager. All trading decisions are yours.

---

## 3. Your account

- You must bring your **own Kite Connect developer app**. No shared or Operator-provided Kite credentials are used.
- Your use must stay within SEBI's **self-plus-family algorithmic-trading scope** as contemplated in §I(c) of the SEBI circular on algo trading by retail investors. **Multi-user or commercial hosting is out of scope.**
- You must keep your Kite credentials, OAuth tokens, and API key confidential. You are responsible for activity under your account.
- You must be **18 years or older** and hold an active Zerodha trading and demat account.

---

## 4. Prohibited use

You must not:

- Host the Service for **multiple end-users** (would violate SEBI §III(a) on broker-vendor empanelment).
- Place orders in a pattern exceeding **10 orders per second (OPS)** — that triggers empanelment obligations the Operator has not met.
- Share, resell, or sublicense your Kite credentials or access tokens.
- Reverse-engineer, scrape, or probe the hosted instance for vulnerabilities. (The **open-source code** is separate and is governed by the MIT licence — you can study, modify, and run that freely.)
- Circumvent or disable safety controls, including the **riskguard** layer, **elicitation confirmations**, or the `ENABLE_TRADING` feature flag.
- Engage in market manipulation, spoofing, layering, wash trading, or any conduct prohibited by SEBI (Prohibition of Fraudulent and Unfair Trade Practices) Regulations, 2003, or the SCRA.

---

## 5. SEBI disclaimer — no investment advice

The Operator is **not registered with SEBI** as an Investment Adviser, Research Analyst, Portfolio Manager, or Stock Broker. Any fees charged are for **software access only** and do not constitute investment advice or research.

Analytics, indicators, backtests, and tool outputs produced by the Service are **informational only** and are not personalised advice. Consult a **SEBI-registered Investment Adviser** before making trading or investment decisions.

Any Algo-ID or unique-order-code requirements imposed by SEBI or the exchanges are handled at the **Zerodha OMS / broker layer**, not by the Service.

---

## 6. Intellectual property

The source code is released under the **MIT Licence**. See https://github.com/Sundeepg98/kite-mcp-server.

**"Kite"**, **"Kite Connect"**, and **"Zerodha"** are trademarks of Zerodha Broking Ltd. and/or its affiliates. The Service is an **independent project** and is **not affiliated with, endorsed by, or sponsored by Zerodha**.

---

## 7. Limitation of liability

The Service is provided **"as is" and "as available"**, with no warranties of merchantability, fitness for a particular purpose, non-infringement, uptime, accuracy, or suitability for any trading strategy.

To the maximum extent permitted by law:

- The Operator's total aggregate liability for any claim arising out of or relating to the Service is capped at **the fees you paid in the twelve (12) months preceding the claim, or ₹0 if no fees were paid**.
- **You bear all trading risk.** Losses, missed trades, slippage, exchange outages, Kite API failures, and latency-related outcomes are your responsibility.
- **Paper-trading results are simulated and are not indicative of future performance.**
- You agree to **indemnify and hold the Operator harmless** from claims arising out of your use of the Service, your violations of these Terms, or your violations of applicable law.

---

## 8. Governing law and disputes

These Terms are governed by the laws of **India**. Any dispute will first be addressed through **30 days of good-faith negotiation** with the Grievance Officer at `sundeepg8@gmail.com`.

If unresolved, the dispute will be referred to **arbitration under the Arbitration and Conciliation Act, 1996**, before a **sole arbitrator** appointed by mutual agreement, with the **seat at Bengaluru** and proceedings in **English**. Matters arising under the Securities Contracts (Regulation) Act, 1956 or the SEBI Act, 1992 remain with the appropriate regulator, including SEBI and the Securities Appellate Tribunal (SAT).

---

## 9. Termination

- **You can stop** using the Service at any time via the self-service account deletion in the dashboard and/or by emailing `sundeepg8@gmail.com`.
- **We may suspend or terminate** your access for violations of these Terms, security concerns, or compelled legal actions.
- **If we shut down the Service**, we will give at least **30 days' notice** and make a **data export** available to you during that window.

---

## 10. Changes to these Terms

Revisions are versioned using semantic versioning. For **material changes**, we will provide at least **15 days' advance notice** via email and a banner on the Service before the change takes effect. Continued use after the effective date constitutes acceptance of the revised Terms.

---

## 11. Contact

- **Operator:** Sundeep Govarthinam (sole proprietorship, India)
- **Email:** `sundeepg8@gmail.com`
- **Repository:** https://github.com/Sundeepg98/kite-mcp-server
