# Terms of Service

**Kite MCP Server** | Effective: 3 April 2026 | Last updated: 3 April 2026

> [!IMPORTANT]
> **LAWYER REVIEW NEEDED**: This document is a good-faith draft by the operator, not reviewed by a licensed attorney. Before commercial launch, have an Indian technology/fintech lawyer review Sections 3, 6, 7, 8, and 11 in particular. Budget INR 15,000-30,000 for a proper legal review.

---

## 1. What This Service Is

Kite MCP Server ("the Service") is a software tool that connects AI assistants (Claude, ChatGPT, VS Code Copilot, or any MCP-compatible client) to your Zerodha Kite brokerage account via the Kite Connect API.

The Service is operated by **Sundeep Govarthinam** ("the Operator"), an individual based in India.

**The Service is a tool, not a financial advisor.** It executes actions you or your AI assistant request. It does not recommend trades, pick stocks, or manage your portfolio autonomously.

## 2. Who Can Use This Service

- You must be 18 years or older.
- You must hold a valid Zerodha trading and demat account.
- You must have your own Kite Connect developer app credentials (API key and secret) from [developers.kite.trade](https://developers.kite.trade).
- You must comply with all applicable Indian laws, including SEBI regulations and the Foreign Exchange Management Act (FEMA).

## 3. Critical Disclaimers

### 3.1 Not Financial Advice

**This Service does not provide investment advice, financial advice, or trading recommendations.** The Operator is **not registered** with the Securities and Exchange Board of India (SEBI) as an Investment Adviser (IA), Research Analyst (RA), or Stock Broker.

Any analysis, technical indicators (RSI, MACD, Bollinger Bands, Greeks), or market data provided through the tools is **purely informational**. It does not constitute a recommendation to buy, sell, or hold any security.

**You should consult a SEBI-registered investment adviser before making trading decisions.**

### 3.2 Trading Risk

**Trading in securities involves substantial risk of loss.** You may lose some or all of your invested capital. Past performance, including results from paper trading mode, does not guarantee future results. The Operator does not guarantee any profits or protection against losses.

### 3.3 AI Limitations

**AI assistants can and do make errors.** They may:

- Misinterpret your instructions
- Hallucinate facts, prices, or analysis
- Place orders you did not intend
- Provide incorrect calculations or technical analysis

**You are solely responsible for reviewing and confirming every order before execution.** The Service includes safety controls (riskguard checks, elicitation confirmations) as a convenience, but these are not foolproof. They do not replace your own judgment.

### 3.4 No Warranty

The Service is provided **"as is" and "as available"** without warranties of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.

## 4. Your Responsibilities

- **Your credentials, your risk.** You provide your own Kite API key and secret. You are responsible for keeping them secure.
- **Your trades, your decisions.** Every order placed through the Service is your responsibility, whether initiated by you directly or by an AI assistant acting on your instructions.
- **Verify before confirming.** Always review order details (instrument, quantity, price, order type) before confirming execution.
- **Monitor your account.** Do not rely solely on the Service to track your positions, margins, or P&L.
- **Keep your Kite session active.** The Service depends on a valid Kite access token. Tokens expire daily around 6 AM IST.

## 5. Acceptable Use

You agree **not** to:

- Use the Service for market manipulation, front-running, spoofing, layering, or any activity prohibited by SEBI.
- Place automated orders at a frequency or volume that violates Zerodha's rate limits or API terms.
- Attempt to circumvent safety controls or riskguard checks.
- Share your account access or allow unauthorized third parties to use your session.
- Reverse-engineer, scrape, or attack the Service infrastructure.
- Use the Service to provide investment advisory services to others without proper SEBI registration.

Violation of these terms may result in immediate suspension of your access.

## 6. Data Handling

Your data is handled as described in our [Privacy Policy](/privacy). In summary:

- **Kite API credentials** are encrypted with AES-256-GCM at rest.
- **Trading activity** is logged in an audit trail for your review and safety.
- **We do not sell, share, or monetize your data.**
- **You can delete your account and all associated data** at any time via the self-service dashboard or by contacting the Operator.

## 7. Limitation of Liability

**To the maximum extent permitted by Indian law:**

- The Operator is **not liable** for any trading losses, missed opportunities, incorrect order executions, or financial damages arising from use of the Service.
- The Operator is **not liable** for errors, omissions, or inaccuracies in AI-generated analysis or recommendations.
- The Operator is **not liable** for downtime, service interruptions, data loss, or security breaches beyond what is required by the Digital Personal Data Protection Act, 2023.
- The Operator's total cumulative liability, if any, shall not exceed the amount you paid for the Service in the 12 months preceding the claim, or INR 5,000, whichever is lower.

**You agree to indemnify** the Operator against any claims, damages, or legal proceedings arising from your use of the Service, your trading activity, or your violation of these terms.

## 8. SEBI and Regulatory Compliance

- The Operator does **not** hold any SEBI registration (Investment Adviser, Research Analyst, Stock Broker, Portfolio Manager, or any other category).
- The Service is a **technology tool** that facilitates access to your own brokerage account. It is comparable to a trading terminal, not an advisory service.
- SEBI's Algo-ID requirements for algorithmic trading are handled at the broker (Zerodha) level via their OMS, not by the Service.
- You are solely responsible for compliance with SEBI regulations applicable to your trading activity, including position limits, margin requirements, and reporting obligations.

## 9. Pricing and Payment

- The Service currently offers a **free tier** with limited functionality.
- Paid tiers may be introduced in the future. You will be notified of pricing changes at least 30 days in advance.
- Paid features will be clearly identified before you commit. No charges will be applied without your explicit consent.

## 10. Account Termination

- **By you:** You may delete your account at any time. All your data (credentials, audit trail, alerts, watchlists, paper trades) will be permanently erased.
- **By the Operator:** The Operator may suspend or terminate your access for violation of these terms, abusive behavior, or if required by law. You will be notified with a reason unless prohibited by legal process.

## 11. Governing Law and Disputes

- These terms are governed by the **laws of India**.
- Any disputes shall be subject to the **exclusive jurisdiction of the courts in Chennai, Tamil Nadu, India**.
- Before filing any legal claim, you agree to attempt resolution by contacting the Operator directly and allowing 30 days for response.

## 12. Changes to These Terms

- The Operator may update these terms. Material changes will be communicated via the Service dashboard or email (if provided) at least 15 days before they take effect.
- Continued use after the effective date constitutes acceptance of the updated terms.
- Previous versions will be archived and available upon request.

## 13. Open Source

The Kite MCP Server codebase is available under the MIT License. These Terms of Service govern your use of the **hosted service** at `kite-mcp-server.fly.dev`, not the open-source code itself. If you self-host the software, these terms do not apply to your self-hosted instance.

## 14. Contact

For questions about these terms, account issues, or to exercise your rights:

- **Email:** sundeepg8@gmail.com
- **GitHub:** [github.com/Sundeepg98/kite-mcp-server](https://github.com/Sundeepg98/kite-mcp-server)
- **Response time:** Within 30 days for formal requests; typically faster for general inquiries.

---

*By using the Kite MCP Server, you acknowledge that you have read, understood, and agree to these Terms of Service.*
