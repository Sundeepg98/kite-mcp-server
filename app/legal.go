package app

import "html/template"

// termsHTML contains the pre-rendered Terms of Service content.
// Source of truth: TERMS.md in the repository root.
const termsHTML template.HTML = `
<h1>Terms of Service</h1>
<p class="meta">Effective: 3 April 2026 &middot; Last updated: 3 April 2026</p>

<div class="callout">
<strong>LAWYER REVIEW NEEDED:</strong> This document is a good-faith draft by the operator, not reviewed by a licensed attorney. Before commercial launch, have an Indian technology/fintech lawyer review Sections 3, 6, 7, 8, and 11 in particular.
</div>

<h2>1. What This Service Is</h2>
<p>Kite MCP Server ("the Service") is a software tool that connects AI assistants (Claude, ChatGPT, VS Code Copilot, or any MCP-compatible client) to your Zerodha Kite brokerage account via the Kite Connect API.</p>
<p>The Service is operated by <strong>Sundeep Govarthinam</strong> ("the Operator"), an individual based in India.</p>
<p><strong>The Service is a tool, not a financial advisor.</strong> It executes actions you or your AI assistant request. It does not recommend trades, pick stocks, or manage your portfolio autonomously.</p>

<h2>2. Who Can Use This Service</h2>
<ul>
<li>You must be 18 years or older.</li>
<li>You must hold a valid Zerodha trading and demat account.</li>
<li>You must have your own Kite Connect developer app credentials (API key and secret) from <a href="https://developers.kite.trade" target="_blank" rel="noopener">developers.kite.trade</a>.</li>
<li>You must comply with all applicable Indian laws, including SEBI regulations and the Foreign Exchange Management Act (FEMA).</li>
</ul>

<h2>3. Critical Disclaimers</h2>

<h3>3.1 Not Financial Advice</h3>
<p><strong>This Service does not provide investment advice, financial advice, or trading recommendations.</strong> The Operator is <strong>not registered</strong> with the Securities and Exchange Board of India (SEBI) as an Investment Adviser (IA), Research Analyst (RA), or Stock Broker.</p>
<p>Any analysis, technical indicators (RSI, MACD, Bollinger Bands, Greeks), or market data provided through the tools is <strong>purely informational</strong>. It does not constitute a recommendation to buy, sell, or hold any security.</p>
<p><strong>You should consult a SEBI-registered investment adviser before making trading decisions.</strong></p>

<h3>3.2 Trading Risk</h3>
<p><strong>Trading in securities involves substantial risk of loss.</strong> You may lose some or all of your invested capital. Past performance, including results from paper trading mode, does not guarantee future results. The Operator does not guarantee any profits or protection against losses.</p>

<h3>3.3 AI Limitations</h3>
<p><strong>AI assistants can and do make errors.</strong> They may:</p>
<ul>
<li>Misinterpret your instructions</li>
<li>Hallucinate facts, prices, or analysis</li>
<li>Place orders you did not intend</li>
<li>Provide incorrect calculations or technical analysis</li>
</ul>
<p><strong>You are solely responsible for reviewing and confirming every order before execution.</strong> The Service includes safety controls (riskguard checks, elicitation confirmations) as a convenience, but these are not foolproof. They do not replace your own judgment.</p>

<h3>3.4 No Warranty</h3>
<p>The Service is provided <strong>"as is" and "as available"</strong> without warranties of any kind, express or implied, including but not limited to warranties of merchantability, fitness for a particular purpose, accuracy, or non-infringement.</p>

<h2>4. Your Responsibilities</h2>
<ul>
<li><strong>Your credentials, your risk.</strong> You provide your own Kite API key and secret. You are responsible for keeping them secure.</li>
<li><strong>Your trades, your decisions.</strong> Every order placed through the Service is your responsibility, whether initiated by you directly or by an AI assistant acting on your instructions.</li>
<li><strong>Verify before confirming.</strong> Always review order details (instrument, quantity, price, order type) before confirming execution.</li>
<li><strong>Monitor your account.</strong> Do not rely solely on the Service to track your positions, margins, or P&amp;L.</li>
<li><strong>Keep your Kite session active.</strong> The Service depends on a valid Kite access token. Tokens expire daily around 6 AM IST.</li>
</ul>

<h2>5. Acceptable Use</h2>
<p>You agree <strong>not</strong> to:</p>
<ul>
<li>Use the Service for market manipulation, front-running, spoofing, layering, or any activity prohibited by SEBI.</li>
<li>Place automated orders at a frequency or volume that violates Zerodha's rate limits or API terms.</li>
<li>Attempt to circumvent safety controls or riskguard checks.</li>
<li>Share your account access or allow unauthorized third parties to use your session.</li>
<li>Reverse-engineer, scrape, or attack the Service infrastructure.</li>
<li>Use the Service to provide investment advisory services to others without proper SEBI registration.</li>
</ul>
<p>Violation of these terms may result in immediate suspension of your access.</p>

<h2>6. Data Handling</h2>
<p>Your data is handled as described in our <a href="/privacy">Privacy Policy</a>. In summary:</p>
<ul>
<li><strong>Kite API credentials</strong> are encrypted with AES-256-GCM at rest.</li>
<li><strong>Trading activity</strong> is logged in an audit trail for your review and safety.</li>
<li><strong>We do not sell, share, or monetize your data.</strong></li>
<li><strong>You can delete your account and all associated data</strong> at any time via the self-service dashboard or by contacting the Operator.</li>
</ul>

<h2>7. Limitation of Liability</h2>
<p><strong>To the maximum extent permitted by Indian law:</strong></p>
<ul>
<li>The Operator is <strong>not liable</strong> for any trading losses, missed opportunities, incorrect order executions, or financial damages arising from use of the Service.</li>
<li>The Operator is <strong>not liable</strong> for errors, omissions, or inaccuracies in AI-generated analysis or recommendations.</li>
<li>The Operator is <strong>not liable</strong> for downtime, service interruptions, data loss, or security breaches beyond what is required by the Digital Personal Data Protection Act, 2023.</li>
<li>The Operator's total cumulative liability, if any, shall not exceed the amount you paid for the Service in the 12 months preceding the claim, or INR 5,000, whichever is lower.</li>
</ul>
<p><strong>You agree to indemnify</strong> the Operator against any claims, damages, or legal proceedings arising from your use of the Service, your trading activity, or your violation of these terms.</p>

<h2>8. SEBI and Regulatory Compliance</h2>
<ul>
<li>The Operator does <strong>not</strong> hold any SEBI registration (Investment Adviser, Research Analyst, Stock Broker, Portfolio Manager, or any other category).</li>
<li>The Service is a <strong>technology tool</strong> that facilitates access to your own brokerage account. It is comparable to a trading terminal, not an advisory service.</li>
<li>SEBI's Algo-ID requirements for algorithmic trading are handled at the broker (Zerodha) level via their OMS, not by the Service.</li>
<li>You are solely responsible for compliance with SEBI regulations applicable to your trading activity, including position limits, margin requirements, and reporting obligations.</li>
</ul>

<h2>9. Pricing and Payment</h2>
<ul>
<li>The Service currently offers a <strong>free tier</strong> with limited functionality.</li>
<li>Paid tiers may be introduced in the future. You will be notified of pricing changes at least 30 days in advance.</li>
<li>Paid features will be clearly identified before you commit. No charges will be applied without your explicit consent.</li>
</ul>

<h2>10. Account Termination</h2>
<ul>
<li><strong>By you:</strong> You may delete your account at any time. All your data (credentials, audit trail, alerts, watchlists, paper trades) will be permanently erased.</li>
<li><strong>By the Operator:</strong> The Operator may suspend or terminate your access for violation of these terms, abusive behavior, or if required by law. You will be notified with a reason unless prohibited by legal process.</li>
</ul>

<h2>11. Governing Law and Disputes</h2>
<ul>
<li>These terms are governed by the <strong>laws of India</strong>.</li>
<li>Any disputes shall be subject to the <strong>exclusive jurisdiction of the courts in Chennai, Tamil Nadu, India</strong>.</li>
<li>Before filing any legal claim, you agree to attempt resolution by contacting the Operator directly and allowing 30 days for response.</li>
</ul>

<h2>12. Changes to These Terms</h2>
<ul>
<li>The Operator may update these terms. Material changes will be communicated via the Service dashboard or email (if provided) at least 15 days before they take effect.</li>
<li>Continued use after the effective date constitutes acceptance of the updated terms.</li>
<li>Previous versions will be archived and available upon request.</li>
</ul>

<h2>13. Open Source</h2>
<p>The Kite MCP Server codebase is available under the MIT License. These Terms of Service govern your use of the <strong>hosted service</strong> at <code>kite-mcp-server.fly.dev</code>, not the open-source code itself. If you self-host the software, these terms do not apply to your self-hosted instance.</p>

<h2>14. Contact</h2>
<p>For questions about these terms, account issues, or to exercise your rights:</p>
<ul>
<li><strong>Email:</strong> sundeepg98@gmail.com</li>
<li><strong>GitHub:</strong> <a href="https://github.com/Sundeepg98/kite-mcp-server" target="_blank" rel="noopener">github.com/Sundeepg98/kite-mcp-server</a></li>
<li><strong>Response time:</strong> Within 30 days for formal requests; typically faster for general inquiries.</li>
</ul>

<p style="margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 0.85rem; color: var(--text-2);"><em>By using the Kite MCP Server, you acknowledge that you have read, understood, and agree to these Terms of Service.</em></p>
`

// privacyHTML contains the pre-rendered Privacy Policy content.
// Source of truth: PRIVACY.md in the repository root.
const privacyHTML template.HTML = `
<h1>Privacy Policy</h1>
<p class="meta">Effective: 3 April 2026 &middot; Last updated: 3 April 2026</p>

<div class="callout">
<strong>LAWYER REVIEW NEEDED:</strong> This policy is drafted in good faith to comply with India's Digital Personal Data Protection Act, 2023 (DPDP Act) and DPDP Rules, 2025. It has not been reviewed by a licensed attorney. Before commercial launch, have an Indian data privacy lawyer review this document.
</div>

<h2>1. Who We Are (Data Fiduciary)</h2>
<p><strong>Data Fiduciary:</strong> Sundeep Govarthinam (individual, India-based)<br>
<strong>Contact:</strong> sundeepg98@gmail.com<br>
<strong>Service:</strong> Kite MCP Server &mdash; an AI-powered trading tool for Zerodha Kite</p>
<p>Under the DPDP Act, 2023, the Operator acts as a <strong>Data Fiduciary</strong> &mdash; the person who determines the purpose and means of processing your personal data.</p>

<h2>2. What Personal Data We Collect</h2>
<table>
<thead><tr><th>Data</th><th>Purpose</th><th>Basis</th></tr></thead>
<tbody>
<tr><td><strong>Email address</strong></td><td>Account identity, session management, grievance contact</td><td>Consent (provided during OAuth login)</td></tr>
<tr><td><strong>Kite API key and secret</strong></td><td>Authenticate with your Zerodha account on your behalf</td><td>Consent (you provide these voluntarily)</td></tr>
<tr><td><strong>Kite access token</strong></td><td>Execute API calls to Zerodha on your behalf</td><td>Consent (generated after you authorize via Kite login)</td></tr>
<tr><td><strong>Trading activity audit trail</strong></td><td>Safety controls, dispute resolution, your review via dashboard</td><td>Legitimate use of the Service</td></tr>
<tr><td><strong>Price alerts and watchlists</strong></td><td>Provide alert and watchlist features you configure</td><td>Consent (you create these)</td></tr>
<tr><td><strong>Paper trading data</strong></td><td>Provide paper trading simulation feature</td><td>Consent (you create these)</td></tr>
<tr><td><strong>IP address</strong></td><td>Rate limiting, abuse prevention</td><td>Legitimate use of the Service</td></tr>
</tbody>
</table>

<h3>What We Do NOT Collect</h3>
<ul>
<li>We do <strong>not</strong> collect your Zerodha login password (Kite's OAuth flow handles this).</li>
<li>We do <strong>not</strong> collect Aadhaar, PAN, bank account details, or KYC documents.</li>
<li>We do <strong>not</strong> use analytics services, tracking pixels, or advertising SDKs.</li>
<li>We do <strong>not</strong> collect data from minors (users must be 18+).</li>
</ul>

<h2>3. How Your Data Is Protected</h2>
<table>
<thead><tr><th>Measure</th><th>Details</th></tr></thead>
<tbody>
<tr><td><strong>Encryption at rest</strong></td><td>Kite API credentials and access tokens are encrypted with AES-256-GCM using keys derived via HKDF from a server secret</td></tr>
<tr><td><strong>Encryption in transit</strong></td><td>All connections use TLS (HTTPS)</td></tr>
<tr><td><strong>Access control</strong></td><td>Per-user data isolation; your data is only accessible to your authenticated session</td></tr>
<tr><td><strong>Audit logging</strong></td><td>All tool calls are logged with timestamps for accountability</td></tr>
<tr><td><strong>Authentication</strong></td><td>OAuth 2.1 with JWT tokens (4-hour expiry)</td></tr>
<tr><td><strong>Cookie policy</strong></td><td>One JWT authentication cookie per session. No tracking cookies. No third-party cookies.</td></tr>
<tr><td><strong>Infrastructure</strong></td><td>Hosted on Fly.io, Mumbai (BOM) region. Data stays in India.</td></tr>
<tr><td><strong>Backup</strong></td><td>SQLite database continuously replicated to Cloudflare R2 via Litestream</td></tr>
</tbody>
</table>

<h2>4. How We Use Your Data</h2>
<p>Your data is used <strong>only</strong> to:</p>
<ol>
<li><strong>Provide the Service</strong> &mdash; authenticate you with Zerodha, execute your trading requests, display your portfolio, manage your alerts.</li>
<li><strong>Safety controls</strong> &mdash; riskguard checks, order validation, elicitation confirmations.</li>
<li><strong>Audit trail</strong> &mdash; record what actions were taken through the Service, so you can review them on your dashboard.</li>
<li><strong>Abuse prevention</strong> &mdash; rate limiting by IP address.</li>
<li><strong>Grievance resolution</strong> &mdash; if you raise a complaint, we may reference your audit trail.</li>
</ol>

<p><strong>We do NOT use your data for:</strong></p>
<ul>
<li>Advertising or marketing</li>
<li>Selling or sharing with third parties</li>
<li>Training AI models</li>
<li>Profiling or automated decision-making beyond what you explicitly request</li>
<li>Any purpose other than providing and securing the Service</li>
</ul>

<h2>5. Data Sharing</h2>
<p><strong>We do not share your personal data with any third party</strong> except:</p>
<ul>
<li><strong>Zerodha / Kite Connect</strong> &mdash; Your API credentials and trading requests are sent to Zerodha's servers to execute your instructions. This is the core function of the Service. Zerodha's privacy policy governs their handling of your data.</li>
<li><strong>Fly.io</strong> &mdash; Our hosting provider. They process data as a sub-processor under their terms. Data is stored in the Mumbai region.</li>
<li><strong>Cloudflare R2</strong> &mdash; Encrypted database backups are stored on Cloudflare R2.</li>
<li><strong>Law enforcement</strong> &mdash; If required by Indian law, court order, or legal process.</li>
</ul>
<p>We do <strong>not</strong> sell your data. We do <strong>not</strong> share it with advertisers, analytics providers, or data brokers.</p>

<h2>6. Data Retention</h2>
<table>
<thead><tr><th>Data</th><th>Retention</th></tr></thead>
<tbody>
<tr><td><strong>Kite API credentials</strong></td><td>Until you delete your account or rotate credentials</td></tr>
<tr><td><strong>Kite access token</strong></td><td>Expires daily (~6 AM IST); cached until expiry</td></tr>
<tr><td><strong>Audit trail (tool call logs)</strong></td><td>5 years (per SEBI record-keeping requirements, applied as a precaution)</td></tr>
<tr><td><strong>Price alerts and watchlists</strong></td><td>Until you delete them or delete your account</td></tr>
<tr><td><strong>Paper trading data</strong></td><td>Until you delete it or delete your account</td></tr>
<tr><td><strong>IP addresses in rate limit logs</strong></td><td>Transient; not persisted beyond the server process</td></tr>
</tbody>
</table>
<p>After account deletion, all your data is permanently erased except the audit trail, which is retained for 5 years from the date of creation for regulatory compliance. You may request a copy of your audit trail before deleting your account.</p>

<h2>7. Your Rights (Data Principal Rights)</h2>
<p>Under the DPDP Act, 2023, you have the following rights:</p>

<h3>7.1 Right to Access</h3>
<p>You can view all your data through the Service dashboard at any time &mdash; portfolio, alerts, audit trail, and account settings.</p>

<h3>7.2 Right to Correction</h3>
<p>You can update your Kite API credentials via the self-service dashboard. If any data is inaccurate, contact the Operator.</p>

<h3>7.3 Right to Erasure</h3>
<p>You can delete your account and all associated data via the self-service dashboard. This is immediate and irreversible (except audit trail retained per Section 6).</p>

<h3>7.4 Right to Grievance Redressal</h3>
<p>If you have a complaint about how your data is handled:</p>
<ol>
<li><strong>Contact the Operator</strong> at sundeepg98@gmail.com with a description of your concern.</li>
<li><strong>Acknowledgment</strong> within 7 days.</li>
<li><strong>Resolution</strong> within 30 days.</li>
<li><strong>Escalation:</strong> If unsatisfied, you may file a complaint with the <strong>Data Protection Board of India</strong> once it is constituted and operational.</li>
</ol>

<h3>7.5 Right to Nominate</h3>
<p>Under the DPDP Act, you may nominate another person to exercise your data rights in the event of your death or incapacity. Contact the Operator to register a nominee.</p>

<h3>7.6 Withdrawal of Consent</h3>
<p>You may withdraw consent at any time by deleting your account. Withdrawal does not affect the lawfulness of processing before the withdrawal.</p>

<h2>8. Cookies</h2>
<table>
<thead><tr><th>Cookie</th><th>Purpose</th><th>Duration</th><th>Type</th></tr></thead>
<tbody>
<tr><td>JWT session cookie</td><td>Authenticate your dashboard session</td><td>4 hours</td><td>Essential (first-party)</td></tr>
</tbody>
</table>
<p>That is the only cookie. No analytics cookies. No advertising cookies. No third-party cookies.</p>

<h2>9. Data Breach Notification</h2>
<p>In the event of a personal data breach:</p>
<ul>
<li>The Operator will notify the <strong>Data Protection Board of India</strong> within 72 hours (once constituted).</li>
<li>Affected users will be notified <strong>without unreasonable delay</strong> via email (if available) or a prominent notice on the Service.</li>
<li>The notification will include: what happened, what data was affected, what steps are being taken, and what you should do (e.g., rotate your Kite API credentials).</li>
</ul>

<h2>10. Cross-Border Data Transfer</h2>
<ul>
<li>The primary database is hosted in <strong>Mumbai, India</strong> (Fly.io BOM region).</li>
<li>Encrypted backups are stored on <strong>Cloudflare R2</strong> (region may vary).</li>
<li>No personal data is intentionally transferred to countries restricted under the DPDP Act. If Cloudflare stores backup replicas outside India, the data is encrypted at rest and the encryption key remains in India.</li>
</ul>

<h2>11. Children</h2>
<p>The Service is not intended for anyone under 18 years of age. We do not knowingly collect personal data from minors. If we learn that a user is under 18, their account will be deleted.</p>

<h2>12. Changes to This Policy</h2>
<p>Material changes will be communicated via the Service dashboard or email at least 15 days before they take effect. The previous version will be archived and available upon request.</p>

<h2>13. Contact and Grievance Officer</h2>
<p>For privacy-related questions, data requests, or complaints:</p>
<p><strong>Sundeep Govarthinam</strong> (Grievance Officer)<br>
<strong>Email:</strong> sundeepg98@gmail.com<br>
<strong>Response time:</strong> Acknowledgment within 7 days, resolution within 30 days.</p>

<p style="margin-top: 32px; padding-top: 16px; border-top: 1px solid var(--border); font-size: 0.85rem; color: var(--text-2);"><em>By using the Kite MCP Server, you consent to the collection and processing of your personal data as described in this Privacy Policy.</em></p>
`
