> **DRAFT — not yet in force.** This notice will replace any prior version at the time of public launch. Placeholders (e.g., `<your product email>`) must be substituted before publication.

> **REPLACE ALL `<your product email>` PLACEHOLDERS WITH A DEDICATED PRODUCT EMAIL BEFORE PUBLISHING. Do NOT use any Foundation-context email.**

# Privacy Notice — kite-mcp-server

**Last updated:** `<YYYY-MM-DD>`

This Privacy Notice describes how personal data is processed by the hosted instance of **kite-mcp-server** at `https://kite-mcp-server.fly.dev`. It is written to meet the minimum content requirements of Rule 3(1) of the Digital Personal Data Protection Rules, 2025, read with the Digital Personal Data Protection Act, 2023 ("DPDP").

---

## 1. Who we are

The hosted instance is operated by **Sundeep Govarthinam**, a sole proprietorship based in India ("we", "us", "the Operator"). For DPDP purposes, the Operator is the **Data Fiduciary** for personal data processed through the hosted instance.

- **Grievance Officer:** Sundeep Govarthinam
- **Contact:** `<your product email>`
- **Source code:** https://github.com/Sundeepg98/kite-mcp-server

If you self-host the code from the repository, **you are your own Data Fiduciary** and this notice does not apply to your deployment.

---

## 2. Data we collect

We collect only what is necessary to make the service work:

- **Kite API credentials** (your Kite Connect API key and API secret) — AES-256-GCM encrypted at rest.
- **Kite access tokens** — daily expiry at ~06:00 IST, encrypted at rest.
- **OAuth email address** — used to key your per-user credential record.
- **Tool-call audit log** — timestamp, tool name, redacted parameters, outcome, and a hash chain linking entries for tamper-evidence.
- **Optional Telegram chat ID** — only if you explicitly enable Telegram notifications.
- **Transient IP address** — held briefly in memory for rate limiting; not persisted to the audit log in raw form.

**We do not collect:** your Kite password, PAN, Aadhaar, bank account details, demat credentials, advertising identifiers, or third-party analytics data.

---

## 3. Why we collect it

| Data | Purpose |
|---|---|
| Kite API credentials | Authenticate to Zerodha Kite Connect on your behalf |
| Access tokens | Keep your session alive during the Kite daily window |
| OAuth email | Identify you across sessions and scope your data |
| Audit log | Security, incident response, regulatory accountability |
| Telegram chat ID | Deliver alerts and briefings you opted into |
| Transient IP | Rate-limit abuse and prevent brute-force attempts |

---

## 4. Legal basis

Processing is based on your **explicit consent** under §6 of the DPDP Act. Consent is captured at two points: (a) when you click **Authorize** in the OAuth flow, and (b) when you submit your Kite developer-app credentials. You may withdraw consent at any time (see section 8).

---

## 5. How we store and protect data

- **Encryption at rest:** AES-256-GCM with keys derived via HKDF from a server secret. Applies to Kite credentials, access tokens, and OAuth client secrets.
- **Encryption in transit:** TLS 1.2+ on all endpoints.
- **Hosting:** Fly.io, Mumbai (`bom`) region — data resides in India.
- **Backups:** SQLite WAL streamed via Litestream to an encrypted Cloudflare R2 bucket in the APAC region.
- **Access isolation:** every MCP session is scoped to a single email; one user cannot read another's data.
- **Retention:** audit log entries are automatically purged after **90 days** (configurable via `AUDIT_RETENTION_DAYS`). Credentials and tokens persist only until you delete your account or withdraw consent.
- **Deletion SLA:** deletion requests are actioned within **7 days**.

---

## 6. Who we share data with

We do not sell, rent, or share your data for marketing or model-training purposes. The only disclosures are:

- **Zerodha / Kite Connect API** — calls you initiate (placing an order, fetching holdings, etc.) are forwarded to Zerodha. This is inherent to the service.
- **Sub-processors** — Fly.io (compute + primary storage, Mumbai) and Cloudflare R2 (encrypted backups, APAC).
- **Law enforcement** — only if compelled by a lawful, written order under Indian law. We will notify you unless legally barred.

**Explicitly excluded:** advertising networks, third-party analytics, AI model training.

---

## 7. Your rights under DPDP

You have the right to:

- **Access** a summary of your personal data being processed.
- **Correct, complete, or update** inaccurate data.
- **Erase** your data (subject to any legal-retention obligation).
- **Withdraw consent** at any time; processing will stop and data will be deleted per section 5.
- **Nominate** another individual to exercise these rights if you are incapacitated or deceased.
- **Grievance redressal** — contact the Grievance Officer above. We will acknowledge within 7 days and resolve within 30 days.
- **Escalate** unresolved grievances to the **Data Protection Board of India** under §13 of the DPDP Act.

---

## 8. Breach notification

If we become aware of a personal-data breach:

- We will notify **CERT-In within 6 hours** per the MeitY Directions of 28 April 2022.
- We will notify the **Data Protection Board of India** per §8(5) of the DPDP Act, in the form and timeline prescribed by the DPDP Rules.
- We will notify affected users by **email within 72 hours**, including the nature of the breach, likely consequences, and mitigation steps.

---

## 9. Cookies

The hosted instance sets a single **essential JWT session cookie** used to maintain your authenticated dashboard session. We do not set advertising, analytics, or cross-site tracking cookies. Because the only cookie is strictly necessary for service delivery, no consent banner is required under current Indian guidance.

---

## 10. Changes to this notice

Revisions to this notice are versioned using semantic versioning. For **material changes** that affect your rights or the categories of data we process, we will provide **at least 15 days' advance notice** via email and a banner on the service before the change takes effect.

---

## 11. Contact

- **Grievance Officer:** Sundeep Govarthinam
- **Email:** `<your product email>`
- **Repository:** https://github.com/Sundeepg98/kite-mcp-server

Self-hosted deployments of the open-source code are outside the scope of this notice; operators of those deployments are their own Data Fiduciary and must publish their own privacy notice.
