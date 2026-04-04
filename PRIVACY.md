# Privacy Policy

**Kite MCP Server** | Effective: 3 April 2026 | Last updated: 3 April 2026

> [!IMPORTANT]
> **LAWYER REVIEW NEEDED**: This policy is drafted in good faith to comply with India's Digital Personal Data Protection Act, 2023 (DPDP Act) and DPDP Rules, 2025. It has not been reviewed by a licensed attorney. Before commercial launch, have an Indian data privacy lawyer review this document. Budget INR 10,000-20,000.

---

## 1. Who We Are (Data Fiduciary)

**Data Fiduciary:** Sundeep Govarthinam (individual, India-based)
**Contact:** sundeepg98@gmail.com
**Service:** Kite MCP Server — an AI-powered trading tool for Zerodha Kite

Under the DPDP Act, 2023, the Operator acts as a **Data Fiduciary** — the person who determines the purpose and means of processing your personal data.

## 2. What Personal Data We Collect

| Data | Purpose | Basis |
|------|---------|-------|
| **Email address** | Account identity, session management, grievance contact | Consent (provided during OAuth login) |
| **Kite API key and secret** | Authenticate with your Zerodha account on your behalf | Consent (you provide these voluntarily) |
| **Kite access token** | Execute API calls to Zerodha on your behalf | Consent (generated after you authorize via Kite login) |
| **Trading activity audit trail** | Safety controls, dispute resolution, your review via dashboard | Legitimate use of the Service |
| **Price alerts and watchlists** | Provide alert and watchlist features you configure | Consent (you create these) |
| **Paper trading data** | Provide paper trading simulation feature | Consent (you create these) |
| **IP address** | Rate limiting, abuse prevention | Legitimate use of the Service |

### What We Do NOT Collect

- We do **not** collect your Zerodha login password (Kite's OAuth flow handles this).
- We do **not** collect Aadhaar, PAN, bank account details, or KYC documents.
- We do **not** use analytics services, tracking pixels, or advertising SDKs.
- We do **not** collect data from minors (users must be 18+).

## 3. How Your Data Is Protected

| Measure | Details |
|---------|---------|
| **Encryption at rest** | Kite API credentials and access tokens are encrypted with AES-256-GCM using keys derived via HKDF from a server secret |
| **Encryption in transit** | All connections use TLS (HTTPS) |
| **Access control** | Per-user data isolation; your data is only accessible to your authenticated session |
| **Audit logging** | All tool calls are logged with timestamps for accountability |
| **Authentication** | OAuth 2.1 with JWT tokens (4-hour expiry) |
| **Cookie policy** | One JWT authentication cookie per session. No tracking cookies. No third-party cookies. |
| **Infrastructure** | Hosted on Fly.io, Mumbai (BOM) region. Data stays in India. |
| **Backup** | SQLite database continuously replicated to Cloudflare R2 via Litestream |

## 4. How We Use Your Data

Your data is used **only** to:

1. **Provide the Service** — authenticate you with Zerodha, execute your trading requests, display your portfolio, manage your alerts.
2. **Safety controls** — riskguard checks, order validation, elicitation confirmations.
3. **Audit trail** — record what actions were taken through the Service, so you can review them on your dashboard.
4. **Abuse prevention** — rate limiting by IP address.
5. **Grievance resolution** — if you raise a complaint, we may reference your audit trail.

**We do NOT use your data for:**

- Advertising or marketing
- Selling or sharing with third parties
- Training AI models
- Profiling or automated decision-making beyond what you explicitly request
- Any purpose other than providing and securing the Service

## 5. Data Sharing

**We do not share your personal data with any third party** except:

- **Zerodha / Kite Connect** — Your API credentials and trading requests are sent to Zerodha's servers to execute your instructions. This is the core function of the Service. Zerodha's privacy policy governs their handling of your data.
- **Fly.io** — Our hosting provider. They process data as a sub-processor under their terms. Data is stored in the Mumbai region.
- **Cloudflare R2** — Encrypted database backups are stored on Cloudflare R2.
- **Law enforcement** — If required by Indian law, court order, or legal process.

We do **not** sell your data. We do **not** share it with advertisers, analytics providers, or data brokers.

## 6. Data Retention

| Data | Retention |
|------|-----------|
| **Kite API credentials** | Until you delete your account or rotate credentials |
| **Kite access token** | Expires daily (~6 AM IST); cached until expiry |
| **Audit trail (tool call logs)** | 5 years (per SEBI record-keeping requirements for brokers and intermediaries, applied as a precaution) |
| **Price alerts and watchlists** | Until you delete them or delete your account |
| **Paper trading data** | Until you delete it or delete your account |
| **IP addresses in rate limit logs** | Transient; not persisted beyond the server process |

After account deletion, all your data is permanently erased except the audit trail, which is retained for 5 years from the date of creation for regulatory compliance. You may request a copy of your audit trail before deleting your account.

## 7. Your Rights (Data Principal Rights)

Under the DPDP Act, 2023, you have the following rights:

### 7.1 Right to Access
You can view all your data through the Service dashboard at any time — portfolio, alerts, audit trail, and account settings.

### 7.2 Right to Correction
You can update your Kite API credentials via the self-service dashboard. If any data is inaccurate, contact the Operator.

### 7.3 Right to Erasure
You can delete your account and all associated data via the self-service dashboard. This is immediate and irreversible (except audit trail retained per Section 6).

### 7.4 Right to Grievance Redressal
If you have a complaint about how your data is handled:

1. **Contact the Operator** at sundeepg98@gmail.com with a description of your concern.
2. **Acknowledgment** within 7 days.
3. **Resolution** within 30 days.
4. **Escalation:** If unsatisfied, you may file a complaint with the **Data Protection Board of India** once it is constituted and operational.

### 7.5 Right to Nominate
Under the DPDP Act, you may nominate another person to exercise your data rights in the event of your death or incapacity. Contact the Operator to register a nominee.

### 7.6 Withdrawal of Consent
You may withdraw consent at any time by deleting your account. Withdrawal does not affect the lawfulness of processing before the withdrawal.

## 8. Cookies

The Service uses **one cookie**:

| Cookie | Purpose | Duration | Type |
|--------|---------|----------|------|
| JWT session cookie | Authenticate your dashboard session | 4 hours | Essential (first-party) |

That is the only cookie. No analytics cookies. No advertising cookies. No third-party cookies. No cookie consent banner is needed because the single cookie is strictly necessary to provide a service you explicitly requested (per DPDP Act guidance on essential cookies).

## 9. Data Breach Notification

In the event of a personal data breach:

- The Operator will notify the **Data Protection Board of India** within 72 hours (once constituted).
- Affected users will be notified **without unreasonable delay** via email (if available) or a prominent notice on the Service.
- The notification will include: what happened, what data was affected, what steps are being taken, and what you should do (e.g., rotate your Kite API credentials).

## 10. Cross-Border Data Transfer

- The primary database is hosted in **Mumbai, India** (Fly.io BOM region).
- Encrypted backups are stored on **Cloudflare R2** (region may vary).
- No personal data is intentionally transferred to countries restricted under the DPDP Act. If Cloudflare stores backup replicas outside India, the data is encrypted at rest and the encryption key remains in India.

## 11. Children

The Service is not intended for anyone under 18 years of age. We do not knowingly collect personal data from minors. If we learn that a user is under 18, their account will be deleted.

## 12. Changes to This Policy

Material changes will be communicated via the Service dashboard or email at least 15 days before they take effect. The previous version will be archived and available upon request.

## 13. Contact and Grievance Officer

For privacy-related questions, data requests, or complaints:

**Sundeep Govarthinam** (Grievance Officer)
**Email:** sundeepg98@gmail.com
**Response time:** Acknowledgment within 7 days, resolution within 30 days.

---

*By using the Kite MCP Server, you consent to the collection and processing of your personal data as described in this Privacy Policy.*
