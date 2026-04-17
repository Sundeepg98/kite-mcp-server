# Evidence Package

Pre-built folder for incident response. In a crisis:
1. Compile all files here into a single PDF
2. Share with counsel / regulator / Zerodha within timelines in [../incident-response.md](../incident-response.md)

## Purpose

When regulators, Zerodha compliance, or legal counsel ask "show us what you've built and how you've operated," every artefact they will reasonably ask for lives here. Under crisis pressure, you should not be scrambling to compile diligence evidence — it should already exist at this path.

## Contents

- [architecture.md](./architecture.md) — system design + ASCII diagram
- [compliance-timeline.md](./compliance-timeline.md) — regulator / Zerodha / legal outreach log
- [user-count.md](./user-count.md) — usage metrics (fill at incident time)
- [revenue.md](./revenue.md) — revenue disclosure (currently pre-revenue)
- [third-party-reviews.md](./third-party-reviews.md) — audits, pentests, code reviews
- [commit-history-highlights.md](./commit-history-highlights.md) — security/compliance commits showing diligence
- [compliance-emails-sent.md](./compliance-emails-sent.md) — outreach log template

## How to keep this current

- Update `commit-history-highlights.md` quarterly (or after any major security feature)
- Log every `kiteconnect@zerodha.com` / SEBI / Spice Route email in `compliance-emails-sent.md`
- Update `compliance-timeline.md` when outreach actually happens (not just planned)
- Leave templates (`user-count.md`, parts of `compliance-emails-sent.md`) empty until incident — they should be filled with real-time data at the moment of need, not stale projections

## Referenced external artefacts

These live outside `docs/evidence/` but are part of the evidence package:

- `/SECURITY_AUDIT_REPORT.md` — 27-pass manual audit, 181 findings resolved
- `/SECURITY_POSTURE.md` or `/docs/SECURITY_POSTURE.md` — current posture doc
- `/SECURITY.md` — public security policy
- `/TERMS.md`, `/PRIVACY.md` — legal docs (marked DRAFT pending counsel review)
- `/ARCHITECTURE.md` — longer-form architecture
- `/docs/incident-response.md` — the crisis runbook this package supports
- `/docs/legal-notes.md` — legal reasoning notes
- Full commit history via `git log --oneline` — this folder summarises highlights only

## Compiling to PDF (at incident time)

```bash
# Example — adapt to your local tools
cd docs/evidence
pandoc README.md architecture.md compliance-timeline.md user-count.md revenue.md \
       third-party-reviews.md commit-history-highlights.md compliance-emails-sent.md \
       -o evidence-package-$(date +%Y-%m-%d).pdf \
       --toc --toc-depth=2
```
