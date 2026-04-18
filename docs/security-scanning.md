# Security scanning

Automated static + dependency-vulnerability scanning runs on every push/PR to
`master`, on a weekly cron (Sunday 03:00 UTC, ~08:30 IST Monday morning), and
on manual dispatch. Workflow: `.github/workflows/security-scan.yml`.

## Scanners

- **gosec** — static analyzer for Go source. Covers common issue classes:
  hardcoded credentials (G101), weak crypto (G401/G501), unsafe file paths
  (G304), SQL string-builder injection (G201), integer overflow (G115),
  unhandled errors (G104), and ~35 more rules.
  - Output: SARIF uploaded to **GitHub Code Scanning** (Security tab → Code
    scanning alerts). Each finding becomes a line-anchored alert with
    severity, rule id, and remediation guidance.
  - Mode: `-no-fail` so the workflow never blocks — Code Scanning is the
    source of truth for triage. The Actions tab still shows a red ✗ if the
    SARIF upload or gosec invocation itself errors.
- **govulncheck** — Go's official reachability-aware CVE scanner. Checks the
  module graph plus the stdlib version against the Go vulnerability database
  (`vuln.go.dev`). Fails the workflow on any **called** vulnerable symbol
  (reachability filter minimises noise from unused transitive deps).

Both scanners run in parallel jobs so one slow scan doesn't block the other.

## Viewing results

1. **GitHub Code Scanning alerts** (primary)
   Repository → *Security* → *Code scanning alerts*. Filters by severity,
   rule, and branch. Each alert shows the offending line with a code-context
   viewer and a "dismiss / fix / won't fix" workflow.
2. **Workflow artifacts** (for SARIF diff / offline analysis)
   Repository → *Actions* → *Security Scan* → pick a run → *Artifacts* →
   `gosec-sarif`. 90-day retention. Download two artifacts to diff between
   runs.
3. **Pull request checks**
   Findings introduced by a PR surface in the *Files changed* tab as inline
   annotations (Code Scanning integration). Reviewers see them alongside
   normal review comments.

## Manual / local invocation

Run the same tools locally before pushing:

```sh
# gosec (text output for terminal; SARIF for diffing against CI)
go install github.com/securego/gosec/v2/cmd/gosec@latest
gosec -fmt=text -exclude-dir=vendor -exclude-dir=.research ./...
gosec -fmt=sarif -out=gosec.local.sarif -exclude-dir=vendor -exclude-dir=.research ./...

# govulncheck (reachability-aware CVE scan)
go install golang.org/x/vuln/cmd/govulncheck@latest
govulncheck ./...
```

Requires Go 1.25+ to match CI.

## Current baseline

- **Last scan**: see the most recent *Security Scan* run under Actions.
- **Accepted exceptions** (suppressed via `// #nosec Gxxx -- justification`):
  none at present. Every suppression **must** include the rule id and a
  prose justification on the same line; un-annotated `#nosec` will not be
  merged.
- **Open findings**: tracked in the Code Scanning dashboard. Severity
  distribution and trend are visible in the Security overview panel.

The v1.0.0 hardening work (Feb–Mar 2026) resolved all 181 audit findings
(see `docs/SECURITY_POSTURE.md`). This workflow guards against regressions
and newly disclosed CVEs in dependencies.

## Responding to findings

| Severity                | SLA                                        | Action                                                                                   |
| ----------------------- | ------------------------------------------ | ---------------------------------------------------------------------------------------- |
| **High / Critical**     | Block deploy until fixed                   | Fix, re-run scan, verify alert auto-closes. If a deploy is already out, hotfix + redeploy. |
| **Medium**              | Ticket within 2 weeks, fix within 6 weeks  | File a tracking issue referencing the alert URL; batch with next minor release.          |
| **Low / Informational** | Periodic sweep (quarterly)                 | Review during the next security posture review; dismiss as "won't fix" with a reason if accepted risk. |

Adding `// #nosec Gxxx -- reason` to Go source is only acceptable when:

1. The finding is a genuine false positive (e.g. gosec flags a test fixture
   password as a hardcoded credential), **or**
2. The risk is explicitly accepted by the maintainer and documented inline.

Every `#nosec` directive is reviewed on the next `go vet` / lint pass.

## Related workflows & docs

- `.github/workflows/security.yml` — lighter-weight inline gosec + govulncheck
  (no SARIF; kept for fast PR feedback).
- `.github/workflows/sbom.yml` — CycloneDX SBOM generation (dependency
  inventory for audit trails). See `docs/sbom.md`.
- `docs/SECURITY_POSTURE.md` — overall security posture and historical audit
  results.
- `docs/incident-response.md` — playbook for responding to a real incident
  (vs. a scanner alert).
