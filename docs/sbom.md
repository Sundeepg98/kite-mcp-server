# Software Bill of Materials (SBOM)

The kite-mcp-server build pipeline publishes a CycloneDX-format SBOM on every
push to `master` and with every tagged release. The SBOM enumerates every Go
module that ends up in the compiled binary, including its version and license.

## Why we publish an SBOM

- **Supply chain transparency.** Addresses OWASP LLM03 (supply chain risk) for
  AI tooling. Downstream operators and customers can scan the SBOM for known
  CVEs without having to re-resolve the dependency graph themselves.
- **Compliance evidence.** SEBI / enterprise customer audits routinely ask for
  a dependency inventory with licenses. The published SBOM is that artefact.
- **Change tracking.** Because an SBOM is produced per commit to `master`,
  dependency drift shows up in diffable artefacts rather than `go.mod` alone.

## What is in the SBOM

Each SBOM lists:

- Every direct and transitive Go module compiled into the server binary.
- The resolved version (module path + pseudo-version / tag).
- The SPDX license identifier where available, with the fallback of the
  declared license file when no SPDX id is detected.
- A component hash (`bom-ref`) for each module, suitable for dedup when
  aggregating SBOMs across multiple services.
- Build metadata: Go toolchain version, build timestamp, and the tool that
  generated the document (`cyclonedx-gomod`).

It does **not** list:

- The binaries of external services the server talks to (Kite Connect API,
  Telegram, Cloudflare R2, etc.) — those are runtime integrations, not
  compiled-in dependencies.
- Test-only dependencies that do not end up in the production binary.
- Operating-system packages (e.g. Alpine `tzdata`). See `Dockerfile.selfhost`
  for the OS-level package list; a container image SBOM can be produced from
  the final image with `syft` or `trivy` if required.

## Where to download

| Source | Retention | Format |
|--------|-----------|--------|
| GitHub Actions run -> `sbom` artifact | 90 days | JSON + XML |
| GitHub Release asset (tagged versions) | Forever | JSON + XML |
| Locally regenerated (see below) | N/A | JSON + XML |

The workflow that produces these is `.github/workflows/sbom.yml`.

## Verifying the SBOM locally

The SBOM is reproducible from `go.mod` / `go.sum`. To regenerate and compare:

```bash
# 1. Install the same tool the CI uses
go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest

# 2. Produce both formats the CI produces
cyclonedx-gomod mod -licenses -json -output-file kite-mcp-sbom.cdx.json
cyclonedx-gomod mod -licenses        -output-file kite-mcp-sbom.cdx.xml

# 3. Diff against the published artefact (expect only timestamp / serialNumber
#    differences — the component list should match for the same commit).
diff <(jq 'del(.metadata.timestamp, .serialNumber)' kite-mcp-sbom.cdx.json) \
     <(jq 'del(.metadata.timestamp, .serialNumber)' downloaded-sbom.cdx.json)
```

If the component lists differ for the same commit, please file an issue with
the diff attached.

## Running vulnerability scans against the SBOM

The CycloneDX format is widely supported. Consumers can run their own scanners
without needing the source tree:

```bash
# Grype (Anchore) — CVE lookup against OSS vuln databases
grype sbom:./kite-mcp-sbom.cdx.json

# Trivy — CVE + license policy scanning
trivy sbom ./kite-mcp-sbom.cdx.json

# Syft — cross-format conversion, e.g. to SPDX for another auditor
syft convert kite-mcp-sbom.cdx.json -o spdx-json
```

Our own CI runs `govulncheck` (see `.github/workflows/security.yml`) which
reads the Go module graph directly; the SBOM is published for **external**
consumers who do not have access to the source tree.

## Relationship to other supply-chain controls

The SBOM is one of several supply-chain controls. The full picture:

- **govulncheck** (`.github/workflows/security.yml`) — blocks CI on known Go
  CVEs that are actually reachable from our code paths.
- **gosec** (`.github/workflows/security.yml`) — static analysis for insecure
  patterns in our own Go code.
- **v4 watchdog** (`.github/workflows/v4-watchdog.yml`) — alerts on upstream
  Kite Connect SDK major-version changes that would need a migration.
- **SBOM** (this document) — externalises the dependency graph for downstream
  scanning by customers, auditors, and this project's own release reviewers.
