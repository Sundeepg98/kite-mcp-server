# Smart App Control (SAC) runbook for Go test binaries

## Symptom

Running `go test ./kc/riskguard/...` (or any Go package) on Windows
with Smart App Control = On may fail with the test binary being
silently killed or blocked. Re-running with rotated `GOTMPDIR` /
`GOCACHE` does not help — SAC reputation is keyed on the binary's
content hash, not on the path.

## Root cause

SAC enforcement mode permits a binary if **either** of these is true:

1. The binary is signed by a code-signing certificate issued by a CA
   in **Microsoft's Trusted Root Program** (publicly-trusted CA, not a
   self-signed cert in your user store), OR
2. Microsoft's ISG cloud reputation service knows the binary's hash as
   "good" (reputation accumulates from population-wide telemetry).

Source: [Smart App Control overview — Microsoft Learn](https://learn.microsoft.com/windows/apps/develop/smart-app-control/overview)
> "Apps cannot be run unless they are recognized by Microsoft's app
> intelligence services, or they are signed with a trusted certificate
> [issued by a CA in the Microsoft Trusted Root Program]."

`go test` recompiles its test binary on every run with random Go
build IDs, so the content hash changes every time. Therefore Go test
binaries will **never** develop ISG reputation.

### Why self-signed certs don't fully work

The user-scope `GoTools Local Dev` cert (in `CurrentUser\Root`) makes
`Get-AuthenticodeSignature` report `Valid` — but that's standard
Authenticode, **not** SAC enforcement. SAC's CodeIntegrity (CI)
engine evaluates a separate `ValidatedSigningLevel` field; user-store
roots evaluate to `1` ("Unsigned" from CI's view, equivalent to no
signature at all for SAC enforcement).

Diagnostic to confirm on your box: after a SAC block, run

```powershell
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" `
  -MaxEvents 30 | Where-Object { $_.Id -eq 3089 } |
  Select-Object -First 1 |
  ForEach-Object { ([xml]$_.ToXml()).Event.EventData.Data |
    Where-Object Name -in 'ValidatedSigningLevel','PublisherName','KnownRoot' }
```

`ValidatedSigningLevel: 1` + `KnownRoot: 2` confirms that SAC saw
the cert but rejected the trust level.

### What used to seem to work, and why

Earlier verifications appeared to pass after signing. That was
**ISG cloud reputation winning the race**, not the cert: Defender
behavioral telemetry sometimes whitelists a recently-launched-but-
not-blocked path, and the next launch of any binary at that path
(even a fresh hash) succeeds for a brief window. As soon as ISG
flips the path back to neutral, blocks resume. Signing with the
self-signed cert is not what unblocked those runs.

## Mitigation: `scripts/go-test-sac.cmd` + ISG cooldown

There is **no fully-deterministic userspace fix** while SAC is on. The
two effective options are:

### Option 1 (recommended for routine work): wrapper + ISG cooldown

`scripts/go-test-sac.cmd` signs the test binary with the
`GoTools Local Dev` cert (thumbprint
`4ABCEECC23F524EB460409F66B5306C2E1787272`). The signing **does not
unblock SAC enforcement directly** (see "Why self-signed certs don't
fully work" above), but it does:

- Help when SAC's WDAC policy is later upgraded to honor the user-store
  root (e.g., in audit-only modes for dev workflows).
- Make the binary's signature visible in audit logs, easing diagnosis.
- Cost essentially nothing at the wrapper layer (~50ms per launch).

In practice, runs succeed when ISG happens to whitelist the launch path
and fail otherwise. **Expect 30-50% of full-suite runs to fail** with
SAC On. To reduce flake:

1. Wait **30+ seconds** between consecutive full-suite runs. ISG
   reputation telemetry settles in that window.
2. Run smaller `-run TestX` subsets first to "warm" the path.
3. Don't rotate `GOTMPDIR`/`GOCACHE` if a recent run succeeded — reuse
   the path so behavioral whitelisting carries over.

```bash
# From repo root, in any shell:
go test -exec="$PWD/scripts/go-test-sac.cmd" ./kc/riskguard/... -count=1
```

### Option 2 (fastest for hot loops): trusted-CA code-signing cert

For a deterministic fix that survives across sessions, sign with a
real publicly-trusted code-signing certificate (Microsoft Trusted
Signing, or any CA in Microsoft's Trusted Root Program). Cost: ~₹6k/yr
or free via [Microsoft Trusted Signing](https://learn.microsoft.com/azure/trusted-signing/)
for individuals. Once a binary is signed by a publicly-trusted CA,
SAC honors it without ISG involvement.

Update `~/go/bin/sign-bin.ps1` to point at the trusted-CA thumbprint
instead of `4ABCEECC23F524EB460409F66B5306C2E1787272`. The wrapper
itself doesn't change.

### Option 3 (CI / heavy work): build on Linux/WSL

SAC is Windows-only. Run the suite under WSL2 or a Linux container
when the work is verification-heavy:

```bash
wsl -- go test ./kc/riskguard/... -count=1
```

### Constraints (any option)

- The wrapper runs only on Windows (`.cmd`). On Linux/macOS the
  wrapper is unused — `go test` runs as normal without `-exec`.
- The wrapper is **best-effort** — if signing fails it still execs
  the binary so the underlying SAC block error surfaces clearly.

### Re-signing the cert

Cert is valid until 2031-02-13. If/when it expires:

1. Generate a new self-signed cert with `CN=GoTools Local Dev`
2. Add it to `Cert:\CurrentUser\My` and `Cert:\CurrentUser\Root`
3. Update the thumbprint in:
   - `~/go/bin/sign-bin.ps1`
   - `~/go/bin/sign-gopls.ps1`
   - This file
   - `scripts/go-test-sac.cmd` (no thumbprint hardcoded — it calls
     sign-bin.ps1)

## What NOT to do

- Do **NOT** disable SAC or switch it from Enforcement to Evaluation.
- Do **NOT** add the project directory to a Defender exclusion (this
  excludes from realtime AV, which is a security regression).
- Do **NOT** lower the policy on the existing trusted cert.

## Subprocess plugins (spawned children)

Signing the parent test binary via `scripts/go-test-sac.cmd` is **not
enough** when a test spawns a subprocess plugin via `os/exec`. SAC
evaluates each child launch independently against its own content
hash, and freshly-built plugin binaries have no reputation either.

**Symptom:**

```
launch subprocess: fork/exec ...\plugin.exe:
  An Application Control policy has blocked this file.
```

**Fix pattern:** sign the spawned binary right after building it,
before the parent execs it. See `kc/riskguard/subprocess_check_test.go`
`signPluginForSAC` for a concrete example used by the
`buildExamplePlugin` test helper (commit `55b7387`).

The same pattern applies to any operator-deployed third-party plugin:
sign the plugin binary once (`powershell -File ~/go/bin/sign-bin.ps1
-Path /path/to/plugin.exe`) post-build, ship the signed binary.
Production `subprocess_check.go` does not embed signing — it is the
operator's responsibility.

## See also

- `~/go/bin/sign-bin.ps1` — generic signing wrapper (1 file argument)
- `~/go/bin/sign-gopls.ps1` — gopls-specific re-sign script
- User memory section "Smart App Control (SAC)" for original gopls fix
