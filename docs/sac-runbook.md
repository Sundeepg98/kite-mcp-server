# Smart App Control (SAC) runbook for Go test binaries

## Symptom

Running `go test ./kc/riskguard/...` (or any Go package) on Windows
with Smart App Control = On may fail with the test binary being
silently killed or blocked. Re-running with rotated `GOTMPDIR` /
`GOCACHE` does not help — SAC reputation is keyed on the binary's
content hash, not on the path.

## Root cause

SAC permits a binary if **either** of these is true:

1. It is signed by a publisher whose cert is in a trusted root store, or
2. Microsoft's ISG cloud reputation service knows the binary's hash as
   "good" (reputation accumulates from population-wide telemetry).

`go test` recompiles its test binary on every run with random Go
build IDs, so the content hash changes every time. Therefore Go test
binaries will **never** develop ISG reputation. The only durable fix
is signing.

This is the same class of issue as `gopls.exe` being blocked when
freshly compiled via `go install` — see the user-scope memory under
"Smart App Control (SAC)" for the original fix.

## Fix: `scripts/go-test-sac.cmd`

A `go test -exec` wrapper that signs the test binary in place with
the existing `GoTools Local Dev` cert (thumbprint
`4ABCEECC23F524EB460409F66B5306C2E1787272`, already trusted in
`CurrentUser\Root`) before launching it.

### Usage

```bash
# From repo root, in any shell:
go test -exec="$PWD/scripts/go-test-sac.cmd" ./kc/riskguard/... -count=1
```

Or for any other package:

```bash
go test -exec="$PWD/scripts/go-test-sac.cmd" ./mcp/ -run TestSomething -count=1
```

### How it works

1. `go test -exec=<cmd>` tells Go to pass the freshly-built test binary
   to `<cmd>` instead of executing it directly.
2. The wrapper signs the binary in place using
   `~/go/bin/sign-bin.ps1` (which uses the trusted dev cert).
3. The wrapper then `exec`s the now-signed binary with the original
   args. Signing adds a digital signature appendix; SAC validates the
   signature against the trusted root and lets the binary run.

### Constraints

- The cert must already be installed and trusted (one-time setup,
  done previously for gopls). Verify with:

  ```powershell
  Get-ChildItem Cert:\CurrentUser\My\4ABCEECC23F524EB460409F66B5306C2E1787272
  ```

- The wrapper is **best-effort** — if signing fails (cert missing,
  expired, etc.) it still exec's the binary so the underlying SAC
  block error surfaces clearly rather than being masked by a sign
  error.

- The wrapper runs only on Windows (`.cmd`). On Linux/macOS the
  wrapper is unused — `go test` runs as normal without `-exec`.

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

## Fallback: wait-for-cooldown + rotate

If for some reason signing is unavailable (e.g., cert expired and not
yet replaced), the only alternative known to work is:

1. Rotate `GOTMPDIR` and `GOCACHE` to fresh paths (forces a fresh
   build path).
2. Retry. Sometimes SAC enforces a short ban on a recently-blocked
   path; the rotation bypasses path-based bans even though the
   underlying content-hash issue is unchanged.
3. After several minutes of cooldown, the same content may go through
   if Defender's behavioral telemetry has had time to settle.

This is **flaky** and should never be relied on in CI. Use the
signing wrapper.

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
