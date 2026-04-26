# Microsoft Trusted Signing — Migration Scoping for kite-mcp-server

**Status: STOP / DEFER — recommend WSL2 alternative.**
Two stop conditions in the scoping brief are triggered. Details and full scoping below.

## TL;DR

- Trusted Signing is **NOT free for individuals**. It is **$9.99/month minimum** (Basic SKU) on a **paid** Azure subscription. The `sac-runbook.md` claim "free via Microsoft Trusted Signing for individuals" is **incorrect** and should be revised.
- Trusted Signing is **NOT available to individual developers in India**. Public Trust individual eligibility is **USA + Canada only**, and individual onboarding is **paused globally** since April 2025 ahead of GA.
- Even if eligibility were available, the service requires **government-ID identity verification via Au10TIX** and a **paid Azure subscription** (free/trial subscriptions cannot register `Microsoft.CodeSigning`).

**Recommendation: defer Trusted Signing migration. Use Option 3 (WSL2) from the existing runbook for hot loops, accept the existing 50-70% pass rate on Windows for routine work.** Re-evaluate if/when (a) Microsoft expands individual eligibility to India, or (b) the user incorporates a US/Canada/EU/UK entity with 3+ year verifiable tax history.

---

## 1. What MS Trusted Signing is

Microsoft Trusted Signing — rebranded to **Azure Artifact Signing** (the docs URL still works at `learn.microsoft.com/azure/trusted-signing/`) — is Microsoft's fully managed code-signing service launched in public preview in 2024. It replaced the Device Guard Signing Service (DGSSv2). The service issues short-lived (≈3-day) certificates from the **Microsoft Identity Verification Root Certificate Authority 2020**, which chains into the **Microsoft Root Certificate Program** (= Microsoft Trusted Root Program). Identity (organization or individual) is verified once; certificates roll daily.

For our SAC use case, this matters because SAC enforcement honors any cert issued by a CA in the Microsoft Trusted Root Program — Trusted Signing's `Public Trust` profile satisfies this deterministically. That would replace the 50-70% pass rate with 100% deterministic pass for `go test` binaries.

Sources: [Smart App Control: code-signing requirement](https://learn.microsoft.com/windows/apps/develop/smart-app-control/code-signing-for-smart-app-control), [Artifact Signing trust models](https://learn.microsoft.com/azure/artifact-signing/concept-trust-models), [Quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart).

---

## 2. Eligibility check (the dealbreaker)

| Dimension | Requirement | User status |
|---|---|---|
| Geography (Public Trust, individual) | **USA or Canada only** | India — **NOT ELIGIBLE** |
| Geography (Public Trust, organization) | USA, Canada, EU, UK | Not an org |
| Tax history (org) | 3+ years verifiable | N/A |
| Individual onboarding window | **Paused globally since April 2025** ahead of GA | **Closed** |
| Azure subscription type | Paid (PAYG, EA, MCA, CSP) | Would need to create + add payment method |
| Identity verification | Government-issued ID (passport/DL) + selfie via Au10TIX | Possible but only if geo passes |

**Decisive sources:**
- Official Microsoft Learn — [Code signing options](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options): "Individual developers are currently limited to the USA and Canada. If you are an individual developer outside those regions, see OV certificates below."
- Microsoft Q&A 5810735 — "Individual developer onboarding has been paused. This applies to developers in India and other countries outside the USA and Canada." (verified Apr 2026)
- [Artifact Signing FAQ](https://learn.microsoft.com/azure/artifact-signing/faq) — "The Microsoft.CodeSigning resource provider isn't supported on Free or Trial Azure subscriptions. A paid Azure subscription is required."

**The runbook's claim "free via Microsoft Trusted Signing for individuals" is incorrect on two counts** (no free tier; not available in IN). It should be revised in a follow-up edit.

---

## 3. Prerequisites (for completeness, not actionable from IN)

If eligibility ever opens for India, these would be needed before setup can start:

1. **Microsoft Entra tenant ID** (free to create at entra.microsoft.com, takes ~5 min).
2. **Paid Azure subscription** — PAYG with credit card; free/trial subscriptions explicitly cannot register the resource provider. ~₹0 idle, billed only on signing-account creation.
3. **Government-issued ID** (passport, driving license, or photo ID) for Au10TIX video verification — selfie + ID scan via mobile.
4. **Mobile device with Microsoft Authenticator app** (iOS or Android) to receive the Verified ID credential.
5. **Email address NOT shared with the project's other identities** (per user-scope rule, not the foundation address).
6. **Windows 10 1809+ or Windows 11** with Windows SDK SignTool (≥10.0.22621.755), .NET 8 Runtime, MSVC++ Redistributable. (signtool.exe is **not** on the user's box from prior gopls signing — `~/go/bin/sign-bin.ps1` uses `Set-AuthenticodeSignature`, a PowerShell cmdlet, not signtool. signtool would need separate install via `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`.)

**Setup time estimate, end-to-end, IF eligible:** 4-12 business days.
- 30 min: Azure account + Entra tenant + subscription registration.
- 30 min: Trusted Signing account + identity validation request.
- **1-20 business days**: Au10TIX identity verification (typical: 4-7).
- 30 min: certificate profile creation + signtool/dlib install.
- 30 min: integration test.

---

## 4. Step-by-step setup procedure (would-be, if eligibility re-opens)

Captured here for future re-evaluation. **Do not execute today.**

1. **Register paid Azure subscription** at portal.azure.com. Add credit card.
2. **Register `Microsoft.CodeSigning` resource provider** — Subscriptions → [your sub] → Resource providers → search `Microsoft.CodeSigning` → Register. CLI alternative: `az provider register --namespace "Microsoft.CodeSigning"`.
3. **Create Artifact Signing account** — Search "Artifact Signing Accounts" in portal → Create. Fields: account name (3-24 alnum, globally unique), region (East US recommended for low-latency from IN; endpoint `https://eus.codesigning.azure.net`), pricing (Basic = $9.99/mo, 5,000 sigs/mo).
4. **Create identity validation** — On account Overview → Identity validations → New identity → Individual → Public. Fill: legal first/last name (matches government ID exactly), primary email, address (matches utility bill / bank statement). Status goes In Progress.
5. **Complete Au10TIX verified ID flow** — Click email link → "Get verified here through our trusted ID-verifiers" → AU10TIX → enter email + PIN → enter phone → scan QR on mobile → Microsoft Authenticator → present ID + selfie. Status flips to **Completed** within ~15 min after the AU10TIX step succeeds.
6. **Create certificate profile** — Account → Certificate profiles → Create → Public Trust → name (5-100 alnum) → Verified CN/O = the identity validation just completed → Create.
7. **Install Artifact Signing Client Tools** — `winget install -e --id Microsoft.Azure.ArtifactSigningClientTools`. This bundles signtool.exe (Windows SDK), .NET 8 Runtime, MSVC++ Redist, and the `Azure.CodeSigning.Dlib.dll` plugin.
8. **Create `metadata.json`** at `~/.claude/mcp-servers/trusted-signing-metadata.json`:
   ```json
   {
     "Endpoint": "https://eus.codesigning.azure.net",
     "CodeSigningAccountName": "<your-account-name>",
     "CertificateProfileName": "<your-profile-name>",
     "ExcludeCredentials": ["ManagedIdentityCredential"]
   }
   ```
   (`ExcludeCredentials` avoids `CredentialUnavailableException` outside Azure VMs.)
9. **Test signature** on a sample binary. From PowerShell (logged in via `az login`):
   ```powershell
   & "C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /v /debug /fd SHA256 `
     /tr "http://timestamp.acs.microsoft.com" /td SHA256 `
     /dlib "C:\Program Files\Microsoft\ArtifactSigning\bin\Azure.CodeSigning.Dlib.dll" `
     /dmdf "$env:USERPROFILE\.claude\mcp-servers\trusted-signing-metadata.json" `
     C:\path\to\test.exe
   ```
10. **Verify SAC stops blocking** — `Get-AuthenticodeSignature C:\path\to\test.exe` should report Signer = `<your name>, <your country>` and Status = Valid. Then the diagnostic from `sac-runbook.md`:
    ```powershell
    Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 30 |
      Where-Object { $_.Id -eq 3089 } | Select-Object -First 1
    ```
    `ValidatedSigningLevel` must be `≥ 8` (Authenticode + trusted root) — not `1`.

---

## 5. Integration with existing `scripts/go-test-sac.cmd`

Minimal wrapper change — replace the `~/go/bin/sign-bin.ps1` invocation:

**Current (line 35):**
```cmd
powershell -NoProfile -ExecutionPolicy Bypass -File "%USERPROFILE%\go\bin\sign-bin.ps1" -Path "%BIN%" >nul
```

**Proposed (Trusted Signing):**
```cmd
"C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe" sign /fd SHA256 ^
  /tr "http://timestamp.acs.microsoft.com" /td SHA256 ^
  /dlib "C:\Program Files\Microsoft\ArtifactSigning\bin\Azure.CodeSigning.Dlib.dll" ^
  /dmdf "%USERPROFILE%\.claude\mcp-servers\trusted-signing-metadata.json" ^
  "%BIN%" >nul 2>&1
```

That's a **~1500ms-per-binary** overhead (vs ~50ms for self-signed) due to remote certificate fetch + timestamping. Acceptable for `go test -count=1` runs but adds up for `-race` / `-cover` matrices.

**No other code changes required.** Subprocess plugins (`subprocess_check_test.go:signPluginForSAC`) would need a parallel update to call the same signtool invocation.

---

## 6. Migration plan (if it ever becomes feasible)

- **Phase 0** — Setup MS Trusted Signing account (no code change). 30 min active + 4-7 days waiting on Au10TIX.
- **Phase 1** — Dual-signing test: temporary wrapper signs with **both** the self-signed cert (existing) and the MS cert (new), via `signtool sign /a` + chained `Set-AuthenticodeSignature -IncludeChain All`. Run full `go test ./...` 10 times. Confirm:
  - 0 SAC blocks observed in `CodeIntegrity/Operational` event log.
  - `Get-WinEvent | Where-Object Id -eq 3089` reports `ValidatedSigningLevel: 8` (or higher) for MS-signed binaries.
- **Phase 2** — Switch wrapper to MS-only signing. Update `docs/sac-runbook.md` Section "Mitigation" to make Option 2 the default. Keep Options 1 (self-signed) and 3 (WSL2) as fallbacks.
- **Phase 3** — Deprecate `GoTools Local Dev` cert. Leave in `Cert:\CurrentUser\Root` for ~1 month so existing-binary signatures remain Valid (not Trusted but Valid). Then delete via `Remove-Item Cert:\CurrentUser\Root\4ABCEECC23F524EB460409F66B5306C2E1787272`.

---

## 7. Cost estimate

**Recurring:**
- **$9.99/month** (Basic SKU): 5,000 signatures/month included. After quota: $0.005/sig.
- **$0.005/signature** overage. A typical `go test ./...` run signs 1 test binary per package; the repo has ~80 packages, so ~80 sigs/run. 5,000 / 80 ≈ 62 full-suite runs/month within quota — comfortable for solo dev.
- **₹0 Azure compute** (no VM, no storage). Trusted Signing account itself is the only billable item.
- **Currency**: billed in USD on Azure invoice. ~₹830/month at ₹83/USD.

**One-time (person-hours):**
- **~3 hours active work** spread across **4-12 business days** elapsed (mostly Au10TIX wait).

**Per-signing (recurring):**
- **Negligible** if `scripts/go-test-sac.cmd` already wraps `go test`. Wrapper change is one-line. Marginal latency: +1.5s/binary (vs +0.05s self-signed). For full `go test ./... -race -count=1`, ~80 binaries × 1.5s = +120s wall time per run. Trade-off: +120s vs avoiding 30-50% retry rate.

---

## 8. Risks / gotchas (from official docs + community)

- **Identity validation can fail / require resubmission.** Up to 3 documentation upload attempts. If Au10TIX rejects (poor lighting, expired ID, address mismatch), full re-submission required.
- **Account suspension on misuse.** Microsoft may revoke certificates and suspend account if any signed binary is reported as malware. Cert revocation is retroactive — already-signed binaries become Untrusted on next CRL refresh.
- **Cert short validity** (~3 days). All signed binaries MUST be timestamped (`/tr http://timestamp.acs.microsoft.com /td SHA256`) — without timestamp, signatures expire and SAC blocks again.
- **Region/endpoint mismatch = HTTP 403.** The endpoint URI must match the region of the signing account. East US → `https://eus.codesigning.azure.net`. Wrong region = `SignerSign() failed`.
- **Free Azure subscriptions blocked.** PAYG required. Trial subs cannot register `Microsoft.CodeSigning`.
- **No SmartScreen instant trust.** Even with Trusted Signing, SmartScreen reputation must accumulate from population telemetry. (For our use case — SAC unblocking on dev box — this is irrelevant; SAC honors the cert directly.)
- **Account-lapse behavior.** If billing fails or you delete the account, certificate profiles are stopped. Already-signed binaries with valid timestamps remain trusted until the cert in the chain is revoked or the timestamp fails.
- **CodeIntegrity event log polling required to confirm SAC actually honored it.** `Get-AuthenticodeSignature` showing Valid is **not** sufficient (the runbook already calls this out — same trap applies to Trusted Signing testing).
- **Rate limiting**: undocumented, but FAQ implies signing throttling at ~10/sec. Not a concern for single-user `go test` workflow.

---

## 9. Decision recommendation: **DEFER**

**Stop conditions in the brief that are triggered:**
1. > "If MS Trusted Signing requires Azure subscription + monthly fee (not free for individuals) → stop, document the finding, recommend WSL2 instead in the doc."
   - **Triggered.** $9.99/month minimum on paid Azure subscription. Runbook claim is wrong.
2. > "If setup requires identity verification beyond GitHub identity (e.g., DUNS number, business registration) → stop, document, recommend deferring."
   - **Triggered.** Au10TIX video ID + selfie + government-issued ID + matching address proof.

**Plus the unstated dealbreaker: India is not eligible.** Even if the user accepts the cost and the ID flow, the service is unavailable to individual developers outside USA/Canada, and individual onboarding has been paused globally since April 2025.

### Recommended path forward

**Use Option 3 from the existing runbook (WSL2)** for verification-heavy / hot-loop work:

```bash
wsl -- go test ./kc/riskguard/... -count=1
```

Keep Option 1 (`scripts/go-test-sac.cmd` + self-signed cert) for routine Windows-side runs. The 50-70% pass rate is annoying but acceptable for solo dev — the 30-second cooldown between full runs is the lowest-cost mitigation. The runbook already documents both correctly.

### Conditional reopen criteria

Re-evaluate Trusted Signing if **any** of these change:
- Microsoft announces individual-developer onboarding for India (watch [Trusted Signing public-preview thread](https://techcommunity.microsoft.com/blog/microsoft-security-blog/trusted-signing-is-now-open-for-individual-developers-to-sign-up-in-public-previ/4273554) and Microsoft Q&A tag `azure-trusted-signing`).
- User incorporates a Pvt Ltd or US LLC with 3+ years verifiable tax history (per kite-cost-estimates: ~₹55-85k filing for IN Pvt Ltd; org Trusted Signing tier still $9.99/mo).
- The annual signing volume justifies an OV cert (~$150-300/yr from DigiCert/Sectigo) — cheaper than 12 × $9.99 = $120/yr Trusted Signing only if individual eligibility re-opens. **OV certs work worldwide for individuals.**

### Cheaper alternative worth flagging

**OV code-signing cert from Certum** (~$70/yr first-year promo, includes hardware token). Available worldwide for individuals. Same SAC trust outcome as Trusted Signing. Tradeoff: hardware token = 1 signing machine, no CI/CD friendly. Acceptable for solo dev box. Future investigation candidate, not in scope for this scoping doc.

---

## Appendix: corrections to existing docs

These follow-up edits should be tracked but are **out of scope** for this scoping pass (per the brief: "DO NOT modify scripts/go-test-sac.cmd or docs/sac-runbook.md"):

1. `docs/sac-runbook.md` line 99-100: claim "or free via Microsoft Trusted Signing for individuals" is **factually incorrect**. Should read: "Microsoft Trusted Signing — $9.99/month, currently US/Canada individuals only, individual onboarding paused since Apr 2025."
2. User-scope MEMORY.md "Smart App Control" section: add note that Trusted Signing is not a viable migration target for the user's geography until eligibility expands. (Updated below.)

---

## Appendix B: existing-cert investigation (Apr 26, 2026)

Before finalising DEFER, audited every cert store on the system to rule out a free reusable cert from a prior package install. **Result: no usable trusted-CA cert exists.** DEFER confirmed.

### Inventory: ALL certs system-wide with private keys (any EKU)

| # | Store | Thumbprint (prefix) | Subject | EKU | Source | SAC-usable? |
|---|---|---|---|---|---|---|
| 1 | `CurrentUser\My` | `4ABCEEC...` | CN=GoTools Local Dev | Code Signing | self-signed (our own gopls fix) | **No** — self-signed root, fails CI level 1 |
| 2 | `CurrentUser\My` | `B7A1A13...` | CN=bf8b6f81-...-907862d87331 | (none / all uses) | likely Windows Hello / WebAuthn / MeshKit dev sandbox | No — no Code Signing EKU |
| 3 | `CurrentUser\My` | `9E69EE7...` | CN=515e280f-...-c9b4b2c1038f | Client Authentication | Microsoft Entra ID device-join (issuer `MS-Organization-Access`) | No — no Code Signing EKU |
| 4 | `CurrentUser\My` | `869E943...` | CN=4e0e732d-...-88e83a598cd7 | (none / all uses) | dev sandbox (paired with #6) | No — no Code Signing EKU |
| 5 | `CurrentUser\My` | `50ECB06...` | CN=trust_4e0e732d-...-88e83a598cd7 | (none / all uses) | dev sandbox companion | No — no Code Signing EKU |
| 6 | `CurrentUser\My` | `1AEF4B6...` | CN=trust_bf8b6f81-...-907862d87331 | (none / all uses) | dev sandbox companion | No — no Code Signing EKU |

Plus 1 entry without private key (Apple iPhone Device CA `5FA62D8...`) — not signing-capable.

`LocalMachine\My`: **0** certs. `LocalMachine\Root`: 0 Microsoft-issued certs with private keys. The 12 Microsoft Trusted Root CAs in `CurrentUser\Root` (Authenticode, Identity Verification 2020, Root CA 2010/2011/2017, etc.) are **public-key-only roots** — they validate signatures but cannot issue them.

### Chain validation on the only Code Signing EKU candidate

```
Cert: 4ABCEECC... (GoTools Local Dev)
Chain elements: [self] only — chain root = the cert itself
Issuer: CN=GoTools Local Dev (== Subject)
Chain.Build = True (because we placed it in CurrentUser\Root)
But: chain root is NOT in Microsoft Trusted Root Program
→ SAC sees ValidatedSigningLevel=1 (= Unsigned), KnownRoot=2
```

Confirmed: the only existing Code Signing cert is exactly the one the runbook already calls out as inadequate for SAC. SAC test-sign step skipped — no point re-confirming a known-failing cert.

### Updated recommendation: **DEFER confirmed**

No free path forward via existing certs. The system has no MS-trusted code-signing cert installed by Visual Studio, .NET SDK, Windows SDK, GitHub Desktop, or any other package. The `bf8b6f81/4e0e732d/trust_*` certs look like MeshKit / Loop / Windows-Hello dev sandbox material — none have Code Signing EKU, all are self-signed or chain to non-Trusted-Root issuers.

Stop condition #2 from the cert-investigation brief triggers: **"No certs found / all chain-invalid → STOP, confirm DEFER."**

Same recommendation stands: keep `scripts/go-test-sac.cmd` + self-signed for routine, use WSL2 for hot loops, accept 30-50% Win pass rate. Cheapest worldwide-individual upgrade path remains Certum OV cert (~$70/yr first-year promo, hardware token) — separate scoping if/when justified.

---

## Appendix C: alternative cert-acquisition packages (Apr 26, 2026)

Followup to user question: "why don't we download a package that has a cert?" Investigated 7 candidates that put a chain-valid cert into the user's store. **One winner: Certum Open Source Code Signing.**

### Comparison table

| Option | Cost (yr1 / renewal) | India OK | SAC accepts? | Setup time | Friction |
|---|---|---|---|---|---|
| **Certum Open Source Code Signing** | **€104 (~₹9,400) yr1 / €29 (~₹2,600)/yr** | **Yes** (DHL ships worldwide; verified UK case) | **Yes — chain confirmed** (Certum Trusted Network CA already in user's CurrentUser\Root from Windows Update) | ~3 days end-to-end | Hardware smartcard + reader required; one-time IDnow video KYC + utility bill + GitHub OSS proof |
| Certum SimplySign cloud individual (non-OS variant) | ~€199/yr | Yes | Yes (same chain) | ~2-3 days | Higher cost; same KYC; cloud (no hardware) |
| SSL.com IV Code Signing — eSigner cloud | $180/yr (~₹15,000) | Likely yes (worldwide) | Yes (Authenticode-issued) | ~2-3 days | Cloud HSM; KYC required; quotas (240 sigs/yr) |
| SSL.com IV Code Signing — Yubikey FIPS token | $180/yr + token shipping | Likely yes | Yes | ~5-7 days | Hardware token logistics + India customs |
| DigiCert KeyLocker (cloud) | ~$370+/yr (KeyLocker is **add-on** to base cert) | Likely yes | Yes | ~3-5 days | Most expensive; per-operation crypto cost |
| **Sigstore Cosign + Fulcio** (FREE, OSS) | **$0** | Yes | **NO — TWO blockers**: (1) Cosign uses **ECC**, SAC requires **RSA**; (2) Cosign produces detached/sigstore signatures, NOT Authenticode | n/a | Hard blocker — cannot be made to work for PE/SAC today |
| GitHub Actions ephemeral signing via Sigstore | $0 | Yes | NO (same Sigstore blockers) | n/a | Same blocker |
| Codegic 30-day "free" trial | $0 trial | Yes | **NO** — Codegic explicitly states "not a publicly trusted CA"; not in MS Trusted Root | n/a | Useless for SAC |
| Self-hosted Smallstep / private CA | $0 | Yes | NO (same as GoTools — root not in MS Trusted Root) | n/a | Same problem we already have |

### Verdict: Certum Open Source Code Signing wins

**Why Certum-OS is the actionable path:**

1. **India eligibility confirmed.** Certum (Asseco/Unizeto, Poland) ships worldwide via DHL. The 2025 first-hand walkthrough at piers.rocks documents a successful UK purchase (Poland → UK in 1 day via DHL); India shipping is the same DHL international network. Certum requires no in-region presence; KYC is via IDnow video (driving licence + selfie) which works globally.
2. **SAC acceptance verified theoretically.** The Certum Trusted Network CA root (`07E032E020...`) is **already** in `CurrentUser\Root` on the user's box, delivered by Windows Update via the Microsoft Trusted Root Program. Any cert Certum issues chains to that root → SAC's CodeIntegrity engine will see `KnownRoot=4` (trusted-program root) and `ValidatedSigningLevel ≥ 8` (Authenticode-trusted). **No theoretical reason SAC will reject a Certum-OS-signed binary.** Empirical confirmation requires the cert in hand — cannot be tested today.
3. **Cheapest worldwide individual option.** €104 first year / €29 renewal beats every alternative by 2-15x. ~₹9,400 yr1 then ~₹2,600/yr.
4. **Hardware smartcard is acceptable for solo dev box** — one signing machine is the workflow already.

**Eligibility caveat (must verify before ordering):** kite-mcp-server qualifies as an active OSS project — public on GitHub at `Sundeepg98/kite-mcp-server` with commit history. Certum requires "active developer in at least one Open Source project" + URL of an active OSS project. Apache-2.0 license preferred but not strictly mandated by Certum (typically OSI-approved license suffices). User to confirm which license the kite-mcp-server repo is under before applying.

**Estimated time-to-first-signed-binary if user proceeds:** **3-5 business days** (1 day order + KYC; 2 days Certum issue; 1 day DHL India transit; ~2 hours driver/SignService install).

### Wrapper integration (1-line change, post-cert-arrival)

After cert is on the smartcard and Windows recognises it via `proCertum CardManager`:

1. Find the Certum-issued cert in `Cert:\CurrentUser\My` — note its thumbprint (e.g. `XXXXXXXX...`).
2. Edit `~/go/bin/sign-bin.ps1` line referencing `4ABCEECC23F524EB460409F66B5306C2E1787272`, replace with the new thumbprint.
3. `scripts/go-test-sac.cmd` requires **zero changes** — it just calls `sign-bin.ps1`.

That's it. Cost: $0 wrapper change, ~₹9,400 cert cost, deterministic SAC unblocking.

### Updated recommendation: **PROCEED — Certum Open Source Code Signing**

Beats DEFER. Replaces both Trusted Signing (geo-blocked + paid) AND the self-signed cert (SAC-rejected). Order at https://shop.certum.eu/open-source-code-signing.html. Total budget: ~₹10,000 first year, ~₹3,000/yr renewal. India ships fine. Decision deferred to user; if user proceeds, follow-on dispatch can wire the wrapper change post-cert-arrival.

**Note: Appendix D below revises this — WSL2 dominates Certum for THIS codebase.**

---

## Appendix D: WSL2 alternative scoped (Apr 26, 2026)

User question: WSL2 vs Certum order. **Verdict: WSL2 dominates Certum for this codebase.** $0, ~30 min setup, zero KYC, zero shipping. Only loss is signing Windows release binaries — but kite-mcp-server **has no Windows release artifact**: production target is Fly.io Linux Docker. Certum buys nothing the user actually needs.

### Setup procedure (Windows 11 Home — concrete commands)

WSL2 ships free with Windows 11 Home (no Pro license required since 2021).

```powershell
# As admin from PowerShell — no separate downloads needed
wsl --install -d Ubuntu-24.04          # ~3-5 min, includes auto-reboot
# After reboot, Ubuntu launches automatically — set username/password (~30s)
```

Then inside the new Ubuntu shell:

```bash
sudo apt update && sudo apt install -y git build-essential   # ~2 min
# Repo needs Go 1.25.8; Ubuntu 24.04 apt ships Go 1.22 — install upstream:
wget https://go.dev/dl/go1.25.8.linux-amd64.tar.gz
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf go1.25.8.linux-amd64.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc && source ~/.bashrc
git clone https://github.com/Sundeepg98/kite-mcp-server.git ~/projects/kite-mcp-server
cd ~/projects/kite-mcp-server && go test ./... -count=1   # ~5-10 min full suite
```

**End-to-end time: ~25-35 min wall, ~10 min active.**

### kite-mcp test compatibility — full audit

Audited every Windows-conditional in production tests (excluded `.claude/worktrees/` agent copies). Result: **zero blockers**, multiple wins. Confirms orchestrator's pre-finding: all branches are Linux-aware, no `t.Skip()` for non-Windows.

| Location | Pattern | WSL2 effect |
|---|---|---|
| `main_test.go:97/128/154` | `if windows { binary += ".exe" }` | Portable — wraps filename suffix only, no-op on Linux. |
| `kc/riskguard/subprocess_check_test.go:59` | `if windows { Skip("chmod semantics") }` | **Skipped on Win, runs on Linux.** Coverage WIN. |
| `kc/riskguard/subprocess_check_test.go:288` | `if windows { out += ".exe" }` | Filename suffix; portable. |
| `kc/riskguard/subprocess_check_test.go:320` | `signPluginForSAC: if !windows { return }` | **HELPER function returning early on Linux** — not a `t.Skip`. Calling tests still execute. SAC signing problem just **disappears**. |
| `app/ratelimit_reload_test.go:84` | `if PathSeparator == '\\' { Skip("SIGHUP") }` | **Skipped on Win, runs on Linux.** Coverage WIN. |
| `app/graceful_restart_unix.go` | `//go:build !windows` | Compiles + runs only on Linux. |
| `app/graceful_restart_windows.go` | `//go:build windows` | Stub on Win. |
| `app/graceful_restart_integration_test.go:1` | `//go:build !windows && integration` | **Linux-only test.** Currently NEVER runs on Win box. WSL2 unlocks it. |
| `ratelimit_test.go:651/667/687/709` | literal `"/tmp/test.db"` | Pure string equality assertions — file never opened. Passes on both. |

**Direct response to orchestrator's "verify the inverse direction" question:** the only `runtime.GOOS != "windows"` branch is in `signPluginForSAC` (line 320). It's not a test-skip — it's a Windows-only helper that gracefully no-ops on Linux. **No Linux-skipping tests exist in the codebase.** Therefore Windows-only test coverage that gets lost in WSL2 = **zero tests**.

Plus: SQLite uses `modernc.org/sqlite` (pure Go, no cgo). **No native toolchain dependencies.** `go test` Just Works in WSL2.

**Net coverage on Linux > Windows for THIS codebase:** unlocks `graceful_restart_integration_test.go`, `TestSubprocessCheck_StaleExecutableFallback` (chmod), and `TestStartRateLimitReloadLoop_SIGHUPUpdatesLimits`. **Three tests gained, zero lost.**

### Dev workflow tradeoffs

- **Source of truth: `~/projects/kite-mcp-server` inside WSL2** (Linux ext4, fast). NOT `/mnt/d/Sundeep/...` — the 9P bridge is 10-100x slower for Go's many-small-file workload (`go test ./...` over `/mnt/d/` can take 4-5x longer per run).
- **Editor (Windows-side Claude Code) reads via `\\wsl$\Ubuntu-24.04\home\<user>\projects\kite-mcp-server`** — that path is 100% read/write capable from Windows tooling, just slow for bulk operations. Or run a separate Claude Code instance inside WSL2 directly for max speed.
- **Git:** clone fresh inside WSL2 as shown. Push from WSL2 normally — gh CLI works there too (`sudo apt install gh`). Don't shuttle files between Windows checkout and WSL2 checkout.
- **File watch:** native ext4 watch is normal; cross-FS watching from Windows-side editors via `\\wsl$\` works but laggy. Keep the editor inside WSL2 if file-watch latency matters.
- **Per-run speed:** `go test ./...` on ext4 inside WSL2 is roughly **same speed as Windows native** (no SAC overhead, no signing, no flake). The 30-50% retry loss on Windows native is gone — WSL2 hits 100% pass rate deterministically.

### Cost / ranking matrix

| Dimension | WSL2 | Certum OS |
|---|---|---|
| Cost yr1 | **$0** | €104 (~₹9,400) |
| Cost yr2+ | **$0** | €29 (~₹2,600) / yr |
| Setup time | **~30 min** | 3-5 business days |
| KYC required | **No** | Yes (IDnow + utility bill + GitHub URL) |
| Hardware logistics | **None** | Smartcard + reader; DHL India transit |
| Runs Win-native go test deterministically | No (still flaky) | **Yes (100%)** |
| Signs Windows release binaries | No (no Windows binaries in this project) | Yes |
| Compatibility loss | **Zero** (audit complete; gains 3 tests) | n/a (stays on Win) |
| Disk footprint | ~3 GB Ubuntu image + repo clone | None |

### Final ranking

**WSL2 wins for kite-mcp-server.** Three reinforcing reasons:

1. **No Windows release artifact exists.** Production = `flyctl deploy -a kite-mcp-server` → Linux Docker on Fly.io. Local Windows test binaries are throwaway; the Certum cert would sign artifacts that never ship.
2. **Compatibility audit clean.** Every Windows-conditional in the codebase is either a portable filename wrap or an explicit `Skip` that becomes a real test on Linux. **Linux unlocks 3 tests Windows currently misses** — strict coverage gain. The lone `!= "windows"` branch is a helper no-op, not a test skip — zero Linux-skipping tests.
3. **$0 + 30 min beats ₹9,400 + 5 days** when both endpoints reach the same goal (`go test ./...` deterministic).

**The runbook's Option 3 ("WSL2 for heavy work") was actually under-stated** — it's not just for heavy work, it's the dominant default. Certum's only advantage (signing Windows release binaries) is irrelevant here.

### Recommended Windows-side workflow after WSL2 adoption

- Keep `scripts/go-test-sac.cmd` + GoTools self-signed cert as-is for the rare case the user wants to verify a binary on Win-native (e.g. installer smoke). Document accept-flake behavior.
- Move primary `go test ./...` to WSL2.
- Drop the Certum order from priority. Re-evaluate only if/when the project ships a signed Windows installer.

### Caveats / limitations

- WSL2 needs ~3 GB free disk (Ubuntu image) and ~2 GB RAM at peak `go test -race`. Trivial on a modern dev box.
- Hyper-V / Virtual Machine Platform must be on. Modern Win 11 has these by default; older boxes may need `wsl --install` to enable both.
- Some Windows-only debuggers (Delve via VS Code Windows-side) need `dlv` running inside WSL2 too, with VS Code Remote-WSL extension. Standard pattern, well-documented.
- `gh` CLI auth state is per-WSL2-instance, not shared with Windows. One-time `gh auth login` inside the Ubuntu shell.
- If the user later DOES need Windows binary signing (e.g. shipping a `.exe` installer), revisit Certum then.
