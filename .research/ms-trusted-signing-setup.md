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
