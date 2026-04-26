# WSL2 setup runbook for kite-mcp-server

Concrete, step-by-step procedure to get `go test ./...` running deterministically
on this dev box without Smart App Control flake. Companion to
[`.research/ms-trusted-signing-setup.md`](../.research/ms-trusted-signing-setup.md)
Appendix D, which explains *why* WSL2 dominates the Certum / Trusted Signing
alternatives for this codebase.

**Estimated total time: ~30 min wall, ~10 min active.** The bulk is `wsl --install`
download + reboot + first-launch Linux init.

## Pre-flight

Detected on this machine 2026-04-26:

- Windows 11 Home Single Language, version 25H2 (build 26200.8246) — `wsl --install` supported.
- `wsl --status` returns "WSL is not installed" — fresh install path.
- HEAD on master: `10191aa`.

If a future operator finds `wsl --status` reports an existing distro, **skip Phase 2**
and jump to Phase 3 (workspace setup).

---

## Phase 1 — autonomous prep (DONE)

Everything an agent could do without user interaction has been completed:

- WSL state probed (not installed).
- This runbook authored.
- Compatibility audit verified zero Windows-specific test blockers.
  See `.research/ms-trusted-signing-setup.md` Appendix D.

---

## Phase 2 — USER STEPS (interactive, requires elevation + reboot)

### USER STEP 2.1 — open elevated PowerShell

Right-click Start → **Windows PowerShell (Admin)** or **Terminal (Admin)** →
accept the UAC prompt.

### USER STEP 2.2 — run install (one command)

```powershell
wsl --install -d Ubuntu-24.04
```

This single command:
1. Enables `Microsoft-Windows-Subsystem-Linux` Windows feature.
2. Enables `VirtualMachinePlatform` Windows feature.
3. Sets the default WSL version to 2.
4. Downloads the WSL kernel + Ubuntu 24.04 distro image (~600 MB; takes 2–5 min).
5. Schedules the install to finish on next reboot.

**Expected output ends with: "The requested operation is successful. Changes will not
be effective until the system is rebooted."**

If this is a corporate-managed device and Group Policy blocks
`Microsoft-Windows-Subsystem-Linux`, the command fails. In that case, stop and
contact IT — there is no workaround at the user level.

### USER STEP 2.3 — reboot

```powershell
Restart-Computer
```

(Or use Start → Power → Restart.) **Required** — virtualization features only attach to
the running kernel after reboot.

### USER STEP 2.4 — first Ubuntu launch (sets Linux user)

After reboot, the Ubuntu installer auto-launches in a new console window. If it
doesn't, open Start → type `Ubuntu` → click the Ubuntu 24.04 tile.

You'll be prompted for:
- **Linux username** — pick a short lowercase identifier (e.g. `dell` or `sg`); does
  NOT need to match your Windows username.
- **Linux password** — any password; you'll need it for `sudo`. **Not** Windows-tied;
  WSL2 has no SSO with Windows.

When you see the bash prompt `<username>@<hostname>:~$`, Phase 2 is done.

### USER STEP 2.5 — confirm to the agent

Tell the agent: **"WSL2 is up, username is `<username>`."**

The agent will then resume Phase 3 over your shoulder by issuing commands you
run inside the Ubuntu shell, OR will guide you through pasting them yourself.

---

## Phase 3 — workspace setup (run inside Ubuntu shell)

### Step 3.1 — apt baseline

```bash
sudo apt update && sudo apt install -y git build-essential ca-certificates curl
```

`build-essential` pulls gcc/make for any future cgo, even though kite-mcp-server
is currently pure Go. ~2 min.

### Step 3.2 — install Go 1.25.8 (repo requires this exact major.minor)

Ubuntu 24.04 apt ships Go 1.22 — too old. Install upstream:

```bash
GO_VERSION=1.25.8
wget -q https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz -O /tmp/go.tar.gz
sudo rm -rf /usr/local/go
sudo tar -C /usr/local -xzf /tmp/go.tar.gz
echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
echo 'export PATH=$PATH:$HOME/go/bin' >> ~/.bashrc
source ~/.bashrc
go version  # → expect: go version go1.25.8 linux/amd64
```

### Step 3.3 — clone repo into Linux native filesystem (NOT `/mnt/d/`)

```bash
mkdir -p ~/projects
cd ~/projects
git clone https://github.com/Sundeepg98/kite-mcp-server.git
cd kite-mcp-server
git status
```

**Why `~/projects` and not `/mnt/d/Sundeep/projects`:** the `/mnt/` path is the
9P-bridge mount of your Windows D: drive. Reads/writes cross the kernel
boundary on every syscall — Go's many-small-file workload (each `go test`
package = dozens of stat/open/read calls) runs **10–100× slower** there. ext4
inside WSL2 is native-speed.

If you need to share files with Windows tools (e.g. open this Linux clone from
a Windows-side editor), browse to `\\wsl$\Ubuntu-24.04\home\<username>\projects\kite-mcp-server`
in File Explorer. Read/write works; just don't run `go test` over it.

### Step 3.4 — sanity-check build

```bash
cd ~/projects/kite-mcp-server
go build ./...
```

First run: ~2–5 min (downloads modules, compiles deps). If it fails for a
non-obvious reason, capture the error and report.

### Step 3.5 — sanity-check small test package

```bash
go test ./kc/billing/... -count=1
```

Expected: `ok` lines, exit 0, < 10 seconds. The `kc/billing` package is small
and self-contained — a clean PASS here means the env is wired.

### Step 3.6 — full suite (optional confidence check)

```bash
go test ./... -count=1 2>&1 | tee /tmp/wsl2-first-run.log
```

Expected: full PASS in 5–10 min. The test count should match (or slightly
exceed) what you saw on Windows — see Appendix D for the three Linux-only
tests that get unlocked.

---

## Phase 4 — daily workflow

### Run tests in WSL2

From the Ubuntu shell:

```bash
cd ~/projects/kite-mcp-server
go test ./... -count=1
```

No SAC, no signing wrapper, no flake. Deterministic.

### Edit from Windows-side editors (optional)

Open `\\wsl$\Ubuntu-24.04\home\<username>\projects\kite-mcp-server` in your editor.
Reads/writes work; file-watching across the bridge is laggy. For tight inner-loop
work, run the editor inside WSL2 (`code .` from the Ubuntu shell launches VS Code
with the Remote-WSL extension; the same trick works for any IDE that has a Remote
extension).

### Git operations

`git push`, `gh pr create`, etc. all work from inside WSL2. One-time setup:

```bash
sudo apt install -y gh
gh auth login        # interactive — pick GitHub.com → HTTPS → web flow
git config --global user.name "Sundeep"
git config --global user.email "<your commit email>"
```

Note: `gh` auth state is per-WSL2-instance, not shared with Windows-side `gh`.
You'll authenticate once inside WSL2; thereafter persisted.

### When to still use Windows-side `go test`

- Smoke-checking a Windows `.exe` artifact (rare — kite-mcp-server has none).
- Reproducing a SAC-specific bug you can't reproduce in Linux.

For everything else, default to WSL2.

---

## Rollback / uninstall

If WSL2 turns out to be a poor fit:

```powershell
# As admin PowerShell:
wsl --unregister Ubuntu-24.04   # delete the distro and its filesystem (~3 GB)
wsl --uninstall                 # remove the WSL platform itself
# Optionally also disable the Windows features:
Disable-WindowsOptionalFeature -Online -FeatureName VirtualMachinePlatform -NoRestart
Disable-WindowsOptionalFeature -Online -FeatureName Microsoft-Windows-Subsystem-Linux -NoRestart
Restart-Computer
```

Your Windows-side `scripts/go-test-sac.cmd` + GoTools self-signed cert keep
working untouched throughout — WSL2 is purely additive.

---

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| `wsl --install` fails with "feature not present" | Group Policy blocks WSL on managed device | Contact IT; no user workaround |
| `wsl --install` fails with "virtualization not enabled in BIOS" | VT-x / SVM disabled in firmware | Reboot into BIOS/UEFI, enable Intel VT-x or AMD-V, save, reboot |
| `go test` is glacially slow inside WSL2 | Repo cloned under `/mnt/d/...`, not `~/projects/...` | Re-clone into `~/projects/kite-mcp-server` (Linux ext4) |
| `gh auth login` web flow times out | Browser-side popup blocker | Use device-code flow: `gh auth login --web=false` and copy URL manually |
| Out of memory during `go test -race` | WSL2 default 50% RAM cap | Create `%USERPROFILE%\.wslconfig` with `[wsl2]\nmemory=8GB` and `wsl --shutdown` |

## Phase 5 — WSL2 gopls LSP route (durable SAC bypass)

After Phase 4 is established, route Claude Code's Go LSP through WSL2 gopls
instead of Windows-side `gopls.exe`. This ELIMINATES the recurring SAC block on
gopls — durable fix, no signing required. Self-signed Authenticode is
ISG-dependent (50-70% pass per `docs/sac-runbook.md`); this path is 100%
deterministic because SAC doesn't see the WSL2 binary at all.

### What was set up (already done by agent for this user, 2026-04-26)

- `gopls v0.21.1` installed in WSL2 at `/root/go/bin/gopls` (via
  `wsl -d Ubuntu -u root /usr/local/go/bin/go install golang.org/x/tools/gopls@latest`).
- `~/.claude/cclsp.json` Go entry rewritten to spawn the WSL2 binary:
  - **Before:** `["cmd.exe", "/c", "C:\\Users\\Dell\\go\\bin\\gopls.exe"]`
  - **After:**  `["wsl.exe", "-d", "Ubuntu", "-u", "root", "/root/go/bin/gopls"]`
- Backup: `~/.claude/cclsp.json.bak-pre-wsl2` (one-line revert if anything goes
  wrong: `Copy-Item -Force ~/.claude/cclsp.json.bak-pre-wsl2 ~/.claude/cclsp.json`).
- Smoke test from Windows PowerShell `wsl.exe -d Ubuntu -u root /root/go/bin/gopls
  version` returned `golang.org/x/tools/gopls v0.21.1` exit 0 — wrapper route
  confirmed working.

### USER STEP 5.1 — restart Claude Code

Close Claude Code entirely (not just the window — exit the process via the
system tray icon if present) and relaunch. The next time it edits a `.go` file,
cclsp will spawn `wsl.exe ... gopls` instead of the Windows-side `gopls.exe`.
SAC will not see a Windows process trying to launch — it sees `wsl.exe` (a
trusted Microsoft binary) starting; the gopls process runs entirely inside the
Linux VM where SAC has no jurisdiction.

### USER STEP 5.2 — wait for LSP to initialize

First spawn after restart: 2-5 seconds (cold cclsp + first cross-FS read).
Subsequent edits: typically same-as-Windows responsiveness (~100-300ms hover).

### USER STEP 5.3 — test by hovering a Go symbol

Open any `.go` file from this repo (e.g.
`D:\Sundeep\projects\kite-mcp-server\app\app.go`), hover over a function name.
Expect tooltip with type signature and doc comment. If you see one, gopls is
talking to Claude Code through the WSL2 wrapper — durable fix is live.

### USER STEP 5.4 — revert if broken

If gopls goes silent or Claude Code reports LSP errors:

```powershell
Copy-Item -Force "$env:USERPROFILE\.claude\cclsp.json.bak-pre-wsl2" "$env:USERPROFILE\.claude\cclsp.json"
# Restart Claude Code; you're back to the Windows-side gopls + signing path.
```

### USER STEP 5.5 — latency tradeoff (informational)

Reading source files for the LSP crosses the `\\wsl$\` 9P bridge if your
project tree lives on Windows-side (`D:\Sundeep\projects\kite-mcp-server`) and
cross-FS reads are 50-200ms slower per request than native ext4. For solo dev
this is unnoticeable. If hover/completion feels sluggish during heavy
multi-file analysis, the optimum is to clone the repo inside WSL2 home (per
Phase 3 step 3.3) and edit there — but that requires moving your editor
inside WSL2 too. Current setup edits Windows-side, gopls reads cross-FS — fine
for routine work.

### Why this is the durable fix

| Path | SAC sees | Determinism |
|---|---|---|
| Windows `gopls.exe` + self-signed cert | Untrusted hash; ISG roulette | 50-70% pass |
| Windows `gopls.exe` + Microsoft Trusted Signing cert | MS-trusted root | 100% — but paid + India-blocked |
| **WSL2 `/root/go/bin/gopls` via wsl.exe wrapper** | Only sees `wsl.exe` (Microsoft-signed, Trusted) | **100% — no cert needed** |

`wsl.exe` is signed by Microsoft and lives in `C:\Windows\System32\` — it's an
inherently trusted launcher. Whatever Linux process it spawns is opaque to SAC.
That's why this path is deterministic without any code-signing infrastructure.

---

## See also

- [`.research/ms-trusted-signing-setup.md`](../.research/ms-trusted-signing-setup.md) Appendix D — full WSL2 vs Certum analysis + compatibility audit.
- [`docs/sac-runbook.md`](sac-runbook.md) — Windows-side fallback (kept as-is).
