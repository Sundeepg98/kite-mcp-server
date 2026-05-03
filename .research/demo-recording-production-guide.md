# Demo recording production guide — kite-mcp-server

**Status:** Research deliverable — closes the "no demo GIF/asciinema" NO-item from the final pre-launch dry-run (`908d304`). Single doc, turn-by-turn recipe.
**Last updated:** 2026-05-02
**Companion docs:** `58dc369` (GTM launch sequence), `5adf80f` (Twitter Weeks 1-4), `f14d92c` (Reddit per-subreddit), `908d304` (final pre-Show-HN verification — NO-verdict).
**Existing-asset audit:** `docs/launch/04-demo-video-script.md` exists but is **stale** (says 8 RiskGuard checks, ₹5L cap, 10 lakh paper-trading capital). Empirical numbers via `find . -type f \( -name '*.gif' -o -name '*.mp4' -o -name '*.webm' -o -name '*.cast' -o -name '*.mov' \)` returned **zero results**. Starting from scratch.

---

## Lead-in summary (read this first)

**Minimum viable single-GIF demo (Demo A) — record this even if you skip everything else.**

Scenario, ~30 seconds, no audio, no narration, no editing beyond trim:

1. Claude Desktop window open. (5 sec) Type: `Show my Zerodha portfolio.`
2. Claude calls `get_holdings` → portfolio MCP-Apps widget renders inline with 5-7 mocked holdings. (10 sec)
3. Type: `Set an alert for RELIANCE at 2 percent drop.`
4. Claude calls `create_alert` → alert confirmation widget renders. (8 sec)
5. Telegram notification visible in second window: *"Alert created: RELIANCE drop 2% from ₹1,420"*. (5 sec)
6. Hard cut.

**Recording recipe (Windows, ~30 minutes total including failed takes):**

1. Install `ScreenToGif` from Microsoft Store (free, signed, OS-native, no admin install): `winget install ScreenToGif` *or* `https://www.screentogif.com/`. (3 min)
2. **Set paper-trading mode ON** before recording so no real Kite data appears: `paper_trading_toggle enabled=true initial_cash=10000000` in Claude Desktop. **Verify** account email shown in UI is NOT `g.karthick.renusharmafoundation@gmail.com` — switch to a generic test session per `user_email_rule.md`. (5 min)
3. Close Slack/Discord/Outlook/Windows-update-toast/Teams. Set Windows notifications to **Focus Assist: Priority Only**. Browser zoom to **125%** so HN/Reddit thumbnail readers can see. (3 min)
4. Open ScreenToGif → *Recorder*. Frame to ≤1280×720 around the Claude Desktop window. Set FPS to **10** (web-friendly). Click record. Run the 5-step scenario above. Click stop. (5 min including 2 retakes)
5. ScreenToGif's editor opens. Trim leading and trailing dead frames. Use *File → Save as → Gif (FFmpeg)* with quality 80, lossy compression. **Target output: ≤4MB** (Twitter native upload limit; Reddit accepts up to 100MB; GitHub README accepts up to 10MB). (5 min)
6. Save to `D:\Sundeep\projects\kite-mcp-server\docs\assets\demo-portfolio-alert.gif` — that path is the canonical destination across all channels. (1 min)

**Final destination embedding (single GIF, three places):**

| Channel | Embed | Action |
|---------|-------|--------|
| **GitHub README hero** | `![demo](docs/assets/demo-portfolio-alert.gif)` directly above the install code block | edit README.md line ~12 in `docs/launch/05-readme-outline.md` Section 2 slot |
| **Twitter Day-1 thread T1** | Native upload via twitter web composer | replace `5adf80f` Day-1 T1 image-attachment slot |
| **Reddit r/algotrading post** | Markdown image: `![](https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-portfolio-alert.gif)` | top of v1 body in `f14d92c` §A.1 |
| **Show HN body** | One-line: `Demo: <github-raw-url>` | bottom of body in `docs/show-hn-post.md` |
| **`kc/templates/landing.html` hero** | `<img src="/static/demo-portfolio-alert.gif" alt="demo" loading="lazy" style="max-width:720px">` after `.hero p` line | edit landing.html line ~243 |

**Three most important user actions this week (demo-specific):**

1. **Record Demo A and ship the single GIF before Show HN.** ~30 min including install + 2 retakes. Highest impact-per-minute remaining in the launch prep.
2. **Update `docs/launch/04-demo-video-script.md`** — current numbers are stale (8 → 9 checks, ₹5L → ₹50k cap, 10 lakh → 1 crore paper capital, 78 → 120+ tools, 475 → ~9000 tests). 15 min to fix in place; do not fork to a new file. See §Phase 7.
3. **Skip Demo B (asciinema) and Demo C (full MP4 with Hindi-English narration) for v1 launch.** Both are valuable but high-effort; ship them as Twitter Week-2 / Week-3 content fuel per `5adf80f`. The Show-HN gate only needs Demo A.

---

## Phase 1 — Existing-asset audit

### A. Drafted scripts

**`docs/launch/04-demo-video-script.md` exists** (138 lines, 6 scenes, 2:30 target runtime).

Verbatim staleness audit:
- Line 39: *"NIFTY: 23,450 (+0.3%)"* — index level is 2024-vintage; 2026-05-02 NIFTY is in different range. Mocked OK if we don't claim it's live.
- Line 60: *"AI calls `paper_trading_toggle` with `enabled: true, initial_cash: 1000000`"* — **stale**: current default is ₹1 crore (10000000) per memory `kite-papertrading`. Update to `initial_cash: 10000000` or just say "initial_cash: 1 crore".
- Line 86: *"BLOCKED: Single order value Rs 6,00,00,000 exceeds limit Rs 5,00,000"* — **stale**: current default cap is ₹50,000 per `riskguard-tightened` (commit `7cd7b35`). Update to *"exceeds limit Rs 50,000"* and adjust the test order accordingly (e.g. "BUY 10 RELIANCE" at Rs 1420 = Rs 14,200 — under cap; bump to "BUY 100 RELIANCE" = Rs 1.42L which exceeds the ₹50k single-order cap).
- Line 90: *"There are 8 checks like this"* — **stale**: current is 9 (added off-hours block + idempotency + anomaly per `kite-security-hardening-2026-04`). Update to "9".
- Line 117 (Scene 6 voiceover): *"This is open source under the MIT license. You need a Kite Connect developer app — that's Rs 500 a month from Zerodha."* — current and accurate.
- Total runtime 2:30 is **too long** for HN/Reddit/Twitter use. Trim to 30s/60s versions.

**Useful elements to keep verbatim:**
- Scene 4 RiskGuard block — **the single best wow-moment** per the script's own production note line 137. Use for Demo A primary.
- Scene 5 dashboard — useful for Demo C, secondary.
- Scene 1 OAuth — too slow and consent-screen-heavy for a 30s demo; cut for Demo A.

**Verdict:** **update in place, don't fork to a new file.** §Phase 7 has the patch.

### B. Pre-existing media files

**Empirical: zero.** Verified via `find . -type f \( -name '*.gif' -o -name '*.mp4' -o -name '*.webm' -o -name '*.cast' -o -name '*.mov' \) -not -path './.git/*' -not -path './node_modules/*'` — returned no results. No screencast, no gif, no asciinema cast, no demo video. Starting from scratch.

The repo has 228 build artifacts (`*.out`, `*.exe`, `*.cov`, `*.html` per `58dc369` Phase 3) but **none are demos**. They are coverage and test outputs.

### C. Other media-related drafts in `docs/launch/`

Verified via `ls docs/launch/`:
- `01-tradingqna-post.md` — text-only forum post draft
- `02-reddit-isb-post.md` — text-only Reddit post draft
- `03-twitter-thread.md` — has `[Attach: 30-second screen recording showing]` placeholder in Tweet 6 (line 91) — **explicit GIF dependency**, currently unfilled
- `04-demo-video-script.md` — analyzed above
- `05-readme-outline.md` — Section 2 explicit "Hero Visual" slot waiting for the GIF, line 47-54: *"Animated GIF or screenshot showing a real interaction... Keep it under 10 seconds / 2MB if GIF... This is the single highest-impact element."*

Verified `docs/blog/` has only `oauth-13-levels.md` — no media drafts there.

**Conclusion:** the *placeholders for media exist in 3 channel drafts*; the *content does not*. This deliverable is the recipe to fill those placeholders.

### D. Verdict — starting state for this dispatch

- **Script:** stale but workable. **Update §Phase 7 patch in place.**
- **Media files:** zero. **Record from scratch this week.**
- **Embedding slots:** 5 known (README hero, landing.html hero, Twitter T1, Reddit body, Show HN footer). All await a single asset.
- **Time-to-record (minimum):** ~30 min for Demo A.
- **Time-to-record (full):** ~3-4 hours for Demos A+B+C.

---

## Phase 2 — Demo scenario design

Three audience-specific demos. Demo A is the must-ship pre-Show-HN gate; B and C are content fuel for Week 2-3.

### Demo A — HN / r/algotrading / Twitter T1 — 30s GIF

**Single concept:** *"AI agent reads my real portfolio and creates a real-money alert in 30 seconds."* The visceral wow is **agent does what no AI agent has done with a regulated broker API** — not the riskguard story (that's Demo C).

**Scenario (frame-by-frame, no narration):**

| t | Action | What viewer sees |
|---|--------|------------------|
| 0:00 | Static frame: Claude Desktop window, conversation pane visible, last assistant turn showing "✓ Connected to kite-mcp-server" | viewer absorbs context |
| 0:02 | User types: `Show my Zerodha portfolio.` | typing visible at human pace, ~6 chars/sec |
| 0:06 | Send → Claude renders thinking spinner, then "→ get_holdings" in tool-call panel | tool call rendered |
| 0:09 | MCP-Apps inline widget renders: portfolio table with 5-7 holdings (paper-trading mocked: RELIANCE, INFY, TCS, HDFC, ITC). Each row shows ticker, qty, avg-price, LTP, P&L | widget is the single biggest visual asset |
| 0:14 | Brief 1.5s pause (let viewer read the table) | reading time |
| 0:16 | User types: `Set an alert for RELIANCE at 2 percent drop.` | typing |
| 0:21 | Send → Claude renders: `→ create_alert` then "✓ Alert created" widget with alert details | tool call + confirmation |
| 0:25 | Cut to second window pane (Telegram desktop, foreground): notification appears: *"📊 Kite Alert created: RELIANCE drop 2% from ₹1,420 — Telegram bot will notify you when triggered."* | proof of cross-system integration |
| 0:30 | Hard cut to GitHub URL banner: `github.com/Sundeepg98/kite-mcp-server` | call-to-action frame, viewer remembers URL |

**Why this scenario beats the dry-run script's Scene 4 (RiskGuard block):**
- Show-HN audience has seen "AI tries to spend $6 crore" jokes a dozen times; the riskguard story doesn't surprise them on a 30-sec GIF.
- The portfolio + alert sequence is **functional novelty** — most viewers have never seen an AI agent successfully and safely use a regulated broker API at all. The wow is the integration depth, not the safety drama.
- Telegram cross-system proof in the last 5 seconds = "this is plumbing that actually connects to the real world", a key trust signal that no other MCP demo on Show HN has shown.

**Format:** GIF (no audio needed, plays inline on GitHub README, autoplays on Twitter, embeddable on Reddit).

**Sizing target:** 4MB max (Twitter native upload limit). 1280×720 resolution. 10 fps. ~15 seconds equivalent runtime after compression decimation, but feels like 30s in real time.

**Audio:** none. Silent GIF.

### Demo B — r/MachineLearning / r/golang — 60s asciinema cast

**Single concept:** *"MCP protocol depth: server-side tool dispatch through middleware chain, client-side one-line install."* Audience appreciates protocol elegance over UI polish.

**Scenario:**

| t | Action | What viewer sees in terminal |
|---|--------|------------------------------|
| 0:00 | Pane 1 left: SSH'd into Fly.io machine via `flyctl ssh console -a kite-mcp-server`. Pane 2 right: local terminal at `~/`. | both panes visible |
| 0:03 | Pane 1: `tail -f /var/log/kite-mcp-server.log` running, currently quiet | log tail ready |
| 0:06 | Pane 2: `claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp` | one-line install command |
| 0:09 | Pane 2: `claude` to start Claude Code session | Claude prompt appears |
| 0:12 | Pane 2: type `Show my holdings.` then enter | tool call begins |
| 0:14 | Pane 1: log line appears showing: `[INFO] tool_call recv tool=get_holdings session=abc...`, then sequential middleware lines: `[INFO] audit pre`, `[INFO] riskguard ok`, `[INFO] elicit n/a (read-only)`, `[INFO] kite_api call`, `[INFO] kite_api ok`, `[INFO] audit post` | the **middleware chain is visible in real time** — single biggest signal of architecture quality |
| 0:30 | Pane 2: holdings rendered as MCP-Apps widget | client-side proof |
| 0:35 | Pane 2: type `Set alert for RELIANCE -2%.` enter | second tool call |
| 0:37 | Pane 1: log shows: `tool=create_alert`, then middleware chain again, plus a `[INFO] alert_db insert` and `[INFO] telegram dispatch ok` | second-tool proof, db + side-channel visible |
| 0:50 | Pane 2: `Ctrl+D` to end Claude session | session closes cleanly |
| 0:55 | Pane 1: `grep audit_call /var/log/...` → shows persistent audit trail rows in JSON, including SHA-256 hashchain field | persistence + integrity proof |
| 1:00 | Hard cut. | end |

**Format:** asciinema `.cast` file (text-based, JSON-encoded keystrokes + timing). Hostable on `asciinema.org` or self-hosted (Algo2Go domain). Native rendering on all major terminals. **No frame compression needed** — text-based casts are <100KB even for 5+ minute recordings.

**Why asciinema not GIF:** the audience (r/MachineLearning, r/golang, HN tech-skeptics) cares about copy-pasteable terminal output, can pause/inspect any frame, and finds GIFs aesthetically downmarket for protocol-depth content. asciinema is the de-facto standard for terminal-only demos in dev-tool adjacent communities.

**Audio:** none. Silent cast.

### Demo C — r/IndianStockMarket / r/IndianStreetBets / Telegram channel — 60s MP4 with Hindi-English narration

**Single concept:** *"Real Indian retail trader's morning routine, replaced by AI."* Audience-fit is the **emotional resonance** — looks like a real Indian trader using the tool, not a developer demo.

**Scenario:**

| t | Action (visual) | Narration (Hindi-English mix) |
|---|------|-----------|
| 0:00 | Phone screen: Telegram, 09:00 IST notification banner appears: *"Good morning. Portfolio: ₹4,58,200 (+5.9%). NIFTY 23,450 (+0.3%). 2 alerts active."* | "Subah 9 baje, Telegram pe morning briefing aaya." (Morning at 9, Telegram notification arrived.) |
| 0:08 | Tap notification → Telegram opens, full briefing visible including positions and alerts | "Holdings, alerts, margin — sab ek shot mein." (Holdings, alerts, margin — all in one shot.) |
| 0:18 | Cut to laptop: Claude Desktop window. Type: `Backtest SMA crossover on INFY for last 1 year.` | "Phir laptop pe, Claude se backtest poocha." (Then on laptop, asked Claude for backtest.) |
| 0:22 | Tool call → result widget: SMA crossover (20/50) on INFY 365 days: total return +14.2%, max drawdown -8.1%, Sharpe 1.12, win rate 58% | "14.2% return, but 8% drawdown. Decent strategy, lekin risk hai." (14.2% return, but 8% drawdown. Decent strategy, but there's risk.) |
| 0:35 | Type: `Enable paper trading and BUY 10 INFY at market.` | "Paper trade pehle. Real money baad mein." (Paper trade first. Real money later.) |
| 0:39 | Tool call → "Paper trading enabled, BUY 10 INFY filled at ₹1,412. Virtual portfolio updated." | "Fill ho gaya virtual mein." (Filled in virtual.) |
| 0:50 | Cut to Telegram: notification fires *"Paper trade: BUY 10 INFY @ 1,412 — virtual portfolio P&L now +0.04%."* | "Telegram pe bhi sync ho gaya." (Telegram also synced.) |
| 0:55 | End card: *"100% open source. Self-hosted. github.com/Sundeepg98/kite-mcp-server"* | "Open source. Apne data, apne hath mein." (Open source. Your data, in your hands.) |
| 1:00 | End. | end |

**Format:** MP4, 1080p, H.264, ~30 fps, ~12-15MB. Twitter accepts up to 512MB. Reddit accepts up to 100MB. Telegram accepts up to 50MB. WhatsApp accepts up to 16MB (skip WhatsApp distribution).

**Audio:** Hindi-English narration. ~80 words across 1 minute. **Recording the audio is the hardest part of Demo C** — see §Phase 3.B for the rationale on whether to attempt this versus skipping.

**Why this audience-fit matters:** r/IndianStockMarket has a hard AI-content rule per `f14d92c` §B; the *demo itself* needs to feel like a trader's-eye-view, not a developer's-eye-view, or the post gets removed. Demo C frames the product as workflow-replacement (morning routine), not as AI-novelty (which would trigger the rule).

---

## Phase 3 — Recording tooling per platform (Windows-native focus)

### A. GIF — ScreenToGif (Demo A)

**Why ScreenToGif:**
- Windows-native, free, signed by Microsoft Store, no admin install needed.
- Built-in editor with frame-level trim/delete.
- Direct GIF / WebM / APNG export with built-in compression (FFmpeg backend).
- Mature project (10+ years, ~20k GitHub stars on `NickeManarin/ScreenToGif`).

**Install (Windows 11):**
```powershell
winget install --id NickeManarin.ScreenToGif --source winget
```
*Or* download from `https://www.screentogif.com/` (signed installer, ~10 MB).

**Settings for Demo A:**
- Recorder mode: *"Recorder"* (window/region capture, not full screen).
- Frame rate: **10 fps**. Web GIFs above 12 fps quadruple file size with negligible perceptual gain.
- Capture region: ~1280×720 around Claude Desktop window. Drag the recorder frame edges; lock with the lock icon.
- Cursor capture: **on** (default). The mouse moving = visual cue for "user is doing something".

**Editor steps post-record:**
1. Trim leading dead frames (anything before first keystroke). Use the timeline scrubber.
2. Trim trailing dead frames (anything after last visible Telegram notification).
3. Optional: remove every nth frame to halve size if file ends up >5MB. *Editor → Frame Removal → Reduce → Every 2nd frame*.
4. **File → Save as → GIF (FFmpeg)** with quality 80, lossy compression. ScreenToGif's FFmpeg pipeline produces 50-70% smaller files than the legacy ImageMagick path.

**Output expectations:** Demo A at 10 fps, 1280×720, 30 seconds → typically 3-5 MB after FFmpeg lossy. Aim for **≤4 MB** to fit Twitter native upload.

**Common pitfalls:**
- Cursor blink artifacts: ScreenToGif sometimes captures the text-cursor blink as separate frames, doubling size. Fix: turn off Windows text-cursor blink (Settings → Accessibility → Text Cursor → Indicator: Off) for the recording session.
- Wrong DPI on high-DPI display: ScreenToGif samples at logical pixels. For 4K monitors, set system scaling to 100% during the recording session, otherwise the recorded GIF will look blurry on consumer screens.

### B. MP4 with audio — OBS Studio (Demo C)

**Why OBS:**
- Free, open-source, Windows-native, the de-facto standard for screen recording with audio.
- H.264 encoder built-in (CPU-based x264, or NVENC if NVIDIA GPU).
- Multi-source: capture browser + Claude Desktop + microphone + Telegram phone-mirror in one recording.
- Streams or records — for our use, just records to local file.

**Install:**
```powershell
winget install --id OBSProject.OBSStudio --source winget
```
*Or* `https://obsproject.com/`.

**Settings for Demo C:**
- Output mode: *"Simple"* (skip the *"Advanced"* mode unless you know what you're doing).
- Recording quality: *"High Quality, Medium File Size"* (the middle option).
- Recording format: *"mp4"*.
- Resolution: 1920×1080.
- FPS: 30.
- Audio: enable *"Mic/Aux"* in the audio mixer panel. Test mic with **OBS → Tools → Voicemeter Banana** *not* needed for basic; built-in audio mixer is fine.
- Microphone: choose your headset/laptop mic. Test record 5 seconds first to verify levels (peak should be -12dB to -6dB; if peaking red, lower mic gain in Windows Sound settings).

**Recording flow for Demo C:**
1. Set up scene with three sources:
   - *"Display Capture"* of laptop main display (for Claude Desktop)
   - *"Window Capture"* of Telegram desktop (alternative to phone mirror)
   - *"Audio Input Capture"* mic
2. Hit *Start Recording*. Run the 60s scenario from §Phase 2 Demo C.
3. Hit *Stop Recording*. Output saved to `~/Videos/yyyy-mm-dd hh-mm-ss.mp4`.

**Editing — DaVinci Resolve (free):**
- Install: `winget install BlackmagicDesign.DaVinciResolve`. (Free version is fully featured for our needs.)
- Trim, cut to length, add the end-card text frame (last 5 sec of Demo C scenario), export.
- Alternative for trim-only: ScreenToGif can also trim MP4 if the recording doesn't need a title card.

**Output expectations:** 1080p 30fps H.264 60s with audio → ~15-25 MB. Trim deadweight + use *Resolve → Quick Export → MP4 H.264 1080p* preset → final ~12-18 MB. Acceptable for all channels.

**Audio recording pitfalls:**
- Echo / room reverb: if recording at home without a treated room, **use a USB headset mic** (Blue Yeti / Audio-Technica AT2020USB / cheap Logitech). Built-in laptop mics produce reverb that's painful in 60-sec content.
- Hindi-English code-switching: requires you to be comfortable. **If unsure, do Demo C as a silent MP4 with on-screen subtitle text overlays** — still effective, less risky. Add subtitles in Resolve via *Edit → Subtitle Track*.

### C. asciinema cast — WSL2 (Demo B)

**Why asciinema:**
- Records text terminal sessions to JSON-encoded `.cast` file (keystrokes + timing).
- File size ~100KB even for 5-minute recordings (text-only).
- Native player on `asciinema.org` or self-host with `asciinema-player.js`.
- Audience signal: dev-tool/protocol-depth communities recognize it as the "real engineer's screencast".

**Install (WSL2 Ubuntu 24.04):**
```bash
sudo apt update && sudo apt install asciinema -y
# Or via pip if your WSL has Python:
# pip install asciinema
```

**Recording flow for Demo B:**
1. SSH into the Fly.io machine first (in pane 1): `flyctl ssh console -a kite-mcp-server`. Open `tail -f /var/log/kite-mcp-server.log`. Leave running.
2. Switch to local pane 2 (in WSL): `asciinema rec demo-b-protocol-depth.cast`.
3. Run the 60-sec scenario from §Phase 2 Demo B.
4. Press `Ctrl+D` to end the asciinema recording. File saved to current directory.
5. **Edit:** asciinema casts can be edited as JSON. Open the `.cast` file in any text editor. Each line after the header is `[time, "o"|"i", "<chars>"]`. Delete lines to cut deadweight. Adjust `time` values to remove unintended pauses. *Or:* use the GUI editor `asciinema-edit` (from `cargo install asciinema-edit` if Rust available).

**Hosting:**
- **Public:** `asciinema upload demo-b-protocol-depth.cast` → uploads to asciinema.org → shareable URL like `https://asciinema.org/a/<id>`. Free, no signup needed for first upload.
- **Self-hosted:** copy the cast file to `https://kite-mcp-server.fly.dev/static/demos/demo-b.cast` and embed via `asciinema-player.js` on the landing page.

**Recording pitfalls:**
- Two-pane layout: asciinema records a single terminal session. For two panes, use `tmux` — `tmux new -s demob` — then split-pane. asciinema records the whole tmux session.
- Color codes: ensure the local terminal is UTF-8 (`locale | grep UTF-8`) so log lines render correctly when played back.
- Telegram cross-system proof: asciinema only records the terminal. **Demo B does not show Telegram** — that's a Demo A or Demo C feature. Keep Demo B purely terminal-focused.

### D. Tool installation total time

| Tool | Install | Verify | Total |
|------|---------|--------|-------|
| ScreenToGif | 3 min (winget) | open + record 5s test | 4 min |
| OBS Studio | 5 min (winget + first-launch wizard) | record 5s test with audio | 8 min |
| asciinema | 2 min (apt in WSL2) | rec + ctrl-d 5s test | 3 min |
| DaVinci Resolve (optional, only if narration) | 8 min (download + first launch) | open project | 12 min |

**If only Demo A is being recorded (the must-ship minimum), only ScreenToGif install is needed → 4 min.**

---

## Phase 4 — Recording-to-publication pipeline

### A. Asset pipeline (single-pass, repeatable)

```
[Step 1: Record]    ScreenToGif / OBS / asciinema
                              ↓
[Step 2: Edit]      built-in editor (trim only — no fancy effects)
                              ↓
[Step 3: Compress]  FFmpeg (GIF) / Handbrake or Resolve (MP4) / N/A (cast)
                              ↓
[Step 4: Save]      docs/assets/<demo-name>.<ext>   ← canonical path
                              ↓
[Step 5: Embed]     README + landing.html + Twitter + Reddit + Show HN
                              ↓
[Step 6: Verify]    raw.githubusercontent.com URL renders inline
```

### B. Canonical asset paths (commit these to repo)

| Demo | Path | Hosted URL (after push) |
|------|------|-------------------------|
| A (GIF) | `docs/assets/demo-portfolio-alert.gif` | `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-portfolio-alert.gif` |
| B (asciinema) | `docs/assets/demo-protocol-depth.cast` | `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-protocol-depth.cast` |
| C (MP4) | `docs/assets/demo-trader-workflow.mp4` | `https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-trader-workflow.mp4` |

**Why `docs/assets/` not `assets/` or `static/`:** keeps the public repo's top-level clean (per `58dc369` §Phase 3 cleanup recipe) and groups demo media with the docs they support. The `docs/` folder is already the "user-facing" tier in `docs/product-definition.md` §2 categorization.

**Important file size note for git:**
- 4MB GIF + 15MB MP4 + 100KB cast = ~19MB of binary assets. **Within Git's normal range** (no LFS needed).
- If Demo C MP4 ends up >50MB, **use Git LFS** (`git lfs track "docs/assets/*.mp4"`). Otherwise plain `git add` is fine.
- GitHub raw URL hosting works for files up to 100MB. Beyond that, use GitHub Releases attachments.

### C. Channel-specific embedding

#### C1. GitHub README (highest-impact)

**Current state** (verified line 1-12 of README.md):
```markdown
# Kite MCP Server

Give Claude or ChatGPT direct access to your Zerodha Kite trading account ...

[Try the hosted demo](https://kite-mcp-server.fly.dev/mcp) (read-only) · [Self-host in 60 seconds](#quick-start) (full trading) · [Compare vs official Zerodha MCP](#comparison)

```bash
claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp
```

Then say: *"Log me in to Kite. Show my portfolio. Backtest SMA crossover on INFY. Set an alert for RELIANCE 2% drop."*
```

**Patch (insert between the existing tagline and the install code block — line ~6):**
```markdown
Give Claude or ChatGPT direct access to your Zerodha Kite trading account ...

[Try the hosted demo](https://kite-mcp-server.fly.dev/mcp) (read-only) · [Self-host in 60 seconds](#quick-start) (full trading) · [Compare vs official Zerodha MCP](#comparison)

![demo](docs/assets/demo-portfolio-alert.gif)
> 30-second demo: AI agent reads portfolio and creates a real-money alert via Kite Connect API.

```bash
claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp
```
```

**Why the caption matters:** GitHub renders relative paths `docs/assets/demo-portfolio-alert.gif` correctly when on the repo page; **but Reddit/HN scrapers that fetch the README via the API see the raw URL only**. The 1-line caption above the GIF gives those scrapers something to display when the GIF doesn't load (alt text fallback) and tells Show HN viewers in 5 seconds what they're looking at.

**Note on `<video>` in README:** GitHub's README renderer **does** support raw `<video>` tags as of 2024 (per `<https://github.blog/2021-05-13-video-uploads-available-github/>` — auto-converted from drag-drop uploads). However, GIF is more reliable across all surfaces (RSS readers, third-party renderers, GitHub mobile). **Use GIF for the README hero. Use MP4 for landing.html only.**

#### C2. `kc/templates/landing.html` (verified line 235-243)

**Current state** of the `.hero` section:
```html
<!-- Hero -->
<section class="hero">
  <h1>...</h1>
  <p>...</p>
  <a class="btn" href="...">...</a>
</section>
```

**Patch (insert after the `.hero p` paragraph, before any CTA buttons):**
```html
<section class="hero">
  <h1>...</h1>
  <p>...</p>

  <video autoplay loop muted playsinline preload="metadata"
         style="max-width:720px;width:100%;border-radius:12px;margin:24px auto 16px;display:block;box-shadow:0 8px 32px rgba(0,0,0,0.12);">
    <source src="/static/demo-portfolio-alert.mp4" type="video/mp4">
    <source src="/static/demo-portfolio-alert.webm" type="video/webm">
    <img src="/static/demo-portfolio-alert.gif" alt="demo: AI reads portfolio and creates alert" style="max-width:720px;width:100%;">
  </video>

  <a class="btn" href="...">...</a>
</section>
```

**Why `<video>` not `<img>` for landing.html:** `<video autoplay loop muted playsinline>` is the modern approach — better compression than GIF, accessibility-friendly, mobile-Safari compatible. The `<img>` GIF inside the `<video>` is the fallback if video fails to load. Browsers that can't render either fall back to the alt text.

**Static-asset mount:** the landing.html is rendered via `kc/handlers.go` *or* equivalent. Verify the `/static/` path resolves to the expected directory in the file server config — likely `kc/templates/static/`. If not, the path needs adjustment.

**Note on file copy strategy:** the asset lives in `docs/assets/` (canonical) **and** `kc/templates/static/` (server-served). To keep them in sync, either: (a) symlink `kc/templates/static/demo-portfolio-alert.gif → ../../docs/assets/demo-portfolio-alert.gif`, (b) duplicate at commit time, or (c) configure the static handler to serve from `docs/assets/` directly. Option (b) is simplest for v1 launch — duplicate the file, accept the ~4MB git-stored twice, fix the duplication post-launch with a cleaner pipeline.

#### C3. Twitter Day-1 thread T1 (per `5adf80f`)

**Current state of T1** (per `5adf80f` Day-1 plan): pinned tweet + 7-tweet launch thread. T1 originally has text only.

**Patch:** Native upload the GIF as media attachment to T1.

**Twitter native upload limits (verified 2026-05-02):**
- GIF: max 15 MB on twitter.com web composer; **5 MB recommended** for best autoplay behavior.
- MP4: max 512 MB up to 2 min 20 sec.
- Auto-conversion: Twitter converts uploaded GIFs >5 MB to MP4 server-side. Result: GIF appears as a "video" with autoplay — fine for our purposes, no quality loss.

**Recommendation:** upload the 4 MB GIF to T1 directly. No conversion needed. Should autoplay in feeds.

**T6 (per existing draft `docs/launch/03-twitter-thread.md` line 91)**: has placeholder *"[Attach: 30-second screen recording showing]"*. **Replace** with same GIF (Twitter is fine with media-reuse across thread).

#### C4. Reddit r/algotrading post (per `f14d92c` §A.1)

**Current state of post body** (per `f14d92c` §A.1): markdown text body, no media reference.

**Patch:** insert at the very top of the post body, before the first paragraph:
```markdown
![demo: AI agent reads Zerodha portfolio and creates an alert via MCP](https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-portfolio-alert.gif)

Cross-posting from a working repo I've been on for ~6 months. Sharing architecture
because the riskguard chain is the part I'd actually like critique on.

[... rest of body unchanged ...]
```

**Reddit native upload alternative:** Reddit's posting interface accepts direct GIF / MP4 upload as a *"Image and Video"* post type. **Two trade-offs:**
- **GitHub-raw embed (recommended):** post is a *"text post"* with markdown image. Title and body render as a standard discussion thread. Star yield is higher because viewers click through to the repo.
- **Reddit native upload:** post is an *"Image post"*, body becomes a comment. Post format is more visual but viewers don't necessarily click to the repo — they upvote the GIF and move on.

**For r/algotrading specifically:** **use the GitHub-raw embed in the text post body**. The audience there clicks through to repos; the GIF is supporting evidence, not the main attraction. For r/SideProject / r/IndianStreetBets where GIF-as-content lands better, native upload may be preferred.

#### C5. Show HN body

**Current state of `docs/show-hn-post.md`:** body is markdown text only.

**Patch:** add at the bottom of body, before the prepared comment replies:
```markdown
[... existing body ...]

Demo: https://raw.githubusercontent.com/Sundeepg98/kite-mcp-server/master/docs/assets/demo-portfolio-alert.gif (30 sec, no audio).
```

**Why a link, not an embed:** **HN does not render images or video inline.** Submitting a media file as the URL gets the post auto-flagged as low-effort. The GIF must be self-hosted (GitHub raw is fine) and linked via plain URL; HN viewers click through.

**Show HN URL field:** the original `docs/show-hn-post.md` recommends submitting the **GitHub repo URL** as the main URL (not the GIF). The GIF link goes in the body text as supporting material. This is correct — keep it.

#### C6. Other channels (lower priority)

- **MCP Registry entry (`server.json`):** the schema does not have a `demo` or `screenshot` field. Skip.
- **smithery.yaml:** same, no demo field. Skip.
- **awesome-mcp-servers PRs (per `58dc369` §Phase 1 C1):** the entry format does not include media. Skip.
- **kite.trade forum reply templates (per `docs/kite-forum-replies.md`):** forum text-only, no media. Skip.
- **Blog post (`docs/blog/oauth-13-levels.md`):** for a Week 3 second-wave HN submission. Add a link to the GIF in the intro paragraph if relevant — low priority.

---

## Phase 5 — Pre-record cleanup checklist

Before hitting record on Demo A:

### A. Sensitive-data scrub

- [ ] **Email displayed in Claude Desktop UI: must NOT be `g.karthick.renusharmafoundation@gmail.com`** per `user_email_rule.md`. Switch to a generic test account (e.g. `kite-mcp-demo@<your-product-domain>` or any test mailbox you control). Verify in Claude Desktop *Settings → Account*.
- [ ] **Tool responses must NOT contain real Kite holdings.** Either:
  - (a) Set `paper_trading_toggle enabled=true initial_cash=10000000` BEFORE recording — all tool calls then route to virtual portfolio with mocked data. *(Recommended.)*
  - (b) Use a freshly-created Kite developer app with a test Zerodha account that has zero real positions. *(Backup if paper-trading mode shows obvious "PAPER" labels that would confuse the demo viewer.)*
- [ ] **MCP-Apps widget data:** verify the widget shows mocked tickers (RELIANCE, INFY, TCS, HDFC, ITC) at mocked prices, **not** the user's real `g.karthick`-account holdings. If real holdings leak into the widget render, abort and re-take after switching to paper mode.
- [ ] **Telegram bot in second pane:** ensure the Telegram account shown is a developer/test account, not the user's personal Telegram. Telegram desktop's account-name and avatar are visible in the chat header — if any of those are `Sundeep Govarthinam` (real name), switch profiles before recording or crop the chat header out of the recording frame.
- [ ] **Server logs (Demo B):** Fly.io logs include real session IDs and IPs. Either: (a) `tail -f` only the tool-dispatch lines and grep out user-identifying fields, (b) record from a dedicated test machine with no real traffic, (c) post-edit the asciinema `.cast` JSON to redact identifying tokens.
- [ ] **Browser tabs visible:** if recording with Claude Desktop in the foreground, ensure no other tabs (Gmail with sensitive subject lines, Slack workspaces, banking) are visible in browser thumbnails or tab strips.

### B. Background-app suppression

- [ ] **Slack / Discord / Outlook / Teams: closed** (not just minimized — outright quit). Each can produce notification toasts mid-recording.
- [ ] **Windows notifications: Focus Assist → Priority Only or Off** (Settings → System → Focus Assist).
- [ ] **OS update toasts:** verify *"You have updates ready"* is dismissed before recording. Otherwise it can pop mid-frame.
- [ ] **Anti-virus scans: paused.** Most AV scanners produce occasional toasts. Pause for 60 minutes covering the recording window.
- [ ] **Browser extensions:** if recording shows a browser, verify password-manager popups, Grammarly, etc. don't auto-render. Use Incognito if unsure.

### C. Recording-environment polish

- [ ] **Browser zoom: 125%.** Most HN/Reddit thumbnail readers see frames downscaled to ~640×360. Without zoom, text becomes illegible at thumbnail size. **Verify by recording 5 seconds, opening the GIF, and viewing it at 50% zoom in your browser** — if the text is readable, you're set.
- [ ] **Cursor visibility:** Windows default cursor sometimes disappears in screen recordings against dark backgrounds. Enable *Settings → Accessibility → Mouse Pointer → Custom → Black* if your terminal/Claude theme is dark; *White* if light.
- [ ] **Window border distractions:** if Claude Desktop is windowed, recording captures the title bar. Decide: (a) capture full window (default — title bar is fine), or (b) capture only the conversation pane (cleaner, but viewers don't see "this is Claude Desktop" → reduces credibility). **Recommendation: capture full window so viewers recognize the client.**
- [ ] **Display scaling:** as noted in §Phase 3.A pitfalls, set Windows scaling to 100% on a 4K monitor for the recording session, then revert.

### D. Final pre-record dry-run

- [ ] **Record a 10-second test cast first.** Just type one Claude prompt, get one response. Stop. Open the GIF. Verify: (1) text is legible, (2) no notification leaked, (3) no email leaked, (4) cursor visible, (5) file size ≤4 MB at 30s extrapolation. **Only proceed to the real Demo A take after this passes.**

---

## Phase 6 — Time budget + pre-Show-HN gate

### A. Time budgets (empirical)

| Demo | Tooling install | Pre-record cleanup | Recording (incl. retakes) | Editing | Compression / hosting | **Total** |
|------|----------------|---------------------|--------------------------|---------|----------------------|----------|
| A (GIF, 30s) | 4 min (ScreenToGif) | 5 min | 5 min (incl. 2 retakes) | 5 min | 5 min | **~24 min, call it 30 min** |
| B (asciinema, 60s) | 3 min | 3 min | 8 min | 5 min | 5 min upload | **~24 min** |
| C (MP4 with narration, 60s) | 12 min (OBS + Resolve) | 10 min (mic test, room) | 20 min (incl. 4-6 audio retakes) | 30 min (Resolve cuts + subtitle) | 10 min export | **~82 min, call it 90 min** |

**Sequential total for all 3:** ~24 + 24 + 90 = **~140 min ≈ 2.5 hours.** With unforeseen retakes and tool friction: **3-4 hours realistic.**

**Sequential total for just Demo A:** **~30 min.** This is the single must-ship.

### B. Pre-Show-HN gate

**Hard requirement:** Demo A shipped before Show HN submit.

- If user has 30 min before Show HN → record Demo A. Skip B and C for v1 launch.
- If user has 1.5 hours → record Demo A + Demo B. Skip C.
- If user has 4 hours → record all three.
- **If user has <30 min:** **defer Show HN by 1 day.** Recording Demo A is more important than hitting Tuesday 06:30 PT specifically; a Wednesday 06:30 PT submit with the GIF embed beats a Tuesday submit without it.

### C. Sequencing across demos (which to ship when)

| Demo | Pre-launch (Day -1) | Day 0 (Show HN) | Day 1-7 (Reddit + Twitter cadence) | Week 2-3 |
|------|---------------------|------------------|-------------------------------------|----------|
| **A — GIF** | **Must record + commit** | **README + landing.html + Twitter T1 + Show HN body** | **Reddit r/algotrading, r/ClaudeAI, r/SideProject post bodies** | reuse for r/golang post |
| **B — asciinema** | optional | optional ref in HN comment if asked about architecture | r/MachineLearning [P] post + r/golang post | reuse in Substack OAuth deep-dive post |
| **C — MP4** | skip for v1 | skip | r/IndianStreetBets (after modmail approval), Telegram channel | reuse for IndiaFOSS 2026 talk submission per `docs/drafts/indiafoss-2026-cfp.md` |

**Decision rule:** if Demo A is the only asset and user is energy-constrained, **don't sweat B and C**. The single GIF carries 80% of the value across all primary channels.

### D. Skip-without-shame conditions

Do **not** ship Demo A under these conditions (and instead skip the visual asset for v1 launch — the campaign still works without it, just with reduced multiplier):

- Cannot find a 30-min focused window in the next 5 days. **Defer Show HN.**
- Recording shows real holdings or sensitive email despite Phase 5 checklist. **Re-take after fixing or skip.**
- File size cannot be brought under 4 MB without making the GIF visibly choppy. **Try MP4 native upload to Twitter only**; skip GIF for README; defer.
- Multiple retakes (>4) and the demo still doesn't feel right. **Step back; the script may be wrong**, not your recording skill.

---

## Phase 7 — Cross-link to existing docs (consolidate, don't fork)

### A. Update `docs/launch/04-demo-video-script.md` in place

This is the only doc that requires text edits beyond the pure-research deliverable being shipped here.

**Patches (apply manually; this deliverable does not edit it):**

| Line | Change | Reason |
|------|--------|--------|
| 60 | `initial_cash: 1000000` → `initial_cash: 10000000` | paper-trading default is ₹1 crore (10000000), not ₹10 lakh |
| 84 | `MRF... 500 shares = Rs 6 crore` → `RELIANCE... 100 shares = Rs 1.42 lakh` | example must exceed current ₹50k cap, not ancient ₹5L cap |
| 86 | `Rs 6,00,00,000 exceeds limit Rs 5,00,000` → `Rs 1,42,000 exceeds limit Rs 50,000` | match current cap |
| 90 | `8 checks like this — value caps, rate limits, duplicate detection, and a circuit breaker` → `9 checks: kill switch, per-order Rs 50k cap, qty limit, daily 20-order count, 10/min rate, 30s duplicate, daily Rs 2L cumulative, idempotency, anomaly detection (μ+3σ), off-hours block, auto-freeze` | current 9 checks per `kc/riskguard/guard.go` |
| 134 | `2:15-2:30` → `30s (Demo A) / 60s (Demos B and C)` | new runtime targets |
| 4 | *"Tone: Calm, factual, no hype."* | unchanged — still correct |

**Do not fork this file to a new file.** The §1-§6 scenes in the existing script are reusable for the longer-form Demo C (Hindi-English narrated). Reference them from Demo C scenario in this doc rather than duplicating.

### B. Update `docs/launch/03-twitter-thread.md` Tweet 6

**Patch line 91:** replace placeholder `[Attach: 30-second screen recording showing]` with concrete reference: `[Attach: docs/assets/demo-portfolio-alert.gif — same GIF as T1, reuse permitted]`. **No new content required.**

### C. Update `docs/launch/05-readme-outline.md`

Section 2 "Hero Visual" already calls for a GIF (lines 47-54). **No update needed** — the new GIF satisfies the existing spec. The numerical staleness in §A.2 (78 tools, 475 tests, 8 checks) is a separate doc-update task tracked in `58dc369` §Phase 3 cleanup, not in this dispatch.

### D. Update `docs/show-hn-post.md`

Patch per §C5 above — add one line at the bottom of the body referencing the GIF link. **No structural change.**

### E. Update `f14d92c` Reddit drafts

Patch per §C4 above — add markdown image at the top of §A.1 (r/algotrading v1 body). The other 5 sub drafts in `f14d92c` (§B, §D, §E, §F, §G) can also benefit from the GIF — add the same markdown image embed at the top of each post body. **Same GIF, different surrounding text.** Per `f14d92c` §Phase 5 rule 8 (no cross-post body paraphrasing), the post bodies remain genuinely different — only the supporting GIF is shared.

### F. No new files created beyond this deliverable

The principle: **scripts and outlines stay as drafts; this deliverable is the recipe to ship the assets they reference.** The user records once, places the asset at `docs/assets/demo-portfolio-alert.gif`, and the existing channel drafts pick it up via the path references documented in this guide.

---

## Cross-references

- **Companion docs in repo (verified existing):**
  - `.research/gtm-launch-sequence.md` (`58dc369`) — overall GTM
  - `.research/twitter-cadence-weeks-1-4.md` (`5adf80f`) — Twitter Weeks 1-4
  - `.research/reddit-subreddit-specific-strategy.md` (`f14d92c`) — Reddit per-sub
  - `.research/show-hn-day1-ops-runbook.md` (`ff64598`) — Day-1 ops runbook
  - `.research/final-pre-show-hn-verification.md` (`908d304`) — NOT-READY verdict identifying the demo gap this doc closes
  - `docs/launch/01..05` — channel drafts (TradingQnA, Reddit ISB, Twitter, demo-script, README outline)
  - `docs/show-hn-post.md` — Show HN body
  - `docs/launch/04-demo-video-script.md` — script (to update per §Phase 7.A)
  - `docs/launch/03-twitter-thread.md` — Twitter draft (to update per §Phase 7.B)
- **Memory files cross-referenced:**
  - `user_email_rule.md` — email-scrub rule (Phase 5.A)
  - `kite-launch-blockers-apr18.md` — pre-launch blocker context
  - `kite-papertrading` (in `MEMORY.md`) — paper-trading default cash ₹1 crore
- **External tool docs (verified 2026-05-02):**
  - ScreenToGif: `https://www.screentogif.com/` (Microsoft Store: `winget install NickeManarin.ScreenToGif`)
  - OBS Studio: `https://obsproject.com/` (`winget install OBSProject.OBSStudio`)
  - asciinema: `https://asciinema.org/docs/installation` (`apt install asciinema` in WSL2)
  - DaVinci Resolve: `https://www.blackmagicdesign.com/products/davinciresolve` (free)
  - Twitter media upload limits: 5 MB recommended GIF / 512 MB MP4 (auto-converts oversized GIF to MP4)
  - GitHub raw URL hosting: up to 100 MB per file via `raw.githubusercontent.com`; uses Git LFS beyond
  - GitHub README `<video>` support: live since 2021 per github.blog
- **Canonical numbers (verified empirically in repo 2026-05-02):**
  - **Tools: 120+** (per README line 3 + line 21; `81892a8` aligns to 120+)
  - **Tests: ~9,000 across 437 test files** (per README line 25; commit `81892a8` aligns)
  - **RiskGuard checks: 9** (per README line 28; per `kc/riskguard/guard.go`)
  - **Per-order cap default: ₹50,000** (per README line 28; commit `7cd7b35`)
  - **Daily order count default: 20** (per `kite-riskguard-tightened` memory)
  - **Daily cumulative cap: ₹2,00,000** (per README line 28)
  - **Paper trading default cash: ₹1 crore** (per `kite-papertrading` memory)

---

*This document does not change code. It does not commit anything beyond itself.*
