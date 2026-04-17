# Release Checklist

Pre-flight for cutting a Kite MCP Server release. Runs top to bottom.
Skip a step only with a recorded reason.

Context: [CHANGELOG.md](../CHANGELOG.md) `Unreleased` section describes
what is shipping; [server.json](../server.json) is the public manifest.

---

## 1. Before tagging

On the branch you intend to tag (usually `master`):

```bash
go build ./...
go vet ./...
go test ./... -count=1
go test ./... -race -count=1 -short   # or: just test-race
```

- [ ] All of the above pass clean.
- [ ] `CHANGELOG.md` `[Unreleased]` section covers every user-visible
      change. Use the Keep-a-Changelog subsections (Added / Changed /
      Fixed / Security / Removed). End each entry with a short commit
      SHA in backticks, e.g. `` (`ee345e0`) ``.
- [ ] Version bumped in `server.json` → `"version": "X.Y.Z"`. If the
      tool surface changed materially, also bump
      `_meta.io.modelcontextprotocol.registry/publisher-provided.capabilities.tools`
      (see step 6 for the threshold).
- [ ] No unresolved `TODO`, `FIXME`, `WIP`, or `XXX` introduced by
      release commits.
- [ ] Branch tracks `origin/master`, working tree clean.
- [ ] `./scripts/smoke-test.sh` passes 9/9 against the currently
      deployed server (baseline for step 5).

## 2. Tagging

Release tags are **signed**. The `release.yml` workflow triggers on
any `v*` tag push.

```bash
git tag -s v1.0.1 -m "v1.0.1 — per-user session management + healthz components"
git push origin v1.0.1
```

- [ ] Tag verifies: `git tag -v v1.0.1` shows a valid signature.
- [ ] Tag name matches `vMAJOR.MINOR.PATCH` exactly (CI regex is strict).
- [ ] Tag message is the one-line release summary (same wording you'll
      use on GitHub).

Wrong commit? Delete locally and re-tag **before** pushing. After the
tag has been pushed, do not force-delete remotely — the MCP Registry
caches manifests by version.

## 3. Release notes

- [ ] Copy `CHANGELOG.md` `[Unreleased]` verbatim into the GitHub
      release body (strip the header — GitHub adds the `vX.Y.Z` title).
- [ ] Rename the section in `CHANGELOG.md` to `[X.Y.Z] — YYYY-MM-DD`.
      Add the new `compare/vA...vB` link at the bottom of the file
      following the existing pattern.
- [ ] Attach the Linux AMD64 binary if the release workflow produced
      one (check the Actions run linked from the tag).
- [ ] Pin a comment on the release for any operator-required actions
      (breaking changes, env-var renames, manual migration steps).

## 4. Deploy

```bash
./scripts/deploy.sh
```

This script (see `scripts/deploy.sh`) runs: `git push` → capture
previous release version → `flyctl deploy -a kite-mcp-server` → poll
`flyctl status` until `started` (max 180s) → sleep 3s for Litestream
restore → run `smoke-test.sh` against the live URL.

- [ ] Deploy succeeds; machine reaches `started`.
- [ ] Smoke reports 9/9 pass.
- [ ] On smoke failure, `deploy.sh` prints the rollback command but
      does **not** auto-roll. Decide based on the failing check —
      `/mcp` 500 or missing OAuth metadata → rollback immediately:
      `flyctl releases rollback <prev-version> -a kite-mcp-server`.

## 5. Post-deploy verification

```bash
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq .
```

- [ ] Top-level `status: ok`.
- [ ] `components.audit.status: ok` and `dropped_count: 0`. `disabled`
      or `dropping` is a compliance gap — investigate before moving on.
- [ ] `components.riskguard.status: ok`. A `defaults-only` value means
      production started in DevMode, which should never ship.
- [ ] `components.kite_connectivity` and `components.litestream` both
      `unknown` is expected (neither is probed in-process).
- [ ] One real MCP tool call succeeds end-to-end. Easiest: call
      `get_profile` (read-only, tier-free, idempotent) — it round-trips
      OAuth, session lookup, Kite adapter, audit write, response
      serialisation.
- [ ] Dashboard SSO still works: `/dashboard` loads with the cookie
      set during OAuth callback (commit `0038a23`). A bounce to
      `/auth/browser-login` means the cookie is not being set.
- [ ] `flyctl logs -a kite-mcp-server | head -100` — no panics, no
      app-level ERROR lines.

## 6. MCP Registry

Skip if the tool surface and deployment topology haven't changed. Bump
and republish when any of these change: tool count (add/remove, not
rename), OAuth flow, supported clients, region, egress IP, or any
`capabilities.*` flag.

- [ ] Bump `server.json` `version` to match the tag.
- [ ] Update `capabilities.tools` to `len(mcp.GetAllTools())` (the
      legacy `/healthz` body exposes this as `tools`).
- [ ] Commit `server.json` on `master` as `chore(registry): ...`.
- [ ] Publish:
      ```bash
      ./mcp-publisher login github   # must be logged in as Sundeepg98
      ./mcp-publisher publish
      ```
      Namespace `io.github.sundeepg98/*` is irrevocable (commit `142a5e1`).
- [ ] Confirm the new version appears at
      https://modelcontextprotocol.info/tools/registry/ within 5–10 min.
      Smithery and Glama pull on their own schedule — their listings lag.

## 7. Communication

Do registry first so external click-throughs land on the new version.

- [ ] GitHub release body renders correctly on the Releases page.
- [ ] Pin a Discussion under `Announcements` with a one-paragraph
      "what this means for you" at the top.
- [ ] Optional Twitter thread — template in
      [docs/launch/03-twitter-thread.md](launch/03-twitter-thread.md).
      Patch releases rarely need a thread; reserve for minor/major
      bumps or standout security fixes.
- [ ] Refresh [README.md](../README.md) badges if any advertised
      number changed (tool count, test count, coverage). These drift
      silently — rescan every release.

---

## When something goes sideways

- Smoke failed after deploy: copy the rollback hint
  `deploy.sh` printed, execute, then re-run `./scripts/smoke-test.sh`.
- Tag pushed to the wrong commit: delete the remote tag only if no
  Fly workflow has started yet. Otherwise let the release ride and
  cut a patch on top.
- Registry publish failed: the CLI prints the cause. Usually either
  version already published (bump again) or namespace mismatch
  (check `name:` in `server.json`).
- `dropped_count > 0` within an hour of deploy: not necessarily a
  release issue. Compare against the prior release at the same
  wall-clock time; rollback only if higher. See
  [operator-playbook.md](operator-playbook.md) § 1.
