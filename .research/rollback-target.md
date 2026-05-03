# Rollback Target — Last-Known-Good Fly.io Release

> Snapshot taken 2026-05-02 before launch deploy of claim-integrity + post-`14a188e` commits.

## Production state at snapshot

| Field | Value |
|-------|-------|
| **Release version** | `v180` |
| **Status** | `complete` |
| **Deployed by** | `sundeepg8@gmail.com` |
| **Deploy date** | Apr 19 2026 04:51 UTC |
| **Machine ID** | `2863d22b7eee18` |
| **Region** | `bom` (Mumbai) |
| **Image tag** | `deployment-01KPJ1468H7P6FTZZTPZVSHHRH` |
| **Image digest** | `sha256:d97145078778a14ee89dd09e11bf110ba5e08de6d5c9621df203fa6f6fc7a284` |
| **Registry** | `registry.fly.io` |
| **Repository** | `kite-mcp-server` |
| **Server name label** | `io.github.sundeepg98/kite-trading` |

## Rollback command (if launch deploy regresses)

```bash
# Roll back to v180 by re-deploying its image digest
/c/Users/Dell/.fly/bin/flyctl.exe deploy \
  -a kite-mcp-server \
  --image "registry.fly.io/kite-mcp-server@sha256:d97145078778a14ee89dd09e11bf110ba5e08de6d5c9621df203fa6f6fc7a284"
```

Alternative (release-promote):

```bash
/c/Users/Dell/.fly/bin/flyctl.exe releases rollback v180 -a kite-mcp-server
```

## Reason for snapshot

Last-known-good before May 2026 launch deploy. Outgoing deploy includes:
- Claim integrity fix (16,209 → ~9,000 tests; 117 → 120+ tools)
- All commits past `14a188e fix(e2e): tool-surface uses structural assertions vs strict SHA pin`

## Recent release history (context)

```
v180  complete  Apr 19 2026 04:51  (current production, rollback target)
v179  complete  Apr 18 2026 13:41
v178  complete  Apr 18 2026 03:27
v177  complete  Apr 17 2026 13:40
v176  complete  Apr 17 2026 12:54
v175  complete  Apr 13 2026 09:43
v174  complete  Apr 13 2026 08:37
v173  failed    Apr 13 2026 08:28  (skip — failed deploy)
v172  running   Apr 13 2026 08:01
```
