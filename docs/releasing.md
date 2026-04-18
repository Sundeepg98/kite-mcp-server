# Releasing

## Pre-req (one time)

- `gh` CLI authenticated: `gh auth status`
- `cyclonedx-gomod` installed: `go install github.com/CycloneDX/cyclonedx-gomod/cmd/cyclonedx-gomod@latest`

## Steps

1. Ensure `docs/release-notes-vX.Y.Z.md` exists (see `docs/release-notes-v1.1.0.md` for template)
2. Ensure master is clean + up to date with origin
3. Dry-run: `./scripts/release.sh vX.Y.Z --dry-run`
4. Run: `./scripts/release.sh vX.Y.Z`
5. Deploy: `flyctl deploy -a kite-mcp-server`

## Rollback

- Delete the GitHub Release via `gh release delete vX.Y.Z`
- Delete the tag: `git tag -d vX.Y.Z && git push origin --delete vX.Y.Z`
- Deploy prior version: `flyctl rollback vN -a kite-mcp-server` (find N via `flyctl releases`)
