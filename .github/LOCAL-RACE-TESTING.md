# Local `-race` testing on Windows

The Go race detector requires cgo. On Windows, cgo requires a C compiler
in `PATH`. The repo's CI runs `-race` on ubuntu-latest via the
`test-race.yml` workflow, so local `-race` is optional — but cheap to
enable when you want fast iteration on a suspected race.

## Why this matters

The prior test-architecture audit listed "`-race` not runnable on
Windows" as a hard ceiling. It isn't. Three independent paths, all
5-10 minutes, give a local Windows developer `-race`. The paths differ
in scope:

1. **MinGW-w64** — adds `gcc` to `PATH`, enables cgo for any Go build.
   Smallest footprint.
2. **WSL2** — runs the full Linux toolchain, matches CI exactly.
   Best fidelity.
3. **Devcontainer / Codespaces** — no local install, cloud-runtime.
   Best for cross-device work.

Pick one. The repo itself is unchanged.

## Path 1 — MinGW-w64 (recommended for pure Windows dev)

```powershell
# PowerShell (admin not required)
winget install --id=ScoopInstaller.Scoop -e     # if scoop not yet installed
scoop install mingw
# Or, without scoop:
winget install MSYS2.MSYS2
# ... then in an MSYS2 shell: pacman -S mingw-w64-ucrt-x86_64-gcc
```

Verify:

```bash
where gcc          # must resolve
go env CGO_ENABLED # should print 1; if 0, run: go env -w CGO_ENABLED=1
go test -race ./kc/riskguard/...
```

Expected: race-detector symbols compiled in, tests run ~2x slower
(normal race overhead).

Troubleshooting:
- `go: cannot find GCC` — `gcc` not in `PATH`. Open a fresh shell so
  scoop/MSYS2's `PATH` change is picked up.
- Long-path errors on `go build` — enable Windows long paths:
  `git config --global core.longpaths true` + Group Policy edit.

## Path 2 — WSL2 Ubuntu (best fidelity, matches CI)

```powershell
wsl --install -d Ubuntu-22.04
# Reboot when prompted, then in the Ubuntu shell:
sudo apt update && sudo apt install -y gcc make
# Install Go 1.25.x from https://go.dev/dl/ — follow Linux tarball instructions.
```

Inside WSL, the repo lives at `/mnt/d/Sundeep/projects/kite-mcp-server`
(Windows D:\ mount). Run tests there:

```bash
cd /mnt/d/Sundeep/projects/kite-mcp-server
go test -race ./...
```

Tradeoff: filesystem I/O across the 9P mount is ~5x slower than native
NTFS. For iterative `-race` runs, clone the repo into the Linux home
dir (`~/kite-mcp-server`) and push changes back via `git`.

## Path 3 — Devcontainer / Codespaces (zero local install)

Add `.devcontainer/devcontainer.json`:

```json
{
  "image": "mcr.microsoft.com/devcontainers/go:1.25",
  "features": {
    "ghcr.io/devcontainers/features/github-cli:1": {}
  },
  "postCreateCommand": "go mod download",
  "remoteEnv": {
    "CGO_ENABLED": "1"
  }
}
```

Open the repo in VS Code → "Reopen in Container" (or launch a GitHub
Codespace). `go test -race ./...` works out of the box inside the
container.

## When to actually run `-race` locally

The CI workflow already runs `-race` on every push. Run it locally
when:

- A CI `-race` failure reproduces intermittently — local `-count=N`
  iteration is faster than pushing to re-run CI.
- Writing new concurrent code (new goroutine-spawning package, new
  channel pattern) — run `-race` on the change before pushing.
- Debugging a suspected `sync.Mutex` misuse or atomic-ordering issue.

Don't run `-race` by default; it's ~2x slower and its signal is
noisiest when you already suspect a race.

## Related

- `.github/workflows/test-race.yml` — CI runs race on each push/PR.
- `.github/workflows/ci.yml` — default CI runs `-race` on the main
  test job.
- `testutil/clock.go` — fake clock port; eliminates many race-adjacent
  timing flakes that `-race` would otherwise surface.
