# scripts/

Operational scripts for the Kite MCP Server.

## smoke-test.sh

Post-deploy E2E smoke test. Answers the question "is the deployed server
actually healthy?" in under 20 seconds.

**What it checks (9 checks):**

1. `/healthz` returns 200
2. `/healthz?format=json` returns JSON with `status: ok` (or `degraded`)
3. `/.well-known/oauth-authorization-server` returns valid OAuth metadata
4. `/.well-known/oauth-protected-resource` returns valid OAuth metadata
5. `/` landing page contains the static egress IP `209.71.68.157`
6. `/mcp` returns 401 or 405 without auth (NOT 500 - middleware is wired)
7. `/oauth/authorize` without params returns 400 (handler is live)
8. `/oauth/authorize` with valid PKCE params 302s to `kite.zerodha.com`
9. `/healthz` warm response time under 500ms (2 warmup + 5 timed)

**Usage:**

```bash
./scripts/smoke-test.sh                                # default: https://kite-mcp-server.fly.dev
./scripts/smoke-test.sh https://other-host.example     # custom URL
```

Exits `0` if all pass, `1` if any fail. `jq` is optional (grep fallback).

## deploy.sh

One-shot wrapper for the full deploy pipeline:

1. `git push`
2. `flyctl deploy -a kite-mcp-server`
3. Wait for machine state `started` (up to 3 min)
4. Run `smoke-test.sh` against the live URL

If the smoke test fails, deploy.sh does **not** auto-rollback. It prints the
rollback command (`flyctl releases rollback <version>`) and lets you decide.

**Usage:**

```bash
./scripts/deploy.sh                    # push + deploy + verify
./scripts/deploy.sh --skip-push        # skip git push (already pushed)
./scripts/deploy.sh --app other-app    # deploy a different Fly app
./scripts/deploy.sh --url https://...  # smoke-test against a custom URL
```

## When to use each

| Situation                                      | Script                                        |
|------------------------------------------------|-----------------------------------------------|
| You just ran `flyctl deploy` manually          | `./scripts/smoke-test.sh`                     |
| You want the whole pipeline in one command     | `./scripts/deploy.sh`                         |
| You want to verify a local tunnel / staging    | `./scripts/smoke-test.sh https://your-url`    |
| Rollback failed, re-verify old version is up   | `./scripts/smoke-test.sh`                     |

## Requirements

- `bash` (works on Git Bash for Windows)
- `curl`
- `flyctl` or `flyctl.exe` (auto-detected in PATH and `~/.fly/bin/`)
- `jq` optional - falls back to `grep` when absent
- No Python, Node, or other runtime deps
