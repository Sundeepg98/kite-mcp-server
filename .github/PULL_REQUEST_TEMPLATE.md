<!--
Thanks for contributing! Please fill this out so reviewers can move quickly.
See CONTRIBUTING.md for local setup.
-->

## What

<!-- A one-sentence summary of the change. -->

## Why

<!-- The motivation. Link to an issue if one exists: "Closes #123". -->

## Testing done

<!-- How did you verify this works? Paste commands + output if useful. -->

- [ ] Added / updated unit tests
- [ ] Manual test against hosted server or local Kite sandbox
- [ ] N/A — <!-- explain -->

## Compliance (for order-tool changes only)

<!-- Skip this section if your PR doesn't touch order-placement tools. -->

- [ ] `ENABLE_TRADING` gate preserved (Path 2 compliance)
- [ ] RiskGuard check integration verified
- [ ] Audit trail entry present
- [ ] No performance claims / advice framing

## Checklist

- [ ] `go build ./...` passes
- [ ] `go vet ./...` is clean
- [ ] `go test ./... -count=1` passes
- [ ] `just lint` is clean (or equivalent `gofmt` + `golangci-lint`)
- [ ] New code has tests (see `.claude/CLAUDE.md` — TDD is required for new features, ≥ 80% coverage)
- [ ] `CHANGELOG.md` updated if the change is user-facing
- [ ] New tools route through a use case (`kc/usecases/`) rather than calling `session.Broker.*` directly
- [ ] New tools have proper annotations (title, readOnlyHint, destructiveHint, idempotentHint, openWorldHint)
- [ ] If adding an advisory-sounding tool (recommendations, forecasts, signals): "Not investment advice" disclaimer added to the tool description
- [ ] Sensitive data (tokens, PII) is redacted from logs and audit trail
- [ ] No secrets committed (`.env`, API keys, JWT secrets — grep for `_SECRET`, `_KEY`, `_TOKEN`)

## Screenshots / demos

<!-- Optional — especially useful for widget / dashboard / UI changes. -->

## Reviewer notes

<!-- Anything reviewers should pay special attention to. -->
