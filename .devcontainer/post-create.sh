#!/usr/bin/env bash
# Post-create provisioning for kite-mcp-server devcontainer.
# Installs Go tooling, pre-fetches modules, and runs a smoke vet.
set -euo pipefail

echo "==> Installing Go tooling (gopls, delve, staticcheck, golangci-lint)"
go install golang.org/x/tools/gopls@latest
go install github.com/go-delve/delve/cmd/dlv@latest
go install honnef.co/go/tools/cmd/staticcheck@latest
# golangci-lint: prefer the official installer (pinned channel) over `go install`.
curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh \
  | sh -s -- -b "$(go env GOPATH)/bin" v1.61.0

echo "==> Fetching Go modules"
go mod download

echo "==> Running go vet ./..."
go vet ./...

# Remind contributor to seed a local .env (don't auto-copy: .env may contain secrets).
if [ ! -f .env ] && [ -f .env.example ]; then
  echo ""
  echo "==> Next step: copy .env.example to .env and fill in your credentials:"
  echo "    cp .env.example .env"
fi

echo "==> Devcontainer ready."
