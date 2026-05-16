#!/bin/bash
# WSL2 Tier 3 build verification — used by orchestrator extraction agent
export PATH=/usr/local/go/bin:/usr/bin:/bin
cd /mnt/d/Sundeep/projects/kite-mcp-server || exit 1
echo "=== go version ==="
go version
echo "=== arg: $1 ==="
case "$1" in
  build-all)
    go build ./... 2>&1 | tail -20
    ;;
  build-gowork-off)
    GOWORK=off go build ./... 2>&1 | tail -20
    ;;
  vet-all)
    go vet ./... 2>&1 | tail -20
    ;;
  pkg-build)
    cd "$2" && go build ./... 2>&1 | tail -20
    ;;
  pkg-build-gowork-off)
    cd "$2" && GOWORK=off go build ./... 2>&1 | tail -20
    ;;
  pkg-vet)
    cd "$2" && go vet ./... 2>&1 | tail -20
    ;;
  pkg-test)
    cd "$2" && go test -count=1 -timeout=60s ./... 2>&1 | tail -30
    ;;
  pkg-test-skip)
    cd "$2" && go test -count=1 -timeout=60s -skip "$3" ./... 2>&1 | tail -30
    ;;
  pkg-tidy)
    cd "$2" && go mod tidy 2>&1 | tail -20
    ;;
  raw)
    eval "$2"
    ;;
  *)
    echo "Usage: $0 {build-all|build-gowork-off|vet-all|pkg-build|pkg-build-gowork-off|pkg-vet|pkg-test|pkg-test-skip|pkg-tidy|raw} [args...]"
    exit 2
    ;;
esac
