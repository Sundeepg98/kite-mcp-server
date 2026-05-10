FROM golang:1.25.8-alpine AS builder
RUN apk add --no-cache jq
WORKDIR /app
# Multi-module workspace setup (see go.work + .research/disintegrate-and-
# holistic-architecture.md). The root go.mod has `replace` directives
# pointing each in-tree extracted module at ./<path>, so each
# extracted-module's go.mod must be present BEFORE `go mod download`
# runs — otherwise the resolver fails with "open <module>/go.mod: no
# such file or directory". Pre-stage every manifest before download.
# Add another COPY line per future module extraction when they get
# their own go.mod. Note: broker + kc/money were removed from this
# pre-stage list as of Phase B canary deletion — they are now fetched
# from algo2go/kite-mcp-broker@v0.1.0 + algo2go/kite-mcp-money@v0.1.0
# via GOPROXY during go mod download instead of being in-tree COPY'd.
COPY go.mod go.sum ./
COPY app/providers/go.mod app/providers/go.sum* app/providers/
COPY kc/papertrading/go.mod kc/papertrading/go.sum* kc/papertrading/
COPY kc/riskguard/go.mod kc/riskguard/go.sum* kc/riskguard/
COPY kc/sectors/go.mod kc/sectors/go.sum* kc/sectors/
COPY kc/telegram/go.mod kc/telegram/go.sum* kc/telegram/
COPY kc/usecases/go.mod kc/usecases/go.sum* kc/usecases/
COPY plugins/go.mod plugins/go.sum* plugins/
COPY testutil/go.mod testutil/go.sum* testutil/
RUN go mod download
COPY . .
# VERSION sourced from server.json (single source of truth for the registry
# manifest version) unless overridden via --build-arg VERSION=vX.Y.Z. Avoids
# the prior drift where Dockerfile hardcoded v1.1.0 while server.json was
# bumped to v1.3.0 and beyond. Tool-count-drift CI pins the registry
# manifest; this build pulls from the same source so the deployed binary's
# main.MCP_SERVER_VERSION matches what the registry advertises.
ARG VERSION=""
RUN VERSION_RESOLVED="${VERSION:-v$(jq -r '.version' server.json)}" && \
    echo "Building with VERSION=${VERSION_RESOLVED}" && \
    CGO_ENABLED=0 go build -ldflags "-s -w -X main.MCP_SERVER_VERSION=${VERSION_RESOLVED}" -o kite-mcp-server .

# Download Litestream for SQLite backup replication
ARG LITESTREAM_VERSION=0.5.10
ADD https://github.com/benbjohnson/litestream/releases/download/v${LITESTREAM_VERSION}/litestream-${LITESTREAM_VERSION}-linux-x86_64.tar.gz /tmp/litestream.tar.gz
RUN tar -C /usr/local/bin -xzf /tmp/litestream.tar.gz

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata bash && \
    adduser -D -H appuser && \
    mkdir -p /data && chown appuser /data
COPY --from=builder /app/kite-mcp-server /usr/local/bin/
COPY LICENSE /LICENSE
COPY NOTICE /NOTICE
COPY --from=builder /usr/local/bin/litestream /usr/local/bin/litestream
COPY etc/litestream.yml /etc/litestream.yml
COPY scripts/run.sh /scripts/run.sh
RUN chmod +x /scripts/run.sh
LABEL io.modelcontextprotocol.server.name="io.github.sundeepg98/kite-trading"
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/healthz || exit 1
USER appuser
CMD ["/scripts/run.sh"]
