ARG VERSION=v1.1.0
FROM golang:1.25.8-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.MCP_SERVER_VERSION=${VERSION}" -o kite-mcp-server .

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
