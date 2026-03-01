ARG VERSION=v0.0.0
FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION
RUN CGO_ENABLED=0 go build -ldflags "-s -w -X main.MCP_SERVER_VERSION=${VERSION}" -o kite-mcp-server .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates tzdata && \
    adduser -D -H appuser && \
    mkdir -p /data && chown appuser /data
COPY --from=builder /app/kite-mcp-server /usr/local/bin/
HEALTHCHECK --interval=30s --timeout=3s CMD wget -qO- http://localhost:8080/ || exit 1
USER appuser
CMD ["kite-mcp-server"]
