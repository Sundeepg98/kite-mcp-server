FROM golang:1.24-alpine AS builder
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o kite-mcp-server .

FROM alpine:latest
RUN apk add --no-cache ca-certificates tzdata
COPY --from=builder /app/kite-mcp-server /usr/local/bin/
CMD ["kite-mcp-server"]
