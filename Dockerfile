# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine AS builder
RUN apk add --no-cache gcc musl-dev
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/auth-proxy-server ./cmd/server && \
    CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /out/admin-cli ./cmd/admin-cli

FROM alpine:3.24
RUN apk add --no-cache ca-certificates && \
    addgroup -S authproxy && adduser -S -u 10001 -G authproxy authproxy && \
    mkdir -p /app /data && chown authproxy:authproxy /data
WORKDIR /app
COPY --from=builder /out/auth-proxy-server /app/auth-proxy-server
COPY --from=builder /out/admin-cli /app/admin-cli
COPY --from=builder /src/templates /app/templates
USER authproxy
EXPOSE 8080
HEALTHCHECK --interval=15s --timeout=3s --start-period=30s --retries=3 \
    CMD wget -q -O /dev/null http://127.0.0.1:8080/healthz || exit 1
CMD ["/app/auth-proxy-server"]
