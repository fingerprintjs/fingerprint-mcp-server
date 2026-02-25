FROM golang:1.25-alpine AS builder

ARG VERSION=dev

WORKDIR /app

RUN apk add --no-cache make

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN make build VERSION="$VERSION"

FROM alpine:3

RUN apk add --no-cache ca-certificates

WORKDIR /app

COPY --from=builder /app/fingerprint-mcp-server /app/fingerprint-mcp-server

# 8080 can be changed to a different port via app config
EXPOSE 8080

ENTRYPOINT ["/app/fingerprint-mcp-server"]
