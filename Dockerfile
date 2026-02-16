# Build stage
FROM golang:1.23-alpine AS builder

WORKDIR /app

# Install git (required for fetching dependencies)
RUN apk add --no-cache git

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the binary
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o fingerprint-mcp-server .

# Runtime stage
FROM alpine:latest

RUN apk --no-cache add ca-certificates

WORKDIR /app

# Copy the binary from builder
COPY --from=builder /app/fingerprint-mcp-server .

# Expose port for SSE transport
EXPOSE 8080

# Default to stdio transport
ENTRYPOINT ["/app/fingerprint-mcp-server"]
