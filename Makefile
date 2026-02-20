TAG     ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo untagged)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION ?= $(TAG)+$(COMMIT)

MODULE  = github.com/fingerprintjs/fingerprint-mcp-server
LDFLAGS = -X '$(MODULE)/internal/config.VERSION=$(VERSION)'

.PHONY: generate build docker

generate:
	go run ./cmd/generate-schema

build: generate
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o fingerprint-mcp-server ./cmd/fingeprint-mcp-server

docker:
	docker build --build-arg VERSION=$(VERSION) -t fingerprint-mcp-server .
