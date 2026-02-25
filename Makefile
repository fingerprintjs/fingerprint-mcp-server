TAG     ?= $(shell git describe --tags --abbrev=0 2>/dev/null || echo untagged)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
VERSION ?= $(TAG)+$(COMMIT)

MODULE  = github.com/fingerprintjs/fingerprint-mcp-server
LDFLAGS = -X 'main.VERSION=$(VERSION)'

.PHONY: generate build docker

generate:
	go generate ./internal/schema/...

build: generate
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o fingerprint-mcp-server ./cmd/fingerprint-mcp-server

PLATFORM ?= linux/$(shell go env GOARCH)

docker:
	docker build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t fingerprint-mcp-server .
