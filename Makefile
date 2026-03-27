VERSION ?= $(shell git describe --tags --always)
LDFLAGS ?= -X main.VERSION=$(VERSION)

.PHONY: generate build test docker

generate:
	go generate ./internal/schema/...

build: generate
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o fingerprint-mcp-server ./cmd/fingerprint-mcp-server

test:
	go test -v -count=1 ./...

PLATFORM ?= linux/$(shell go env GOARCH)

docker:
	docker build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t fingerprint-mcp-server .
