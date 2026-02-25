.PHONY: generate build docker

generate:
	go generate ./internal/schema/...

build: generate
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o fingerprint-mcp-server ./cmd/fingerprint-mcp-server

PLATFORM ?= linux/$(shell go env GOARCH)

docker:
	docker build --platform $(PLATFORM) --build-arg VERSION=$(VERSION) -t fingerprint-mcp-server .
