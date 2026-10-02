.PHONY: build test lint vet fmt vulncheck cover docker web refdata-snapshot
GO ?= go
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X main.version=$(VERSION)

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o bin/deckard ./cmd/deckard

test:
	$(GO) test -race -count=1 ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -l -w .

lint:
	golangci-lint run ./...

vulncheck:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

cover:
	$(GO) test -race -coverprofile=coverage.out ./... && $(GO) tool cover -func=coverage.out | tail -1

web:
	cd web && npm ci && npm run build

docker:
	docker build -t deckard:$(VERSION) .

# Regenerate the embedded fallback copies of the refreshable reference data
# (takeover fingerprints, shared-infrastructure ranges) from the live public
# sources. Run by a scheduled CI job that opens a PR when the files change.
# Pass ARGS="-only takeover|shared", "-check" or "-force" as needed.
refdata-snapshot:
	$(GO) run ./cmd/refdata-snapshot $(ARGS)
