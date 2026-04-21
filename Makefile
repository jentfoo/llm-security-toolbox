export GO111MODULE = on

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -ldflags "-s -w -X github.com/go-appsec/toolbox/sectool/config.Version=$(VERSION)"

ifneq ($(shell command -v bash),)
test test-all: SHELL := bash
test test-all: .SHELLFLAGS := -o pipefail -c
_FILTER := | grep -v "no test files"
endif

.PHONY: build build-sectool build-secagent build-cross clean test test-all test-cover bench lint

build: build-sectool build-secagent

build-sectool:
	@mkdir -p bin
	go build $(LDFLAGS) -o bin/sectool ./sectool

build-secagent:
	@mkdir -p bin
	cd controller/secagent && go build -o ../../bin/secagent ./cmd/secagent

PLATFORMS := linux-amd64 linux-arm64 darwin-amd64 darwin-arm64 windows-amd64 windows-arm64

build-cross:
	@mkdir -p bin
	@for platform in $(PLATFORMS); do \
		os=$$(echo $$platform | cut -d'-' -f1); \
		arch=$$(echo $$platform | cut -d'-' -f2); \
		ext=""; \
		if [ "$$os" = "windows" ]; then ext=".exe"; fi; \
		echo "Building sectool for $$os/$$arch..."; \
		GOOS=$$os GOARCH=$$arch go build $(LDFLAGS) -o bin/sectool-$$platform$$ext ./sectool; \
		if [ "$$os" = "windows" ]; then \
			(cd bin && zip sectool-$$platform.zip sectool-$$platform$$ext && rm sectool-$$platform$$ext); \
		else \
			gzip bin/sectool-$$platform; \
		fi; \
	done

clean:
	rm -rf bin/

test:
	go test -short ./... $(_FILTER)
	cd controller/secagent && go test -short ./... $(_FILTER)

test-all:
	go test -race -cover ./... $(_FILTER)
	cd controller/secagent && go test -race -cover ./... $(_FILTER)

test-cover:
	go test -race -coverprofile=test.out ./... && go tool cover --html=test.out

bench:
	go test --benchmem -benchtime=20s -bench='Benchmark.*' -run='^$$' ./...

lint:
	golangci-lint run --timeout=600s && go vet ./...
	cd controller/secagent && golangci-lint run --timeout=600s --config=$(CURDIR)/.golangci.yml && go vet ./...
