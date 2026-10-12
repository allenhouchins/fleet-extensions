# Makefile for apple_accounts osquery extension

EXT=apple_accounts.ext

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w"

all: $(EXT)

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Architecture-specific binaries plus a universal binary
$(EXT): apple_accounts-x86_64.ext apple_accounts-arm64.ext
	lipo -create -output $(EXT) apple_accounts-x86_64.ext apple_accounts-arm64.ext

apple_accounts-x86_64.ext:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o apple_accounts-x86_64.ext .

apple_accounts-arm64.ext:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o apple_accounts-arm64.ext .

build: all

clean:
	$(GOCLEAN)
	rm -f $(EXT) apple_accounts-x86_64.ext apple_accounts-arm64.ext

test:
	$(GOTEST) -v ./...

# Development: run with osqueryi. Reading other users' accounts databases
# needs root and Full Disk Access.
dev: all
	sudo osqueryi --extension $(EXT) --allow-unsafe

.PHONY: all deps build clean test dev
