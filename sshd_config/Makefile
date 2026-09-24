# Makefile for sshd_config osquery extension

EXT=sshd_config.ext

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w"

all: macos linux

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# macOS: architecture-specific binaries plus a universal binary
macos: $(EXT)

$(EXT): sshd_config-x86_64.ext sshd_config-arm64.ext
	lipo -create -output $(EXT) sshd_config-x86_64.ext sshd_config-arm64.ext

sshd_config-x86_64.ext:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o sshd_config-x86_64.ext .

sshd_config-arm64.ext:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o sshd_config-arm64.ext .

# Linux
linux: sshd_config-amd64.ext sshd_config-linux-arm64.ext

sshd_config-amd64.ext:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o sshd_config-amd64.ext .

sshd_config-linux-arm64.ext:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o sshd_config-linux-arm64.ext .

build: all

clean:
	$(GOCLEAN)
	rm -f $(EXT) sshd_config-x86_64.ext sshd_config-arm64.ext \
		sshd_config-amd64.ext sshd_config-linux-arm64.ext

test:
	$(GOTEST) -v ./...

# Development: run with osqueryi
dev: macos
	osqueryi --extension $(EXT)

.PHONY: all deps macos linux build clean test dev
