# Makefile for homebrew_info osquery extension

# Binary names
BINARY_NAME=homebrew_info.ext
X86_64_BINARY=homebrew_info-x86_64.ext
ARM64_BINARY=homebrew_info-arm64.ext

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w"

# Default target
all: deps build

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build universal binary (requires both architecture-specific binaries)
$(BINARY_NAME): $(X86_64_BINARY) $(ARM64_BINARY)
	lipo -create -output $(BINARY_NAME) $(X86_64_BINARY) $(ARM64_BINARY)

# Build x86_64 (Intel) binary
$(X86_64_BINARY):
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(X86_64_BINARY) -v

# Build arm64 (Apple Silicon) binary
$(ARM64_BINARY):
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(ARM64_BINARY) -v

# Build the extension (universal binary)
build: $(BINARY_NAME)

# Build for multiple platforms (creates all three binaries)
build-all: $(BINARY_NAME)

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(X86_64_BINARY) $(ARM64_BINARY)

# Run tests
test:
	$(GOTEST) -v ./...

# Install the extension (requires sudo)
install: build
	sudo cp $(BINARY_NAME) /usr/local/bin/

# Uninstall the extension
uninstall:
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

# Development: run with osqueryi
dev: build
	osqueryi --extension $(BINARY_NAME)

.PHONY: all deps build build-all clean test install uninstall dev

