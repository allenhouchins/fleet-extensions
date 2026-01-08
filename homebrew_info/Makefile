# Makefile for homebrew_info osquery extension

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod

# Binary names
BINARY_NAME=homebrew_info.ext
BINARY_UNIX=$(BINARY_NAME)

# Build flags
LDFLAGS=-ldflags "-s -w"

# Default target
all: deps build

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# Build the extension
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) -v

# Build for multiple platforms
build-all:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-amd64 -v
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-arm64 -v

# Clean build artifacts
clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-*

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

