# Makefile for softwareupdate osquery extension

BINARY_NAME=softwareupdate.ext
X86_64_BINARY=softwareupdate-x86_64.ext
ARM64_BINARY=softwareupdate-arm64.ext

GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

LDFLAGS=-ldflags "-s -w"

all: deps build

deps:
	$(GOMOD) download
	$(GOMOD) tidy

$(BINARY_NAME): $(X86_64_BINARY) $(ARM64_BINARY)
	lipo -create -output $(BINARY_NAME) $(X86_64_BINARY) $(ARM64_BINARY)

$(X86_64_BINARY):
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(X86_64_BINARY) -v

$(ARM64_BINARY):
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(ARM64_BINARY) -v

build: $(BINARY_NAME)

build-all: $(BINARY_NAME)

clean:
	$(GOCLEAN)
	rm -f $(BINARY_NAME) $(X86_64_BINARY) $(ARM64_BINARY)

test:
	$(GOTEST) -v ./...

install: build
	sudo cp $(BINARY_NAME) /usr/local/bin/

uninstall:
	sudo rm -f /usr/local/bin/$(BINARY_NAME)

dev: build
	osqueryi --extension $(BINARY_NAME)

.PHONY: all deps build build-all clean test install uninstall dev
