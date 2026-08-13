# Makefile for ai_agent_sessions osquery extension

EXT=ai_agent_sessions.ext

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
GOTEST=$(GOCMD) test
GOMOD=$(GOCMD) mod

# Build flags
LDFLAGS=-ldflags "-s -w"

all: macos linux windows

# Install dependencies
deps:
	$(GOMOD) download
	$(GOMOD) tidy

# macOS: architecture-specific binaries plus a universal binary
macos: $(EXT)

$(EXT): ai_agent_sessions-x86_64.ext ai_agent_sessions-arm64.ext
	lipo -create -output $(EXT) ai_agent_sessions-x86_64.ext ai_agent_sessions-arm64.ext

ai_agent_sessions-x86_64.ext:
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-x86_64.ext .

ai_agent_sessions-arm64.ext:
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-arm64.ext .

# Linux
linux: ai_agent_sessions-amd64.ext ai_agent_sessions-linux-arm64.ext

ai_agent_sessions-amd64.ext:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-amd64.ext .

ai_agent_sessions-linux-arm64.ext:
	GOOS=linux GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-linux-arm64.ext .

# Windows
windows: ai_agent_sessions-amd64.exe ai_agent_sessions-arm64.exe

ai_agent_sessions-amd64.exe:
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-amd64.exe .

ai_agent_sessions-arm64.exe:
	GOOS=windows GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o ai_agent_sessions-arm64.exe .

build: all

clean:
	$(GOCLEAN)
	rm -f $(EXT) ai_agent_sessions-x86_64.ext ai_agent_sessions-arm64.ext \
		ai_agent_sessions-amd64.ext ai_agent_sessions-linux-arm64.ext \
		ai_agent_sessions-amd64.exe ai_agent_sessions-arm64.exe

test:
	$(GOTEST) -v ./...

# Development: run with osqueryi
dev: macos
	osqueryi --extension $(EXT)

.PHONY: all deps macos linux windows build clean test dev
