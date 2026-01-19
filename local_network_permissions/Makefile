.PHONY: build clean test deps run help all

EXT=local_network_permissions.ext
SRC=.

all: $(EXT)

$(EXT): local_network_permissions-x86_64.ext local_network_permissions-arm64.ext
	lipo -create -output $(EXT) local_network_permissions-x86_64.ext local_network_permissions-arm64.ext

local_network_permissions-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -o local_network_permissions-x86_64.ext $(SRC)

local_network_permissions-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o local_network_permissions-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) local_network_permissions-x86_64.ext local_network_permissions-arm64.ext

deps:
	go mod tidy

test:
	go test -v ./...

run: build
	@echo "Starting osquery with local_network_permissions extension..."
	@echo "Make sure osquery is installed"
	sudo osqueryi --extension=./local_network_permissions.ext

help:
	@echo "Available targets:"
	@echo "  build      - Build the local_network_permissions extension (universal binary)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run unit tests"
	@echo "  deps       - Install dependencies"
	@echo "  run        - Run with osquery (requires sudo)"
	@echo "  help       - Show this help"
