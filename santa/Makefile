.PHONY: build clean test deps run help

EXT=santa.ext
SRC=.

all: $(EXT)

$(EXT): santa-x86_64.ext santa-arm64.ext
	lipo -create -output $(EXT) santa-x86_64.ext santa-arm64.ext

santa-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -o santa-x86_64.ext $(SRC)

santa-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o santa-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) santa-x86_64.ext santa-arm64.ext

deps:
	go mod tidy

test: build
	@echo "Testing Santa extension..."
	@echo "Note: This requires osquery to be installed and Santa to be running"
	@echo "Run: osqueryi --extension=./santa.ext --socket=/tmp/osquery.sock"

run: build
	@echo "Starting osquery with Santa extension..."
	@echo "Make sure osquery is installed and Santa is running"
	osqueryi --extension=./santa.ext --socket=/tmp/osquery.sock

help:
	@echo "Available targets:"
	@echo "  build      - Build the Santa extension (universal binary)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Test the extension with osquery"
	@echo "  deps       - Install dependencies"
	@echo "  run        - Run with osquery"
	@echo "  help       - Show this help" 