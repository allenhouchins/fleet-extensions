.PHONY: build clean test deps run help

EXT=mise.ext
SRC=.

all: $(EXT)

$(EXT): mise-x86_64.ext mise-arm64.ext
	lipo -create -output $(EXT) mise-x86_64.ext mise-arm64.ext

mise-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -o mise-x86_64.ext $(SRC)

mise-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o mise-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) mise-x86_64.ext mise-arm64.ext

deps:
	go mod tidy

test:
	go test -v ./...

run: build
	@echo "Starting osquery with mise extension..."
	@echo "Make sure osquery is installed"
	osqueryi --extension=./mise.ext

help:
	@echo "Available targets:"
	@echo "  build      - Build the mise extension (universal binary)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Run unit tests"
	@echo "  deps       - Install dependencies"
	@echo "  run        - Run with osquery"
	@echo "  help       - Show this help"
