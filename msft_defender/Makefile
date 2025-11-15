.PHONY: build clean test deps run help

EXT=mdatp_extension.ext
SRC=.

all: $(EXT)

$(EXT): mdatp_extension-x86_64.ext mdatp_extension-arm64.ext
	lipo -create -output $(EXT) mdatp_extension-x86_64.ext mdatp_extension-arm64.ext

mdatp_extension-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -o mdatp_extension-x86_64.ext $(SRC)

mdatp_extension-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o mdatp_extension-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) mdatp_extension-x86_64.ext mdatp_extension-arm64.ext

deps:
	go mod tidy

test: build
	@echo "Testing Microsoft Defender extension..."
	@echo "Note: This requires osquery to be installed and Microsoft Defender to be running"
	@echo "Run: osqueryi --extension=./mdatp_extension.ext --socket=/tmp/osquery.sock"

run: build
	@echo "Starting osquery with Microsoft Defender extension..."
	@echo "Make sure osquery is installed and Microsoft Defender is running"
	osqueryi --extension=./mdatp_extension.ext --socket=/tmp/osquery.sock

help:
	@echo "Available targets:"
	@echo "  build      - Build the Microsoft Defender extension (universal binary)"
	@echo "  clean      - Remove build artifacts"
	@echo "  test       - Test the extension with osquery"
	@echo "  deps       - Install dependencies"
	@echo "  run        - Run with osquery"
	@echo "  help       - Show this help"

