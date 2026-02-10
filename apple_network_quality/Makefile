.PHONY: build clean test deps all

EXT=apple_network_quality.ext
SRC=.

all: $(EXT)

# Create universal binary from architecture-specific binaries
$(EXT): apple_network_quality-x86_64.ext apple_network_quality-arm64.ext
	lipo -create -output $(EXT) apple_network_quality-x86_64.ext apple_network_quality-arm64.ext

# Build Intel/x86_64 binary
apple_network_quality-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -ldflags "-s -w" -o apple_network_quality-x86_64.ext $(SRC)

# Build ARM64/Apple Silicon binary
apple_network_quality-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -ldflags "-s -w" -o apple_network_quality-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) apple_network_quality-x86_64.ext apple_network_quality-arm64.ext

deps:
	go mod tidy

test:
	go test -v ./...
