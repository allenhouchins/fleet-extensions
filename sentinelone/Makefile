.PHONY: build clean test deps all

all: sentinelone-darwin-amd64.ext sentinelone-darwin-arm64.ext sentinelone-windows-amd64.ext

sentinelone-darwin-amd64.ext:
	GOARCH=amd64 GOOS=darwin go build -o sentinelone-darwin-amd64.ext .

sentinelone-darwin-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o sentinelone-darwin-arm64.ext .

sentinelone-windows-amd64.ext:
	GOARCH=amd64 GOOS=windows go build -o sentinelone-windows-amd64.ext .

build: all

clean:
	rm -f sentinelone-darwin-amd64.ext sentinelone-darwin-arm64.ext sentinelone-windows-amd64.ext

deps:
	go mod tidy

test:
	go test ./...
