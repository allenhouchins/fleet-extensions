.PHONY: build clean test deps all

all: snap_packages-amd64.ext snap_packages-arm64.ext

snap_packages-amd64.ext:
	GOARCH=amd64 GOOS=linux go build -o snap_packages-amd64.ext .

snap_packages-arm64.ext:
	GOARCH=arm64 GOOS=linux go build -o snap_packages-arm64.ext .

build: all

clean:
	rm -f snap_packages-amd64.ext snap_packages-arm64.ext

deps:
	go mod tidy

test:
	go test ./... 