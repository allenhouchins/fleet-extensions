.PHONY: build clean test deps all

all: ubuntu_pro-amd64.ext ubuntu_pro-arm64.ext

ubuntu_pro-amd64.ext:
	GOARCH=amd64 GOOS=linux go build -o ubuntu_pro-amd64.ext .

ubuntu_pro-arm64.ext:
	GOARCH=arm64 GOOS=linux go build -o ubuntu_pro-arm64.ext .

build: all

clean:
	rm -f ubuntu_pro-amd64.ext ubuntu_pro-arm64.ext

deps:
	go mod tidy

test:
	go test ./...
