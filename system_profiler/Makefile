.PHONY: build clean test deps all

EXT=system_profiler.ext
SRC=.

all: $(EXT)

$(EXT): system_profiler-x86_64.ext system_profiler-arm64.ext
	lipo -create -output $(EXT) system_profiler-x86_64.ext system_profiler-arm64.ext

system_profiler-x86_64.ext:
	GOARCH=amd64 GOOS=darwin go build -o system_profiler-x86_64.ext $(SRC)

system_profiler-arm64.ext:
	GOARCH=arm64 GOOS=darwin go build -o system_profiler-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) system_profiler-x86_64.ext system_profiler-arm64.ext

deps:
	go mod tidy

test:
	go test ./... 