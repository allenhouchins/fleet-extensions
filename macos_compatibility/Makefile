EXT=macos_compatibility.ext
SRC=macos_compatibility.go

all: $(EXT)

$(EXT): macos_compatibility-x86_64.ext macos_compatibility-arm64.ext
	lipo -create -output $(EXT) macos_compatibility-x86_64.ext macos_compatibility-arm64.ext

macos_compatibility-x86_64.ext: $(SRC)
	GOARCH=amd64 GOOS=darwin go build -o macos_compatibility-x86_64.ext $(SRC)

macos_compatibility-arm64.ext: $(SRC)
	GOARCH=arm64 GOOS=darwin go build -o macos_compatibility-arm64.ext $(SRC)

build: all

clean:
	rm -f $(EXT) macos_compatibility-x86_64.ext macos_compatibility-arm64.ext

deps:
	go mod tidy 