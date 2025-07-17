EXT=nuget_packages.ext
SRC=main.go

all: macos windows

macos: $(EXT)

$(EXT): nuget_packages-x86_64.ext nuget_packages-arm64.ext
	lipo -create -output $(EXT) nuget_packages-x86_64.ext nuget_packages-arm64.ext

nuget_packages-x86_64.ext: $(SRC)
	GOARCH=amd64 GOOS=darwin go build -o nuget_packages-x86_64.ext $(SRC)

nuget_packages-arm64.ext: $(SRC)
	GOARCH=arm64 GOOS=darwin go build -o nuget_packages-arm64.ext $(SRC)

windows: nuget_packages-amd64.exe nuget_packages-arm64.exe

nuget_packages-amd64.exe: $(SRC)
	GOARCH=amd64 GOOS=windows go build -o nuget_packages-amd64.exe $(SRC)

nuget_packages-arm64.exe: $(SRC)
	GOARCH=arm64 GOOS=windows go build -o nuget_packages-arm64.exe $(SRC)

build: all

clean:
	rm -f $(EXT) nuget_packages-x86_64.ext nuget_packages-arm64.ext nuget_packages-amd64.exe nuget_packages-arm64.exe

deps:
	go mod tidy

tidy:
	go mod tidy 