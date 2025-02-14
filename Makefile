.PHONY: docs

default: help

## build : Builds the program for both architecture
build: build64 build32

## build64 : Builds the program for 64-bits arch
build64:
	GOOS=windows GOARCH=amd64 go build -o moonboots_x64.exe

## build32 : Builds the program for 32-bits archs
build32:
	GOOS=windows GOARCH=386 go build -o moonboots_x86.exe

## release : Creates and push the release archive
release: build32
	VERSION=$(shell wine ./moonboots_x86.exe --version|cut -d" " -f 3) goreleaser release --clean
	rm -f dist/moonboots_release_all.zip
	zip -j -r dist/moonboots_release_all.zip dist/**/*.exe
	zip -r dist/moonboots_release_all.zip LICENSE README.md demo/

## docs : Serve the documentation
docs:
	docsify serve ./docs

## help : Shows this help
help: Makefile
	@printf ">] Moonboots 🌕\n\n"
	@sed -n 's/^##//p' $< | column -t -s ':' |  sed -e 's/^/ /'
	@printf ""
