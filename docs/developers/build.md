# Build
Thanks to Go, building Moonboots on Linux is not a problem. 

## CLI
The following commands will build Moonboots for moonboots on both architectures:

+ **x86**
```bash
GOOS=windows GOARCH=386 go build -o moonboots_x86.exe
```

+ **x64**
```bash
GOOS=windows GOARCH=amd64 go build -o moonboots_x64.exe
```

## Makefile
The project's Makefile contains the command to build Moonboots for x86 and x64.

```cli
$ make
>] Moonboots 🌕

  build      Builds the program for both architecture.
  build64    Builds the program for 64-bits arch.
  build32    Builds the program for 32-bits archs.
  release    Creates the release archive.
  docs       Serve the documentation.
  help       Shows this help.
```
