## Description
Moonboots helps malware analysts bootstrap shellcode through multiple methods.

It currently implements multiple shellcode loading techniques in pure Go based on [Ne0nd0g](https://github.com/Ne0nd0g/go-shellcode)'s work and can be easily extended by adding new loader plugins.

## Documentation
Docs available on [https://ma111e.github.io/moonboots/](https://ma111e.github.io/moonboots/).

## Usage
```cli
Usage:
  moonboots [flags]

Examples:
# Run an hex or base64-encoded shellcode using the default "createthread" method
  moonboots.exe -s <shellcode>

# Fetch the shellcode from the clipboard
  moonboots.exe -c

# Clean the input to only keep hexadecimal values. This allows for quick testing of shellcodes coming from various sources without having to clean it first, like C source code or \x and 0x prefixed shellcode 
  moonboots.exe -c --dirty-hex

# Inject the shellcode contained in the file into a new cmd.exe process using the "etwpcreateetwthread" method
  moonboots.exe -m etwpcreateetwthread --target cmd.exe -s <shellcode>
  moonboots.exe -m etwpcreateetwthread --target cmd.exe -f <filepath>

# Inject the shellcode into the current process with the given PID using the "createremotethread" method
  moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>

# Check if a specific method is working
  moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>

# Inject the shellcode into the current process with the given PID using the "createremotethread" method
  moonboots.exe -m <method> --demo

# Calc.exe shellcodes:
## x86: fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5636d642e657865202f432063616c632e65786500
## x64: fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500

Flags:
  -A, --admin                   Self elevate to high-integrity if needed (might trigger UAC)
  -a, --args string             Args to pass to the new process. Alias for '-o args="<cli>"'
  -c, --clipboard               Fetch shellcode from the clipboard
  -d, --debug                   Debug output
  -D, --demo                    Execute a built-in demo shellcode spawning calc.exe
  -C, --dirty-hex               Attempt to clean the shellcode by keeping only hexadecimal values ([a-fA-F0-9]). 
  -f, --file string             File containing the shellcode to load in raw, hex or base64 format
  -h, --help                    help for moonboots
  -i, --idle                    Enter an infinite loop before starting the shellcode to allow debugger to attach
  -m, --method string           Method to use to load the shellcode. Available: [createfiber createremotethreadnative createthread createthreadnative queueapc createprocess createremotethread earlybird etwpcreate rtlcreateuserthread syscall uuid] (default "createthread")
  -o, --option stringToString   Set options for the loader, such as the target program to inject your shellcode in. Repeat it for each option, as many times as needed, e.g. '-o target=notepad.exe -o args="C:\users\user\Desktop\mydoc.txt"' (default [])
  -p, --pid string              PID of the process to target. Alias for '-o pid=<PID>'
  -P, --pid-pipe string         Specify the name of the rendez-vous pipe to pass the PID of the loaded shellcode to the parent process. This feature is enabled only if this flag is used
  -E, --priv-debug              Enable debug privileges. The program will self elevate to high-integrity if the current rights are too low (might trigger UAC)
  -e, --sc-encoding string      Specify the encoding of the input shellcode if the wrong one is selected automatically. This would be required for base64-encoded shellcode that would result in a valid hex-encoded string or ascii shellcode. Valid encodings: [base64 hex raw]
  -s, --shellcode string        Shellcode in hex (i.e. '50515253...') or base64 format (i.e. 'UFFSU1ZX...')
  -t, --target string           Target executable to inject shellcode into. Alias for '-o target="<path>"'
  -v, --verbose                 Verbose output
      --version                 version for moonboots
```
