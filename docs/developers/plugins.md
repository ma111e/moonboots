# Plugins
Moonboots have been created with extensibility in mind. This page describe how to create a plugin and add your own loader to the program.

## TL;DR
To add a new loader, copy one of the stub below to `internal/loaders/<myloader>.go`, then implement your technique in the `Run` function.

Setting `<loader>.Injector` to `true` in the init function of your plugin will result in the program automatically handle the `target`, `args` and `pid` CLI user parameters and load the target process accordingly. You can access the target's `*windows.ProcessInformation` object in your code through the `<loader>.TargetProcess` member.

If your technique requires the target to be suspended, you can set `<loader>.SuspendProcess` to `true`. The target process' execution will be resumed after the `Run` method returns, right before closing every handle in `<loader>.TargetProcess`. 

You can also expose your own custom parameters by setting the `<loader>.ValidArgs` string array. The user will then be able to set them through the CLI with the `--option|-o` flag, e.g. `--option myparam=<value>`. Proxy CLI flags can easily be added as well for a better user experience - full details in the [Loaders arguments](#loaders-arguments) section.

Console logging is handled by [logrus](https://github.com/sirupsen/logrus).

## Standard loader
A "standard" loader boostraps the shellcode to run in the existing process. 

You will find below a simple implementation.

> Console outputs and error handling have been removed to make it easier to read. The full source code is available in `internal/loaders/createthread.go`.

```go
package loaders

import (
	"github.com/BonjourMalware/moonboots/internal/consts"
	"github.com/BonjourMalware/moonboots/internal/win32"
	"golang.org/x/sys/windows"
	"os"
	"unsafe"
)

/*
This program executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Call CreateThread on shellcode address
	5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This program leverages the functions from golang.org/x/sys/windows to call Windows procedures instead of manually loading them
*/

const LdrCreateThread = "createthread"

type CreateThreadLdr struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrCreateThread, &CreateThreadLdr{})
}

func (ldr CreateThreadLdr) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateThreadLdr) Run(shellcode []byte, _ map[string]string) error {
	addr, _ := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)

	var oldProtect uint32
	windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	CreateThread := kernel32.NewProc("CreateThread")
	thread, _, _ := CreateThread.Call(0, 0, addr, win32.Null, 0, 0)
	
	windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
	return nil
}
```

<details>
<summary><b>Stub</b> <i>(click to expand 👇)</i></summary>

```go
package loaders

import (
	"github.com/BonjourMalware/moonboots/internal/consts"
	//log "github.com/sirupsen/logrus"
)

/*
This program executes shellcode in the current process using the following steps
	1. ...
    2. ...
    3. ...

<additional notes>
*/

const LdrMyMethod = "mymethod"

type MyMethodLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrMyMethod, &MyMethodLoader{})
}

func (ldr MyMethodLoader) ValidArchs() []string {
	//return consts.VALID_ARCH_386
	//return consts.VALID_ARCH_AMD64
	return consts.VALID_ARCH_BOTH
}

func (ldr MyMethodLoader) Run(shellcode []byte, _ map[string]string) error {
	// Your code here
	return nil
}
```

</details>

## Remote loader
A "remote" loader interacts with other processes.

The main addition is the support for user-specified arguments (see [Loaders arguments](#loaders-arguments)), which can be used to inject the shellcode in a running process or to use a specific executable to spawn a dummy one.

You will find below a simple implementation.

> Console outputs and error handling have been removed to make it easier to read. The full source code is available in `internal/loaders/createremotethread.go`.

```go
package loaders

import (
	"github.com/BonjourMalware/moonboots/internal/consts"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*
This program executes shellcode in a remote process using the following steps
 1. Get a handle to the target process
 1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
 2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
 3. Change the memory page permissions to Execute/Read with VirtualProtectEx
 4. Execute the entrypoint of the shellcode in the remote process with CreateRemoteThread
 5. Close the handle to the remote process

This program leverages the functions from golang.org/x/sys/windows WHERE POSSIBLE to call Windows procedures instead of manually loading them
*/

const (
	LdrCreateRemoteThread = "createremotethread"
)

type CreateRemoteThreadLoader struct {
	Base
}

func init() {
	ldr := &CreateRemoteThreadLoader{}
	ldr.Injector = true
	ldr.SuspendProcess = true

	AvailableLoaders.Register(LdrCreateRemoteThread, ldr)
}

func (ldr CreateRemoteThreadLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateRemoteThreadLoader) Run(shellcode []byte, _ map[string]string) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	addr, _, _ := VirtualAllocEx.Call(uintptr(ldr.TargetProcess.ProcessId), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	
	WriteProcessMemory.Call(uintptr(ldr.TargetProcess.ProcessId), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	
	oldProtect := windows.PAGE_READWRITE
	VirtualProtectEx.Call(uintptr(ldr.TargetProcess.ProcessId), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	
	CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	return nil
}

```

<details>
<summary><b>Stub</b> <i>(click to expand 👇)</i></summary>

```go
package loaders

import (
	"github.com/BonjourMalware/moonboots/internal/consts"
    //log "github.com/sirupsen/logrus"
)

/*
This program executes shellcode in the current process using the following steps
	1. ...
    2. ... 
    3. ...

<additional notes>
*/

const LdrMyMethod = "mymethod"

type MyMethodLdr struct {
	Base
}

func init() {
	ldr := MyMethodLdr{}
	ldr.Injector = true
	ldr.SuspendProcess = true

	AvailableLoaders.Register(LdrMyMethod, ldr)
}

func (ldr MyMethodLdr) ValidArchs() []string {
	//return consts.VALID_ARCH_386
	//return consts.VALID_ARCH_AMD64
	return consts.VALID_ARCH_BOTH
}

func (ldr MyMethodLdr) Run(shellcode []byte, args map[string]string) error {
    // Your code here
    return nil
}
```

</details>

## Managed use
Note that the call to `ReportPID` function - used to report back the PID of the process running the shellcode to other process that would need it - is handled by the program automatically.

## Loaders arguments
### Basics
The `--option|-o <key>=<value>` flag allows the user to pass parameters to the loaders. It can be used, for example, to target a specific process via its PID when injecting a shellcode, e.g. `--option myparam=<value>`.

To make it available to your implementation, you have to add it to the `<loader>.ValidArgs` string array with `<loader>.AddValidArgs` before registering your plugin.

For example:

```go
func init() {
	ldr := &MyMethodLoader{}
	ldr.AddValidArgs([]string{"myparam"})

	AvailableLoaders.Register(LdrCreateRemoteThread, ldr)
}
```

The custom values are exposed through the `Args` string array.

### Proxy flag

Creating an alias for these custom parameters to expose them as dedicated CLI flags is a simple two steps process. First, you have to add the long name of the new CLI flag to the `aliasedArgs` string array in the `var()` declaration of the `cmd/moonboots/root.go` file. Then, register your flag in the `init` function.

For example, to add a custom parameter named *myparam*:

```go
// cmd/moonboots/root.go
var(
	[...]
    aliasedArgs = []string{"target", "args", "pid", "myparam"}
    [...]
)

func init() {
    [...]
    RootCmd.Flags().StringP("myparam", "X", "", "My custom parameter description. Alias for '-o myparam=<value>'")
    [...]
}
```

> Your argument can be anything other than string; however, you'll need to convert it to the right type in the body of the `Run` function.
