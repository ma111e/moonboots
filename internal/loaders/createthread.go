package loaders

import (
	"fmt"
	"github.com/ma111e/moonboots/internal/consts"
	"github.com/ma111e/moonboots/internal/win32"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*
This technique executes shellcode in the current process using the following steps
	1. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	2. Copy the shellcode to the allocated memory space
	3. Change the memory page permissions to Execute/Read with VirtualProtect
	4. Call CreateThread on shellcode address
	5. Call WaitForSingleObject so the program does not end before the shellcode is executed

This technique leverages the functions from golang.org/x/sys/windows to call Windows procedures instead of manually loading them
*/

const (
	LdrCreateThread = "createthread"
)

type CreateThreadLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrCreateThread, &CreateThreadLoader{})
}

func (ldr CreateThreadLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateThreadLoader) Run(shellcode []byte) error {
	log.Debugln("Calling VirtualAlloc for shellcode")

	addr, err := windows.VirtualAlloc(uintptr(0), uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil {
		return fmt.Errorf("Error calling VirtualAlloc: %s", err)
	}

	if addr == 0 {
		return fmt.Errorf("Errorf() failed and returned 0")
	}

	log.Printf("Allocated %d bytes", len(shellcode))

	log.Debugln("Copying shellcode to memory with copy")

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)

	log.Println("Shellcode copied to memory")

	log.Debugln("Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ")
	var oldProtect uint32
	err = windows.VirtualProtect(addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, &oldProtect)
	if err != nil {
		return fmt.Errorf("Error calling VirtualProtect: %s", err)
	}
	log.Println("Shellcode memory region changed to PAGE_EXECUTE_READ")

	log.Debugln("Calling CreateThread...")
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	CreateThread := kernel32.NewProc("CreateThread")
	thread, _, err := CreateThread.Call(0, 0, addr, win32.Null, 0, 0)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling CreateThread: %s", err)
	}
	log.Println("Shellcode Executed")

	log.Debugln("Calling WaitForSingleObject...")

	event, err := windows.WaitForSingleObject(windows.Handle(thread), 0xFFFFFFFF)
	if err != nil {
		return fmt.Errorf("Error calling WaitForSingleObject: %s", err)
	}
	log.Printf("WaitForSingleObject returned with %d", event)

	return nil
}
