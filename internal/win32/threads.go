package win32

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/saferwall/pe"
	"golang.org/x/sys/windows"
	"reflect"
	"syscall"
	"unsafe"
)

const (
	ThreadQuerySetWin32StartAddress uintptr = 0x09
)

func GetMainThread(proc windows.Handle) (windows.Handle, uint32, error) {
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	NtQueryInformationThread := ntdll.NewProc("NtQueryInformationThread")

	ReadProcessMemory := kernel32.NewProc("ReadProcessMemory")
	QueryFullProcessImageNameW := kernel32.NewProc("QueryFullProcessImageNameW")

	var procBasicInfo windows.PROCESS_BASIC_INFORMATION
	var returnLength uint32

	err := windows.NtQueryInformationProcess(proc, windows.ProcessBasicInformation, unsafe.Pointer(&procBasicInfo), uint32(reflect.TypeOf(procBasicInfo).Size()), &returnLength)
	if err != nil {
		return 0, 0, err
	}

	var peb windows.PEB
	_, _, err = ReadProcessMemory.Call(uintptr(proc), uintptr(unsafe.Pointer(procBasicInfo.PebBaseAddress)), uintptr(unsafe.Pointer(&peb)), unsafe.Sizeof(peb), Null)
	if err != nil && err != windows.ERROR_SUCCESS {
		return 0, 0, nil
	}

	var imageFilename string
	for bufLen, limit := syscall.MAX_PATH, syscall.MAX_PATH*4; bufLen <= limit; bufLen *= 2 {
		buf := make([]uint16, bufLen)
		_, _, _ = QueryFullProcessImageNameW.Call(uintptr(proc), Null, uintptr(unsafe.Pointer(&buf[0])), uintptr(unsafe.Pointer(&bufLen)))
		if int(bufLen) > 0 {
			imageFilename = windows.UTF16ToString(buf[:bufLen])
			break
		}
	}
	if imageFilename == "" {
		return 0, 0, errors.Wrap(err, "Failed to fetch target process image full path: insufficient buffer")
	}

	peHeader, err := pe.New(imageFilename, &pe.Options{})
	if err != nil {
		return 0, 0, err
	}

	err = peHeader.Parse()
	if err != nil {
		return 0, 0, err
	}

	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, uint32(procBasicInfo.UniqueProcessId))
	if err != nil {
		return 0, 0, err
	}

	if snap == windows.InvalidHandle {
		return 0, 0, err
	}

	var threadEntry windows.ThreadEntry32
	threadEntry.Size = uint32(reflect.TypeOf(threadEntry).Size())

	err = windows.Thread32First(snap, &threadEntry)
	if err != nil {
		return 0, 0, err
	}

	var mainThreadID uint32
	var mainThread windows.Handle

	for {
		err = windows.Thread32Next(snap, &threadEntry)
		if err == windows.ERROR_NO_MORE_FILES {
			break
		}

		if err != nil {
			return 0, 0, errors.Wrap(err, "failed to fetch main thread ID")
		}

		if threadEntry.OwnerProcessID != uint32(procBasicInfo.UniqueProcessId) {
			continue
		}

		thread, err := windows.OpenThread(windows.THREAD_QUERY_INFORMATION, false, threadEntry.ThreadID)
		if err != nil {
			return 0, 0, err
		}

		var ThreadQuerySetWin32StartAddress uintptr = 0x09
		var threadStartAddr uintptr
		ntStatus, _, err := NtQueryInformationThread.Call(uintptr(thread), ThreadQuerySetWin32StartAddress, uintptr(unsafe.Pointer(&threadStartAddr)), reflect.TypeOf(threadStartAddr).Size(), uintptr(0))
		if err != nil && ntStatus != uintptr(windows.ERROR_SUCCESS) {
			return 0, 0, fmt.Errorf(fmt.Sprintf("error calling NtQueryInformationThread:\n\t%s", err))
		}
		if ntStatus != uintptr(windows.ERROR_SUCCESS) {

			return 0, 0, fmt.Errorf(fmt.Sprintf("NtQueryInformationThread returned NTSTATUS: %x(%d).", ntStatus, ntStatus) + fmt.Sprintf("error calling NtQueryInformationThread:\n\t%s", syscall.Errno(ntStatus)))
		}

		var entryPoint uint32
		if peHeader.Is32 {
			optionalHeader := peHeader.NtHeader.OptionalHeader.(pe.ImageOptionalHeader32)
			entryPoint = optionalHeader.AddressOfEntryPoint
		} else {
			optionalHeader := peHeader.NtHeader.OptionalHeader.(pe.ImageOptionalHeader64)
			entryPoint = optionalHeader.AddressOfEntryPoint
		}

		if uintptr(entryPoint)+peb.ImageBaseAddress == threadStartAddr {
			mainThreadID = threadEntry.ThreadID
			mainThread = thread
			break
		}
	}

	return mainThread, mainThreadID, nil
}

func ListThreads(pid uint32) ([]uint32, error) {
	snap, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		return nil, err
	}

	threadIDs := make([]uint32, 0)

	var threadEntry windows.ThreadEntry32
	threadEntry.Size = uint32(unsafe.Sizeof(threadEntry))

	err = windows.Thread32First(snap, &threadEntry)
	if err != nil {
		if err != windows.ERROR_NO_MORE_FILES {
			return nil, err
		} else {
			return nil, nil
		}
	}
	if threadEntry.OwnerProcessID == pid {
		threadIDs = append(threadIDs, threadEntry.ThreadID)
	}
	for {
		err = windows.Thread32Next(snap, &threadEntry)
		if err != nil {
			break
		}
		if threadEntry.OwnerProcessID == pid {
			threadIDs = append(threadIDs, threadEntry.ThreadID)
		}
	}
	if err != windows.ERROR_NO_MORE_FILES {
		return nil, err
	}
	return threadIDs, nil
}
