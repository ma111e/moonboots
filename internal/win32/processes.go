package win32

import (
	"fmt"
	"golang.org/x/sys/windows"
)

func SuspendProcess(pid uint32) error {
	kernel32 := windows.NewLazyDLL("kernel32.dll")
	suspendThread := kernel32.NewProc("SuspendThread")

	threads, err := ListThreads(pid)
	if err != nil {
		return fmt.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		thread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			return fmt.Errorf("could not open thread %d, reason: %w", tid, err)
		}

		r0, _, err := suspendThread.Call(uintptr(thread))
		if r0 == DwordNegativeOne {
			return fmt.Errorf("could not suspend thread %d, reason: %w", tid, err)
		}
	}
	return nil
}

func ResumeProcess(pid uint32) error {
	threads, err := ListThreads(pid)
	if err != nil {
		return fmt.Errorf("could not list process threads, reason: %w", err)
	}
	for _, tid := range threads {
		hThread, err := windows.OpenThread(windows.THREAD_SUSPEND_RESUME, false, tid)
		if err != nil {
			return fmt.Errorf("could not open thread %d, reason: %w", tid, err)
		}
		_, err = windows.ResumeThread(hThread)
		windows.CloseHandle(hThread)

		if err != nil {
			return fmt.Errorf("could not open resume thread %d, reason: %w", tid, err)
		}
	}

	return nil
}
