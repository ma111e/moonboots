package loaders

import (
	"encoding/binary"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/ma111e/moonboots/internal/settings"
	"github.com/ma111e/moonboots/internal/win32"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"syscall"
	"time"
)

type Base struct {
	Loader
	Settings
	TargetProcess *windows.ProcessInformation
	Args          map[string]string

	Error error

	//validArgs []string
	//Injector       bool
	//SuspendProcess bool
}

func (b *Base) IsInjector() bool {
	return b.Injector
}

func (b *Base) SetError(err error) {
	b.Error = err
}

func (b *Base) HasError() bool {
	return b.Error != nil
}

// Cleanup handles restoring the system to a stable state after running the shellcode. Mostly needed for injection techniques
func (b *Base) Cleanup() error {
	if b.TargetProcess != nil {
		time.Sleep(500 * time.Millisecond)

		if b.SuspendProcess {
			log.Debugln("Resuming target process...")
			err := win32.ResumeProcess(b.TargetProcess.ProcessId)
			if err != nil {
				log.WithField("err", err).Warnf("failed to resume target process")
			}
		}

		if settings.DelayOnReturn > 0 {
			log.WithField("delay", settings.DelayOnReturn.String()).Println("Delaying cleanup...")
			time.Sleep(settings.DelayOnReturn)
		}

		if b.HasError() && !settings.Keep {
			err := windows.TerminateProcess(b.TargetProcess.Process, 0)
			if err != nil {
				log.WithField("err", err).Warnf("failed to terminate process")
			} else {
				return nil
			}
		}

		if b.TargetProcess.Process > 0 {
			log.Debugln("Calling CloseHandle on target process...")
			err := windows.CloseHandle(b.TargetProcess.Process)
			if err != nil {
				log.WithField("err", err).Warnf("failed to close target process handle")
			}
		}

		if b.TargetProcess.Thread > 0 {
			log.Debugln("Calling CloseHandle on target process thread...")
			err := windows.CloseHandle(b.TargetProcess.Thread)
			if err != nil {
				log.WithField("err", err).Warnf("failed to close target's thread handle")
			}
		}

	}

	return nil
}

// LoadTarget populates the target process information.
// It's a proxy method that automatically spawns the dummy process and returns its data, or build it from a remote process if the --pid flag is passed.
// It returns a full windows.ProcessInformation object.
func (b *Base) LoadTarget() error {
	var err error

	if pid, ok := b.Args["pid"]; ok {
		var iPid int
		iPid, err = strconv.Atoi(pid)
		if err != nil {
			return err
		}

		b.TargetProcess, err = b.NewProcInfoFromPID(iPid)
		if err != nil {
			return err
		}

		if b.SuspendProcess {
			err = win32.SuspendProcess(uint32(iPid))
			if err != nil {
			}
			return err
		}
	} else {
		b.TargetProcess, err = b.SpawnDummyProc()
	}

	return err
}

// NewProcInfoFromPID fetches a remote windows.ProcessInformation from its PID
func (b *Base) NewProcInfoFromPID(pid int) (*windows.ProcessInformation, error) {
	proc, err := windows.OpenProcess(
		win32.PROCESS_ALL_ACCESS,
		false,
		uint32(pid),
	)
	if err != nil {
		return nil, errors.Wrapf(err, "Check that the specified process is still running. Failed to open process with PID %d", pid)
	}

	/////
	// Failed to find a way to cast the rawPeb byte array to a windows.PEB struct, falling back to raw API call

	//var peb windows.PEB
	//rawPeb := make([]byte, int(reflect.TypeOf(peb).Size()))
	//err = windows.ReadProcessMemory(proc, uintptr(unsafe.Pointer(procBasicInfo.PebBaseAddress)), &rawPeb[0], reflect.TypeOf(rawPeb).Size(), nil)
	//if err != nil {
	//	return nil, err
	//}
	//
	//err = binary.Read(bytes.NewBuffer(rawPeb[:]), binary.BigEndian, &peb)
	//if err != nil {
	//	return nil, err
	//}

	mainThreadHandle, mainthreadID, err := win32.GetMainThread(proc)
	if err != nil {
		return nil, errors.Wrap(err, "failed to find the main thread")
	}

	if mainthreadID == 0 {
		return nil, fmt.Errorf("Failed to find main thread ID")
	}

	procInfo := &windows.ProcessInformation{
		Process:   proc,
		Thread:    mainThreadHandle,
		ProcessId: uint32(pid),
		ThreadId:  mainthreadID,
	}

	return procInfo, nil
}

// SpawnDummyProc spawns a new dummy process in a suspended state and returns its windows.ProcessInformation
func (b *Base) SpawnDummyProc() (*windows.ProcessInformation, error) {
	target := "C:\\Windows\\System32\\notepad.exe"
	if argsTarget, ok := b.Args["target"]; ok {
		absTargetPath := argsTarget

		if !filepath.IsAbs(argsTarget) {
			var err error
			absTargetPath, err = exec.LookPath(argsTarget)
			if err != nil {
				log.Printf("Binary '%s' not found in PATH. Try using the full path instead.\n", argsTarget)
			}
		}

		target = absTargetPath
	}

	cli := ""
	if argsCli, ok := b.Args["args"]; ok {
		cli = argsCli
	}

	targetProcNameUTF16, _ := syscall.UTF16PtrFromString(target)
	cliUTF16, _ := syscall.UTF16PtrFromString(cli)

	log.Debugf("Calling CreateProcess to start: %s %s...", target, cli)

	var startupFlags uint32 = windows.STARTF_USESTDHANDLES | windows.DETACHED_PROCESS

	if b.SuspendProcess {
		startupFlags |= windows.CREATE_SUSPENDED
	}

	startupInfo := &windows.StartupInfo{
		Flags:      startupFlags,
		ShowWindow: 1,
	}
	procInfo := &windows.ProcessInformation{}

	err := windows.CreateProcess(targetProcNameUTF16, cliUTF16, nil, nil, true, windows.CREATE_SUSPENDED, nil, nil, startupInfo, procInfo)
	if err != nil && err != windows.ERROR_SUCCESS {
		return nil, fmt.Errorf("Error calling CreateProcess: %s", err)
	}

	log.Printf("Successfully createdd the %s process (PID %d)", target, procInfo.ProcessId)

	return procInfo, nil
}

// Parse loads the arbitrary arguments given by the user into the loader. It returns an error if an unknown or erroneous
// argument is passed. Calling Parse is REQUIRED before using the loader's args.
func (b *Base) Parse(args map[string]string) error {
	b.Args = map[string]string{}
	for name, val := range args {
		var found bool
		for _, valid := range b.ValidArgs {
			if name == valid {
				found = true
				break
			}
		}

		if !found {
			return fmt.Errorf("unsupported arg: %s", name)
		}

		b.Args[name] = val
	}

	return nil
}

// AddValidArgs merges the given args with the current ValidArgs array
func (b *Base) AddValidArgs(args []string) {
	for _, arg := range args {
		var exists bool

		for _, existing := range b.ValidArgs {
			if arg == existing {
				exists = true
				break
			}
		}

		if !exists {
			b.ValidArgs = append(b.ValidArgs, arg)
		}
	}
}

// ReportPID sends back the PID of the target process through a named pipe.
// Its name is set via the --pid-pipe flag, which is stored in the settings.PIDPipeName global variable.
// This feature is needed when Moonboots is called by another process for synchronization purposes.
// In this case, the parent process is responsible for passing the rendez-vous pipe name.
func (b *Base) ReportPID() error {
	if settings.PIDPipeName == "" {
		return nil
	}

	conn, err := winio.DialPipe(settings.PIDPipeName, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

	var pid uint32
	if b.Injector {
		pid = b.TargetProcess.ProcessId
	} else {
		pid = uint32(os.Getpid())
	}

	buffer := make([]byte, 4)
	binary.LittleEndian.PutUint32(buffer, pid)
	_, err = conn.Write(buffer)
	if err != nil {
		return err
	}
	return nil
}
