package elevate

import (
	"github.com/ma111e/moonboots/internal/win32"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/windows"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func RequireElevated() error {
	currentProcToken := windows.GetCurrentProcessToken()
	integrity, err := win32.GetTokenIntegrityLevel(currentProcToken)
	if err != nil {
		return errors.Wrap(err, "failed to get token integrity level")
	} else {
		log.Info("Process has integrity: ", strings.ToUpper(win32.IntegrityMapping[integrity]))

		if integrity < win32.SECURITY_MANDATORY_HIGH_RID {
			log.Info("Restarting with admin privileges")
			keepConsole := true
			err = RerunElevatedWithPID(os.Args[1:], keepConsole)
			if err != nil {
				return err
			}

			os.Exit(0)
		}
	}

	return nil
}

func RerunElevatedWithPID(args []string, keepConsole bool) error {
	executable, err := os.Executable()
	if err != nil {
		return err
	}

	exeFullpath, err := filepath.Abs(executable)
	if err != nil {
		return err
	}

	log.Infof("Running %s %s", exeFullpath, args)
	return RunAs(exeFullpath, args, keepConsole)
}

func RunAs(exe string, args []string, keepConsole bool) error {
	verb := "runas"

	verbPtr, _ := syscall.UTF16PtrFromString(verb)
	exePtr, _ := syscall.UTF16PtrFromString("cmd.exe")
	cwd, err := os.Getwd()
	if err != nil {
		return err
	}

	args = append([]string{"cd", "/d", cwd, "&&", exe}, args...)
	if keepConsole {
		args = append([]string{"/k"}, args...)
	}

	argPtr, _ := syscall.UTF16PtrFromString(strings.Join(args, " "))

	var showCmd int32 = 1 //SW_NORMAL

	err = windows.ShellExecute(0, verbPtr, exePtr, argPtr, nil, showCmd)
	if err != nil {
		return err
	}

	return nil
}
