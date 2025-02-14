package moonboots

import (
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/Microsoft/go-winio"
	"github.com/d-tsuji/clipboard"
	"github.com/ma111e/moonboots/internal/consts"
	"github.com/ma111e/moonboots/internal/elevate"
	"github.com/ma111e/moonboots/internal/loaders"
	"github.com/ma111e/moonboots/internal/settings"
	"github.com/ma111e/moonboots/internal/strutils"
	"github.com/ma111e/moonboots/internal/win32"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/spf13/viper"
	"os"
	"regexp"
	"runtime"
	"strings"
)

var (
	RootCmd = &cobra.Command{
		Use:     "moonboots [flags]",
		Version: "1.0.0",
		Example: fmt.Sprintf(`# Run an hex or base64-encoded shellcode using the default "createthread" method
  moonboots.exe -s <shellcode>

# Fetch the shellcode from the clipboard
  moonboots.exe -c

# Clean the input to only keep hexadecimal values. This allows for quick testing of shellcodes coming from various sources without having to clean it first, like C source code or \x and 0x prefixed shellcode 
  moonboots.exe -Cc

# Inject the shellcode contained in the file into a new cmd.exe process using the "etwpcreate" method
  moonboots.exe -m etwpcreate --target cmd.exe -s <shellcode>
  moonboots.exe -m etwpcreate --target cmd.exe -f <filepath>

# Inject the shellcode into the current process with the given PID using the "createremotethread" method
  moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>
  
# Check if a specific method is working
  moonboots.exe --pid <x86 process PID> -m createremotethread -s <shellcode>

# Inject the shellcode into the current process with the given PID using the "createremotethread" method
  moonboots.exe -m <method> --demo

# Calc.exe shellcodes:
## x86: fce8820000006089e531c0648b50308b520c8b52148b72280fb74a2631ffac3c617c022c20c1cf0d01c7e2f252578b52108b4a3c8b4c1178e34801d1518b592001d38b4918e33a498b348b01d631ffacc1cf0d01c738e075f6037df83b7d2475e4588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe05f5f5a8b12eb8d5d6a018d85b20000005068318b6f87ffd5bbe01d2a0a68a695bd9dffd53c067c0a80fbe07505bb4713726f6a0053ffd5636d642e657865202f432063616c632e65786500
## x64: fc4883e4f0e8c0000000415141505251564831d265488b5260488b5218488b5220488b7250480fb74a4a4d31c94831c0ac3c617c022c2041c1c90d4101c1e2ed524151488b52208b423c4801d08b80880000004885c074674801d0508b4818448b40204901d0e35648ffc9418b34884801d64d31c94831c0ac41c1c90d4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b04884801d0415841585e595a41584159415a4883ec204152ffe05841595a488b12e957ffffff5d48ba0100000000000000488d8d0101000041ba318b6f87ffd5bbe01d2a0a41baa695bd9dffd54883c4283c067c0a80fbe07505bb4713726f6a00594189daffd563616c632e65786500
`),
		Run: Run,
		PreRunE: func(cmd *cobra.Command, args []string) error {
			cmd.Flags().VisitAll(func(flag *pflag.Flag) {
				viper.BindPFlag(flag.Name, flag)
				viper.BindEnv(strings.ToUpper(flag.Name))
			})

			// Can't mark all flags as required
			if len(args) > 0 && len(viper.GetString("file")) == 0 && len(viper.GetString("shellcode")) == 0 && !settings.Demo {
				return fmt.Errorf("No shellcode specified: use '--shellcode' or '--file' to do so. The '--demo' flag is available to run a demo shellcode that spawns calc.exe")
			}

			if encoding := viper.GetString("sc-encoding"); encoding != "" {
				var encodingIsValid bool
				for _, valid := range validScEncoding {
					if encoding == valid {
						encodingIsValid = true
						break
					}
				}

				if !encodingIsValid {
					log.Fatalf("Invalid encoding: %s. Available: %v", encoding, validScEncoding)
				}
			}

			if len(os.Args) == 1 {
				cmd.Help()
				os.Exit(0)
			}

			return nil
		},
	}
)

var (
	//method string
	//shellcodeFilepath string
	//shellcode         []byte
	validScEncoding = []string{"base64", "hex", "raw"}

	loaderArgs map[string]string

	aliasedArgs = []string{"target", "args", "pid"}
)

func init() {
	RootCmd.Flags().StringVarP(&settings.PIDPipeName, "pid-pipe", "P", "", "Specify the name of the rendez-vous pipe to pass the PID of the loaded shellcode to the parent process. This feature is enabled only if this flag is used")
	RootCmd.Flags().BoolVarP(&settings.Idle, "idle", "i", false, "Enter an infinite loop before starting the shellcode to allow debugger to attach")
	RootCmd.Flags().BoolVarP(&settings.Keep, "keep", "k", false, "Don't terminate the target process on error")
	RootCmd.Flags().DurationVarP(&settings.DelayOnReturn, "delay-on-return", "w", 0, "Add a delay after the injection routine has returned and before cleanup")
	RootCmd.Flags().BoolP("verbose", "v", false, "Verbose output")
	RootCmd.Flags().BoolP("debug", "d", false, "Debug output")
	RootCmd.Flags().BoolVarP(&settings.Demo, "demo", "D", false, "Execute a built-in demo shellcode spawning calc.exe")
	RootCmd.Flags().StringP("file", "f", "", "File containing the shellcode to load in raw, hex or base64 format")
	RootCmd.Flags().StringP("sc-encoding", "e", "", fmt.Sprintf("Specify the encoding of the input shellcode if the wrong one is selected automatically. This would be required for base64-encoded shellcode that would result in a valid hex-encoded string or ascii shellcode. Valid encodings: %s", validScEncoding))
	RootCmd.Flags().StringP("shellcode", "s", "", "Shellcode in hex (i.e. '50515253...') or base64 format (i.e. 'UFFSU1ZX...')")
	RootCmd.Flags().BoolP("clipboard", "c", false, "Fetch shellcode from the clipboard")
	RootCmd.Flags().BoolP("dirty-hex", "C", false, "Attempt to clean the shellcode by removing prefixes and keeping only hexadecimal runes [a-fA-F0-9]. This allows copying shellcode from various sources without having to clean it first, like C source code or \\x and 0x prefixed shellcode ")
	RootCmd.Flags().BoolP("admin", "A", false, "Self elevate to high-integrity if needed (might trigger UAC)")
	RootCmd.Flags().BoolP("priv-debug", "E", false, "Enable debug privileges. The program will self elevate to high-integrity if the current rights are too low (might trigger UAC)")

	RootCmd.Flags().StringP("method", "m", "createthread", fmt.Sprintf("Method to use to load the shellcode. Available: %v", loaders.AvailableLoaders.List()))
	RootCmd.Flags().StringToStringVarP(&loaderArgs, "option", "o", map[string]string{}, `Set options for the loader, such as the target program to inject your shellcode in. Repeat it for each option, as many times as needed, e.g. '-o target=notepad.exe -o args="C:\users\user\Desktop\mydoc.txt"'`)

	RootCmd.Flags().StringP("pid", "p", "", "PID of the process to target. Alias for '-o pid=<PID>'")
	RootCmd.Flags().StringP("target", "t", "", `Target executable to inject shellcode into. Alias for '-o target="<path>"'`)
	RootCmd.Flags().StringP("args", "a", "", `Args to pass to the new process. Alias for '-o args="<cli>"'`)

	RootCmd.MarkFlagsMutuallyExclusive("shellcode", "file")
	RootCmd.MarkFlagsMutuallyExclusive("shellcode", "clipboard")
	RootCmd.MarkFlagsMutuallyExclusive("file", "clipboard")

	log.SetLevel(log.ErrorLevel)
}

func Run(_ *cobra.Command, _ []string) {
	if viper.GetBool("verbose") {
		log.SetLevel(log.InfoLevel)
	}

	if viper.GetBool("debug") {
		log.SetLevel(log.DebugLevel)
	}

	var err error
	var shellcode []byte
	scEncoding := viper.GetString("sc-encoding")
	rawShellcode := viper.GetString("shellcode")

	if viper.GetBool("clipboard") {
		rawShellcode, err = clipboard.Get()
		if err != nil {
			log.Fatalln(err)
		}
	}

	if viper.GetBool("dirty-hex") {
		scEncoding = "hex"

		chunks := strings.Split(rawShellcode, "\n")
		stripped := chunks
		for idx, chunk := range chunks {
			chunk = strutils.TrimBefore(chunk, "=")
			chunk = strutils.TrimAfter(chunk, "//")
			chunk = strutils.TrimAfter(chunk, "#")

			stripped[idx] = chunk
		}

		rawShellcode = strings.Join(stripped, "")

		// \x is handled by the regex
		rawShellcode = strings.ReplaceAll(rawShellcode, "0x", "")

		onlyNums := regexp.MustCompile(`[^a-fA-F0-9]+`)
		rawShellcode = onlyNums.ReplaceAllString(rawShellcode, "")

		if rawShellcode == "" {
			log.WithField("err", "Empty shellcode").Fatalln("Failed to parse dirty shellcode")
		}

		log.Debugf("Cleaned shellcode: %s", rawShellcode)
	}

	shellcodeFilepath := viper.GetString("file")
	if len(shellcodeFilepath) > 0 {
		content, err := os.ReadFile(shellcodeFilepath)
		if err != nil {
			log.Fatalln(err)
		}

		// Allow raw shellcode from files
		// Note that custom shellcode crafted through deep madness (e.g. https://www.usenix.org/system/files/woot20-paper-patel_0.pdf)
		// might defeat the check. In this case, the encoding should be forced using '--sc-encoding [base64|hex|raw]'
		rawShellcode = string(content)

		if !strutils.HasOnlyPrintable(content) {
			if scEncoding == "" {
				scEncoding = "raw"
			}
		}
	}

	switch scEncoding {
	case "base64":
		if shellcode, err = base64.StdEncoding.DecodeString(rawShellcode); err != nil {
			log.WithField("err", err).Fatalln("Invalid base64 shellcode")
		}

	case "hex":
		if shellcode, err = hex.DecodeString(rawShellcode); err != nil {
			log.WithField("err", err).Fatalln("Invalid hex shellcode")
		}

	case "raw":
		shellcode = []byte(rawShellcode)

	default:
		if shellcode, err = hex.DecodeString(rawShellcode); err != nil {
			if shellcode, err = base64.StdEncoding.DecodeString(rawShellcode); err != nil {
				log.WithField("err", err).Fatalln("Unsupported shellcode. Use either raw shellcode (with the '--file' flag), base64 or hex encoding")
			}
		}
	}

	if settings.Demo {
		switch runtime.GOARCH {
		case "386":
			shellcode = consts.DEMO_SHELLCODE_386
		case "amd64":
			shellcode = consts.DEMO_SHELLCODE_AMD64
		default:
			log.Fatalf("Unsupported arch (%s)\n", runtime.GOARCH)
		}
	}

	ldr, err := loaders.AvailableLoaders.Get(viper.GetString("method"))
	if err != nil {
		log.Fatalln(err)
	}

	compatible := false
	for _, valid := range ldr.ValidArchs() {
		if valid == runtime.GOARCH {
			compatible = true
			break
		}
	}

	if !compatible {
		log.Fatalf("This method is incompatible with the '%s' version of Moonboots. Recompile it using the right architecture or use another pre-compiled binary (e.g. moonboots_x64.exe to use amd64-compatible methods). Supported architecture by this method: %v", runtime.GOARCH, ldr.ValidArchs())
	}

	if settings.Idle {
		shellcode = append([]byte{0xEB, 0xFE}, shellcode...)
		log.Println("Patched shellcode with EB FE")
	}

	for _, name := range aliasedArgs {
		if val := viper.GetString(name); val != "" {
			loaderArgs[name] = val
		}
	}

	if viper.GetBool("admin") {
		err = elevate.RequireElevated()
		if err != nil {
			log.WithField("err", err).Fatal("Failed to get token integrity level")
			return
		}
	}

	if viper.GetBool("priv-debug") {
		err = winio.EnableProcessPrivileges([]string{win32.SE_DEBUG_NAME})
		if err != nil {
			log.WithField("err", err).Warnln("Failed to set SeDebugPrivilege")

			err = elevate.RequireElevated()
			if err != nil {
				log.WithField("err", err).Warnln("Failed to get token integrity level, skipping elevation")
				return
			}
		}
	}

	err = ldr.Parse(loaderArgs)
	if err != nil {
		log.WithField("err", err).Error("Failed to parse arguments")
		return
	}

	if ldr.IsInjector() {
		err = ldr.LoadTarget()
		if err != nil {
			log.WithField("err", err).Error("Failed to load injector target")
			return
		}
	}

	defer func() {
		err = ldr.Cleanup()
		if err != nil {
			log.WithField("err", err).Error("Cleanup failed")
			return
		}

		log.Println("Cleaned up")
	}()

	err = ldr.ReportPID()
	if err != nil {
		log.WithField("err", err).Error("Failed to report PID")
		return
	}

	err = ldr.Run(shellcode)
	if err != nil {
		ldr.SetError(err)
		log.WithField("err", err).Error("Failed to run the shellcode")
		return
	}
}
