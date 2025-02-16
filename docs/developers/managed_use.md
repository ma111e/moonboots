# Managed use

For some use cases, Moonboots must be able to be used as a loader by another program. 

The `--pid-pipe` flag is available to specify a name for a rendez-vous pipe to which the PID of the process running the shellcode will be sent back.

For simplicity's sake, we'll be using a [winio](https://github.com/microsoft/go-winio) pipe for the examples below.

Here is the Moonboots implementation (client-side):

```go
// ReportPID sends back the PID of the target process through a named pipe.
// Its name is set via the --pid-pipe flag, which is stored in the settings.PIDPipeName global variable.
// This feature is needed when Moonboots is called by another process for synchronization purposes.
// In this case, the parent process is responsible for passing the rendez-vous pipe name.
func ReportPID() error {
	var pid uint32

	if settings.PIDPipeName == "" {
		return nil
	}

	conn, err := winio.DialPipe(settings.PIDPipeName, nil)
	if err != nil {
		return err
	}
	defer conn.Close()

    // If the loader is an injector, then send back the injected process' PID.
	// Else, it means that the loader runs the shellcode in the current process. 
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

```

Here is an example of a server-side implementation, starting Moonboots with the `--pid-pipe` pipe set and waiting for its callback:

```go
func main(){
	arch := "x64"
	shellcode := "<SHELLCODE>"
	args := shlex.Split(fmt.Sprintf(`moonboots_%s.exe -m createthread -s "%s"`, arch, shellcode))
    pipeName := fmt.Sprintf(`\\.\pipe\MYPIPE_%d`, time.Now().UnixMilli())
    args = append(args, "--pid-pipe", pipeName)
    
    pipe, err := winio.ListenPipe(pipeName, &winio.PipeConfig{
        SecurityDescriptor: "D:P(A;;GA;;;WD)", // Access granted to Everyone
        MessageMode:        true,
    })
    if err != nil {
        return 0, errors.Wrap(err, "failed to create PID reporting pipe")
    }
    defer pipe.Close()
	
	// Do stuff
	[...]
	
	pid, err := waitForPIDReport(pipe, timeout)
	if err != nil {
		return 0, err
	}

	// Interact with the PID, i.e. create a memory dump
	[...]
}

func waitForPIDReport(pipe net.Listener, timeout time.Duration) (uint32, error) {
	pid := make([]byte, 4)

	// Wait for the child process to connect to the named pipe
	conn, err := pipe.Accept()
	if err != nil {
		return 0, errors.Wrap(err, "failed to accept connection")
	}
	defer conn.Close()

	timeout = time.Millisecond * 500
	err = conn.SetDeadline(time.Now().Add(timeout))
	if err != nil {
		return 0, errors.Wrap(err, "failed to set read timeout")
	}

	// Read the child process's PID from the named pipe
	_, err = conn.Read(pid)
	if err != nil && errors.Is(err, winio.ErrTimeout) {
		return 0, errors.Wrap(err, "PID report took too long (timeout)")
	}

	if err != nil && err != io.EOF {
		return 0, errors.Wrap(err, "failed to read PID from pipe")
	}
	return binary.LittleEndian.Uint32(pid), nil
}
```
