# Base

The `loaders.Base` structure implements the `Loader` plugin interface and exposes several methods that could be useful when implementing a new loader. 

#### ***⚠️ Including it in your loader's struct is mandatory.***

### Settings
#### Injector 
- Type: `bool`
- Default: `false`

Setting `<loader>.Injector` to `true` in the init function of your plugin will result in the program automatically handle the `target`, `args` and `pid` CLI user parameters and load the target process accordingly. You can access the target's `*windows.ProcessInformation` object in your code through the `<loader>.TargetProcess` member.

***Example***
```go
ldr := &MyLoader{}
ldr.Injector = true
```

#### SuspendProcess
- Type: `bool`
- Default: `false`

If your technique requires the target to be suspended, you can set `<loader>.SuspendProcess` to `true`. The target process' execution will be resumed after the `Run` method returns, right before closing every handle in `<loader>.TargetProcess`. 

***Example***
```go
ldr := &MyLoader{}
ldr.SuspendProcess = true
```

#### ValidArgs
- Type: `[]string`
- Default: `{}`

The `ValidArgs` string array defines which parameters are valid for the user to pass through the `--option|-o` flag. You must add any custom argument you want to expose to the user to this array.

***Example***
```go
ldr := &MyLoader{}
ldr.AddValidArgs([]string{"myparam"})
```

> You should always use the helper method `AddValidArgs`, which merges additional parameters with the existing set.

### Methods
#### AddValidArgs
```go
func (b *Base) AddValidArgs(args []string)
```

`AddValidArgs` merges the passed args string array with the current `ValidArgs`.

***Example***
```go
ldr := &MyLoader{}
ldr.AddValidArgs([]string{"myparam"})
```

#### NewProcInfoFromPID
```go
func (b *Base) NewProcInfoFromPID(pid int) (*windows.ProcessInformation, error)
```

`NewProcInfoFromPID` fetches data from a remote process given its PID, and returns a filled `windows.ProcessInformation`.

***Example***
```go
pid := 1234
procInfo, err := NewProcInfoFromPID(pid)
if err != nil{
	return errors.Wrap(err, "failed to fetch process information from PID %d", pid)
}

[...]
```

#### SpawnDummyProc
```go
func (b *Base) SpawnDummyProc() (*windows.ProcessInformation, error)
```

`SpawnDummyProc` spawns a new dummy process in a suspended state and returns its `windows.ProcessInformation`.

***Example***
```go
procInfo, err := SpawnDummyProc()
if err != nil{
	return errors.Wrap(err, "failed to spawn dummy process")
}

[...]
```
