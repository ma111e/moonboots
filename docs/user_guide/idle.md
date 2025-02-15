# Idle
The `--idle|-i` flag will prepend the `EB FE` byte sequence to the shellcode before loading it. This will make the shellcode jump to this instruction indefinitely, creating an infinite loop. 

This is useful when attaching a debugger to the bootstrap program, as it won't be able to attach to a suspended process.
