# SentinelGone
When you are too lazy to prepend some shellcode to your agents shellcode or something idk.

Just another shitpost, don't mind me.

What it does:
- Fixes ntdll address in `InMemoryOrderModuleList` (DllBase)
- Makes S1's VEH point towards a `EXCEPTION_CONTINUE_EXECUTION` in `Kernelbase.dll` (find more gadgets yourself)

Uses 2 special usermode APCs (threads don't need to be alertable). 

You can just use a protect/write/protect combo if you really want to. 

Pick your poison.
#### Compiling
```
x86_64-w64-mingw32-gcc -c bof.c -o bof.o
```

#### Usage
```
SentinelGone <pid>
```
