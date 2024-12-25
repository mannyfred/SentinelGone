# SentinelGone
When you are too lazy to prepend some shellcode to your agents shellcode or something idk.

Just another shitpost, don't mind me.

Fixes ntdll address in `InMemoryOrderModuleList` and makes S1's VEH point towards a `return -1` (aka `EXCEPTION_CONTINUE_EXECUTION`) in `Kernelbase.dll` (find more gadgets yourself)

Uses 2 special usermode APCs (threads don't need to be alertable), but you can just use a protect/write/protect combo if you really want to. 

Pick your poison.

#### Usage
```
SentinelGone <pid>
```