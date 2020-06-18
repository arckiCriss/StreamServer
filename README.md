# StreamServer
A binary stream server. This server streams a PE file in instruction by instruction, while mutating the result so that the 
original code is not recoverable.

## Limitations
* Code that reads itself is unstable, as such, some packers (VMP virtualization) are unstable [1]  
* Imports are not currently working, but are planned (use function pointers, PEB, etc. until then)  
* SEH is not tested  
  

[1] It's possible to detect where the client is reading memory at, and load that memory in, so that such code may work. I may 
add this to the repository at some point if it is stable.

## Planned
This is a short list of things I plan to do myself over the following months.  

1) Full IAT support
2) Support for relocating code so that it may be executed in different regions randomly
3) Outputting mutated code, possibly using a JIT compiler of some sort
4) Unit tests

## Building
1) Build libudis86
2) Place libdus86 headers & libraries in appropriate folders
3) Build project in visual studio

## Running
This is a PoC, and not meant to be a full fledged DRM solution (although one day it may be.) It currently supports streaming one 
single binary to every connected user.

```
StreamServer.exe BinaryPath.dll
```
