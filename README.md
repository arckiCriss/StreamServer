# StreamServer
A binary stream server. This server streams a PE file in instruction by instruction, while mutating the result so that the 
original code is not recoverable.

![G](https://i.imgur.com/h72lzH7.gif)

## Limitations
* Code that reads itself is unstable, as such, some packers (VMP virtualization) are unstable [1]  
* SEH is not tested  
  

[1] It's possible to detect where the client is reading memory at, and load that memory in, so that such code may work. I may 
add this to the repository at some point if it is stable. I did manage to run a VMP ultra binary with a few minutes of testing, 
although it needs further work.

## Planned
This is a short list of things I plan to do myself over the following months.  

1) Support for relocating code so that it may be executed in different regions randomly
2) Outputting mutated code, possibly using a JIT compiler of some sort
3) Unit tests

## Building
1) Build libudis86
2) Place libdus86 headers & libraries in appropriate folders
3) Install mongocxx driver x64 triplet using vcpkg
4) Install cryptopp x64 triplet using vcpkg
5) Build project in visual studio

## Running
This is a PoC, and not meant to be a full fledged DRM solution (although one day it may be.) It currently supports streaming one 
single binary to every connected user.

```
StreamServer.exe BinaryPath.dll
```
