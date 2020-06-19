# StreamServer
A binary stream server. This server streams a PE file in instruction by instruction, while mutating the result so that the 
original code is not recoverable.

![G](https://i.imgur.com/h72lzH7.gif)

## Limitations
* Code that reads itself is unstable [1]  
* SEH, and various other PE features are not tested  

[1] It's possible to detect where the client is reading memory at, and load that memory in, so that such code may work. I may 
add this to the repository at some point if it is stable. I did manage to run a VMP ultra binary with a few minutes of testing, 
although it needs further work.

## Features
* Instruction streaming
* Control flow unrolling, by replacing all conditionals with direct branches
* Robust networking based on fragments, able to handle arbitrary packet sizes
* Encrypted networking using RSA key exchange w/ AES
* Database backend, with easy to use C++ object wrappers
* Account system, with secure password storage

#### Planned
* Further work torwards obfuscating inner working of the process (generating API wrappers over using direct imports, etc.)
* Mutation of code during the streaming process
* Plugin support
* Unit tests

## Building
1) Build libudis86
2) Place libdus86 headers & libraries in appropriate folders
3) Install mongocxx driver x64 triplet using vcpkg
4) Install cryptopp x64 triplet using vcpkg
5) Proper encryption with key exchange
6) Build project in visual studio

## Running
It supports streaming one single binary to every connected user out of the box.

```
StreamServer.exe BinaryPath.dll
```
