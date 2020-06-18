#pragma once
#include <windows.h>
#include <cstdint>
#include "Arch.h"

#pragma comment (lib, "Ws2_32.lib")

#define PACKET_LEN 0x200

#define OP_C2S_LOGIN 1
#define OP_C2S_INITIALIZED 2
#define OP_C2S_REQUEST_INSTRUCTION 3

#define OP_S2C_INIT 1
#define OP_S2C_WRITE 2

#pragma pack(push, 1)
//
// A login packet.
//
struct PacketC2SLogin {
	//
	// The version of the loader.
	//
	UINT32 Version = 0;
};

//
// An initialized packet.
//
struct PacketC2SInitialized {
	//
	// The base of the allocated memory.
	//
	PVOID Allocated = NULL;
};

//
// A request instruction packet.
//
struct PacketC2SRequestInstruction {
	//
	// The address of the requested instruction.
	//
	PVOID Address = NULL;
	//
	// CPU state.
	//
	CpuState State;
};

//
// An init packet.
//
struct PacketS2CInit {
	//
	// The length of the image.
	//
	UINT64 Length;
	//
	// The entry point offset.
	//
	UINT64 Off;
};

//
// A write packet.
//
struct PacketS2CWrite {
	//
	// The address to write at.
	//
	PVOID Address = NULL;
	//
	// The length of the data.
	//
	UINT64 Length = 0;
	//
	// The data.
	//
	CHAR Data[0x100] = { 0 };
};
#pragma pack(pop)