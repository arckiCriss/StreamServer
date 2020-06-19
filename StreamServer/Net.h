#pragma once
#include <windows.h>
#include <cstdint>

#include <cryptopp/aes.h>

#include "Arch.h"

#pragma comment (lib, "Ws2_32.lib")

#define PACKET_LEN 0x200

#define OP_C2S_LOGIN 1
#define OP_C2S_INITIALIZED 2
#define OP_C2S_REQUEST_INSTRUCTION 3
#define OP_C2S_FULFILL_REQUEST_SYMBOL_ADDR 4

#define OP_S2C_INIT 1
#define OP_S2C_WRITE 2
#define OP_S2C_REQUEST_SYMBOL_ADDR 3
#define OP_S2C_RUN_CODE 4

#pragma pack(push, 1)
struct RsaBlock {
	//
	// The login username.
	//
	CHAR Username[18] = { 0 };
	//
	// The login password.
	//
	CHAR Password[72] = { 0 };
	//
	// The AES key to use.
	//
	UCHAR SendKey[CryptoPP::AES::MAX_KEYLENGTH];
	//
	// The AES IV to use.
	//
	UCHAR SendIv[CryptoPP::AES::BLOCKSIZE];
	//
	// The AES key to use.
	//
	UCHAR RecvKey[CryptoPP::AES::MAX_KEYLENGTH];
	//
	// The AES IV to use.
	//
	UCHAR RecvIv[CryptoPP::AES::BLOCKSIZE];
};
//
// Verify the size fits in RSA block.
//
static_assert(sizeof(RsaBlock) < (2048 / 8), "Invalid size");

//
// A login packet.
//
struct PacketC2SLogin {
	//
	// The version of the loader.
	//
	UINT32 Version = 0;
	//
	// The size of the RSA block.
	//
	SIZE_T RsaBlockSize = 0;
	//
	// A block of RSA encrypted data.
	//
	CHAR RsaBlock[0x1000] = { 0 };
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
// A fulfillment packet for a symbol address request.
//
struct PacketC2SFulfillRequestSymbolAddress {
	//
	// The unique (for this session) id of the request being fulfilled.
	//
	UINT64 RequestId;
	//
	// The address of the symbol.
	//
	PVOID Address;
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

//
// A request module address packet.
//
struct PacketS2CRequestSymbolAddress {
	//
	// The unique (for this session) id of the request being made.
	//
	UINT64 RequestId;
	//
	// The name of the module containing the symbol.
	//
	CHAR ModuleName[MAX_PATH];
	//
	// The name of the symbol itself.
	//
	CHAR SymbolName[MAX_PATH];
};

//
// A request for running the code.
//
struct PacketS2CRunCode {
	char Dummy[1] = { 0 };
};
#pragma pack(pop)