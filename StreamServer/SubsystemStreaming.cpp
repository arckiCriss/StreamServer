#include "Server.h"
#include "Logging.h"
#include "Config.h"
#include "Pe.h"

#include <udis86.h>
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <map>

#define SET_BIT (1u << 31)

//
// The default code area to stream in.
//
static char DefaultCodeArea[] = {
	0x48, 0xC7, 0xC0, 0x66, 0x06, 0x00, 0x00,
	0xc3
};

//
// The cheat image.
//
static PCHAR Image = NULL;

//
// A table of jmp mnemonics to CPU flags.
//
static unsigned int JmpFlagTable[500] = { 0 };

//
// Retrieves the size of the loaded image.
//
static UINT64 SizeOfImage(VOID) {
	auto Dos = (PIMAGE_DOS_HEADER)Image;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Image + Dos->e_lfanew);
	return Nt->OptionalHeader.SizeOfImage;
}

//
// Retrieves the entry poitn of the loaded image.
//
static UINT64 EpOfImage(VOID) {
	auto Dos = (PIMAGE_DOS_HEADER)Image;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Image + Dos->e_lfanew);
	return Nt->OptionalHeader.AddressOfEntryPoint;
}

//
// Builds the jmp table.
//
static VOID BuildJmpTable(VOID) {
	JmpFlagTable[ud_mnemonic_code::UD_Ijp] = 0x4u | SET_BIT;
	JmpFlagTable[ud_mnemonic_code::UD_Ijnp] = 0x4u;

	JmpFlagTable[ud_mnemonic_code::UD_Ijo] = 0x800u | SET_BIT;
	JmpFlagTable[ud_mnemonic_code::UD_Ijno] = 0x800u;

	JmpFlagTable[ud_mnemonic_code::UD_Ijs] = 0x80u | SET_BIT;
	JmpFlagTable[ud_mnemonic_code::UD_Ijns] = 0x80u;

	JmpFlagTable[ud_mnemonic_code::UD_Ijz] = 0x40u | SET_BIT;
	JmpFlagTable[ud_mnemonic_code::UD_Ijnz] = 0x40u;
}

//
// Resolves imports.
//
static BOOLEAN PeResolveImports(ServerClient *Client) {
	auto Base = (PBYTE)Client->Image;
	auto Dos = (PIMAGE_DOS_HEADER)Base;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Base + Dos->e_lfanew);

	auto Rva = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
	if (!Rva) {
		return TRUE;
	}

	auto ImportDescriptor = (PIMAGE_IMPORT_DESCRIPTOR)(Base + Rva);
	if (!ImportDescriptor) {
		return TRUE;
	}

	for (; ImportDescriptor->FirstThunk; ++ImportDescriptor) {
		auto ModuleName = (PCHAR)(Base + ImportDescriptor->Name);
		if (!ModuleName) {
			continue;
		}

		for (auto Thunk = (PIMAGE_THUNK_DATA)(Base + ImportDescriptor->FirstThunk); Thunk->u1.AddressOfData; ++Thunk) {
			auto ImportByName = (PIMAGE_IMPORT_BY_NAME)(Base + Thunk->u1.AddressOfData);
			auto Off = (UINT64)&Thunk->u1.Function - (UINT64)Base;
			auto NewAddr = (UINT64)Client->Allocated + Off;

			auto Id = Client->SymbolRequestId++;
			auto &Request = Client->SymbolRequests[Id];
			Request.FillAddress = (PVOID)NewAddr;

			PacketS2CRequestSymbolAddress NB;
			NB.RequestId = Id;
			strcpy_s(NB.ModuleName, ModuleName);
			strcpy_s(NB.SymbolName, ImportByName->Name);
			Client->SendWrapped(OP_S2C_REQUEST_SYMBOL_ADDR, NB);
		}
	}

	return TRUE;
}


//
// Determines if the provided address is within bounds.
//
static BOOLEAN IsWithinBounds(ServerClient *Client, PVOID Addr) {
	auto Off = (UINT64)Addr - (UINT64)Client->Allocated;
	return Off < SizeOfImage();
}

//
// Determines if the provided address is code.
//
static BOOLEAN IsCode(ServerClient *Client, PVOID Addr) {
	auto Dos = (PIMAGE_DOS_HEADER)Image;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Image + Dos->e_lfanew);
	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; ++i, ++Section) {
		auto IsCode = (Section->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE));
		if (!IsCode) {
			continue;
		}

		auto Begin = (PVOID)((PCHAR)Client->Allocated + Section->VirtualAddress);
		auto End = (PVOID)((PCHAR)Client->Allocated + Section->VirtualAddress + Section->SizeOfRawData);
		if (Addr >= Begin && Addr < End) {
			return TRUE;
		}
	}

	return FALSE;
}


//
// Writes a range of memory from image.
//
static VOID WriteFromImage(ServerClient *Client, PVOID At, SIZE_T Size) {
	auto Rem = Size;
	auto Off = 0;
	while (Rem) {
		auto ToWrite = min(0x100, Rem);

		PacketS2CWrite NB;
		NB.Address = (PCHAR)Client->Allocated + (UINT64)At + Off;
		memcpy(NB.Data, (PCHAR)Client->Image + (UINT64)At + Off, ToWrite);
		NB.Length = ToWrite;
		Client->SendWrapped(OP_S2C_WRITE, NB);

		Rem -= ToWrite;
		Off += ToWrite;
	}
}

//
// Writes breakpoints to the provided range.
//
static VOID WriteBps(ServerClient *Client, PVOID At, SIZE_T Size) {
	auto Rem = Size;
	auto Off = 0;

	UCHAR Ccs[0x100];
	memset(Ccs, 0xcc, sizeof(Ccs));

	while (Rem) {
		auto ToWrite = min(0x100, Rem);

		PacketS2CWrite NB;
		NB.Address = (PCHAR)Client->Allocated + (UINT64)At + Off;
		memcpy(NB.Data, Ccs, ToWrite);
		NB.Length = ToWrite;
		Client->SendWrapped(OP_S2C_WRITE, NB);

		Rem -= ToWrite;
		Off += ToWrite;
	}
}


static VOID OnRequestInstructionPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	if (!Client->Allocated) {
		Client->Disconnect();
		return;
	}

	auto Body = (PacketC2SRequestInstruction*)P->Body;
	auto Off = (UINT64)Body->Address - (UINT64)Client->Allocated;
	if (!IsWithinBounds(Client, Body->Address)) {
		LOG("Request out of bounds...");
		return;
	}

	ud_t u;
	ud_init(&u);
	ud_set_input_buffer(&u, (UINT8*)Client->Image + Off, SizeOfImage() - Off);
	ud_set_mode(&u, 64);
	auto Length = ud_disassemble(&u);
	if (Length <= 0 || Length > 0x15) {
		LOG("Invalid disassembly length...");
		return;
	}

	// LOG("Requesting " << Body->Address);

	//
	// If we injected other instructions in place of the original one..
	//
	auto Injected = FALSE;
#ifdef UNROLL_CONTROL_FLOW
	if (u.operand[0].type == ud_type::UD_OP_JIMM) {
		if (JmpFlagTable[u.mnemonic]) {
			auto Cleaned = JmpFlagTable[u.mnemonic] & 0xfffffffu;
			auto BranchTaken = FALSE;

			if (JmpFlagTable[u.mnemonic] & SET_BIT) {
				BranchTaken = (Body->State.EFlags & Cleaned) == Cleaned;
			} else {
				BranchTaken = (Body->State.EFlags & Cleaned) == 0x0;
			}

			UINT32 Offset;
			if (BranchTaken) {
				// jmp directly there
				memcpy(&Offset, (PCHAR)Client->Image + Off + Length - 4, 4);
				Offset += (Length - 5);
			} else {
				// jmp anyways fuck them
				Offset = (Length - 5);
			}

			UCHAR Opcodes[5];
			Opcodes[0] = OP_JMP_IMM32;
			memcpy(&Opcodes[1], &Offset, 4);

			PacketS2CWrite NB;
			NB.Address = Body->Address;
			memcpy(NB.Data, Opcodes, Length);
			NB.Length = Length;
			Client->SendWrapped(OP_S2C_WRITE, NB);

			Injected = TRUE;
		}
	}
#endif

	if (!Injected) {
		PacketS2CWrite NB;
		NB.Address = Body->Address;
		memcpy(NB.Data, (PCHAR)Client->Image + Off, Length);
		NB.Length = Length;
		Client->SendWrapped(OP_S2C_WRITE, NB);
	}
}

//
// Initializes the image from disk.
//
static BOOLEAN InitImage(CONST std::string &Path) {
	char Directory[MAX_PATH];
	if (!GetCurrentDirectoryA(MAX_PATH, Directory)) {
		LOG("Failed to initialize image");
		return FALSE;
	}

	auto WholePath = std::string(Directory) + "\\" + Path;
	std::basic_ifstream<BYTE> File(WholePath.c_str(), std::ios::binary);
	auto Bytes = std::vector<BYTE>((std::istreambuf_iterator<BYTE>(File)), std::istreambuf_iterator<BYTE>());

	Image = (PCHAR)malloc(Bytes.size());
	memcpy(Image, Bytes.data(), Bytes.size());
	return TRUE;
}

VOID SubsystemStreamingInitialized(ServerClient *Client, PacketC2SInitialized *P) {
	if (!P->Allocated) {
		Client->Disconnect();
		return;
	}

	LOG("Initialized at " << P->Allocated);
	Client->Allocated = P->Allocated;
	Client->Image = malloc(SizeOfImage());

	auto Dos = (PIMAGE_DOS_HEADER)Image;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Image + Dos->e_lfanew);

	PeMapHeaders((PBYTE)Image, Nt, (PBYTE)Client->Image);
	PeMapSections((PBYTE)Image, Nt, (PBYTE)Client->Image);
	PeResolveRelocations((PBYTE)Image, Nt, (PBYTE)Client->Allocated, (PBYTE)Client->Image);
	PeResolveImports(Client);

	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; ++i, ++Section) {
		//
		// Skip code, we stream this in line by line :)
		//
		auto IsCode = (Section->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE));
		if (IsCode) {
			WriteBps(Client, (PVOID)Section->VirtualAddress, Section->SizeOfRawData);
		} else {
			WriteFromImage(Client, (PVOID)Section->VirtualAddress, Section->SizeOfRawData);
		}
	}

	PacketS2CRunCode NB;
	Client->SendWrapped(OP_S2C_RUN_CODE, NB);
}

VOID SubsystemStreamingOnNewConnection(ServerClient *Client) {
	PacketS2CInit Body;
	Body.Length = SizeOfImage();
	Body.Off = EpOfImage();

	Client->SendWrapped(OP_S2C_INIT, Body);
}

VOID SubsystemStreamingInitNet(Server *Server) {
	Server->RegisterHandler(OP_C2S_REQUEST_INSTRUCTION, OnRequestInstructionPacket, NULL, sizeof(PacketC2SRequestInstruction));
}

BOOLEAN SubsystemStreamingInit(LPCSTR ImageName) {
	LOG("Building jmp table");
	BuildJmpTable();

	LOG("Reading image");
	if (!InitImage(ImageName)) {
		return FALSE;
	}

	LOG("Initialized");
	return TRUE;
}