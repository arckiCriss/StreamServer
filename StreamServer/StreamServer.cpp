#include "Server.h"
#include "Logging.h"
#include "Config.h"

#include <udis86.h>
#include <Windows.h>
#include <winnt.h>
#include <iostream>
#include <fstream>
#include <map>

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

#define SET_BIT (1u << 31)

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
// Translates an address to a file section.
//
static PIMAGE_SECTION_HEADER PeTranslateRawSection(PIMAGE_NT_HEADERS Nt, DWORD Rva) {
	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; ++i, ++Section) {
		if (Rva >= Section->VirtualAddress && Rva < Section->VirtualAddress + Section->Misc.VirtualSize) {
			return Section;
		}
	}

	return NULL;
}

//
// Translates an address to a file address.
//
static PVOID PeTranslateRaw(PBYTE Base, PIMAGE_NT_HEADERS Nt, DWORD Rva) {
	auto Section = PeTranslateRawSection(Nt, Rva);
	if (!Section) {
		return NULL;
	}

	return Base + Section->PointerToRawData + (Rva - Section->VirtualAddress);
}

//
// Maps headers into memory.
//
static BOOLEAN PeMapHeaders(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped) {
	memcpy(Mapped, Base, Nt->OptionalHeader.SizeOfHeaders);
	return TRUE;
}

//
// Maps sections into memory.
//
static BOOLEAN PeMapSections(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped) {
	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; ++i, ++Section) {
		auto SectionSize = min(Section->SizeOfRawData, Section->Misc.VirtualSize);
		if (!SectionSize) {
			continue;
		}

		auto MappedSection = Mapped + Section->VirtualAddress;
		memcpy(MappedSection, Base + Section->PointerToRawData, SectionSize);
	}

	return TRUE;
}

//
// Resolves relocations.
//
static VOID PeResolveRelocations(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE NewBase, PBYTE Mapped) {
	auto &BaseRelocDir = Nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (!BaseRelocDir.VirtualAddress) {
		return;
	}

	auto Reloc = (PIMAGE_BASE_RELOCATION)(PeTranslateRaw(Base, Nt, BaseRelocDir.VirtualAddress));
	if (!Reloc) {
		return;
	}

	for (auto CurrentSize = 0UL; CurrentSize < BaseRelocDir.Size; ) {
		auto RelocCount = (Reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		auto RelocData = (PWORD)((PBYTE)(Reloc)+sizeof(IMAGE_BASE_RELOCATION));
		auto RelocBase = (PBYTE)(Mapped + Reloc->VirtualAddress);

		for (auto i = 0UL; i < RelocCount; ++i, ++RelocData) {
			auto Data = *RelocData;
			auto Type = Data >> 12;
			auto Offset = Data & 0xFFF;

			if (Type == IMAGE_REL_BASED_DIR64) {
				*(UINT64*)(RelocBase + Offset) += (NewBase - (PBYTE)(Nt->OptionalHeader.ImageBase));
			} else if (Type != 0) {
				LOG("Unhandled relocation " << Type << " " << std::hex << (PVOID)(RelocBase + Offset));
			}
		}

		CurrentSize += Reloc->SizeOfBlock;
		Reloc = (PIMAGE_BASE_RELOCATION)RelocData;
	}
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

		Packet NP;
		NP.Opcode = OP_S2C_WRITE;
		NP.Body = &NB;
		NP.BodyLength = sizeof(NB);

		Client->Send(&NP);

		Rem -= ToWrite;
		Off += ToWrite;
	}
}


//
// Retrieves the address of a register.
//
static PVOID GetRegAddr(CpuState *State, ud_type r) {
	switch (r) {
	case ud_type::UD_R_AL:
	case ud_type::UD_R_AH:
	case ud_type::UD_R_AX:
	case ud_type::UD_R_EAX:
	case ud_type::UD_R_RAX:
		return (PVOID)State->Rax;
	case ud_type::UD_R_CL:
	case ud_type::UD_R_CH:
	case ud_type::UD_R_CX:
	case ud_type::UD_R_ECX:
	case ud_type::UD_R_RCX:
		return (PVOID)State->Rcx;
	case ud_type::UD_R_DL:
	case ud_type::UD_R_DH:
	case ud_type::UD_R_DX:
	case ud_type::UD_R_EDX:
	case ud_type::UD_R_RDX:
		return (PVOID)State->Rdx;
	case ud_type::UD_R_BL:
	case ud_type::UD_R_BH:
	case ud_type::UD_R_BX:
	case ud_type::UD_R_EBX:
	case ud_type::UD_R_RBX:
		return (PVOID)State->Rbx;
	case ud_type::UD_R_SP:
	case ud_type::UD_R_ESP:
	case ud_type::UD_R_RSP:
		return (PVOID)State->Rsp;
	case ud_type::UD_R_BP:
	case ud_type::UD_R_EBP:
	case ud_type::UD_R_RBP:
		return (PVOID)State->Rbp;
	case ud_type::UD_R_SIL:
	case ud_type::UD_R_SI:
	case ud_type::UD_R_ESI:
	case ud_type::UD_R_RSI:
		return (PVOID)State->Rsi;
	case ud_type::UD_R_DIL:
	case ud_type::UD_R_DI:
	case ud_type::UD_R_EDI:
	case ud_type::UD_R_RDI:
		return (PVOID)State->Rdi;
	case ud_type::UD_R_R8B:
	case ud_type::UD_R_R8W:
	case ud_type::UD_R_R8D:
	case ud_type::UD_R_R8:
		return (PVOID)State->R8;
	case ud_type::UD_R_R9B:
	case ud_type::UD_R_R9W:
	case ud_type::UD_R_R9D:
	case ud_type::UD_R_R9:
		return (PVOID)State->R9;
	case ud_type::UD_R_R10B:
	case ud_type::UD_R_R10W:
	case ud_type::UD_R_R10D:
	case ud_type::UD_R_R10:
		return (PVOID)State->R10;
	case ud_type::UD_R_R11B:
	case ud_type::UD_R_R11W:
	case ud_type::UD_R_R11D:
	case ud_type::UD_R_R11:
		return (PVOID)State->R11;
	case ud_type::UD_R_R12B:
	case ud_type::UD_R_R12W:
	case ud_type::UD_R_R12D:
	case ud_type::UD_R_R12:
		return (PVOID)State->R12;
	case ud_type::UD_R_R13B:
	case ud_type::UD_R_R13W:
	case ud_type::UD_R_R13D:
	case ud_type::UD_R_R13:
		return (PVOID)State->R13;
	case ud_type::UD_R_R14B:
	case ud_type::UD_R_R14W:
	case ud_type::UD_R_R14D:
	case ud_type::UD_R_R14:
		return (PVOID)State->R14;
	case ud_type::UD_R_R15B:
	case ud_type::UD_R_R15W:
	case ud_type::UD_R_R15D:
	case ud_type::UD_R_R15:
		return (PVOID)State->R15;
	case ud_type::UD_R_RIP:
		return (PVOID)State->Rip;
	default:
		LOG("Unknown type " << r);
		return NULL;
	}
}

//
// Determines if the provided address is within bounds.
//
BOOLEAN IsWithinBounds(ServerClient *Client, PVOID Addr) {
	auto Off = (UINT64)Addr - (UINT64)Client->Allocated;
	return Off < SizeOfImage();
}

//
// Determines if the provided address is code.
//
BOOLEAN IsCode(ServerClient *Client, PVOID Addr) {
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
// Handles an initialized packet.
//
static VOID OnInitializedPacket(PVOID Ctx, Server *Server, ServerClient *Client, Packet *P) {
	if (Client->Allocated) {
		Client->Disconnect();
		return;
	}

	auto Body = (PacketC2SInitialized*)P->Body;
	if (!Body->Allocated) {
		Client->Disconnect();
		return;
	}

	LOG("Initialized at " << Body->Allocated);
	Client->Allocated = Body->Allocated;
	Client->Image = malloc(SizeOfImage());

	auto Dos = (PIMAGE_DOS_HEADER)Image;
	auto Nt = (PIMAGE_NT_HEADERS)((PCHAR)Image + Dos->e_lfanew);

	PeMapHeaders((PBYTE)Image, Nt, (PBYTE)Client->Image);
	PeMapSections((PBYTE)Image, Nt, (PBYTE)Client->Image);
	PeResolveRelocations((PBYTE)Image, Nt, (PBYTE)Client->Allocated, (PBYTE)Client->Image);

	auto Section = IMAGE_FIRST_SECTION(Nt);
	for (auto i = 0; i < Nt->FileHeader.NumberOfSections; ++i, ++Section) {
		//
		// Skip code, we stream this in line by line :)
		//
		auto IsCode = (Section->Characteristics & (IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE));
		if (IsCode) {
			continue;
		}

		WriteFromImage(Client, (PVOID)Section->VirtualAddress, Section->SizeOfRawData);
	}
}

//
// Handles a request instruction packet.
//
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

			auto Opcodes = (PUCHAR)malloc(Length);
			Opcodes[0] = OP_JMP_IMM32;
			memcpy(&Opcodes[1], &Offset, 4);

			// nop remaining bytes
			auto Remaining = Length - 5;
			for (auto i = 0; i < Remaining; i++) {
				Opcodes[i + 5] = OP_NOP;
			}

			PacketS2CWrite NB;
			NB.Address = Body->Address;
			memcpy(NB.Data, Opcodes, Length);
			NB.Length = Length;

			Packet NP;
			NP.Opcode = OP_S2C_WRITE;
			NP.Body = &NB;
			NP.BodyLength = sizeof(NB);

			Client->Send(&NP);
			free(Opcodes);

			Injected = TRUE;
		}
	}
#endif

	if (!Injected) {
		PacketS2CWrite NB;
		NB.Address = Body->Address;
		memcpy(NB.Data, (PCHAR)Client->Image + Off, Length);
		NB.Length = Length;

		Packet NP;
		NP.Opcode = OP_S2C_WRITE;
		NP.Body = &NB;
		NP.BodyLength = sizeof(NB);

		Client->Send(&NP);
	}
}

//
// Called when a new connection happens.
//
VOID OnNewConnection(ServerClient *Client) {
	LOG("New connection");

	PacketS2CInit Body;
	Body.Length = SizeOfImage();
	Body.Off = EpOfImage();

	Packet Packet;
	Packet.Opcode = OP_S2C_INIT;
	Packet.Body = &Body;
	Packet.BodyLength = sizeof(Body);

	Client->Send(&Packet);
}

VOID OnBadPacket(ServerClient *Client, Packet *Packet) {
	Client->Disconnect();
}

VOID OnMalformedData(ServerClient *Client) {
	Client->Disconnect();
}

//
// Starts the server.
//
BOOLEAN StartServer(VOID) {
	Server Server;
	Server.Port = BIND_PORT;
	Server.OnNewConnection = OnNewConnection;
	Server.OnBadPacket = OnBadPacket;
	Server.OnMalformedData = OnMalformedData;
	Server.RegisterHandler(OP_C2S_INITIALIZED, OnInitializedPacket, NULL, sizeof(PacketC2SInitialized));
	Server.RegisterHandler(OP_C2S_REQUEST_INSTRUCTION, OnRequestInstructionPacket, NULL, sizeof(PacketC2SRequestInstruction));

	LOG("Initializing");
	if (!Server.Init()) {
		LOG("Failed to init!");
		return FALSE;
	}

	LOG("Binding");
	if (!Server.Bind()) {
		LOG("Failed to bind!");
		return FALSE;
	}

	LOG("Accepting new connections");
	Server.Accept();

	return TRUE;
}

//
// Initializes the image from disk.
//
BOOLEAN InitImage(const std::string &Path) {
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

int main(int Argc, const char *Argv[]) {
	if (Argc <= 1) {
		LOG("Correct format: StreamServer BinaryName.exe");
		return 1;
	}

	LOG("Building jmp table");
	BuildJmpTable();

	LOG("Reading image");
	if (!InitImage(Argv[1])) {
		return 1;
	}

	LOG("Starting server");
	if (!StartServer()) {
		return 1;
	}

	LOG("Finished running!");
	std::cin.get();
	return 0;
}
