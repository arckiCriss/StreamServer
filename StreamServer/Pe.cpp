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
// Translates an address to a file section.
//
PIMAGE_SECTION_HEADER PeTranslateRawSection(PIMAGE_NT_HEADERS Nt, DWORD Rva) {
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
PVOID PeTranslateRaw(PBYTE Base, PIMAGE_NT_HEADERS Nt, DWORD Rva) {
	auto Section = PeTranslateRawSection(Nt, Rva);
	if (!Section) {
		return NULL;
	}

	return Base + Section->PointerToRawData + (Rva - Section->VirtualAddress);
}

//
// Maps headers into memory.
//
BOOLEAN PeMapHeaders(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped) {
	memcpy(Mapped, Base, Nt->OptionalHeader.SizeOfHeaders);
	return TRUE;
}

//
// Maps sections into memory.
//
BOOLEAN PeMapSections(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped) {
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
VOID PeResolveRelocations(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE NewBase, PBYTE Mapped) {
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
