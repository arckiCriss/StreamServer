#pragma once
#include <Windows.h>

//
// Translates an address to a file section.
//
PIMAGE_SECTION_HEADER PeTranslateRawSection(PIMAGE_NT_HEADERS Nt, DWORD Rva);

//
// Translates an address to a file address.
//
PVOID PeTranslateRaw(PBYTE Base, PIMAGE_NT_HEADERS Nt, DWORD Rva);

//
// Maps headers into memory.
//
BOOLEAN PeMapHeaders(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped);

//
// Maps sections into memory.
//
BOOLEAN PeMapSections(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE Mapped);

//
// Resolves relocations.
//
VOID PeResolveRelocations(PBYTE Base, PIMAGE_NT_HEADERS Nt, PBYTE NewBase, PBYTE Mapped);