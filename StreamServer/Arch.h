#pragma once
#include <Windows.h>
#include <udis86.h>

#pragma pack(push, 1)
//
// Holds CPU state for the client.
//
struct CpuState {
	DWORD64 Rax;
	DWORD64 Rcx;
	DWORD64 Rdx;
	DWORD64 Rbx;
	DWORD64 Rsp;
	DWORD64 Rbp;
	DWORD64 Rsi;
	DWORD64 Rdi;
	DWORD64 R8;
	DWORD64 R9;
	DWORD64 R10;
	DWORD64 R11;
	DWORD64 R12;
	DWORD64 R13;
	DWORD64 R14;
	DWORD64 R15;
	DWORD64 Rip;
	DWORD EFlags;
};
#pragma pack(pop)

//
// Retrieves the address of a register.
//
static PVOID GetRegAddr(CpuState *State, ud_type r);