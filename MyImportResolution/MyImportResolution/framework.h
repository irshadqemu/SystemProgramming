#pragma once
#include <windows.h>
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers
//Function Prototypes
//Read PE file,  preform signatures tests, sets the PE-Structures
BOOL ReadAndValidatePE(LPCSTR pcsFilename);
//Allocate memory and Copy Sections
BOOL LoadPESection();
//Fix Relocation
BOOL FixRelocations();
//Fix Import Table
BOOL ResolveImportTable();

//Apply proper permissions to all of the sections.
BOOL FixSectionPerm();

BOOL ExecuteTLSCallBacks();

BOOL CallDllMain();
VOID ParseForwardByName(LPCSTR lpForwardStr, LPSTR& lpForwardDll, LPSTR& lpForwardProc);
VOID ParseForwardByOrdinal(LPCSTR lpForwardStr, LPSTR& lpForwardDll, UINT& ForwardProc);

using DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);