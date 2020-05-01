#pragma once
#include <windows.h>
#define WIN32_LEAN_AND_MEAN             // Exclude rarely-used stuff from Windows headers

//A simple structure to hold the PE Structures offsets.
struct PEStruct
{
    //Pointer to raw PE file in memory
    BYTE* pbPEData = nullptr;
    // Total bytes in pbPEData;
    UINT szPEData = 0;        
    IMAGE_DOS_HEADER* pDosHeader = nullptr;
    IMAGE_NT_HEADERS* pNtHeader = nullptr;
    IMAGE_FILE_HEADER* pFileHeader = nullptr;
    IMAGE_OPTIONAL_HEADER* pOptionalHeader = nullptr;
    BYTE* pBaseAddr = nullptr;

}; 

//Function Prototypes
//Read PE file,  preform signatures tests, sets the PE-Structures
BOOL ReadAndValidatePE(LPCSTR pcsFilename, PEStruct * pPEStruct);
//Allocate memory and Copy Sections
BOOL LoadPESection(PEStruct* pPEStruct);
//Fix Relocation
BOOL FixRelocations(PEStruct* pPEStruct);
//Fix Import Table
BOOL ResolveImportTable(PEStruct* pPEStruct);

//Apply proper permissions to all of the sections.
BOOL FixSectionPerm(PEStruct* pPEStruct);

BOOL ExecuteTLSCallBacks(PEStruct* pPEStruct);

BOOL CallDllMain(PEStruct* pPEStruct);
VOID ParseForwardByName(LPCSTR lpForwardStr, LPSTR& lpForwardDll, LPSTR& lpForwardProc);
VOID ParseForwardByOrdinal(LPCSTR lpForwardStr, LPSTR& lpForwardDll, UINT& ForwardProc);

using DLL_ENTRY_POINT = BOOL(WINAPI*)(void* hDll, DWORD dwReason, void* pReserved);