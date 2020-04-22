// MyImportResolution.cpp : Defines the exported functions for the DLL.
//

#include "pch.h"
#include "framework.h"
#include "MyImportResolution.h"



VOID ParseForwardExport(LPCSTR lpForwardStr, LPSTR& lpForwardDll, LPSTR& lpForwardProc);

MYIMPORTRESOLUTION_API FARPROC MyGetProcAddress(HMODULE hModule, LPCSTR lpProcName)
{
    if (hModule == NULL || lpProcName == NULL)
        return NULL;

    // Get a pointer to export dirctory
    BYTE* pBaseAddr = reinterpret_cast<BYTE*>(hModule);
    auto pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER *>(hModule);
    if (pDosHeader->e_magic != 0x5A4D)
        return NULL;
    auto pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pBaseAddr + pDosHeader->e_lfanew);
    if (pNtHeader->Signature != 0x00004550)
        return NULL;
    auto pOptionalHeader = reinterpret_cast<IMAGE_OPTIONAL_HEADER*>(&pNtHeader->OptionalHeader);
    auto pExportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(pBaseAddr + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    
    DWORD pFuncRVA;
    // If it is resolution by oridinal, then top word will be zero and bottom word will have oridinal number. 
    if ((((UINT32)(lpProcName)) & 0xFFFF00000) == 0)
    {
        auto  Ordinal = (USHORT)(((UINT32)(lpProcName)) & 0x0000FFFF);
        if (Ordinal > pExportDir->NumberOfFunctions)
            return NULL;

        pFuncRVA = reinterpret_cast<DWORD*>(pBaseAddr + pExportDir->AddressOfFunctions)[Ordinal - 1];
    }
    else
    {
        //Iterate through Names Array and find the required function.
        USHORT OrdinalIndex = -1;
        auto pArrayOfNamesRVA = reinterpret_cast<DWORD*>(pBaseAddr + pExportDir->AddressOfNames);
        for (UINT i = 0; i < pExportDir->NumberOfNames; i++)
        {
            auto lpCurrentName = reinterpret_cast<LPCSTR>(pBaseAddr + pArrayOfNamesRVA[i]);
            if (strcmp(lpProcName, lpCurrentName) == 0)
            {
                OrdinalIndex = reinterpret_cast<USHORT*>(pBaseAddr + pExportDir->AddressOfNameOrdinals)[i];
                break;
            }
        }
        //if unable to find the name, return NULL
        if (OrdinalIndex == -1)
            return NULL;
        //Get the function RVA
        pFuncRVA = reinterpret_cast<DWORD*>(pBaseAddr + pExportDir->AddressOfFunctions)[OrdinalIndex];
    }

    
    //if FuncRVA points inside the import directory,it is an forwarded export
    auto pExportDirStart = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
    auto pExportDirEnd = pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
    if (pFuncRVA > pExportDirStart && pFuncRVA < pExportDirEnd)
    {
        LPCSTR lpForwardStr = reinterpret_cast<LPCSTR>(pBaseAddr + pFuncRVA);
        LPSTR lpForwardDll, lpForwardProc;
        ParseForwardExport(lpForwardStr, lpForwardDll, lpForwardProc);
        HMODULE hForwardDll = LoadLibraryA(lpForwardDll);
        return MyGetProcAddress(hForwardDll, lpForwardProc); //Recursively call the MyGetProcAddress
    }

    return reinterpret_cast<FARPROC>(pBaseAddr + pFuncRVA);
}

/*
* Parses the forwarded export string of format <Dllname>.<ProcName>
* Parameters:
*   lpForwardStr: forwarded export string NDLL.EnterCriticalSection
*   lpForwardDll: reference to variable that will set to DllName eg NTDLL.dll
*   lpForwardProc: reference to variable that will set to ProcName eg EnterCriticalSection
*/
VOID ParseForwardExport(LPCSTR lpForwardStr, LPSTR &lpForwardDll,  LPSTR &lpForwardProc)
{
 
    auto lpPeriod = strchr(lpForwardStr, '.');
    auto DllNameLen = (UINT)(lpPeriod - lpForwardStr);
    auto ProcNameLen = (UINT)(strlen(lpForwardStr) - DllNameLen - 1);
    
    lpForwardDll = new CHAR[DllNameLen + 5]; //5 byte extra for ".dll\0"
    lpForwardProc = new CHAR[ProcNameLen + 1];

    memcpy_s(lpForwardDll, DllNameLen, lpForwardStr, DllNameLen);
    strncpy_s(&lpForwardDll[DllNameLen], 5, ".dll", 5);

    strncpy_s(lpForwardProc, ProcNameLen + 1, lpPeriod + 1, ProcNameLen + 1);

}
