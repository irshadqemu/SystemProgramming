#include "pch.h"
#include "framework.h"
#include "MyImportResolution.h"
#include <fstream>
#include <iostream>


//Set it to FALSE to force relocations code to execute
#define TRY_LOADIONG_AT_PREFERED_BASE_ADDR TRUE



MYIMPORTRESOLUTION_API HMODULE MyLoadLibraryA(LPCSTR lpLibFileName)
{
    auto * pPEStruct = new PEStruct; //user struct to hold the pointers to PE structures
  
    if (!ReadAndValidatePE(lpLibFileName,  pPEStruct))
    {
        return NULL;
    }
    if (!LoadPESection(pPEStruct))
    {
        return  NULL;
    }
    if (!FixRelocations(pPEStruct))
    {
        return  NULL;
    }
    if (!ResolveImportTable(pPEStruct))
    {
        return  NULL;
    }
    if (!FixSectionPerm(pPEStruct))
    {
        return NULL;
    }
    if (!ExecuteTLSCallBacks(pPEStruct))
    {

        return  NULL;
    }
    if (!CallDllMain(pPEStruct))
    {
        return NULL;
    }
    auto Result = pPEStruct->pBaseAddr;
    delete[] pPEStruct->pbPEData;
    delete pPEStruct;
    return reinterpret_cast<HMODULE>(Result);
}

//Read PE file,  preform signatures tests, sets the PE-Structures
BOOL ReadAndValidatePE(LPCSTR pcsFilename, PEStruct* pPEStruct)
{
    //Read file into  a buffer
    std::ifstream fdInFile(pcsFilename, std::ios::binary | std::ios::ate);
    if (!fdInFile.good())
    {
        std::cerr << "Unable to open the file " << pcsFilename << std::endl;
        fdInFile.close();
        return FALSE;
    }
    auto szFileSize = fdInFile.tellg();
    pPEStruct->szPEData = szFileSize;
    pPEStruct->pbPEData = new BYTE[szFileSize];
    if (!pPEStruct->pbPEData)
    {
        std::cerr << "Unable to allocate memory for reading PE file." << std::endl;
        fdInFile.close();
        return FALSE;
    }
    fdInFile.seekg(0, std::ios::beg);
    fdInFile.read(reinterpret_cast<char*>(pPEStruct->pbPEData), szFileSize);
    fdInFile.close();

    //MZ signature check
    pPEStruct->pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pPEStruct->pbPEData);
    if (pPEStruct->pDosHeader->e_magic != IMAGE_DOS_SIGNATURE)
    {
        std::cerr << pcsFilename << " is not a PE file." << std::endl;
        delete[] pPEStruct->pbPEData;
        return FALSE;
    }

    // Assign structure pointer
    pPEStruct->pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char*>(pPEStruct->pbPEData) + pPEStruct->pDosHeader->e_lfanew);
    //PE signature check
    if (pPEStruct->pNtHeader->Signature != IMAGE_NT_SIGNATURE)
    {
        std::cerr << pcsFilename << " is not a PE file." << std::endl;
        delete[] pPEStruct->pbPEData;
        return FALSE;
    }
    pPEStruct->pOptionalHeader = &pPEStruct->pNtHeader->OptionalHeader;
    pPEStruct->pFileHeader = &pPEStruct->pNtHeader->FileHeader;

    //Perform check for valid palateform
#ifdef _WIN64
    if (pPEStruct->pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::cerr << "Invalid machine architecture. PE is not a 64bit file" << std::endl;
        delete[] pPEStruct->pbPEData;
        return FALSE;
    }
#else
    if (pPEStruct->pFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::cerr << "Invalid machine architecture. PE is not a 32bit file" << std::endl;
        delete[] pPEStruct->pbPEData;
        return FALSE;

    }
#endif // _WIN64
    return TRUE;
}


//Allocate memory and Copy Sections
BOOL LoadPESection(PEStruct* pPEStruct)
{

    if (TRY_LOADIONG_AT_PREFERED_BASE_ADDR)
    {
        pPEStruct->pBaseAddr = reinterpret_cast<BYTE*> (VirtualAlloc(reinterpret_cast<LPVOID>(pPEStruct->pOptionalHeader->ImageBase), pPEStruct->pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    }
    if (!pPEStruct->pBaseAddr)
    {
        //If file is not relocatable return 
        if (pPEStruct->pFileHeader->Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
        {
            std::cerr << "Unable to load the Dll at preffered address. It is not relocatable.";
            return FALSE;
        }
        pPEStruct->pBaseAddr = reinterpret_cast<BYTE*> (VirtualAlloc(nullptr, pPEStruct->pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
        if (!pPEStruct->pBaseAddr)
        {
            std::cerr << "Unable to reserve meory for PE file" << std::endl;
            delete[] pPEStruct->pbPEData;
            return FALSE;
        }
    }

    
 
    if (pPEStruct->pOptionalHeader->SizeOfHeaders > pPEStruct->szPEData)
    {
        std::cerr << "pOptionalHeader->SizeOfHeaders is greater than raw file size. Corrupt file?";
        return FALSE;
    }

    //Copy the headers + section table
    CopyMemory(pPEStruct->pBaseAddr, pPEStruct->pbPEData, pPEStruct->pOptionalHeader->SizeOfHeaders);
    
    //Copy the sections
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pPEStruct->pNtHeader);
    for (UINT i = 0; i < pPEStruct->pFileHeader->NumberOfSections; i++, pSectionHeader++)
    {
        LPVOID pVirutalAddress = pPEStruct->pBaseAddr + pSectionHeader->VirtualAddress;
        LPVOID pPointertoRawData = pPEStruct->pbPEData + pSectionHeader->PointerToRawData;
       
        //check  pPointertoRawData doesn't point outside of array pbPEData
        auto RawPointerEnd = (UINT)((BYTE *)(pPointertoRawData) - pPEStruct->pbPEData) + pSectionHeader->SizeOfRawData;
        if (RawPointerEnd > pPEStruct->szPEData)
        {
            std::cerr << "RawPointer for section " << pSectionHeader->Name << " points outside the raw file. Corrupt file?" << std::endl;
            return FALSE;

        }

        CopyMemory(pVirutalAddress, pPointertoRawData, pSectionHeader->SizeOfRawData);
    }


    return TRUE;

}


//Fix Relocation
BOOL FixRelocations(PEStruct* pPEStruct)
{
    BYTE* RelocationDelta = pPEStruct->pBaseAddr - pPEStruct->pOptionalHeader->ImageBase;
    if (RelocationDelta)//if delta is zero no need for relocations
    {
        //If relocation size is zero, no need for relocation
        if (!pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            return TRUE;
        }

        //Get the virtual address of first IMAGE_BASE_RELOCATION structure
        auto* pRelocationStructure = reinterpret_cast<IMAGE_BASE_RELOCATION*> (pPEStruct->pBaseAddr + pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);

        //Go through each relocation structure and fix relocations
        while (pRelocationStructure->VirtualAddress)
        {

            UINT NumberOfEntries = (pRelocationStructure->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);

            //Get the pointer to first relocation entry
            WORD* pwRelocationInfo = reinterpret_cast<WORD*>(pRelocationStructure + 1);

            for (UINT i = 0; i < NumberOfEntries; i++, pwRelocationInfo++)
            {
                //Top 4 bits dnote the type, bottom 12 bits denote the relocation value
                WORD RelocationType = (*pwRelocationInfo) >> 12;
                WORD RelocationOffsetValue = (*pwRelocationInfo) & 0x0FFF;

#ifdef _WIN64
                if (RelocationType == IMAGE_REL_BASED_DIR64)
                {
                    UINT_PTR* pByteToBePatched = reinterpret_cast<UINT_PTR*>(pPEStruct->pBaseAddr + pRelocationStructure->VirtualAddress + RelocationOffsetValue);
                    *pByteToBePatched += reinterpret_cast<UINT_PTR>(RelocationDelta);
                }
#else
                if (RelocationType == IMAGE_REL_BASED_HIGHLOW)
                {
                    UINT* pByteToBePatched = reinterpret_cast<UINT*>(pPEStruct->pBaseAddr + pRelocationStructure->VirtualAddress + RelocationOffsetValue);
                    *pByteToBePatched += reinterpret_cast<UINT_PTR>(RelocationDelta);
                }

#endif // _WIN64

                //If not padding/skipable relocation type, print error
                else if (RelocationType != IMAGE_REL_BASED_ABSOLUTE)
                {
                    std::cerr << "Unable to fix the relocation Type: " << RelocationType << " Relocation Offset: " << RelocationOffsetValue << " RVA: " << pRelocationStructure->VirtualAddress << std::endl;
                }

            }
            pRelocationStructure = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocationStructure) + pRelocationStructure->SizeOfBlock);

        }
    }
    return TRUE;
}


//Fix Import Table
BOOL ResolveImportTable(PEStruct* pPEStruct)
{
    //If size of Imports in DataDirectory is zero, no imports to resolve
    if (!pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        return TRUE;
    }
    // Get the VA of first import structure
    auto* pImportDescriptorStruct = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pPEStruct->pBaseAddr + pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for (; pImportDescriptorStruct->Name; pImportDescriptorStruct++)
    {
        //Get the name of the DLL and load it
        LPCSTR psImportDllName = reinterpret_cast<LPCSTR>(pPEStruct->pBaseAddr + pImportDescriptorStruct->Name);
        HMODULE hDll = LoadLibraryA(psImportDllName);
        if (hDll == NULL)
        {
            std::cerr << "Unable to load library: " << psImportDllName << "Last Error Code: " << GetLastError << ::std::endl;
            return FALSE;
        }

        // Iterate through thunk arrays and resolve each API 
        ULONG_PTR* pOrignalFirstThunk = reinterpret_cast<ULONG_PTR*>(pPEStruct->pBaseAddr + pImportDescriptorStruct->OriginalFirstThunk);
        ULONG_PTR* pFirstThunk = reinterpret_cast<ULONG_PTR*>(pPEStruct->pBaseAddr + pImportDescriptorStruct->FirstThunk);

        //Some packers don't set the OrignalFirstThunk
        if (!pOrignalFirstThunk)
            pOrignalFirstThunk = pFirstThunk;
        for (; *pFirstThunk; pFirstThunk++, pOrignalFirstThunk++)
        {
            //Import by oridinal
            if (IMAGE_SNAP_BY_ORDINAL(*pOrignalFirstThunk))
            {
                *pFirstThunk = reinterpret_cast<ULONG_PTR> (GetProcAddress(hDll, reinterpret_cast<LPCSTR>(*pOrignalFirstThunk && 0xFFFF)));

            }
            else
            {
                auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pPEStruct->pBaseAddr + *pOrignalFirstThunk);
                *pFirstThunk = reinterpret_cast<ULONG_PTR>(GetProcAddress(hDll, pImportByName->Name));
            }
        }

    }

    return TRUE;
}

//Converts the sections characteristics to permissions 
// that can be used be used with VirtualProtect
DWORD SecPerm2PagePerm(const DWORD SecPerm)
{
    static DWORD Secp2PagePerm[2][2][2] = {
    {
            /* not executable */
            {PAGE_NOACCESS, PAGE_WRITECOPY},
            {PAGE_READONLY, PAGE_READWRITE}
        },
        {
            /* executable */
            {PAGE_EXECUTE, PAGE_EXECUTE_WRITECOPY},
            {PAGE_EXECUTE_READ, PAGE_EXECUTE_READWRITE}
        }
    };
  
    UINT Readable, Writeable, Executable; 
    Executable = (SecPerm & IMAGE_SCN_MEM_EXECUTE) != 0;
    Readable = (SecPerm & IMAGE_SCN_MEM_READ) != 0;
    Writeable = (SecPerm & IMAGE_SCN_MEM_WRITE) != 0;
    DWORD PagePerm = Secp2PagePerm[Executable][Readable][Writeable];

    if (SecPerm & IMAGE_SCN_MEM_NOT_CACHED)
    {
        PagePerm |= PAGE_NOCACHE;
    }

    return PagePerm;
}

//Apply proper permissions to all of the sections
BOOL FixSectionPerm(PEStruct* pPEStruct)
{
    //Mark PE header read-only
    DWORD NewProtect, OldProtect; 
    VirtualProtect(pPEStruct->pBaseAddr, pPEStruct->pOptionalHeader->SizeOfHeaders, PAGE_READONLY, &OldProtect);
    
    //Copy the sections
    auto* pSectionHeader = IMAGE_FIRST_SECTION(pPEStruct->pNtHeader);
    for (UINT i = 0; i < pPEStruct->pFileHeader->NumberOfSections; i++, pSectionHeader++)
    {
        LPVOID pVirutalAddress = pPEStruct->pBaseAddr + pSectionHeader->VirtualAddress;

        //Free discarable section
        if (pSectionHeader->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
        {
            VirtualFree(pVirutalAddress, pSectionHeader->Misc.VirtualSize, MEM_DECOMMIT);
            continue;
        }
        NewProtect = SecPerm2PagePerm(pSectionHeader->Characteristics);
       VirtualProtect(pVirutalAddress, pSectionHeader->Misc.VirtualSize, NewProtect, &OldProtect);
    }
    return TRUE;
}
BOOL ExecuteTLSCallBacks(PEStruct* pPEStruct)
{   //Check the size of TLS callback from data directory
    if (pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pImageTlsDir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pPEStruct->pBaseAddr + pPEStruct->pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);

        //Get array of TLS callbacks address
        auto* pCallBackAddr = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pImageTlsDir->AddressOfCallBacks);
        for (; *pCallBackAddr; pCallBackAddr++)
            (*pCallBackAddr)(pPEStruct->pBaseAddr, DLL_PROCESS_ATTACH, nullptr);
    }
    return TRUE;
}

//Call Entrypoint
BOOL CallDllMain(PEStruct* pPEStruct)
{

    BOOL Result = FALSE;
    //check if DllMain exists
    if (pPEStruct->pOptionalHeader->AddressOfEntryPoint)
    {
        auto MyDllMain = reinterpret_cast<DLL_ENTRY_POINT>(pPEStruct->pBaseAddr + pPEStruct->pOptionalHeader->AddressOfEntryPoint);
        Result = MyDllMain(pPEStruct->pBaseAddr, DLL_PROCESS_ATTACH, NULL);
    }

  
    return Result;
}