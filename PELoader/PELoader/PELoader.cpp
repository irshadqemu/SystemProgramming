
#include "PELoader.h"


#ifdef _WIN64
LPCSTR pcsExecutablePath = "..\\x64\\Debug\\HelloWorld.exe";
#else
LPCSTR pcsExecutablePath =  "..\\Debug\\HelloWorld.exe"; 
#endif // _WIN64

//Set it to FALSE to force relocations code to execute
#define TRY_LOADIONG_AT_PREFERED_BASE_ADDR FALSE


//Define PE structures
BYTE * pbPEData                         = nullptr;
IMAGE_DOS_HEADER* pDosHeader            = nullptr;
IMAGE_NT_HEADERS * pNtHeader            = nullptr;
IMAGE_FILE_HEADER* pFileHeader          = nullptr;
IMAGE_OPTIONAL_HEADER* pOptionalHeader  = nullptr;
BYTE * pBaseAddr                        = nullptr;


int main()
{
    if (!ReadAndValidatePE(pcsExecutablePath))
    {
        std::cerr << "Error in function ReadAndValidatePE\n";
        return -1;
    }
    if (!LoadPESection())
    {
        std::cerr << "Error in function LoadPESection\n";
        return -1;
    }
    if (!FixRelocations())
    {
        std::cerr << "Error in function FixRelocations\n";
        return -1;
    }
    if (!ResolveImportTable())
    {
        std::cerr << "Error in function ResolveImportTable\n";
        return -1;
    }
    if (!ExecuteTLSCallBacks())
    {
        std::cerr << "Error in functionExecuteTLSCallBacks\n";
        return -1;
    }
    return CallEntryPoint();
}

//Read PE file,  preform signatures tests, sets the PE-Structures
BOOL ReadAndValidatePE(LPCSTR pcsFilename)
{
    //Read file into  a buffer
    std::ifstream fdInFile(pcsFilename, std::ios::binary|std::ios::ate);
    if (!fdInFile.good())
    {
        std::cerr << "Unable to open the file " << pcsFilename<<std::endl;
        fdInFile.close();
        return FALSE;
    }
    auto szFileSize = fdInFile.tellg();
    pbPEData = new BYTE[szFileSize];
    if (!pbPEData)
    {
        std::cerr << "Unable to allocate memory for reading PE file." << std::endl;
        fdInFile.close();
        return FALSE;
    }
    fdInFile.seekg(0, std::ios::beg);
    fdInFile.read(reinterpret_cast<char*>(pbPEData), szFileSize);
    fdInFile.close();

    //MZ signature check
    pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER * >(pbPEData);
    if (pDosHeader->e_magic != 0x5A4D)
    {
        std::cerr << pcsFilename << " is not a PE file." << std::endl;
        delete[] pbPEData;
        return FALSE;
    }

    // Assign structure pointer
    pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<char*>(pbPEData) + pDosHeader->e_lfanew);
    //PE signature check
    if (pNtHeader->Signature != 0x00004550)
    {
        std::cerr << pcsFilename << " is not a PE file." << std::endl;
        delete[] pbPEData;
        return FALSE;
    }
    pOptionalHeader = &pNtHeader->OptionalHeader;
    pFileHeader = &pNtHeader->FileHeader;

    //Perform check for valid palateform
#ifdef _WIN64
    if (pFileHeader->Machine != IMAGE_FILE_MACHINE_AMD64)
    {
        std::cerr << "Invalid machine architecture. PE is not a 64bit file" << std::endl;
        delete[] pbPEData;
        return FALSE;
    }
#else
    if (pFileHeader->Machine != IMAGE_FILE_MACHINE_I386)
    {
        std::cerr << "Invalid machine architecture. PE is not a 32bit file" << std::endl;
        delete[] pbPEData;
        return FALSE;

    }
#endif // _WIN64
    return TRUE;
}


//Allocate memory and Copy Sections
BOOL LoadPESection()
{
    
    if (TRY_LOADIONG_AT_PREFERED_BASE_ADDR)
    {
        pBaseAddr = reinterpret_cast<BYTE*> (VirtualAlloc(reinterpret_cast<LPVOID>(pOptionalHeader->ImageBase), pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    }
      if (!pBaseAddr)
      {
         pBaseAddr = reinterpret_cast<BYTE*> (VirtualAlloc(nullptr, pOptionalHeader->SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
         if (!pBaseAddr)
         {
             std::cerr << "Unable to reserve meory for PE file" << std::endl;
             delete[] pbPEData;
             return FALSE;
         }
      }

    //Copy the headers + section table
     CopyMemory(pBaseAddr, pbPEData, pOptionalHeader->SizeOfHeaders);

     //Copy the sections
     auto * pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
     for (UINT i = 0; i < pFileHeader->NumberOfSections; i++, pSectionHeader++)
     {
         LPVOID pVirutalAddress = pBaseAddr + pSectionHeader->VirtualAddress;
         LPVOID pPointertoRawData =  pbPEData + pSectionHeader->PointerToRawData;
         CopyMemory(pVirutalAddress, pPointertoRawData,  pSectionHeader->SizeOfRawData);
     }
       
     
     return TRUE;
    
}


//Fix Relocation
BOOL FixRelocations()
{
    BYTE * RelocationDelta = pBaseAddr - pOptionalHeader->ImageBase;
    if (RelocationDelta)//if delta is zero no need for relocations
    {
        //If relocation size is zero, no need for relocation
        if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
        {
            return TRUE;
        }

        //Get the virtual address of first IMAGE_BASE_RELOCATION structure
        auto * pRelocationStructure = reinterpret_cast<IMAGE_BASE_RELOCATION*> (pBaseAddr + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress);
        
        //Go through each relocation structure and fix relocations
        while (pRelocationStructure->VirtualAddress)
        {
            
            UINT NumberOfEntries = (pRelocationStructure->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            
            //Get the pointer to first relocation entry
            WORD * pwRelocationInfo = reinterpret_cast<WORD*>(pRelocationStructure + 1);

            for (UINT i = 0; i < NumberOfEntries; i++, pwRelocationInfo++)
            {
                //Top 4 bits dnote the type, bottom 12 bits denote the relocation value
                WORD RelocationType = (*pwRelocationInfo) >> 12;
                WORD RelocationOffsetValue = (*pwRelocationInfo) & 0x0FFF;
                
#ifdef _WIN64
                if (RelocationType == IMAGE_REL_BASED_DIR64)
                {
                    UINT_PTR* pByteToBePatched = reinterpret_cast<UINT_PTR*>(pBaseAddr + pRelocationStructure->VirtualAddress + RelocationOffsetValue);
                    *pByteToBePatched += reinterpret_cast<UINT_PTR>(RelocationDelta);
                }
#else
                if (RelocationType == IMAGE_REL_BASED_HIGHLOW)
                {
                    UINT* pByteToBePatched = reinterpret_cast<UINT*>(pBaseAddr + pRelocationStructure->VirtualAddress + RelocationOffsetValue);
                    *pByteToBePatched += reinterpret_cast<UINT_PTR>(RelocationDelta);
                }

#endif // _WIN64

                //If not padding/skipable relocation type, print error
                else if (RelocationType != IMAGE_REL_BASED_ABSOLUTE)
                {
                    std::cerr << "Unable to fix the relocation Type: " << RelocationType << " Relocation Offset: " << RelocationOffsetValue << " RVA: " << pRelocationStructure->VirtualAddress << std::endl;
                }

            }
            pRelocationStructure = reinterpret_cast<IMAGE_BASE_RELOCATION*>( reinterpret_cast<BYTE*>(pRelocationStructure) + pRelocationStructure->SizeOfBlock);

        }
    }
    return TRUE;
}


//Fix Import Table
BOOL ResolveImportTable()
{
    //If size of Imports in DataDirectory is zero, no imports to resolve
    if (!pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
    {
        return TRUE;
    }
    // Get the VA of first import structure
    auto* pImportDescriptorStruct = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBaseAddr + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
    for(;pImportDescriptorStruct->Name; pImportDescriptorStruct++)
    {
        //Get the name of the DLL and load it
        LPCSTR psImportDllName = reinterpret_cast<LPCSTR>(pBaseAddr + pImportDescriptorStruct->Name);
        HMODULE hDll = LoadLibraryA(psImportDllName);
        if (hDll == NULL)
        {
            std::cerr << "Unable to load library: " << psImportDllName << "Last Error Code: " << GetLastError << ::std::endl;
            return FALSE;
        }

        // Iterate through thunk arrays and resolve each API 
        ULONG_PTR* pOrignalFirstThunk = reinterpret_cast<ULONG_PTR*>(pBaseAddr + pImportDescriptorStruct->OriginalFirstThunk);
        ULONG_PTR* pFirstThunk = reinterpret_cast<ULONG_PTR*>(pBaseAddr + pImportDescriptorStruct->FirstThunk);

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
                auto* pImportByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBaseAddr + *pOrignalFirstThunk);
                *pFirstThunk = reinterpret_cast<ULONG_PTR>(GetProcAddress(hDll, pImportByName->Name));
            }
        }

    }

    return TRUE;
}


BOOL ExecuteTLSCallBacks()
{   //Check the size of TLS callback from data directory
    if (pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].Size)
    {
        auto* pImageTlsDir = reinterpret_cast<IMAGE_TLS_DIRECTORY*>(pBaseAddr + pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS].VirtualAddress);
        
        //Get array of TLS callbacks address
        auto* pCallBackAddr = reinterpret_cast<PIMAGE_TLS_CALLBACK*>(pImageTlsDir->AddressOfCallBacks);
        for (; *pCallBackAddr; pCallBackAddr++)
            (*pCallBackAddr)(pBaseAddr, DLL_PROCESS_ATTACH, nullptr);
    }
    return TRUE;
}
//Call Entrypoint
int CallEntryPoint()
{

    int (*pMainFunction)() = reinterpret_cast<int(*)()>(pBaseAddr + pOptionalHeader->AddressOfEntryPoint);
    delete[] pbPEData;
    return pMainFunction();
}