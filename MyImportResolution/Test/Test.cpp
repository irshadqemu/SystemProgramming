

#include <iostream>
#include <Windows.h>
#include "MyImportResolution.h"

DWORD WINAPI LoadAndCall(_In_ LPVOID lpDllName);

int main()
{
    auto hEmptyFile = MyLoadLibraryA("..\\Debug\\ZeroByteFile.dll");
    if (hEmptyFile == NULL)
    {
        std::cout << "Uanble to load ZeroByteFile.dll" << std::endl;
    }
    auto hOneByeFile = MyLoadLibraryA("..\\Debug\\OneByteFile.dll");
    if (hOneByeFile == NULL)
    {
        std::cout << "Uanble to load OneByteFile.dll" << std::endl;
    }
    auto hNonExistantFile = MyLoadLibraryA("..\\Debug\\NonExistantFile.dll");
    if (hNonExistantFile == NULL)
    {
        std::cout << "Uanble to load NonExistantFile.dll" << std::endl;
    }

    DWORD ThreadId;
    HANDLE hThread;
#ifdef _WIN64 

    const char* lpDllName = "..\\Debug\\ordx.dll";
    hThread = CreateThread(NULL, 0, LoadAndCall, (LPVOID)(lpDllName), 0, &ThreadId);

#else
    auto hTestFile = MyLoadLibraryA("..\\Debug\\test1_p.exe");
    if (hNonExistantFile == NULL)
    {
        std::cout << "Uanble to load test1_p.exe" << std::endl;
    }
    const char* lpDllName = "..\\Debug\\ord.dll";
    hThread = CreateThread(NULL, 0, LoadAndCall, (LPVOID)(lpDllName), 0, &ThreadId);


#endif // _WIN64
    WaitForSingleObject(hThread, INFINITE);
    std::cout << "Thread has completed.";

   return 0;
}


DWORD WINAPI LoadAndCall( _In_ LPVOID lpDllName)
{
    
    auto hOrd = MyLoadLibraryA(reinterpret_cast<LPCSTR>(lpDllName));
    if (!hOrd)
    {
        return -1;
    }
    auto pOrd123_1 = MyGetProcAddress(hOrd, MAKEINTRESOURCE(123));
    printf("MyGetProcAddress: ordinal #123: 0x%p\n", (void*)pOrd123_1);
    if (!pOrd123_1)
    {
        return -1;
    }
    pOrd123_1();
    return  0;
}

/*
void TestMyGetProcAddress()
{
    HMODULE hK32Dll = LoadLibraryA("kernel32.dll");
    if (hK32Dll == NULL)
    {
        std::cerr << "Unable to load the kernel 32 library. Error Code:" << GetLastError() << std::endl;
    }
#ifdef _WIN64 
    //Resolve AirtualAlloc by name
    auto pVirtualAlloc_1 = MyGetProcAddress(hK32Dll, "VirtualAlloc");
    auto pVirtualAlloc_x = GetProcAddress(hK32Dll, "VirtualAlloc");
    printf("MyGetProcAddress: VirualAlloc address by name: 0x%p\n", (void*)pVirtualAlloc_1);
    printf("GetProcAddress: VirualAlloc address by name  : 0x%p\n\n", (void*)pVirtualAlloc_x);

    //Resolve VirualAlloc by oridianl
    pVirtualAlloc_1 = MyGetProcAddress(hK32Dll, MAKEINTRESOURCE(0x5D6));
    pVirtualAlloc_x = GetProcAddress(hK32Dll, MAKEINTRESOURCE(0x5D6));
    printf("MyGetProcAddress: VirualAlloc address by ordinal: 0x%p\n", (void*)pVirtualAlloc_1);
    printf("GetProcAddress: VirualAlloc address by ordinal  : 0x%p\n\n", (void*)pVirtualAlloc_x);


    //Resolve forwareded export EnterCriticalSection by name
    auto pEnterCriticalSection_1 = MyGetProcAddress(hK32Dll, "EnterCriticalSection");
    auto pEnterCriticalSection_x = GetProcAddress(hK32Dll, "EnterCriticalSection");
    printf("MyGetProcAddress: EnterCriticalSection address by name: 0x%p\n", (void*)pEnterCriticalSection_1);
    printf("GetProcAddress: EnterCriticalSection address by name  : 0x%p\n\n", (void*)pEnterCriticalSection_x);

    //Resolve forwareded export EnterCriticalSection by oridinal
    pEnterCriticalSection_1 = MyGetProcAddress(hK32Dll, MAKEINTRESOURCE(0x136));
    pEnterCriticalSection_x = GetProcAddress(hK32Dll, MAKEINTRESOURCE(0x136));
    printf("MyGetProcAddress: EnterCriticalSection address by oridinal: 0x%p\n", (void*)pEnterCriticalSection_1);
    printf("GetProcAddress: EnterCriticalSection address by ordinal   : 0x%p\n\n", (void*)pEnterCriticalSection_x);

#else
    //Resolve AirtualAlloc by name
    auto pVirtualAlloc_1 = MyGetProcAddress(hK32Dll, "VirtualAlloc");
    auto pVirtualAlloc_x = GetProcAddress(hK32Dll, "VirtualAlloc");
    printf("MyGetProcAddress: VirualAlloc address by name: 0x%p\n", (void*)pVirtualAlloc_1);
    printf("GetProcAddress: VirualAlloc address by name  : 0x%p\n\n", (void*)pVirtualAlloc_x);

    //Resolve VirualAlloc by oridianl
    pVirtualAlloc_1 = MyGetProcAddress(hK32Dll, MAKEINTRESOURCE(0x5C8));
    pVirtualAlloc_x = GetProcAddress(hK32Dll, MAKEINTRESOURCE(0x5C8));
    printf("MyGetProcAddress: VirualAlloc address by ordinal: 0x%p\n", (void*)pVirtualAlloc_1);
    printf("GetProcAddress: VirualAlloc address by ordinal  : 0x%p\n\n", (void*)pVirtualAlloc_x);


    //Resolve forwareded export EnterCriticalSection by name
    auto pEnterCriticalSection_1 = MyGetProcAddress(hK32Dll, "EnterCriticalSection");
    auto pEnterCriticalSection_x = GetProcAddress(hK32Dll, "EnterCriticalSection");
    printf("MyGetProcAddress: Forwareded Export EnterCriticalSection address by name: 0x%p\n", (void*)pEnterCriticalSection_1);
    printf("GetProcAddress: Forwarded Export EnterCriticalSection address by name  : 0x%p\n\n", (void*)pEnterCriticalSection_x);

    //Resolve forwareded export EnterCriticalSection by oridinal
    pEnterCriticalSection_1 = MyGetProcAddress(hK32Dll, MAKEINTRESOURCE(0x133));
    pEnterCriticalSection_x = GetProcAddress(hK32Dll, MAKEINTRESOURCE(0x133));
    printf("MyGetProcAddress: Forwareded Export  EnterCriticalSection address by oridinal: 0x%p\n", (void*)pEnterCriticalSection_1);
    printf("GetProcAddress:  Forwareded Export EnterCriticalSection address by ordinal   : 0x%p\n\n", (void*)pEnterCriticalSection_x);

    
    //Another test
    HMODULE hOrd = LoadLibraryA("..\\Release\\ord.dll");
    auto pOrd123_x = GetProcAddress(hOrd, MAKEINTRESOURCE(123));
    auto pOrd123_1 = MyGetProcAddress(hOrd, MAKEINTRESOURCE(123));
    printf("MyGetProcAddress: ordinal #123: 0x%p\n", (void*)pOrd123_1);
    printf("GetProcAddress:  ordinal #123 : 0x%p\n\n", (void*)pOrd123_x);
    pOrd123_1();
   
#endif // _WIN64 

}*/