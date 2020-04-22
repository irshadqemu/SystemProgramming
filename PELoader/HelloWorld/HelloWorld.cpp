// HelloWorld.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <iostream>
#include <Windows.h>




VOID WINAPI tls_callback1( PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    std::cout << "I am executing from TLS CallBack 1\n";
}
VOID WINAPI tls_callback2( PVOID DllHandle, DWORD Reason, PVOID Reserved)
{
    std::cout << "I am executing from TLS CallBack 2\n";
}


#ifdef _WIN64
    #pragma comment (linker, "/INCLUDE:_tls_used")
    #pragma comment (linker, "/INCLUDE:p_tls_callback1")
    #pragma const_seg(push)
    #pragma const_seg(".CRT$XLAAA")
    EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
    #pragma const_seg(".CRT$XLAAB")
    EXTERN_C const PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
    #pragma const_seg(pop)
#else
    #pragma comment (linker, "/INCLUDE:__tls_used")
    #pragma comment (linker, "/INCLUDE:_p_tls_callback1")
    #pragma data_seg(push)
    #pragma data_seg(".CRT$XLAAA")
    EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback1 = tls_callback1;
    #pragma data_seg(".CRT$XLAAB")
    EXTERN_C PIMAGE_TLS_CALLBACK p_tls_callback2 = tls_callback2;
    #pragma data_seg(pop)
#endif // _WIN64







int a = 20;
int b = 30;
int add(int c, int d);
int main()
{
    std::cout << "Hello World!\n"<<"Sum of the number is :" << add(a, b)<<std::endl;
    getchar();
    return 0;

}

int add(int d, int c)
{
    return d + c;
}
// Run program: Ctrl + F5 or Debug > Start Without Debugging menu
// Debug program: F5 or Debug > Start Debugging menu

// Tips for Getting Started: 
//   1. Use the Solution Explorer window to add/manage files
//   2. Use the Team Explorer window to connect to source control
//   3. Use the Output window to see build output and other messages
//   4. Use the Error List window to view errors
//   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
//   6. In the future, to open this project again, go to File > Open > Project and select the .sln file
